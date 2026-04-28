import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ── Types ────────────────────────────────────────────────────────────────────

interface CyscanFinding {
  rule_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  file: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  snippet: string;
  cwe: string[];
  fix?: string;
  reachability?: string;
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

// ── State ────────────────────────────────────────────────────────────────────

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let cyscanPath: string | null = null;

// ── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('Cybrium');
  diagnostics = vscode.languages.createDiagnosticCollection('cybrium');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'cybrium.scanFile';
  statusBar.text = '$(shield) Cybrium';
  statusBar.tooltip = 'Click to scan current file';
  statusBar.show();

  context.subscriptions.push(diagnostics, statusBar, outputChannel);

  // Find cyscan binary
  cyscanPath = findCyscan();
  if (!cyscanPath) {
    outputChannel.appendLine('cyscan not found. Install: brew install cybrium-ai/cli/cyscan');
    statusBar.text = '$(shield) Cybrium (not installed)';
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else {
    outputChannel.appendLine(`cyscan found: ${cyscanPath}`);
  }

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('cybrium.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('cybrium.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('cybrium.openDashboard', () => openDashboard()),
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('cybrium');
      if (config.get<boolean>('autoScan', true)) {
        scanDocument(doc);
      }
    }),
  );

  // Scan open file on activation
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  // Code actions (quick fixes)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('*', new CybriumCodeActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );
}

export function deactivate() {
  diagnostics?.dispose();
  statusBar?.dispose();
  outputChannel?.dispose();
}

// ── Scanner ──────────────────────────────────────────────────────────────────

function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No file open to scan');
    return;
  }
  scanDocument(editor.document);
}

function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage('No workspace open');
    return;
  }

  statusBar.text = '$(loading~spin) Scanning workspace...';

  const target = folders[0].uri.fsPath;
  runCyscan(target, (findings) => {
    diagnostics.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const f of findings) {
      const uri = vscode.Uri.file(f.file);
      const key = uri.toString();
      if (!byFile.has(key)) { byFile.set(key, []); }
      byFile.get(key)!.push(findingToDiagnostic(f));
    }

    for (const [uriStr, diags] of byFile) {
      diagnostics.set(vscode.Uri.parse(uriStr), diags);
    }

    updateStatusBar(findings.length);
    vscode.window.showInformationMessage(`Cybrium: ${findings.length} finding(s) across workspace`);
  });
}

function scanDocument(doc: vscode.TextDocument) {
  if (!cyscanPath) { return; }
  if (doc.uri.scheme !== 'file') { return; }

  const filePath = doc.uri.fsPath;
  const ext = path.extname(filePath).slice(1);
  const supportedExts = [
    'py', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'go', 'java', 'kt',
    'rb', 'php', 'rs', 'c', 'h', 'cpp', 'cc', 'cs', 'swift', 'scala',
    'sh', 'bash', 'tf', 'hcl', 'yml', 'yaml', 'json',
  ];
  if (!supportedExts.includes(ext) && !doc.fileName.includes('Dockerfile')) { return; }

  statusBar.text = '$(loading~spin) Scanning...';

  // Write current buffer to temp file (unsaved changes)
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cybrium-'));
  const tmpFile = path.join(tmpDir, path.basename(filePath));
  fs.writeFileSync(tmpFile, doc.getText());

  runCyscan(tmpFile, (findings) => {
    // Map findings back to the original file path
    const diags = findings.map((f) => {
      f.file = filePath;
      return findingToDiagnostic(f);
    });

    diagnostics.set(doc.uri, diags);
    updateStatusBar(diags.length);

    // Cleanup
    try { fs.unlinkSync(tmpFile); fs.rmdirSync(tmpDir); } catch { /* ignore */ }
  });
}

function runCyscan(target: string, callback: (findings: CyscanFinding[]) => void) {
  if (!cyscanPath) { return; }

  const config = vscode.workspace.getConfiguration('cybrium');
  const minSeverity = config.get<string>('severityFilter', 'info');
  const minIdx = SEVERITY_ORDER.indexOf(minSeverity);

  const args = ['scan', target, '--format', 'json'];

  const proc = cp.spawn(cyscanPath, args, { timeout: 30000 });
  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
  proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });

  proc.on('close', (code) => {
    if (stderr) { outputChannel.appendLine(stderr); }

    try {
      const findings: CyscanFinding[] = JSON.parse(stdout);
      const filtered = findings.filter((f) => {
        const idx = SEVERITY_ORDER.indexOf(f.severity);
        return idx >= minIdx;
      });
      callback(filtered);
    } catch {
      // cyscan may output non-JSON (banner, warnings)
      // Try to extract JSON array from output
      const jsonStart = stdout.indexOf('[');
      const jsonEnd = stdout.lastIndexOf(']');
      if (jsonStart >= 0 && jsonEnd > jsonStart) {
        try {
          const findings: CyscanFinding[] = JSON.parse(stdout.slice(jsonStart, jsonEnd + 1));
          const filtered = findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) >= minIdx);
          callback(filtered);
          return;
        } catch { /* fall through */ }
      }
      outputChannel.appendLine(`cyscan output parse failed: ${stdout.slice(0, 200)}`);
      callback([]);
    }
  });

  proc.on('error', (err) => {
    outputChannel.appendLine(`cyscan error: ${err.message}`);
    callback([]);
  });
}

// ── Diagnostic Mapping ───────────────────────────────────────────────────────

function findingToDiagnostic(finding: CyscanFinding): vscode.Diagnostic {
  const range = new vscode.Range(
    Math.max(0, finding.line - 1),
    Math.max(0, finding.column - 1),
    Math.max(0, finding.end_line - 1),
    Math.max(0, finding.end_column - 1),
  );

  const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;
  const diag = new vscode.Diagnostic(range, finding.message, severity);

  diag.source = 'Cybrium';
  diag.code = {
    value: finding.rule_id,
    target: vscode.Uri.parse(`https://app.cybrium.ai/rules/${finding.rule_id}`),
  };

  // Add CWE tags
  if (finding.cwe.length > 0) {
    diag.tags = [];
  }

  // Store fix and metadata for code actions
  (diag as any)._cybriumFix = finding.fix;
  (diag as any)._cybriumSnippet = finding.snippet;
  (diag as any)._cybriumReachability = finding.reachability;

  // Add reachability info to message
  if (finding.reachability === 'unreachable') {
    diag.message += ' [unreachable — may be safe to ignore]';
    diag.severity = vscode.DiagnosticSeverity.Information;
  }

  return diag;
}

// ── Code Actions (Quick Fix) ─────────────────────────────────────────────────

class CybriumCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== 'Cybrium') { continue; }

      const fix = (diag as any)._cybriumFix as string | undefined;
      if (fix) {
        const action = new vscode.CodeAction(
          `Fix: ${diag.code?.toString() ?? 'vulnerability'}`,
          vscode.CodeActionKind.QuickFix,
        );
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(document.uri, diag.range, fix);
        action.diagnostics = [diag];
        action.isPreferred = true;
        actions.push(action);
      }

      // "Explain this vulnerability" action
      const explainAction = new vscode.CodeAction(
        `Explain: ${diag.code?.toString() ?? 'vulnerability'}`,
        vscode.CodeActionKind.QuickFix,
      );
      explainAction.command = {
        command: 'cybrium.explain',
        title: 'Explain vulnerability',
        arguments: [diag],
      };
      actions.push(explainAction);
    }

    return actions;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function findCyscan(): string | null {
  const config = vscode.workspace.getConfiguration('cybrium');
  const configured = config.get<string>('cyscanPath', '');
  if (configured && fs.existsSync(configured)) { return configured; }

  // Check common locations
  const candidates = [
    '/opt/homebrew/bin/cyscan',
    '/usr/local/bin/cyscan',
    '/usr/bin/cyscan',
    path.join(require('os').homedir(), '.cargo/bin/cyscan'),
  ];

  for (const c of candidates) {
    if (fs.existsSync(c)) { return c; }
  }

  // Try `which`
  try {
    const result = cp.execSync('which cyscan', { timeout: 3000 }).toString().trim();
    if (result && fs.existsSync(result)) { return result; }
  } catch { /* not found */ }

  return null;
}

function updateStatusBar(count: number) {
  if (count === 0) {
    statusBar.text = '$(shield) Cybrium: clean';
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = `$(shield) Cybrium: ${count} finding${count !== 1 ? 's' : ''}`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
}

function openDashboard() {
  const config = vscode.workspace.getConfiguration('cybrium');
  const url = config.get<string>('apiUrl', 'https://app.cybrium.ai');
  vscode.env.openExternal(vscode.Uri.parse(url));
}
