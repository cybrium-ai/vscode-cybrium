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
    vscode.commands.registerCommand('cybrium.explain', (diag: vscode.Diagnostic) => explainVulnerability(diag, context)),
    vscode.commands.registerCommand('cybrium.fixAll', () => fixAllFindings()),
    vscode.commands.registerCommand('cybrium.aiFixFile', () => aiFixCurrentFile()),
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

// ── AI Developer Assist ──────────────────────────────────────────────────────

function explainVulnerability(diag: vscode.Diagnostic, context: vscode.ExtensionContext) {
  const ruleId = typeof diag.code === 'object' && diag.code !== null
    ? (diag.code as { value: string }).value
    : String(diag.code ?? '');
  const snippet = (diag as any)._cybriumSnippet || '';
  const fix = (diag as any)._cybriumFix || '';
  const reachability = (diag as any)._cybriumReachability || '';
  const cweMatch = diag.message.match(/CWE-\d+/);
  const cwe = cweMatch ? cweMatch[0] : '';

  const panel = vscode.window.createWebviewPanel(
    'cybriumExplain',
    `Cybrium: ${ruleId}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  const severityColor: Record<string, string> = {
    [vscode.DiagnosticSeverity.Error.toString()]: '#ef4444',
    [vscode.DiagnosticSeverity.Warning.toString()]: '#f59e0b',
    [vscode.DiagnosticSeverity.Information.toString()]: '#3b82f6',
    [vscode.DiagnosticSeverity.Hint.toString()]: '#6b7280',
  };
  const color = severityColor[diag.severity.toString()] ?? '#9ca3af';

  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; color: #e8e8f0; background: #0c0c1a; line-height: 1.6; }
    h1 { font-size: 18px; color: ${color}; margin-bottom: 4px; }
    h2 { font-size: 14px; color: #9ca3af; margin: 20px 0 8px; text-transform: uppercase; letter-spacing: 0.05em; }
    code { background: #1a1a3a; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    pre { background: #12121e; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; border: 1px solid #2a2a3c; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .severity { background: ${color}22; color: ${color}; }
    .cwe { background: #3b82f622; color: #60a5fa; margin-left: 6px; }
    .reach { background: ${reachability === 'unreachable' ? '#22c55e22' : '#ef444422'}; color: ${reachability === 'unreachable' ? '#4ade80' : '#f87171'}; margin-left: 6px; }
    .section { margin: 16px 0; padding: 12px; background: #12121e; border-radius: 8px; border-left: 3px solid ${color}; }
    a { color: #7c5cfc; }
  </style>
</head>
<body>
  <h1>${ruleId}</h1>
  <div>
    <span class="badge severity">${diag.severity === 0 ? 'CRITICAL' : diag.severity === 1 ? 'HIGH' : diag.severity === 2 ? 'MEDIUM' : 'LOW'}</span>
    ${cwe ? `<span class="badge cwe">${cwe}</span>` : ''}
    ${reachability ? `<span class="badge reach">${reachability}</span>` : ''}
  </div>

  <h2>What's Wrong</h2>
  <div class="section">${diag.message.replace(/</g, '&lt;')}</div>

  ${snippet ? `
  <h2>Vulnerable Code</h2>
  <pre>${snippet.replace(/</g, '&lt;')}</pre>
  ` : ''}

  <h2>Why It Matters</h2>
  <div class="section">
    ${cwe === 'CWE-89' ? 'SQL injection allows attackers to execute arbitrary SQL queries, potentially reading, modifying, or deleting database records. It can lead to full database compromise.' :
      cwe === 'CWE-79' ? 'Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users, enabling session hijacking, credential theft, and defacement.' :
      cwe === 'CWE-798' ? 'Hardcoded credentials in source code can be extracted by anyone with access to the repository. If the credential is for a production system, it grants unauthorized access.' :
      cwe === 'CWE-327' ? 'Using weak or broken cryptographic algorithms (MD5, SHA1, DES) provides no real security. Attackers can break these algorithms with commodity hardware.' :
      cwe === 'CWE-502' ? 'Insecure deserialization can lead to remote code execution. Attackers craft malicious serialized objects that execute arbitrary code when deserialized.' :
      'This vulnerability could be exploited by attackers to compromise the security of your application. Address it based on the severity and your threat model.'}
    ${reachability === 'unreachable' ? '<p style="color:#4ade80;margin-top:8px"><strong>Note:</strong> This vulnerability was marked as unreachable — the vulnerable function is not called in your code. Consider deprioritizing.</p>' : ''}
  </div>

  ${fix ? `
  <h2>How to Fix</h2>
  <pre>${fix.replace(/</g, '&lt;')}</pre>
  ` : `
  <h2>How to Fix</h2>
  <div class="section">
    ${cwe === 'CWE-89' ? 'Use parameterized queries or an ORM instead of string concatenation for SQL queries.' :
      cwe === 'CWE-79' ? 'Escape all user input before rendering in HTML. Use framework-provided template escaping (Django auto-escape, React JSX).' :
      cwe === 'CWE-798' ? 'Move credentials to environment variables or a secret manager (Vault, AWS Secrets Manager). Never commit secrets to source code.' :
      'Refer to the CWE reference for specific remediation guidance.'}
  </div>
  `}

  <h2>References</h2>
  <ul>
    ${cwe ? `<li><a href="https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html">${cwe} — MITRE CWE</a></li>` : ''}
    <li><a href="https://app.cybrium.ai/rules/${ruleId}">View in Cybrium Dashboard</a></li>
    <li><a href="https://owasp.org/www-community/vulnerabilities/">OWASP Vulnerability Reference</a></li>
  </ul>
</body>
</html>`;
}

async function fixAllFindings() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || !cyscanPath) {
    vscode.window.showWarningMessage('No file open or cyscan not installed');
    return;
  }

  const filePath = editor.document.uri.fsPath;
  statusBar.text = '$(loading~spin) Fixing...';

  const result = await new Promise<string>((resolve) => {
    const proc = cp.spawn(cyscanPath!, ['fix', filePath, '--format', 'text'], { timeout: 30000 });
    let stdout = '';
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.on('close', () => resolve(stdout));
    proc.on('error', () => resolve(''));
  });

  // Reload the file after cyscan fix modified it
  await vscode.commands.executeCommand('workbench.action.files.revert');
  outputChannel.appendLine(result);

  // Re-scan to update diagnostics
  scanDocument(editor.document);
  vscode.window.showInformationMessage('Cybrium: fixes applied. Check the diff.');
}

async function aiFixCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No file open');
    return;
  }

  const config = vscode.workspace.getConfiguration('cybrium');
  const apiUrl = config.get<string>('apiUrl', 'https://app.cybrium.ai');
  const apiKey = config.get<string>('apiKey', '');

  if (!apiKey) {
    const action = await vscode.window.showWarningMessage(
      'Cybrium API key required for AI Fix. Set it in Settings > Cybrium > API Key.',
      'Open Settings',
    );
    if (action === 'Open Settings') {
      vscode.commands.executeCommand('workbench.action.openSettings', 'cybrium.apiKey');
    }
    return;
  }

  const filePath = editor.document.uri.fsPath;
  const source = editor.document.getText();
  const language = editor.document.languageId;

  statusBar.text = '$(loading~spin) AI generating fix...';

  try {
    const http = await import('http');
    const https = await import('https');
    const url = new URL(`${apiUrl}/api/scans/ai-fix/`);
    const client = url.protocol === 'https:' ? https : http;

    const body = JSON.stringify({
      source,
      language,
      file_path: filePath,
    });

    const resp = await new Promise<string>((resolve, reject) => {
      const req = client.request(url, {
        method: 'POST',
        headers: {
          'Authorization': `Token ${apiKey}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 60000,
      }, (res: any) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => resolve(data));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });

    const result = JSON.parse(resp);
    if (result.fixed_source) {
      // Show diff in a new editor
      const fixedUri = vscode.Uri.parse(`untitled:${path.basename(filePath)}.fixed`);
      const doc = await vscode.workspace.openTextDocument({ content: result.fixed_source, language });
      await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
      vscode.window.showInformationMessage(
        `Cybrium AI: ${result.fixes_applied ?? 0} fix(es) generated. Review the diff and apply.`,
      );
    } else {
      vscode.window.showInformationMessage('Cybrium AI: no fixes needed or AI could not generate fixes.');
    }
  } catch (err: any) {
    vscode.window.showErrorMessage(`Cybrium AI Fix failed: ${err.message}`);
  } finally {
    scanDocument(editor.document);
  }
}
