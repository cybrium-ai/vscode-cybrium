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

export async function activate(context: vscode.ExtensionContext) {
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
    vscode.commands.registerCommand('cybrium.showFindings', () => showFindings()),
    vscode.commands.registerCommand('cybrium.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('cybrium.openDashboard', () => openDashboard()),
    vscode.commands.registerCommand('cybrium.explain', (diag: vscode.Diagnostic) => explainVulnerability(diag, context)),
    vscode.commands.registerCommand('cybrium.fixAll', () => fixAllFindings()),
    vscode.commands.registerCommand('cybrium.aiFixFile', () => aiFixCurrentFile()),
    vscode.commands.registerCommand('cybrium.webScan', () => webScan()),
    vscode.commands.registerCommand('cybrium.repoHealth', () => repoHealth(context)),
    vscode.commands.registerCommand('cybrium.detectFrameworks', () => detectFrameworks()),
    // v0.6.0 — cyradar (AI inventory channel #1: active discovery)
    vscode.commands.registerCommand('cybrium.discoverAITools', () => discoverAITools()),
    vscode.commands.registerCommand('cybrium.discoverAIServers', () => discoverAIServers()),
    // v0.7.0 — cy-tls, cyred, cymail
    vscode.commands.registerCommand('cybrium.tlsScan', () => tlsScan()),
    vscode.commands.registerCommand('cybrium.aiRedTeam', () => aiRedTeam()),
    vscode.commands.registerCommand('cybrium.emailSecurity', () => emailSecurity()),
    // v0.8.0 — RHDA-style dependency analytics webview (donuts + tables)
    vscode.commands.registerCommand('cybrium.dependencyReport', () => dependencyReport(context)),
    // v0.9.0 — Send workspace findings to the Cybrium platform
    vscode.commands.registerCommand('cybrium.sendToCybriumPlatform', () => sendToCybriumPlatform()),
  );

  // Show available tools notification on first activation
  const hasShownWelcome = context.globalState.get<boolean>('cybrium.welcomeShown');
  if (!hasShownWelcome) {
    const tools: string[] = [];
    if (findCyscan()) tools.push('cyscan (SAST/SCA/secrets — 1,067 rules)');
    if (findBinary('cyweb')) tools.push('cyweb (web vulnerability scanner — 22 fuzz categories)');
    if (findBinary('cyprobe')) tools.push('cyprobe (network device discovery)');
    if (findBinary('cyradar')) tools.push('cyradar (AI inference server + local AI-tooling discovery)');
    if (findBinary('cy-tls')) tools.push('cy-tls (SSL/TLS posture)');
    if (findBinary('cyred')) tools.push('cyred (AI red-team — jailbreak / prompt-injection)');
    if (findBinary('cymail')) tools.push('cymail (email-domain security — SPF/DKIM/DMARC)');

    const msg = tools.length > 0
      ? `Cybrium detected: ${tools.join(', ')}. Use Cmd+Shift+P → "Cybrium" for all commands.`
      : 'Cybrium: Install security tools — brew tap cybrium-ai/cli && brew install cyscan cyweb cyprobe';

    const action = await vscode.window.showInformationMessage(msg, 'Show Commands', 'Install Tools');
    if (action === 'Show Commands') {
      vscode.commands.executeCommand('workbench.action.quickOpen', '>Cybrium');
    } else if (action === 'Install Tools') {
      vscode.env.openExternal(vscode.Uri.parse('https://github.com/cybrium-ai/cyscan#install'));
    }
    context.globalState.update('cybrium.welcomeShown', true);
  }

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
    statusBar.command = 'cybrium.scanFile';
    statusBar.tooltip = 'Click to scan current file';
  } else {
    statusBar.text = `$(shield) Cybrium: ${count} finding${count !== 1 ? 's' : ''}`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    // When findings exist, clicking reveals them in the Problems panel
    // rather than silently re-scanning the file.
    statusBar.command = 'cybrium.showFindings';
    statusBar.tooltip = `Click to view ${count} Cybrium finding${count !== 1 ? 's' : ''}`;
  }
}

// Reveal the Cybrium findings the status bar is reporting. They live in VS
// Code's Problems panel (set via the diagnostics collection); open and focus
// it, then narrow the filter to Cybrium-sourced entries so the user sees
// exactly the findings the badge counted.
async function showFindings() {
  // No findings attached anywhere — offer a scan instead of opening an empty panel.
  let total = 0;
  diagnostics.forEach(() => { total += 1; });
  if (total === 0) {
    const action = await vscode.window.showInformationMessage(
      'Cybrium: no findings yet. Scan the current file?',
      'Scan File',
    );
    if (action === 'Scan File') { scanCurrentFile(); }
    return;
  }

  // Open + focus the Problems panel. The `filter` arg is honoured by recent
  // VS Code builds; if it's ignored the panel still opens with all problems,
  // and the Cybrium source column makes our entries obvious.
  try {
    await vscode.commands.executeCommand('workbench.actions.view.problems', { filter: 'Cybrium' });
  } catch {
    await vscode.commands.executeCommand('workbench.panel.markers.view.focus');
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

function findBinary(name: string): string | null {
  // v0.7.0 — honour cybrium.<bin>Path config overrides (cy-tls -> cytlsPath).
  const cfg = vscode.workspace.getConfiguration('cybrium');
  const configKey = `${name.replace(/-/g, '')}Path`;
  const configured = cfg.get<string>(configKey, '');
  if (configured && fs.existsSync(configured)) return configured;

  const candidates = [
    `/opt/homebrew/bin/${name}`,
    `/usr/local/bin/${name}`,
    path.join(require('os').homedir(), `.cargo/bin/${name}`),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  try {
    const r = cp.execSync(`which ${name}`, { timeout: 3000 }).toString().trim();
    if (r && fs.existsSync(r)) return r;
  } catch {}
  return null;
}

async function webScan() {
  const cyweb = findBinary('cyweb');
  if (!cyweb) {
    const action = await vscode.window.showWarningMessage(
      'cyweb not installed. It scans websites for 22 vulnerability types: SQLi, XSS, SSRF, SSTI, XXE, CORS, JWT, LFI, command injection, and more.',
      'Install cyweb',
    );
    if (action === 'Install cyweb') {
      vscode.env.openExternal(vscode.Uri.parse('https://github.com/cybrium-ai/cyweb'));
    }
    return;
  }

  const url = await vscode.window.showInputBox({
    prompt: 'Enter URL to scan',
    placeHolder: 'https://example.com',
    validateInput: (v) => v.startsWith('http') ? null : 'URL must start with http:// or https://',
  });
  if (!url) return;

  statusBar.text = '$(loading~spin) Web scanning...';
  outputChannel.show();
  outputChannel.appendLine(`\n=== Cybrium Web Scan: ${url} ===\n`);

  const proc = cp.spawn(cyweb, ['scan', url, '--format', 'text'], { timeout: 120000 });
  proc.stdout.on('data', (d: Buffer) => outputChannel.append(d.toString()));
  proc.stderr.on('data', (d: Buffer) => outputChannel.append(d.toString()));
  proc.on('close', (code) => {
    outputChannel.appendLine(`\n=== Scan complete (exit ${code}) ===`);
    statusBar.text = '$(shield) Cybrium';
    vscode.window.showInformationMessage(`Cybrium: Web scan of ${url} complete. Check Output panel.`);
  });
}

async function repoHealth(context: vscode.ExtensionContext) {
  if (!cyscanPath) {
    vscode.window.showWarningMessage('cyscan not installed');
    return;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) { vscode.window.showWarningMessage('No workspace open'); return; }

  statusBar.text = '$(loading~spin) Checking health...';
  const target = folders[0].uri.fsPath;

  const result = await new Promise<string>((resolve) => {
    const proc = cp.spawn(cyscanPath!, ['health', target, '--format', 'json'], { timeout: 30000 });
    let stdout = '';
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.on('close', () => resolve(stdout));
    proc.on('error', () => resolve('{}'));
  });
  statusBar.text = '$(shield) Cybrium';

  let parsed: any;
  try { parsed = JSON.parse(result); }
  catch {
    outputChannel.appendLine(result);
    vscode.window.showWarningMessage('Cybrium: cyscan health returned non-JSON. See Output panel.');
    return;
  }

  // Sprint 125 P1 — render the canonical Repo Health payload in the
  // shared resources/webview/repo-health.html template (same one shipped
  // by intellij-cybrium so both extensions render identically).
  openRepoHealthPanel(context, normaliseRepoHealth(parsed));
}

function normaliseRepoHealth(raw: any): {
  score: number; generated_at: string; ecosystem: string;
  summary: { passing: number; failing: number; total: number };
  checks: Array<{ id: string; name: string; category: string; severity: string; passed: boolean; detail?: string; remediation?: string }>;
} {
  const checks = Array.isArray(raw?.checks) ? raw.checks.map((c: any) => ({
    id:        String(c.id || c.rule_id || c.name || ''),
    name:      String(c.name || c.title || c.id || 'Untitled'),
    category:  String(c.category || c.group || ''),
    severity:  String(c.severity || 'info').toLowerCase(),
    passed:    Boolean(c.passed),
    detail:    typeof c.detail === 'string' ? c.detail : undefined,
    remediation: typeof c.remediation === 'string' ? c.remediation :
                 typeof c.fix === 'string'         ? c.fix         : undefined,
  })) : [];
  const passing = checks.filter((c: any) => c.passed).length;
  const failing = checks.length - passing;
  const score = typeof raw?.score === 'number'
    ? raw.score
    : (checks.length ? Math.round(100 * passing / checks.length) : 0);
  return {
    score,
    generated_at: String(raw?.generated_at || new Date().toISOString()),
    ecosystem: String(raw?.ecosystem || raw?.project_kind || ''),
    summary: {
      passing: Number(raw?.summary?.passing ?? passing),
      failing: Number(raw?.summary?.failing ?? failing),
      total:   Number(raw?.summary?.total   ?? checks.length),
    },
    checks,
  };
}

function openRepoHealthPanel(context: vscode.ExtensionContext, report: any) {
  const panel = vscode.window.createWebviewPanel(
    'cybriumRepoHealth', 'Cybrium · Repository Health',
    vscode.ViewColumn.One, { enableScripts: true, retainContextWhenHidden: true },
  );
  const templatePath = path.join(context.extensionPath, 'resources', 'webview', 'repo-health.html');
  let html: string;
  try { html = fs.readFileSync(templatePath, 'utf-8'); }
  catch (err) {
    panel.webview.html = `<html><body style="font-family:sans-serif;padding:24px;color:#e2e8f0;background:#0c111f;">
      <h2>Cybrium repo-health template missing</h2>
      <p>Expected: <code>${templatePath}</code></p>
      <p>${(err as Error).message}</p></body></html>`;
    return;
  }
  const safeJson = JSON.stringify(report)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  html = html.replace(
    /<script id="cybrium-repo-health" type="application\/json">[\s\S]*?<\/script>/,
    `<script id="cybrium-repo-health" type="application/json">${safeJson}</script>`,
  );
  const isDark = vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.Dark
              || vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.HighContrast;
  html = html.replace(
    '<html lang="en" data-theme="dark">',
    `<html lang="en" data-theme="${isDark ? 'dark' : 'light'}">`,
  );
  panel.webview.html = html;
}

async function detectFrameworks() {
  if (!cyscanPath) {
    vscode.window.showWarningMessage('cyscan not installed');
    return;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) { vscode.window.showWarningMessage('No workspace open'); return; }

  statusBar.text = '$(loading~spin) Detecting frameworks...';
  const target = folders[0].uri.fsPath;

  const result = await new Promise<string>((resolve) => {
    const proc = cp.spawn(cyscanPath!, ['frameworks', target, '--format', 'json'], { timeout: 30000 });
    let stdout = '';
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.on('close', () => resolve(stdout));
    proc.on('error', () => resolve('[]'));
  });

  try {
    const frameworks = JSON.parse(result);
    if (frameworks.length === 0) {
      vscode.window.showInformationMessage('No frameworks detected.');
    } else {
      const items = frameworks.map((f: any) =>
        `${f.name} (${f.language}) — ${f.category}${f.version ? ` v${f.version}` : ''}`
      );
      vscode.window.showQuickPick(items, { title: `${frameworks.length} Frameworks Detected`, canPickMany: false });
    }
  } catch {
    outputChannel.appendLine(result);
  }
  statusBar.text = '$(shield) Cybrium';
}

// ── cyradar — AI inventory (Sprint 67 channel #1: active discovery) ─────────

/**
 * Discover AI tooling installed on the current machine.
 * Calls: cyradar local-scan --format json
 * Surfaces CLIs, IDE extensions, desktop AI apps, and on-disk model files.
 */
async function discoverAITools() {
  const cyradar = findBinary('cyradar');
  if (!cyradar) {
    const choice = await vscode.window.showWarningMessage(
      'cyradar not found. Install with: brew install cybrium-ai/cli/cyradar',
      'Open Install Docs'
    );
    if (choice === 'Open Install Docs') {
      vscode.env.openExternal(vscode.Uri.parse('https://github.com/cybrium-ai/cyradar#install'));
    }
    return;
  }

  statusBar.text = '$(sync~spin) Cybrium: scanning local AI tooling…';
  outputChannel.show(true);
  outputChannel.appendLine('cyradar local-scan --format json');

  const result = await new Promise<string>((resolve) => {
    const proc = cp.spawn(cyradar, ['local-scan', '--format', 'json'], { timeout: 60000 });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    proc.on('close', () => {
      if (stderr) { outputChannel.appendLine(stderr); }
      resolve(stdout);
    });
    proc.on('error', (e: Error) => { outputChannel.appendLine(`error: ${e.message}`); resolve('{}'); });
  });

  statusBar.text = '$(shield) Cybrium';

  try {
    const envelope = JSON.parse(result);
    // cyradar wraps its report in an Envelope { report: {...} } — be liberal
    const report = envelope.report ?? envelope;
    const clis = report.clis ?? [];
    const exts = report.ide_extensions ?? [];
    const apps = report.desktop_apps ?? [];
    const models = report.local_models ?? [];

    const total = clis.length + exts.length + apps.length + models.length;
    if (total === 0) {
      vscode.window.showInformationMessage('cyradar: no AI tooling detected on this machine.');
      return;
    }

    const items: vscode.QuickPickItem[] = [];
    if (clis.length) {
      items.push({ label: `$(terminal) ${clis.length} AI CLI${clis.length !== 1 ? 's' : ''}`, kind: vscode.QuickPickItemKind.Separator } as vscode.QuickPickItem);
      for (const c of clis) { items.push({ label: c.name, description: c.version ?? '', detail: c.path }); }
    }
    if (exts.length) {
      items.push({ label: `$(extensions) ${exts.length} IDE extension${exts.length !== 1 ? 's' : ''}`, kind: vscode.QuickPickItemKind.Separator } as vscode.QuickPickItem);
      for (const e of exts) { items.push({ label: e.name, description: e.ide ?? '', detail: e.id ?? '' }); }
    }
    if (apps.length) {
      items.push({ label: `$(window) ${apps.length} desktop app${apps.length !== 1 ? 's' : ''}`, kind: vscode.QuickPickItemKind.Separator } as vscode.QuickPickItem);
      for (const a of apps) { items.push({ label: a.name, description: a.version ?? '', detail: a.path ?? '' }); }
    }
    if (models.length) {
      items.push({ label: `$(database) ${models.length} on-disk model${models.length !== 1 ? 's' : ''}`, kind: vscode.QuickPickItemKind.Separator } as vscode.QuickPickItem);
      for (const m of models) {
        const size = m.size_bytes ? ` · ${(m.size_bytes / (1024 ** 3)).toFixed(1)} GiB` : '';
        items.push({ label: m.name ?? path.basename(m.path ?? ''), description: m.format ?? '', detail: (m.path ?? '') + size });
      }
    }

    vscode.window.showQuickPick(items, {
      title: `Cybrium: ${total} AI artefact${total !== 1 ? 's' : ''} discovered on this machine`,
      canPickMany: false,
    });
  } catch (e) {
    outputChannel.appendLine(`cyradar local-scan: failed to parse output`);
    outputChannel.appendLine(result.slice(0, 4000));
  }
}

/**
 * Sweep a network range / target list for self-hosted AI inference servers.
 * Calls: cyradar discover --targets <input> --format json
 * Prompts the operator for the target CIDR / host list before invoking.
 */
async function discoverAIServers() {
  const cyradar = findBinary('cyradar');
  if (!cyradar) {
    const choice = await vscode.window.showWarningMessage(
      'cyradar not found. Install with: brew install cybrium-ai/cli/cyradar',
      'Open Install Docs'
    );
    if (choice === 'Open Install Docs') {
      vscode.env.openExternal(vscode.Uri.parse('https://github.com/cybrium-ai/cyradar#install'));
    }
    return;
  }

  const targets = await vscode.window.showInputBox({
    title: 'Cybrium: Discover AI inference servers',
    prompt: 'Targets — host, host:port, http(s)://url, or CIDR (e.g. 10.0.0.0/24). Comma-separated.',
    placeHolder: '10.0.0.0/24, ollama.lab.local:11434',
    validateInput: (v) => v.trim().length === 0 ? 'Enter at least one target' : null,
  });
  if (!targets) { return; }

  statusBar.text = '$(sync~spin) Cybrium: cyradar discover…';
  outputChannel.show(true);
  outputChannel.appendLine(`cyradar discover --targets ${targets} --format json`);

  const result = await new Promise<string>((resolve) => {
    const proc = cp.spawn(cyradar, ['discover', '--targets', targets, '--format', 'json'], { timeout: 300000 });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    proc.on('close', () => {
      if (stderr) { outputChannel.appendLine(stderr); }
      resolve(stdout);
    });
    proc.on('error', (e: Error) => { outputChannel.appendLine(`error: ${e.message}`); resolve('{}'); });
  });

  statusBar.text = '$(shield) Cybrium';

  try {
    const envelope = JSON.parse(result);
    const report = envelope.report ?? envelope;
    const findings = report.servers ?? report.findings ?? [];

    if (!Array.isArray(findings) || findings.length === 0) {
      vscode.window.showInformationMessage(`cyradar: no AI servers detected in ${targets}.`);
      return;
    }

    const items = findings.map((f: any) => {
      const label = `${f.product ?? f.signature_id ?? 'unknown'} — ${f.target ?? f.host ?? ''}`;
      const description = f.version ? `v${f.version}` : '';
      const detail = [
        f.endpoint ? `endpoint: ${f.endpoint}` : '',
        f.confidence ? `confidence: ${f.confidence}` : '',
        f.evidence ? `evidence: ${String(f.evidence).slice(0, 80)}` : '',
      ].filter(Boolean).join(' · ');
      return { label, description, detail };
    });

    vscode.window.showQuickPick(items, {
      title: `Cybrium: ${findings.length} AI server${findings.length !== 1 ? 's' : ''} discovered`,
      canPickMany: false,
    });
  } catch {
    outputChannel.appendLine(result.slice(0, 4000));
    vscode.window.showWarningMessage('cyradar returned non-JSON output (see Cybrium output channel).');
  }
}


// ───────────────────────────────────────────────────────────────────
// v0.7.0 — cy-tls / cyred / cymail integrations
//
// Each command:
//   1. Locates the binary via findBinary(); offers a brew-install hint
//      and "Install" link if missing.
//   2. Prompts the user for the per-tool target (host:port / URL / domain).
//   3. Spawns the binary with --format text, streaming stdout/stderr to
//      the Cybrium output channel and the status bar.
// ───────────────────────────────────────────────────────────────────

function runToolInOutput(opts: {
  bin: string;
  binArgs: string[];
  banner: string;
  installHint: string;
  installUrl: string;
  timeoutMs?: number;
}) {
  const found = findBinary(opts.bin);
  if (!found) {
    vscode.window.showWarningMessage(
      `${opts.bin} not installed. ${opts.installHint}`,
      "Install",
    ).then(action => {
      if (action === "Install") {
        vscode.env.openExternal(vscode.Uri.parse(opts.installUrl));
      }
    });
    return;
  }

  statusBar.text = `$(loading~spin) ${opts.bin}...`;
  outputChannel.show();
  outputChannel.appendLine(`
=== ${opts.banner} ===
`);

  const proc = cp.spawn(found, opts.binArgs, { timeout: opts.timeoutMs ?? 180000 });
  proc.stdout.on("data", (d: Buffer) => outputChannel.append(d.toString()));
  proc.stderr.on("data", (d: Buffer) => outputChannel.append(d.toString()));
  proc.on("close", (code) => {
    outputChannel.appendLine(`
=== ${opts.bin} complete (exit ${code}) ===`);
    statusBar.text = "$(shield) Cybrium";
  });
  proc.on("error", (err) => {
    outputChannel.appendLine(`${opts.bin} error: ${err.message}`);
    statusBar.text = "$(shield) Cybrium";
  });
}

async function tlsScan() {
  const target = await vscode.window.showInputBox({
    prompt: "Enter host[:port] to scan SSL/TLS posture",
    placeHolder: "example.com:443",
    validateInput: (v) => v.trim().length > 0 ? null : "Host required",
  });
  if (!target) return;

  runToolInOutput({
    bin: "cy-tls",
    binArgs: ["scan", target, "--format", "text"],
    banner: `Cybrium SSL/TLS Scan: ${target}`,
    installHint: "It probes TLS versions, ciphers, certificates, OCSP, HSTS preload, and 18 other surfaces.",
    installUrl: "https://github.com/cybrium-ai/cy-tls",
  });
}

async function aiRedTeam() {
  const target = await vscode.window.showInputBox({
    prompt: "Enter AI endpoint URL to red-team",
    placeHolder: "https://api.example.com/v1/chat",
    validateInput: (v) => v.startsWith("http") ? null : "URL must start with http:// or https://",
  });
  if (!target) return;

  runToolInOutput({
    bin: "cyred",
    binArgs: ["probe", target, "--format", "text"],
    banner: `Cybrium AI Red-Team: ${target}`,
    installHint: "It runs jailbreak, prompt-injection, and data-exfil probes against AI endpoints.",
    installUrl: "https://github.com/cybrium-ai/cyred",
    timeoutMs: 300000,
  });
}

async function emailSecurity() {
  const domain = await vscode.window.showInputBox({
    prompt: "Email domain to scan (SPF / DKIM / DMARC / MTA-STS / DNSSEC / BIMI)",
    placeHolder: "example.com",
    validateInput: (v) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v.trim())
      ? null
      : "Enter a bare domain (no scheme, no path)",
  });
  if (!domain) return;

  runToolInOutput({
    bin: "cymail",
    binArgs: ["scan", "--domain", domain.trim(), "--format", "text"],
    banner: `Cybrium Email Security: ${domain}`,
    installHint: "It scores email posture (SPF / DKIM / DMARC / MTA-STS / DNSSEC / BIMI) with reputation + leak checks.",
    installUrl: "https://github.com/cybrium-ai/cymail",
  });
}


// ───────────────────────────────────────────────────────────────────
// v0.8.0 — RHDA-style Dependency Analytics Report
//
// Spawns `cyscan supply --format json` on the active workspace, walks
// the output, and renders the result in a webview backed by the shared
// HTML template at resources/webview/report.html. The same template is
// shipped in cybrium-ai/intellij-cybrium so the two extensions stay in
// pixel lock-step.
//
// Canonical report shape (what the HTML expects):
//   {
//     ecosystem, generated_at,
//     summary: { critical, high, medium, low },
//     dependencies: [{
//       name, version, ecosystem, is_direct,
//       direct_vulnerabilities:     [{cve, severity, fixed_in}],
//       transitive_vulnerabilities: [...],
//       remediation: {available, upgrade_to}
//     }],
//     licenses: {
//       summary: { permissive, weak_copyleft, strong_copyleft, proprietary, unknown },
//       by_dependency: [{name, version, license: {name, category}, evidences}]
//     }
//   }
// ───────────────────────────────────────────────────────────────────

interface CanonicalReport {
  ecosystem:   string;
  generated_at: string;
  summary:     { critical: number; high: number; medium: number; low: number };
  dependencies: CanonicalDep[];
  licenses: {
    summary: { permissive: number; weak_copyleft: number; strong_copyleft: number; proprietary: number; unknown: number };
    by_dependency: CanonicalLicenseRow[];
  };
}
interface CanonicalDep {
  name: string;
  version: string;
  ecosystem: string;
  is_direct: boolean;
  direct_vulnerabilities:     Array<{ cve: string; severity: string; fixed_in?: string }>;
  transitive_vulnerabilities: Array<{ cve: string; severity: string; fixed_in?: string }>;
  remediation: { available: boolean; upgrade_to?: string };
}
interface CanonicalLicenseRow {
  name: string;
  version: string;
  license: { name: string; category: string };
  evidences?: string[];
  evidence_count?: number;
}

async function dependencyReport(context: vscode.ExtensionContext) {
  const cyscan = findCyscan();
  if (!cyscan) {
    const action = await vscode.window.showWarningMessage(
      "cyscan not installed. Required for dependency analytics (CVE + license).",
      "Install cyscan",
    );
    if (action === "Install cyscan") {
      vscode.env.openExternal(vscode.Uri.parse("https://github.com/cybrium-ai/cyscan#install"));
    }
    return;
  }

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("Open a workspace folder first.");
    return;
  }
  const workspaceRoot = folders[0].uri.fsPath;

  statusBar.text = "$(loading~spin) Cybrium: dependencies…";
  outputChannel.show();
  outputChannel.appendLine(`\n=== Cybrium Dependency Analytics: ${workspaceRoot} ===\n`);

  let raw = "";
  try {
    raw = await runCommandJson(cyscan, ["supply", workspaceRoot, "--format", "json"], 120000);
  } catch (err) {
    outputChannel.appendLine(`cyscan supply failed: ${(err as Error).message}`);
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showErrorMessage(
      `Cybrium: cyscan supply failed. ${(err as Error).message.slice(0, 200)}`,
    );
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    outputChannel.appendLine("cyscan supply returned non-JSON. Showing first 800 chars:");
    outputChannel.appendLine(raw.slice(0, 800));
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showErrorMessage(
      "Cybrium: cyscan supply returned non-JSON. See output panel.",
    );
    return;
  }

  const report = normalizeReport(parsed);
  outputChannel.appendLine(
    `cyscan: ${report.dependencies.length} deps, ` +
    `${report.summary.critical}C/${report.summary.high}H/${report.summary.medium}M/${report.summary.low}L ` +
    `vulns, ${report.licenses.by_dependency.length} licenses`,
  );
  statusBar.text = "$(shield) Cybrium";

  openDependencyReportPanel(context, report);
}

function runCommandJson(bin: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = cp.spawn(bin, args, { timeout: timeoutMs });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.on("close", (code) => {
      if (code === 0 || stdout.trim().startsWith("{") || stdout.trim().startsWith("[")) {
        resolve(stdout);
      } else {
        reject(new Error(stderr.slice(0, 400) || `exit ${code}`));
      }
    });
    proc.on("error", (err) => reject(err));
  });
}

// Map a raw cyscan severity (string or CVSS number) to one of our 5 buckets.
function normalizeSeverity(s: unknown): "critical" | "high" | "medium" | "low" | "info" {
  if (typeof s === "number") {
    if (s >= 9) return "critical";
    if (s >= 7) return "high";
    if (s >= 4) return "medium";
    if (s > 0)  return "low";
    return "info";
  }
  const t = String(s ?? "info").toLowerCase();
  if (t.startsWith("crit"))   return "critical";
  if (t.startsWith("high"))   return "high";
  if (t.startsWith("med"))    return "medium";
  if (t.startsWith("low"))    return "low";
  return "info";
}

// Map a license-name or SPDX string to a category bucket.
function classifyLicense(name: string): "permissive" | "weak-copyleft" | "strong-copyleft" | "proprietary" | "unknown" {
  const n = name.toUpperCase();
  if (!n || n === "UNKNOWN" || n === "NOASSERTION") return "unknown";
  if (/(GPL-?3|AGPL|GPL-3|GNU GENERAL)/.test(n))    return "strong-copyleft";
  if (/(LGPL|MPL|EPL|CDDL|GPL-?2)/.test(n))         return "weak-copyleft";
  if (/(PROPRIETARY|COMMERCIAL)/.test(n))           return "proprietary";
  // Common permissive licences.
  if (/(MIT|BSD|APACHE|ISC|ZLIB|UNLICENSE|CC0|WTFPL|0BSD|PYTHON)/.test(n)) return "permissive";
  return "unknown";
}

// Accept multiple cyscan output shapes and project into the canonical
// report shape. This is the only place the extension knows about
// cyscan's wire format — keeps the renderer + HTML template
// presentation-only.
function normalizeReport(raw: any): CanonicalReport {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  const licSum  = { permissive: 0, weak_copyleft: 0, strong_copyleft: 0, proprietary: 0, unknown: 0 };
  const dependencies: CanonicalDep[] = [];
  const licenseRows: CanonicalLicenseRow[] = [];

  // Shape A: native cyscan-supply structured output (`dependencies` array).
  const depsRaw: any[] = Array.isArray(raw?.dependencies) ? raw.dependencies
                       : Array.isArray(raw?.deps)         ? raw.deps
                       : [];

  if (depsRaw.length > 0) {
    for (const d of depsRaw) {
      const directVulns: any[] = Array.isArray(d.direct_vulnerabilities) ? d.direct_vulnerabilities
                                 : Array.isArray(d.vulnerabilities)       ? d.vulnerabilities
                                 : [];
      const transitiveVulns: any[] = Array.isArray(d.transitive_vulnerabilities) ? d.transitive_vulnerabilities : [];

      const direct = directVulns.map(v => ({
        cve: v.cve || v.id || v.cve_id || "",
        severity: normalizeSeverity(v.severity ?? v.cvss),
        fixed_in: v.fixed_in || v.fix_version,
      }));
      const transitive = transitiveVulns.map(v => ({
        cve: v.cve || v.id || v.cve_id || "",
        severity: normalizeSeverity(v.severity ?? v.cvss),
        fixed_in: v.fixed_in || v.fix_version,
      }));

      for (const v of direct.concat(transitive)) {
        const s = v.severity;
        if (s === "critical" || s === "high" || s === "medium" || s === "low") summary[s]++;
      }

      const upgradeTo = d.remediation?.upgrade_to ||
        direct.concat(transitive).find(v => v.fixed_in)?.fixed_in;

      dependencies.push({
        name:      String(d.name || d.package || "?"),
        version:   String(d.version || d.current_version || "—"),
        ecosystem: String(d.ecosystem || raw.ecosystem || ""),
        is_direct: Boolean(d.is_direct ?? d.direct ?? false),
        direct_vulnerabilities:     direct,
        transitive_vulnerabilities: transitive,
        remediation: {
          available: Boolean(d.remediation?.available ?? (upgradeTo ? true : false)),
          upgrade_to: upgradeTo,
        },
      });

      const licName = (d.license?.name || d.license || d.licenses?.[0] || "Unknown").toString();
      const category = (d.license?.category || classifyLicense(licName)).replace("_", "-") as keyof typeof licSum | string;
      const catKey = (category === "weak-copyleft" ? "weak_copyleft"
                     : category === "strong-copyleft" ? "strong_copyleft"
                     : category) as keyof typeof licSum;
      if (catKey in licSum) (licSum as any)[catKey]++;
      else                  licSum.unknown++;

      licenseRows.push({
        name:    String(d.name || d.package || "?"),
        version: String(d.version || d.current_version || "—"),
        license: { name: licName, category: catKey.replace("_", "-") },
        evidences: Array.isArray(d.license_evidences) ? d.license_evidences : undefined,
        evidence_count: typeof d.license_evidence_count === "number" ? d.license_evidence_count : undefined,
      });
    }
  } else {
    // Shape B: flat findings list (legacy `cyscan scan --format sarif` /
    // `cyscan supply` early variants). Group by dependency name.
    const findings: any[] = Array.isArray(raw?.findings) ? raw.findings : [];
    type Slot = { name: string; version: string; vulns: any[] };
    const byDep = new Map<string, Slot>();
    for (const f of findings) {
      const name = f.dependency || f.package || (f.location?.uri?.split("/").pop()) || "unknown";
      const key  = name + "@" + (f.version || "?");
      const slot: Slot = byDep.get(key) || { name, version: f.version || "—", vulns: [] };
      slot.vulns.push(f);
      byDep.set(key, slot);
    }
    for (const slot of byDep.values()) {
      const vulns = slot.vulns.map(v => ({
        cve: v.cve || v.id || v.rule_id || "",
        severity: normalizeSeverity(v.severity ?? v.cvss),
        fixed_in: v.fixed_in || v.fix_version,
      }));
      for (const v of vulns) {
        const s = v.severity;
        if (s === "critical" || s === "high" || s === "medium" || s === "low") summary[s]++;
      }
      dependencies.push({
        name: slot.name, version: slot.version, ecosystem: "",
        is_direct: true,
        direct_vulnerabilities: vulns,
        transitive_vulnerabilities: [],
        remediation: { available: Boolean(vulns.find(v => v.fixed_in)) },
      });
    }
  }

  // Honour pre-summarised license counts if cyscan provided them.
  if (raw?.license_summary && typeof raw.license_summary === "object") {
    for (const k of Object.keys(licSum)) {
      if (typeof raw.license_summary[k] === "number") (licSum as any)[k] = raw.license_summary[k];
    }
  }
  if (raw?.summary && typeof raw.summary === "object") {
    for (const k of Object.keys(summary)) {
      if (typeof raw.summary[k] === "number") (summary as any)[k] = raw.summary[k];
    }
  }

  return {
    ecosystem:    String(raw?.ecosystem || dependencies[0]?.ecosystem || "—"),
    generated_at: String(raw?.generated_at || new Date().toISOString()),
    summary,
    dependencies,
    licenses: { summary: licSum, by_dependency: licenseRows },
  };
}

function openDependencyReportPanel(context: vscode.ExtensionContext, report: CanonicalReport) {
  const panel = vscode.window.createWebviewPanel(
    "cybriumDependencyReport",
    "Cybrium · Dependency Analytics",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true },
  );

  // Load the shared template; inject the canonical report JSON into the
  // empty <script id="cybrium-report" type="application/json">{}</script>
  // tag. Same pattern IntelliJ uses with JCEF.
  const templatePath = path.join(
    context.extensionPath, "resources", "webview", "report.html",
  );
  let html: string;
  try {
    html = fs.readFileSync(templatePath, "utf-8");
  } catch (err) {
    panel.webview.html = `<html><body style="font-family:sans-serif;padding:24px;color:#e2e8f0;background:#0c111f;">
      <h2>Cybrium report template missing</h2>
      <p>Expected: <code>${templatePath}</code></p>
      <p>${(err as Error).message}</p>
    </body></html>`;
    return;
  }

  const safeJson = JSON.stringify(report)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");

  html = html.replace(
    /<script id="cybrium-report" type="application\/json">[\s\S]*?<\/script>/,
    `<script id="cybrium-report" type="application/json">${safeJson}</script>`,
  );

  // Theme handoff — set data-theme based on the active VS Code theme so
  // the inline CSS picks the matching variables.
  const isDark = vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.Dark
              || vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.HighContrast;
  html = html.replace(
    '<html lang="en" data-theme="dark">',
    `<html lang="en" data-theme="${isDark ? "dark" : "light"}">`,
  );

  panel.webview.html = html;
}


// ───────────────────────────────────────────────────────────────────
// v0.9.0 — Send workspace findings to the Cybrium platform
//
// Runs cyscan against the workspace, collects findings, and POSTs them
// to POST <apiUrl>/api/scans/findings/ingest/ using the configured
// API key. On success, shows a notification with a "Open in Cybrium"
// button that deep-links to the platform Findings page.
// ───────────────────────────────────────────────────────────────────

interface CybriumIngestFinding {
  rule_id?:        string;
  title:           string;
  severity:        "critical" | "high" | "medium" | "low" | "info";
  description?:    string;
  file?:           string;
  line?:           number;
  snippet?:        string;
  cwe?:            string[];
  recommendation?: string;
  evidence?:       Record<string, unknown>;
}

async function sendToCybriumPlatform() {
  const cfg = vscode.workspace.getConfiguration("cybrium");
  const apiUrl = (cfg.get<string>("apiUrl", "https://app.cybrium.ai") || "").replace(/\/+$/, "");
  const apiKey = cfg.get<string>("apiKey", "") || "";

  if (!apiKey) {
    const action = await vscode.window.showWarningMessage(
      "Cybrium API key is not configured. Set cybrium.apiKey in settings, then retry.",
      "Open settings",
    );
    if (action === "Open settings") {
      vscode.commands.executeCommand("workbench.action.openSettings", "cybrium.apiKey");
    }
    return;
  }

  if (!cyscanPath) {
    vscode.window.showWarningMessage("cyscan not installed — install it first.");
    return;
  }

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("Open a workspace folder first.");
    return;
  }
  const workspaceRoot = folders[0].uri.fsPath;
  const workspaceName = folders[0].name || workspaceRoot;

  statusBar.text = "$(loading~spin) Cybrium: collecting findings…";
  outputChannel.show();
  outputChannel.appendLine(`\n=== Cybrium: send findings for ${workspaceRoot} → ${apiUrl} ===`);

  // 1. Run cyscan to collect findings.
  let raw = "";
  try {
    raw = await runCommandJson(cyscanPath, ["scan", workspaceRoot, "--format", "json"], 180000);
  } catch (err) {
    outputChannel.appendLine(`cyscan failed: ${(err as Error).message}`);
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showErrorMessage(`Cybrium: cyscan failed. ${(err as Error).message.slice(0, 200)}`);
    return;
  }

  let cyscanOutput: any;
  try { cyscanOutput = JSON.parse(raw); }
  catch {
    outputChannel.appendLine("cyscan returned non-JSON. First 500 chars:");
    outputChannel.appendLine(raw.slice(0, 500));
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showErrorMessage("Cybrium: cyscan returned non-JSON. See Output panel.");
    return;
  }

  const findings: CybriumIngestFinding[] = canonicaliseForIngest(cyscanOutput);
  if (findings.length === 0) {
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showInformationMessage("Cybrium: no findings to send.");
    return;
  }

  // 2. POST to the ingest endpoint.
  const body = JSON.stringify({
    source:    "vscode-cybrium",
    scan_type: "ide_ingest",
    host:      workspaceName,
    findings,
  });

  statusBar.text = "$(cloud-upload) Cybrium: uploading…";
  outputChannel.appendLine(`Posting ${findings.length} finding(s) → ${apiUrl}/api/scans/findings/ingest/`);

  let resp: { ok: boolean; status: number; body: string };
  try {
    resp = await httpPost(`${apiUrl}/api/scans/findings/ingest/`, body, {
      "Authorization": `Api-Key ${apiKey}`,
      "Content-Type":  "application/json",
    });
  } catch (err) {
    outputChannel.appendLine(`Network error: ${(err as Error).message}`);
    statusBar.text = "$(shield) Cybrium";
    vscode.window.showErrorMessage(`Cybrium: upload failed. ${(err as Error).message.slice(0, 200)}`);
    return;
  }

  statusBar.text = "$(shield) Cybrium";

  if (!resp.ok) {
    outputChannel.appendLine(`HTTP ${resp.status}: ${resp.body.slice(0, 500)}`);
    if (resp.status === 401) {
      vscode.window.showErrorMessage(
        "Cybrium: API key rejected. Generate a new one under Settings → API Keys on app.cybrium.ai.",
      );
    } else {
      vscode.window.showErrorMessage(
        `Cybrium: upload failed (HTTP ${resp.status}). See Output panel.`,
      );
    }
    return;
  }

  let parsed: any = {};
  try { parsed = JSON.parse(resp.body); } catch { /* ignore */ }
  const dashboard: string = parsed?.dashboard_url || `${apiUrl}/findings`;
  outputChannel.appendLine(`✓ Uploaded ${findings.length} finding(s). Dashboard: ${dashboard}`);

  const open = await vscode.window.showInformationMessage(
    `Cybrium: uploaded ${findings.length} finding(s) to ${new URL(apiUrl).host}.`,
    "Open in Cybrium",
  );
  if (open === "Open in Cybrium") {
    vscode.env.openExternal(vscode.Uri.parse(dashboard));
  }
}

function canonicaliseForIngest(raw: any): CybriumIngestFinding[] {
  const out: CybriumIngestFinding[] = [];
  const sevAllowed = new Set(["critical", "high", "medium", "low", "info"]);

  // Shape A: cyscan SARIF — runs[].results[]
  if (Array.isArray(raw?.runs)) {
    for (const run of raw.runs) {
      for (const r of run.results || []) {
        const loc = r.locations?.[0]?.physicalLocation;
        const file = loc?.artifactLocation?.uri || "";
        const line = loc?.region?.startLine;
        const sev  = sevFromLevel(r.level);
        out.push({
          rule_id:        r.ruleId || "",
          title:          r.message?.text || r.ruleId || "Finding",
          severity:       sev,
          description:    r.message?.text || "",
          file:           file,
          line:           typeof line === "number" ? line : undefined,
          evidence:       r.properties ? { properties: r.properties } : undefined,
        });
      }
    }
    if (out.length > 0) return out;
  }

  // Shape B: cyscan flat findings list / supply output.
  const findings = Array.isArray(raw?.findings) ? raw.findings
                 : Array.isArray(raw)            ? raw
                 : [];
  for (const f of findings) {
    if (typeof f !== "object" || f === null) continue;
    let sev = String(f.severity || "info").toLowerCase();
    if (!sevAllowed.has(sev)) sev = "info";
    out.push({
      rule_id:        String(f.rule_id || f.id || ""),
      title:          String(f.title || f.message || f.rule_id || "Finding").slice(0, 500),
      severity:       sev as CybriumIngestFinding["severity"],
      description:    String(f.message || f.description || ""),
      file:           String(f.file || ""),
      line:           typeof f.line === "number" ? f.line : undefined,
      snippet:        typeof f.snippet === "string" ? f.snippet : undefined,
      cwe:            Array.isArray(f.cwe) ? f.cwe.map(String) : undefined,
      recommendation: typeof f.fix === "string" ? f.fix
                    : typeof f.recommendation === "string" ? f.recommendation
                    : undefined,
    });
  }
  return out;
}

function sevFromLevel(level: string | undefined): CybriumIngestFinding["severity"] {
  switch ((level || "").toLowerCase()) {
    case "error":   return "high";
    case "warning": return "medium";
    case "note":    return "low";
    default:        return "info";
  }
}

function httpPost(
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<{ ok: boolean; status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? require("https") : require("http");
    const req = lib.request(
      {
        method:   "POST",
        hostname: u.hostname,
        port:     u.port || (u.protocol === "https:" ? 443 : 80),
        path:     u.pathname + (u.search || ""),
        headers:  { ...headers, "Content-Length": Buffer.byteLength(body).toString() },
        timeout:  30000,
      },
      (res: any) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const s = (res.statusCode || 0) as number;
          resolve({
            ok: s >= 200 && s < 300,
            status: s,
            body: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(new Error("upload timed out")); });
    req.write(body);
    req.end();
  });
}
