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
    vscode.commands.registerCommand('cybrium.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('cybrium.openDashboard', () => openDashboard()),
    vscode.commands.registerCommand('cybrium.explain', (diag: vscode.Diagnostic) => explainVulnerability(diag, context)),
    vscode.commands.registerCommand('cybrium.fixAll', () => fixAllFindings()),
    vscode.commands.registerCommand('cybrium.aiFixFile', () => aiFixCurrentFile()),
    vscode.commands.registerCommand('cybrium.webScan', () => webScan()),
    vscode.commands.registerCommand('cybrium.repoHealth', () => repoHealth()),
    vscode.commands.registerCommand('cybrium.detectFrameworks', () => detectFrameworks()),
    // v0.6.0 — cyradar (AI inventory channel #1: active discovery)
    vscode.commands.registerCommand('cybrium.discoverAITools', () => discoverAITools()),
    vscode.commands.registerCommand('cybrium.discoverAIServers', () => discoverAIServers()),
    // v0.7.0 — cy-tls, cyred, cymail
    vscode.commands.registerCommand('cybrium.tlsScan', () => tlsScan()),
    vscode.commands.registerCommand('cybrium.aiRedTeam', () => aiRedTeam()),
    vscode.commands.registerCommand('cybrium.emailSecurity', () => emailSecurity()),
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

async function repoHealth() {
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

  try {
    const health = JSON.parse(result);
    const panel = vscode.window.createWebviewPanel('cybriumHealth', 'Cybrium: Repo Health', vscode.ViewColumn.One, {});

    const checksHtml = (health.checks || []).map((c: any) => {
      const icon = c.passed ? '&#10004;' : '&#10008;';
      const color = c.passed ? '#4ade80' : '#ef4444';
      const sevColor = c.severity === 'critical' ? '#ef4444' : c.severity === 'high' ? '#f97316' : c.severity === 'medium' ? '#facc15' : '#9ca3af';
      return `<tr>
        <td style="color:${color};font-size:16px;text-align:center">${icon}</td>
        <td><span style="background:${sevColor}22;color:${sevColor};padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600">${c.severity?.toUpperCase()}</span></td>
        <td>${c.name}</td>
        <td style="color:#9ca3af;font-size:12px">${c.passed ? '' : c.detail}</td>
      </tr>`;
    }).join('');

    const scoreColor = health.score >= 80 ? '#4ade80' : health.score >= 50 ? '#facc15' : '#ef4444';

    panel.webview.html = `<!DOCTYPE html><html><head><style>
      body { font-family: -apple-system, sans-serif; padding: 24px; color: #e8e8f0; background: #0c0c1a; }
      h1 { font-size: 48px; color: ${scoreColor}; margin: 0; }
      table { width: 100%; border-collapse: collapse; margin-top: 16px; }
      td { padding: 8px 12px; border-bottom: 1px solid #1e1e3a; font-size: 13px; }
    </style></head><body>
      <h1>${health.score}/100</h1>
      <p style="color:#9ca3af">Repository Security Health Score</p>
      <table>${checksHtml}</table>
      <p style="color:#6b7280;margin-top:16px;font-size:11px">Powered by cyscan — cybrium.ai</p>
    </body></html>`;
  } catch {
    outputChannel.appendLine(result);
    vscode.window.showInformationMessage('Cybrium: Health check complete. See Output panel.');
  }
  statusBar.text = '$(shield) Cybrium';
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
