import * as vscode from 'vscode';
import * as path from 'path';
import { scanText, Finding, maskSecret, DEFAULT_MAX_FINDINGS_PER_FILE, DEFAULT_MAX_LINE_LENGTH } from '../core';

/**
 * Common binary extensions to skip immediately during file discovery.
 */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tiff',
  '.pdf', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
  '.wasm', '.class', '.jar', '.pyc', '.pyo', '.pyd',
  '.mp3', '.mp4', '.mkv', '.avi', '.mov', '.wav', '.flac',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.db', '.sqlite', '.sqlite3', '.iso', '.dmg'
]);

/**
 * Exclude glob for workspace scanning:
 * Excludes node_modules, .git, out, dist, build, .next, vendor, coverage, and lock files.
 */
const WORKSPACE_EXCLUDE_GLOB = '{**/node_modules/**,**/.git/**,**/out/**,**/dist/**,**/build/**,**/.next/**,**/vendor/**,**/coverage/**,**/*.lock,**/*lock.json,**/*lock.yaml,**/*lock.yml}';

/**
 * Hardening limits to keep scans light on memory.
 */
const MAX_SCAN_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB limit per file
const SCAN_BATCH_SIZE = 20;                      // 20 files per batch
const MAX_FINDINGS_PER_FILE = 50;                // Cap findings at 50 per file
const MAX_FINDINGS_TOTAL = 2000;                 // Cap findings at 2000 total

/**
 * Persistent Output channel for Zawa logs and summary reports.
 */
let outputChannel: vscode.OutputChannel;

/**
 * Checks if a byte buffer contains null bytes (binary file heuristic).
 */
function isBinaryBuffer(buffer: Uint8Array): boolean {
  const checkLength = Math.min(buffer.length, 1024);
  for (let i = 0; i < checkLength; i++) {
    if (buffer[i] === 0x00) {
      return true;
    }
  }
  return false;
}

/**
 * Returns a formatted timestamp string [HH:MM:SS].
 */
function timestamp(): string {
  return `[${new Date().toLocaleTimeString()}]`;
}

/**
 * Maps a Zawa finding into a VS Code diagnostic with squiggles and CWE/CVSS info.
 */
function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const startLine = Math.max(0, finding.line - 1);
  const startCol = Math.max(0, (finding.column ?? 1) - 1);
  const endLine = Math.max(0, (finding.endLine ?? finding.line) - 1);
  const endCol = Math.max(startCol + 1, (finding.endColumn ?? (startCol + finding.snippet.length)) - 1);

  const range = new vscode.Range(startLine, startCol, endLine, endCol);
  // Requirement: show CWE, CVSS, and confidence in the message
  const whyPart = finding.message ? ` (${finding.message})` : '';
  const message = `[${finding.ruleId}] ${finding.name} (${finding.cwe}, CVSS ${finding.cvss}, Confidence: ${finding.confidence})${whyPart}: ${finding.snippet}`;

  let severity = vscode.DiagnosticSeverity.Information;
  if (finding.severity === 'error') {
    severity = vscode.DiagnosticSeverity.Error;
  } else if (finding.severity === 'warning') {
    severity = vscode.DiagnosticSeverity.Warning;
  }

  const diagnostic = new vscode.Diagnostic(range, message, severity);
  diagnostic.source = 'Zawa';
  (diagnostic as any).confidence = finding.confidence;
  diagnostic.code = {
    value: `${finding.ruleId} (${finding.cwe})`,
    target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`)
  };

  return diagnostic;
}

/**
 * Scans a single text document and posts findings to the diagnostic collection.
 */
function scanDocument(
  document: vscode.TextDocument,
  diagnosticCollection: vscode.DiagnosticCollection
): void {
  if (document.uri.scheme !== 'file' && document.uri.scheme !== 'untitled') {
    return;
  }

  try {
    const text = document.getText();
    // Cap findings at 50 per file and skip lines > 2000 chars
    const findings = scanText(text, document.fileName, undefined, MAX_FINDINGS_PER_FILE, DEFAULT_MAX_LINE_LENGTH);
    const diagnostics = findings.map(toDiagnostic);

    diagnosticCollection.set(document.uri, diagnostics);
  } catch (err) {
    if (outputChannel) {
      outputChannel.appendLine(`${timestamp()} [ERROR] Failed to scan active file ${document.fileName}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

/**
 * Hardened workspace scanner:
 * - Excludes node_modules, .git, out, dist, build, .next, vendor, coverage, and lock files.
 * - Processes in batches of 20, yielding to the event loop between batches.
 * - Skips files > 1 MB and lines > 2000 characters.
 * - Caps findings at 50 per file and 2000 total across the workspace.
 * - Provides cancellable progress reporting.
 * - Isolates each file in try/catch to guarantee zero crashes.
 * - Logs errors and a final summary to the "Zawa" Output channel.
 */
async function scanWorkspace(
  diagnosticCollection: vscode.DiagnosticCollection
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showInformationMessage('Zawa: No workspace folder is currently open.');
    return;
  }

  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine(`${timestamp()} Starting workspace scan...`);
  const startTime = Date.now();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Zawa: Scanning Workspace',
      cancellable: true,
    },
    async (progress, token) => {
      let files: vscode.Uri[] = [];

      try {
        files = await vscode.workspace.findFiles('**/*', WORKSPACE_EXCLUDE_GLOB);
      } catch (err) {
        outputChannel.appendLine(`${timestamp()} [ERROR] Failed to discover workspace files: ${err instanceof Error ? err.message : String(err)}`);
        vscode.window.showErrorMessage('Zawa: Error discovering files during workspace scan.');
        return;
      }

      outputChannel.appendLine(`${timestamp()} Discovered ${files.length} candidate file(s) after exclude glob filtering.`);

      diagnosticCollection.clear();

      let scannedCount = 0;
      let totalFindings = 0;
      let affectedFiles = 0;
      let skippedLargeFiles = 0;
      let skippedBinaryFiles = 0;
      let hitTotalCap = false;

      // Process files in small batches to prevent freezing
      for (let i = 0; i < files.length; i += SCAN_BATCH_SIZE) {
        if (token.isCancellationRequested) {
          outputChannel.appendLine(`${timestamp()} [INFO] Workspace scan cancelled by user.`);
          vscode.window.showInformationMessage('Zawa: Workspace scan cancelled.');
          break;
        }

        if (totalFindings >= MAX_FINDINGS_TOTAL) {
          hitTotalCap = true;
          break;
        }

        const batch = files.slice(i, i + SCAN_BATCH_SIZE);

        for (const fileUri of batch) {
          if (token.isCancellationRequested) {
            break;
          }

          if (totalFindings >= MAX_FINDINGS_TOTAL) {
            hitTotalCap = true;
            break;
          }

          // Individual try/catch ensures one corrupt or unreadable file cannot halt the scan
          try {
            const ext = path.extname(fileUri.fsPath).toLowerCase();

            // 1. Skip known binary extensions
            if (BINARY_EXTENSIONS.has(ext)) {
              skippedBinaryFiles++;
              continue;
            }

            // 2. Stat file to check size
            const stat = await vscode.workspace.fs.stat(fileUri);
            if (stat.size > MAX_SCAN_FILE_SIZE_BYTES) {
              skippedLargeFiles++;
              outputChannel.appendLine(
                `${timestamp()} [SKIP] File exceeds 1 MB limit (${(stat.size / 1024).toFixed(0)} KB): ${fileUri.fsPath}`
              );
              continue;
            }

            // 3. Inspect buffer for binary null-byte indicator
            const fileBytes = await vscode.workspace.fs.readFile(fileUri);
            if (isBinaryBuffer(fileBytes)) {
              skippedBinaryFiles++;
              continue;
            }

            // 4. Decode text content
            const content = new TextDecoder('utf-8', { fatal: false }).decode(fileBytes);

            // 5. Scan text with capped per-file findings and 2000-char max line length
            const remainingBudget = Math.min(MAX_FINDINGS_PER_FILE, MAX_FINDINGS_TOTAL - totalFindings);
            const findings = scanText(content, fileUri.fsPath, undefined, remainingBudget, DEFAULT_MAX_LINE_LENGTH);

            scannedCount++;

            if (findings.length > 0) {
              totalFindings += findings.length;
              affectedFiles++;
              diagnosticCollection.set(fileUri, findings.map(toDiagnostic));
            } else {
              diagnosticCollection.delete(fileUri);
            }
          } catch (err) {
            outputChannel.appendLine(
              `${timestamp()} [ERROR] Error reading ${fileUri.fsPath}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }

        // Update progress bar
        progress.report({
          message: `Scanned ${scannedCount} / ${files.length} files`,
          increment: (batch.length / files.length) * 100,
        });

        // Yield to the event loop so the UI remains completely responsive
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }

      const durationMs = Date.now() - startTime;

      // Final summary logging to Output channel
      outputChannel.appendLine(`${timestamp()} Workspace scan completed in ${durationMs} ms.`);
      outputChannel.appendLine(`  - Files scanned: ${scannedCount} / ${files.length}`);
      outputChannel.appendLine(`  - Total findings: ${totalFindings}`);
      outputChannel.appendLine(`  - Affected files: ${affectedFiles}`);
      outputChannel.appendLine(`  - Skipped files (>1MB): ${skippedLargeFiles}`);
      outputChannel.appendLine(`  - Skipped binary files: ${skippedBinaryFiles}`);

      if (hitTotalCap) {
        outputChannel.appendLine(`  - [CAP REACHED] Reached maximum limit of ${MAX_FINDINGS_TOTAL} total findings.`);
        vscode.window.showWarningMessage(
          `Zawa: Workspace scan hit the cap of ${MAX_FINDINGS_TOTAL} findings and stopped early to preserve memory. Found ${totalFindings} issues across ${affectedFiles} file(s).`
        );
      } else if (totalFindings > 0) {
        vscode.window.showWarningMessage(
          `Zawa: Scan completed. Found ${totalFindings} issue(s) across ${affectedFiles} file(s) in ${durationMs} ms.`
        );
      } else {
        vscode.window.showInformationMessage(
          `Zawa: Workspace clean. Scanned ${scannedCount} file(s) with 0 issues in ${durationMs} ms.`
        );
      }
    }
  );
}

/**
 * Helper to escape regex special characters.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Converts any variable name, property name, or string into UPPER_SNAKE_CASE.
 */
export function toUpperSnakeCase(str: string): string {
  if (!str) {
    return 'SECRET_KEY';
  }
  const res = str
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
  return res || 'SECRET_KEY';
}

/**
 * Extracts a candidate variable name from the text preceding a string literal on a line.
 */
export function extractVarNameFromLine(lineText: string, literalStartIndex: number): string {
  let prefix = lineText.substring(0, literalStartIndex).trim();
  // Strip trailing assignment/comparison operators
  prefix = prefix.replace(/\s*(?:===|!==|==|!=|:=|=>|=|\:)\s*$/, '').trim();

  // Pattern 1: dictionary/bracket access: e.g. obj["VAR_NAME"] or os.environ['VAR_NAME']
  const bracketMatch = prefix.match(/\[\s*["']([a-zA-Z0-9_]+)["']\s*\]$/);
  if (bracketMatch) {
    return bracketMatch[1];
  }

  // Pattern 2: quoted property name: e.g. "apiKey" or 'apiKey'
  const quotedMatch = prefix.match(/["']([a-zA-Z0-9_]+)["']$/);
  if (quotedMatch) {
    return quotedMatch[1];
  }

  // Pattern 3: define('VAR_NAME', ...) or similar
  const defineMatch = prefix.match(/define\s*\(\s*["']([a-zA-Z0-9_]+)["']/);
  if (defineMatch) {
    return defineMatch[1];
  }

  // Pattern 4: identifier or property chain: e.g. const apiKey, config.foo.secret_key_base
  const identMatch = prefix.match(/([a-zA-Z0-9_]+)$/);
  if (identMatch) {
    return identMatch[1];
  }

  return 'SECRET_KEY';
}

/**
 * Returns comment syntax for inserting a zawa-ignore comment in the target document.
 */
export function getZawaIgnoreComment(document: vscode.TextDocument): string {
  const lang = document.languageId.toLowerCase();
  const ext = path.extname(document.fileName).toLowerCase();
  const base = path.basename(document.fileName).toLowerCase();

  // Hash (#) comment style
  if (
    [
      'python', 'ruby', 'shellscript', 'bash', 'yaml', 'dockerfile',
      'r', 'perl', 'powershell', 'makefile', 'toml', 'ini', 'properties'
    ].includes(lang) ||
    ['.py', '.rb', '.sh', '.bash', '.zsh', '.yaml', '.yml', '.r', '.pl', '.pm', '.ps1', '.toml', '.ini'].includes(ext) ||
    base === 'dockerfile' || base === 'makefile'
  ) {
    return '# zawa-ignore';
  }

  // HTML / XML comment style
  if (
    ['html', 'xml', 'markdown', 'svg'].includes(lang) ||
    ['.html', '.htm', '.xml', '.md', '.markdown', '.svg'].includes(ext)
  ) {
    return '<!-- zawa-ignore -->';
  }

  // CSS / Block comment style
  if (['css', 'scss', 'less'].includes(lang) || ['.css', '.scss', '.less'].includes(ext)) {
    return '/* zawa-ignore */';
  }

  // SQL / Dash-dash comment style
  if (['sql', 'lua', 'haskell'].includes(lang) || ['.sql', '.lua', '.hs'].includes(ext)) {
    return '-- zawa-ignore';
  }

  // Default C-style line comment
  return '// zawa-ignore';
}

/**
 * Information about a string literal found on a line.
 */
export interface StringLiteralInfo {
  range: vscode.Range;
  value: string;
  raw: string;
  quote: string;
}

/**
 * Unescapes quote characters inside a string literal value.
 */
function unescapeLiteralValue(rawInside: string, quote: string): string {
  if (quote === '"') {
    return rawInside.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  if (quote === "'") {
    return rawInside.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
  }
  return rawInside;
}

/**
 * Finds the string literal enclosing or overlapping with the diagnostic range on a line.
 * Returns null if the diagnostic is not on a string literal.
 */
export function findStringLiteral(
  lineText: string,
  lineNumber: number,
  diagnosticRange: vscode.Range
): StringLiteralInfo | null {
  const regex = /(["'`])((?:\\.|(?!\1)[^\r\n\\])*)\1/g;
  let match: RegExpExecArray | null;

  const diagStart = diagnosticRange.start.character;
  const diagEnd = diagnosticRange.end.character;

  let bestMatch: StringLiteralInfo | null = null;

  while ((match = regex.exec(lineText)) !== null) {
    const quote = match[1];
    const rawInside = match[2];
    const raw = match[0];
    const startChar = match.index;
    const endChar = match.index + raw.length;

    const overlaps = Math.max(startChar, diagStart) < Math.min(endChar, diagEnd);
    const touches = startChar <= diagStart && endChar >= diagEnd;
    const contains = diagStart <= startChar && diagEnd >= endChar;

    if (overlaps || touches || contains) {
      bestMatch = {
        range: new vscode.Range(lineNumber, startChar, lineNumber, endChar),
        value: unescapeLiteralValue(rawInside, quote),
        raw,
        quote
      };
      break;
    }
  }

  return bestMatch;
}

/**
 * Returns whether a diagnostic is high or medium confidence.
 */
function isHighOrMediumConfidence(diagnostic: vscode.Diagnostic): boolean {
  const anyDiag = diagnostic as any;
  if (anyDiag.confidence === 'high' || anyDiag.confidence === 'medium') {
    return true;
  }
  return diagnostic.message.includes('Confidence: high') || diagnostic.message.includes('Confidence: medium');
}

/**
 * Returns language-specific code replacement for environment variable access,
 * or null if the language does not have automatic replacement.
 */
function getLanguageReplacement(document: vscode.TextDocument, varName: string): string | null {
  const lang = document.languageId.toLowerCase();
  const ext = path.extname(document.fileName).toLowerCase();

  // JS / TS
  if (
    ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'].includes(lang) ||
    ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'].includes(ext)
  ) {
    return `process.env.${varName}`;
  }

  // Python
  if (lang === 'python' || ext === '.py') {
    return `os.environ["${varName}"]`;
  }

  // Ruby
  if (lang === 'ruby' || ext === '.rb') {
    return `ENV["${varName}"]`;
  }

  return null;
}

/**
 * Appends NAME=value to .env in the workspace root.
 * Creates .env if missing; never overwrites an existing variable.
 */
async function appendToEnvFile(workspaceRootUri: vscode.Uri, varName: string, secretValue: string): Promise<boolean> {
  const envUri = vscode.Uri.file(path.join(workspaceRootUri.fsPath, '.env'));
  let content = '';
  let exists = false;

  try {
    const raw = await vscode.workspace.fs.readFile(envUri);
    content = new TextDecoder('utf-8').decode(raw);
    exists = true;
  } catch {
    exists = false;
  }

  if (exists) {
    const varPattern = new RegExp(`^[ \\t]*${escapeRegex(varName)}[ \\t]*=`, 'm');
    if (varPattern.test(content)) {
      vscode.window.showWarningMessage(`Zawa: Variable "${varName}" already exists in .env; kept existing value without overwriting.`);
      return false;
    }
    const prefix = content.length > 0 && !content.endsWith('\n') ? '\n' : '';
    const newContent = `${content}${prefix}${varName}=${secretValue}\n`;
    await vscode.workspace.fs.writeFile(envUri, new TextEncoder().encode(newContent));
  } else {
    const newContent = `${varName}=${secretValue}\n`;
    await vscode.workspace.fs.writeFile(envUri, new TextEncoder().encode(newContent));
  }
  return true;
}

/**
 * Adds .env to .gitignore in the workspace root if it is missing.
 */
async function ensureGitignoreHasEnv(workspaceRootUri: vscode.Uri): Promise<void> {
  const gitignoreUri = vscode.Uri.file(path.join(workspaceRootUri.fsPath, '.gitignore'));
  let content = '';
  let exists = false;

  try {
    const raw = await vscode.workspace.fs.readFile(gitignoreUri);
    content = new TextDecoder('utf-8').decode(raw);
    exists = true;
  } catch {
    exists = false;
  }

  if (exists) {
    const lines = content.split(/\r?\n/);
    const hasEnv = lines.some((line) => {
      const trimmed = line.trim();
      return (
        trimmed === '.env' ||
        trimmed === '/.env' ||
        trimmed === '*.env' ||
        trimmed === '.env*' ||
        trimmed === '.env.*' ||
        trimmed === '**/.env'
      );
    });

    if (!hasEnv) {
      const prefix = content.length > 0 && !content.endsWith('\n') ? '\n' : '';
      const newContent = `${content}${prefix}.env\n`;
      await vscode.workspace.fs.writeFile(gitignoreUri, new TextEncoder().encode(newContent));
    }
  } else {
    const newContent = `.env\n`;
    await vscode.workspace.fs.writeFile(gitignoreUri, new TextEncoder().encode(newContent));
  }
}

/**
 * Handles the "Zawa: Move secret to .env" quick fix execution.
 */
async function handleMoveSecretToEnv(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  literalInfo: StringLiteralInfo,
  diagnosticCollection: vscode.DiagnosticCollection
): Promise<void> {
  const lineText = document.lineAt(diagnostic.range.start.line).text;
  const rawVar = extractVarNameFromLine(lineText, literalInfo.range.start.character);
  const defaultVarName = toUpperSnakeCase(rawVar);

  // (1) ask the user to confirm and to accept or edit a variable name (default from the variable name, upper snake case)
  const varNameInput = await vscode.window.showInputBox({
    prompt: 'Enter environment variable name for .env',
    value: defaultVarName,
    validateInput: (value) => {
      if (!value || value.trim().length === 0) {
        return 'Variable name cannot be empty.';
      }
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value.trim())) {
        return 'Variable name must contain only letters, numbers, and underscores, and cannot start with a number.';
      }
      return null;
    }
  });

  if (!varNameInput) {
    return;
  }

  const varName = varNameInput.trim().toUpperCase();

  // Find workspace root
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const workspaceRootUri = workspaceFolder
    ? workspaceFolder.uri
    : (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
      ? vscode.workspace.workspaceFolders[0].uri
      : vscode.Uri.file(path.dirname(document.uri.fsPath)));

  // (3) append NAME=value to .env in the workspace root (create it if missing, never overwrite an existing variable)
  await appendToEnvFile(workspaceRootUri, varName, literalInfo.value);

  // (4) add .env to .gitignore if it is missing
  await ensureGitignoreHasEnv(workspaceRootUri);

  // (2) replace the string literal with process.env.NAME (JS/TS), os.environ["NAME"] (Python) or ENV["NAME"] (Ruby), and for other languages only show a message with the .env line without editing
  const replacement = getLanguageReplacement(document, varName);
  if (replacement !== null) {
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, literalInfo.range, replacement);
    await vscode.workspace.applyEdit(edit);
    scanDocument(document, diagnosticCollection);
  } else {
    // For other languages, only show a message with the .env line without editing
    // Never log or show the full secret value
    vscode.window.showInformationMessage(
      `Zawa: .env line: ${varName}=${maskSecret(literalInfo.value)} (Configure environment loading for ${document.languageId})`
    );
  }
}

/**
 * Handles the "Zawa: Ignore this finding" quick fix execution.
 */
async function handleIgnoreFinding(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  diagnosticCollection: vscode.DiagnosticCollection
): Promise<void> {
  const targetLine = diagnostic.range.start.line;
  const lineText = document.lineAt(targetLine).text;
  const indentMatch = lineText.match(/^([ \t]*)/);
  const indent = indentMatch ? indentMatch[1] : '';
  const commentText = `${indent}${getZawaIgnoreComment(document)}\n`;

  const edit = new vscode.WorkspaceEdit();
  edit.insert(document.uri, new vscode.Position(targetLine, 0), commentText);
  await vscode.workspace.applyEdit(edit);

  scanDocument(document, diagnosticCollection);

  vscode.window.showWarningMessage('Rotate this key if it was ever committed.');
}

/**
 * VS Code CodeActionProvider offering quick fixes for Zawa diagnostics.
 */
export class ZawaCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  public provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    const zawaDiagnostics = context.diagnostics.filter(
      (d) => d.source === 'Zawa'
    );

    if (zawaDiagnostics.length === 0) {
      return actions;
    }

    for (const diagnostic of zawaDiagnostics) {
      // 1. "Zawa: Move secret to .env"
      // Offer ONLY for high and medium confidence findings that are string literals
      if (isHighOrMediumConfidence(diagnostic)) {
        const lineText = document.lineAt(diagnostic.range.start.line).text;
        const literalInfo = findStringLiteral(lineText, diagnostic.range.start.line, diagnostic.range);

        if (literalInfo) {
          const moveAction = new vscode.CodeAction(
            'Zawa: Move secret to .env',
            vscode.CodeActionKind.QuickFix
          );
          moveAction.diagnostics = [diagnostic];
          moveAction.isPreferred = true;
          moveAction.command = {
            command: 'zawa.moveSecretToEnv',
            title: 'Zawa: Move secret to .env',
            arguments: [document, diagnostic, literalInfo]
          };
          actions.push(moveAction);
        }
      }

      // 2. "Zawa: Ignore this finding"
      const ignoreAction = new vscode.CodeAction(
        'Zawa: Ignore this finding',
        vscode.CodeActionKind.QuickFix
      );
      ignoreAction.diagnostics = [diagnostic];
      ignoreAction.command = {
        command: 'zawa.ignoreFinding',
        title: 'Zawa: Ignore this finding',
        arguments: [document, diagnostic]
      };
      actions.push(ignoreAction);
    }

    return actions;
  }
}

/**
 * VS Code Extension Activation Lifecycle
 */
export function activate(context: vscode.ExtensionContext): void {
  // 1. Create Output channel for Zawa
  outputChannel = vscode.window.createOutputChannel('Zawa');
  context.subscriptions.push(outputChannel);

  // 2. Create diagnostic collection for Problem squiggles & panel
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('zawa');
  context.subscriptions.push(diagnosticCollection);

  // 3. Scan active documents already open upon activation
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document, diagnosticCollection);
  }
  for (const doc of vscode.workspace.textDocuments) {
    scanDocument(doc, diagnosticCollection);
  }

  // 4. Scan open files on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      scanDocument(doc, diagnosticCollection);
    })
  );

  // 5. Scan open files on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      scanDocument(doc, diagnosticCollection);
    })
  );

  // 6. Clean diagnostics when file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // 7. Register hardened "Zawa: Scan Workspace" command
  context.subscriptions.push(
    vscode.commands.registerCommand('zawa.scanWorkspace', async () => {
      await scanWorkspace(diagnosticCollection);
    })
  );

  // 8. Register CodeActionProvider for Zawa Quick Fixes
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      new ZawaCodeActionProvider(),
      {
        providedCodeActionKinds: ZawaCodeActionProvider.providedCodeActionKinds
      }
    )
  );

  // 9. Register command for "Zawa: Move secret to .env"
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'zawa.moveSecretToEnv',
      async (
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        literalInfo: StringLiteralInfo
      ) => {
        await handleMoveSecretToEnv(document, diagnostic, literalInfo, diagnosticCollection);
      }
    )
  );

  // 10. Register command for "Zawa: Ignore this finding"
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'zawa.ignoreFinding',
      async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
        await handleIgnoreFinding(document, diagnostic, diagnosticCollection);
      }
    )
  );
}

/**
 * VS Code Extension Deactivation Lifecycle
 */
export function deactivate(): void {
  // Cleanup managed by context.subscriptions
}
