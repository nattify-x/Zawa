import * as vscode from 'vscode';
import * as path from 'path';
import { scanText, Finding, DEFAULT_MAX_FINDINGS_PER_FILE, DEFAULT_MAX_LINE_LENGTH } from '../core';

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
 * Hardening limits to protect machines with low memory (e.g. 6 GB RAM).
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
}

/**
 * VS Code Extension Deactivation Lifecycle
 */
export function deactivate(): void {
  // Cleanup managed by context.subscriptions
}
