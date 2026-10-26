#!/usr/bin/env node
/**
 * Zawa Security Scanner CLI
 * Pure Node.js command-line interface.
 * Zero VS Code dependencies.
 *
 * Usage:
 *   zawa <folder> [--json] [--exclude-tests]
 *   zawa install-hook
 *   zawa uninstall-hook
 *   zawa --staged
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import {
  scanText,
  Finding,
  DEFAULT_RULES,
  isTestOrFixturePath,
  isEnvFile,
  checkGitignoreMatchesEnv,
  createUnignoredEnvFinding,
  theme,
} from '../core';

interface CliOptions {
  command?: 'scan' | 'install-hook' | 'uninstall-hook' | 'staged';
  targetFolder: string;
  isJson: boolean;
  excludeTests: boolean;
  isStaged: boolean;
}

interface CliFileFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: string;
  cwe: string;
  cvss: number;
  file: string;
  line: number;
  column?: number;
  snippet: string;
}

interface ConfidenceCount {
  high: number;
  medium: number;
  low: number;
}

interface CliResult {
  summary: {
    targetFolder: string;
    filesScanned: number;
    totalFindings: number;
    affectedFiles: number;
    durationMs: number;
    hitTotalCap: boolean;
    confidence: ConfidenceCount;
  };
  findings: CliFileFinding[];
}

/**
 * Hardening limits matching the VS Code extension.
 */
const MAX_SCAN_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB
const SCAN_BATCH_SIZE = 20;                      // 20 files per batch
const MAX_FINDINGS_PER_FILE = 50;
const MAX_FINDINGS_TOTAL = 2000;

const EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  'out',
  'dist',
  'build',
  '.next',
  'vendor',
  'coverage',
]);

const LOCK_FILE_NAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'cargo.lock',
  'gemfile.lock',
  'poetry.lock',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tiff',
  '.pdf', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
  '.wasm', '.class', '.jar', '.pyc', '.pyo', '.pyd',
  '.mp3', '.mp4', '.mkv', '.avi', '.mov', '.wav', '.flac',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.db', '.sqlite', '.sqlite3', '.iso', '.dmg',
]);

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  let isJson = false;
  let excludeTests = false;
  let isStaged = false;
  let command: 'scan' | 'install-hook' | 'uninstall-hook' | 'staged' = 'scan';
  let targetFolder = '';

  for (const arg of args) {
    if (arg === 'install-hook') {
      command = 'install-hook';
    } else if (arg === 'uninstall-hook') {
      command = 'uninstall-hook';
    } else if (arg === '--staged') {
      isStaged = true;
      command = 'staged';
    } else if (arg === '--json') {
      isJson = true;
    } else if (arg === '--exclude-tests') {
      excludeTests = true;
    } else if (!targetFolder && !arg.startsWith('-')) {
      targetFolder = arg;
    }
  }

  if (!targetFolder) {
    targetFolder = process.cwd();
  }

  return {
    command,
    targetFolder: path.resolve(targetFolder),
    isJson,
    excludeTests,
    isStaged,
  };
}

function isBinaryBuffer(buffer: Buffer): boolean {
  const checkLength = Math.min(buffer.length, 1024);
  for (let i = 0; i < checkLength; i++) {
    if (buffer[i] === 0x00) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether an environment (.env) file is covered by .gitignore.
 */
function isEnvCoveredByGitignore(filePath: string, targetFolder: string): boolean {
  const normTarget = path.resolve(targetFolder);
  const relPath = path.relative(normTarget, filePath).replace(/\\/g, '/');

  // 1. If targetFolder has a .git directory, query git check-ignore directly
  if (fs.existsSync(path.join(normTarget, '.git'))) {
    try {
      const res = spawnSync('git', ['check-ignore', '-q', '--', relPath], {
        cwd: normTarget,
        encoding: 'utf-8',
        windowsHide: true,
      });
      if (res.status === 0) {
        return true;
      }
    } catch {}
  }

  // 2. Direct inspection of .gitignore files from file dir up to targetFolder
  let dir = path.dirname(filePath);
  while (dir.startsWith(normTarget) || dir === normTarget) {
    const gitignorePath = path.join(dir, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      try {
        const content = fs.readFileSync(gitignorePath, 'utf-8');
        const subRel = path.relative(dir, filePath).replace(/\\/g, '/');
        if (checkGitignoreMatchesEnv(content, subRel)) {
          return true;
        }
      } catch {}
    }
    if (dir === normTarget) {
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }

  return false;
}

/**
 * Recursively discovers candidate files while respecting the exact exclude rules.
 */
function discoverFiles(dir: string, fileList: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const baseName = entry.name.toLowerCase();

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(baseName)) {
        continue;
      }
      discoverFiles(fullPath, fileList);
    } else if (entry.isFile()) {
      // Skip lock files
      if (LOCK_FILE_NAMES.has(baseName) || baseName.endsWith('.lock')) {
        continue;
      }
      // Skip binary extensions
      const ext = path.extname(baseName);
      if (BINARY_EXTENSIONS.has(ext)) {
        continue;
      }
      fileList.push(fullPath);
    }
  }

  return fileList;
}

/**
 * Installs the Zawa pre-commit hook into .git/hooks/pre-commit.
 */
function handleInstallHook(): void {
  const gitDirResult = spawnSync('git', ['rev-parse', '--git-dir'], {
    encoding: 'utf-8',
    windowsHide: true,
  });

  if (gitDirResult.status !== 0 || !gitDirResult.stdout) {
    console.error('[ZAWA] Error: Current directory is not inside a git repository.');
    console.error('Run "git init" before installing the Zawa pre-commit hook.');
    process.exit(1);
  }

  const gitDir = path.resolve(process.cwd(), gitDirResult.stdout.trim());
  const hooksDir = path.join(gitDir, 'hooks');

  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookFile = path.join(hooksDir, 'pre-commit');
  const cliScriptPath = path.resolve(__dirname, 'zawa-cli.js').replace(/\\/g, '/');

  const hookContent = `#!/bin/sh
# Zawa Pre-Commit Hook
# Prevents high-confidence credentials and secrets from being committed.

# 1. Inspect staged files (Added, Copied, Modified)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# 2. Execute Zawa scanner on staged files
if [ -f "./out/cli/zawa-cli.js" ]; then
  node "./out/cli/zawa-cli.js" --staged
  EXIT_CODE=$?
elif [ -n "${cliScriptPath}" ] && [ -f "${cliScriptPath}" ]; then
  node "${cliScriptPath}" --staged
  EXIT_CODE=$?
elif command -v zawa >/dev/null 2>&1; then
  zawa --staged
  EXIT_CODE=$?
else
  npx --yes zawa --staged
  EXIT_CODE=$?
fi

exit $EXIT_CODE
`;

  try {
    fs.writeFileSync(hookFile, hookContent, { mode: 0o755 });
    try {
      fs.chmodSync(hookFile, 0o755);
    } catch {}

    console.log('[ZAWA] Pre-commit hook installed successfully!');
    console.log(`  Target:  ${hookFile}`);
    console.log('  Trigger: Runs automatically on "git commit"');
    console.log('  Scope:   Scans staged files only (git diff --cached --name-only)');
    console.log('  Action:  Blocks commit with exit code 1 on HIGH-confidence findings.');
  } catch (err) {
    console.error(`[ZAWA] Error: Failed to write hook at ${hookFile}:`, err);
    process.exit(1);
  }
}

/**
 * Uninstalls the Zawa pre-commit hook from .git/hooks/pre-commit.
 */
function handleUninstallHook(): void {
  const gitDirResult = spawnSync('git', ['rev-parse', '--git-dir'], {
    encoding: 'utf-8',
    windowsHide: true,
  });

  if (gitDirResult.status !== 0 || !gitDirResult.stdout) {
    console.error('[ZAWA] Error: Current directory is not inside a git repository.');
    process.exit(1);
  }

  const gitDir = path.resolve(process.cwd(), gitDirResult.stdout.trim());
  const hookFile = path.join(gitDir, 'hooks', 'pre-commit');

  if (fs.existsSync(hookFile)) {
    try {
      fs.unlinkSync(hookFile);
      console.log('[ZAWA] Pre-commit hook uninstalled successfully.');
      console.log(`  Removed: ${hookFile}`);
    } catch (err) {
      console.error(`[ZAWA] Error: Failed to delete hook at ${hookFile}:`, err);
      process.exit(1);
    }
  } else {
    console.log(`[ZAWA] No pre-commit hook found at ${hookFile}.`);
  }
}

/**
 * Runs Zawa scanner exclusively on staged git files.
 */
async function handleStagedScan(): Promise<void> {
  const repoRootResult = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf-8',
    windowsHide: true,
  });

  if (repoRootResult.status !== 0 || !repoRootResult.stdout) {
    console.error('[ZAWA] Error: Not a git repository.');
    process.exit(1);
  }

  const repoRoot = path.resolve(repoRootResult.stdout.trim());

  const diffResult = spawnSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], {
    encoding: 'utf-8',
    cwd: repoRoot,
    windowsHide: true,
  });

  if (diffResult.status !== 0) {
    console.error('[ZAWA] Error executing git diff:', diffResult.stderr);
    process.exit(1);
  }

  const stagedFiles = diffResult.stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (stagedFiles.length === 0) {
    process.exit(0);
  }

  const allFindings: CliFileFinding[] = [];

  for (const relPath of stagedFiles) {
    const fullPath = path.resolve(repoRoot, relPath);

    if (!fs.existsSync(fullPath)) {
      continue;
    }

    // Check .env not ignored
    if (isEnvFile(relPath)) {
      if (!isEnvCoveredByGitignore(fullPath, repoRoot)) {
        const envFinding = createUnignoredEnvFinding(relPath);
        allFindings.push({
          ruleId: envFinding.ruleId,
          ruleName: envFinding.name,
          severity: envFinding.severity,
          confidence: envFinding.confidence,
          cwe: envFinding.cwe,
          cvss: envFinding.cvss,
          file: relPath,
          line: envFinding.line,
          column: envFinding.column,
          snippet: envFinding.snippet,
        });
      }
    }

    // Scan file content
    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > MAX_SCAN_FILE_SIZE_BYTES) {
        continue;
      }
      const buffer = fs.readFileSync(fullPath);
      if (isBinaryBuffer(buffer)) {
        continue;
      }
      const content = buffer.toString('utf-8');
      const fileFindings = scanText(content, relPath, DEFAULT_RULES, MAX_FINDINGS_PER_FILE);

      for (const f of fileFindings) {
        allFindings.push({
          ruleId: f.ruleId,
          ruleName: f.name,
          severity: f.severity,
          confidence: f.confidence,
          cwe: f.cwe,
          cvss: f.cvss,
          file: relPath,
          line: f.line,
          column: f.column,
          snippet: f.snippet,
        });
      }
    } catch {
      continue;
    }
  }

  const highFindings = allFindings.filter((f) => f.confidence === 'high');

  if (highFindings.length > 0) {
    console.error('\n================================================================');
    console.error(' [ZAWA] Pre-Commit Security Guard: COMMIT BLOCKED!');
    console.error('================================================================');
    console.error(`Detected ${highFindings.length} HIGH-confidence security finding(s) in staged files:\n`);

    for (const f of highFindings) {
      console.error(`  [HIGH] ${f.ruleId}: ${f.ruleName} (${f.cwe}, CVSS ${f.cvss})`);
      console.error(`    Location: ${f.file}:${f.line}${f.column ? `:${f.column}` : ''}`);
      console.error(`    Snippet:  ${f.snippet}\n`);
    }

    console.error('----------------------------------------------------------------');
    console.error('Commit blocked to protect your repository from secret leakage.');
    console.error('');
    console.error('How to resolve:');
    console.error('  1. Remove or rotate the secret from your staged file(s).');
    console.error('  2. If intentional or a known test decoy, add a comment:');
    console.error('       // zawa-ignore');
    console.error('     on the same line or line directly above the finding.');
    console.error('  3. Or bypass this pre-commit check:');
    console.error('       git commit --no-verify');
    console.error('================================================================\n');

    process.exit(1);
  }

  if (allFindings.length > 0) {
    console.log(`[ZAWA] Staged check: ${allFindings.length} non-blocking (medium/low) finding(s). Commit allowed.`);
  }

  process.exit(0);
}

async function runCli(): Promise<void> {
  const options = parseArgs();

  if (options.command === 'install-hook') {
    handleInstallHook();
    return;
  }

  if (options.command === 'uninstall-hook') {
    handleUninstallHook();
    return;
  }

  if (options.command === 'staged') {
    await handleStagedScan();
    return;
  }

  if (!fs.existsSync(options.targetFolder)) {
    console.error(`Error: Directory not found: ${options.targetFolder}`);
    process.exit(1);
  }

  const startTime = Date.now();
  const candidateFiles = discoverFiles(options.targetFolder);

  let scannedCount = 0;
  let affectedFilesCount = 0;
  let hitTotalCap = false;
  const allFindings: CliFileFinding[] = [];

  // Process in small batches of 20 with event loop yields
  for (let i = 0; i < candidateFiles.length; i += SCAN_BATCH_SIZE) {
    if (allFindings.length >= MAX_FINDINGS_TOTAL) {
      hitTotalCap = true;
      break;
    }

    const batch = candidateFiles.slice(i, i + SCAN_BATCH_SIZE);

    for (const filePath of batch) {
      if (allFindings.length >= MAX_FINDINGS_TOTAL) {
        hitTotalCap = true;
        break;
      }

      const relPath = path.relative(options.targetFolder, filePath).replace(/\\/g, '/');

      // If --exclude-tests is specified, drop test and fixture files entirely
      if (options.excludeTests && isTestOrFixturePath(relPath)) {
        continue;
      }

      // Check unignored .env files
      if (isEnvFile(filePath)) {
        if (!isEnvCoveredByGitignore(filePath, options.targetFolder)) {
          const envFinding = createUnignoredEnvFinding(relPath || path.basename(filePath));
          allFindings.push({
            ruleId: envFinding.ruleId,
            ruleName: envFinding.name,
            severity: envFinding.severity,
            confidence: envFinding.confidence,
            cwe: envFinding.cwe,
            cvss: envFinding.cvss,
            file: relPath || path.basename(filePath),
            line: envFinding.line,
            column: envFinding.column,
            snippet: envFinding.snippet,
          });
          affectedFilesCount++;
        }
      }

      // Individual file error boundary
      try {
        const stat = fs.statSync(filePath);

        // Skip files > 1 MB
        if (stat.size > MAX_SCAN_FILE_SIZE_BYTES) {
          continue;
        }

        const buffer = fs.readFileSync(filePath);

        // Skip binary files
        if (isBinaryBuffer(buffer)) {
          continue;
        }

        const content = buffer.toString('utf-8');
        const remainingBudget = Math.min(MAX_FINDINGS_PER_FILE, MAX_FINDINGS_TOTAL - allFindings.length);

        // Pass relative path so scanner correctly lowers confidence on test/fixture files
        const fileFindings = scanText(content, relPath, DEFAULT_RULES, remainingBudget);

        scannedCount++;

        if (fileFindings.length > 0) {
          affectedFilesCount++;

          for (const f of fileFindings) {
            allFindings.push({
              ruleId: f.ruleId,
              ruleName: f.name,
              severity: f.severity,
              confidence: f.confidence,
              cwe: f.cwe,
              cvss: f.cvss,
              file: relPath || path.basename(filePath),
              line: f.line,
              column: f.column,
              snippet: f.snippet,
            });
          }
        }
      } catch {
        // Continue on unreadable files
        continue;
      }
    }

    // Yield to Node event loop between batches
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  const durationMs = Date.now() - startTime;

  const confidenceCounts: ConfidenceCount = {
    high: allFindings.filter((f) => f.confidence === 'high').length,
    medium: allFindings.filter((f) => f.confidence === 'medium').length,
    low: allFindings.filter((f) => f.confidence === 'low').length,
  };

  const result: CliResult = {
    summary: {
      targetFolder: options.targetFolder,
      filesScanned: scannedCount,
      totalFindings: allFindings.length,
      affectedFiles: affectedFilesCount,
      durationMs,
      hitTotalCap,
      confidence: confidenceCounts,
    },
    findings: allFindings,
  };

  if (options.isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printTextReport(result);
  }

  // Exit with non-zero code if error-severity findings were discovered
  const hasErrors = allFindings.some((f) => f.severity === 'error');
  process.exit(hasErrors ? 1 : 0);
}

function printTextReport(result: CliResult): void {
  console.log('\n================================================================');
  console.log(' Zawa Security Scanner (Offline)');
  console.log('================================================================');
  console.log(`Target: ${result.summary.targetFolder}`);
  console.log('----------------------------------------------------------------');

  if (result.findings.length === 0) {
    console.log('No security issues detected. Your code is clean!');
  } else {
    console.log(`Discovered ${result.findings.length} finding(s):\n`);

    for (const f of result.findings) {
      const confidenceBadge = `[Confidence: ${f.confidence}]`;
      const sevBadge = `[${f.severity.toUpperCase()}]`;

      console.log(`${sevBadge} ${f.ruleId}: ${f.ruleName} (${f.cwe}, CVSS ${f.cvss}) ${confidenceBadge}`);
      console.log(`  Location: ${f.file}:${f.line}${f.column ? `:${f.column}` : ''}`);
      console.log(`  Snippet:  ${f.snippet}\n`);
    }
  }

  console.log('----------------------------------------------------------------');
  console.log('Scan Summary:');
  console.log(`  Files scanned:   ${result.summary.filesScanned}`);
  console.log(`  Total findings:  ${result.summary.totalFindings}`);
  console.log(`  Confidence:      High: ${result.summary.confidence.high} | Medium: ${result.summary.confidence.medium} | Low: ${result.summary.confidence.low}`);
  console.log(`  Affected files:  ${result.summary.affectedFiles}`);
  console.log(`  Total time:      ${result.summary.durationMs} ms`);

  if (result.summary.hitTotalCap) {
    console.log(`  [NOTE] Finding limit of ${MAX_FINDINGS_TOTAL} reached. Scan stopped early.`);
  }

  console.log('================================================================\n');
}

runCli().catch((err) => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
