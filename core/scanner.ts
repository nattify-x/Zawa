/**
 * Zawa Scanner Engine
 * Pure TypeScript scanning logic without VS Code imports.
 */

import { isDocumentedExampleKey, isJwtExpired } from './entropy';
import { DEFAULT_RULES } from './rules';
import { Confidence, Finding, Rule } from './types';

/**
 * Maximum character count permitted per line before it is skipped (e.g. minified code).
 */
export const DEFAULT_MAX_LINE_LENGTH = 2000;

/**
 * Maximum findings captured per individual file to protect memory.
 */
export const DEFAULT_MAX_FINDINGS_PER_FILE = 50;

/**
 * Checks whether a given path or filename belongs to a test, spec, mock, or fixture file.
 * Matches /(spec|test|tests|__tests__|mock|fixture)/i in path or *.spec.* / *.test.* filenames.
 */
export function isTestOrFixturePath(filePath?: string, rootFolder?: string): boolean {
  if (!filePath) {
    return false;
  }
  let targetPath = filePath.replace(/\\/g, '/');
  if (rootFolder) {
    const normRoot = rootFolder.replace(/\\/g, '/').replace(/\/+$/, '');
    if (targetPath.startsWith(normRoot)) {
      targetPath = targetPath.slice(normRoot.length);
    }
  }
  const baseName = targetPath.split('/').pop() || targetPath;
  return /(spec|test|tests|__tests__|mock|fixture)/i.test(targetPath) ||
         /\.(spec|test)\./i.test(baseName);
}

/**
 * Checks whether a given path is a documentation file (.md, .txt)
 * or an environment template (.env.example, .env.sample, .env.template).
 */
export function isDocOrTemplatePath(filePath?: string): boolean {
  if (!filePath) {
    return false;
  }
  const norm = filePath.replace(/\\/g, '/');
  const baseName = norm.split('/').pop() || norm;
  const lowerBase = baseName.toLowerCase();

  // 1. .md and .txt documentation files
  if (lowerBase.endsWith('.md') || lowerBase.endsWith('.txt')) {
    return true;
  }

  // 2. .env.example / .env.sample / .env.template files
  if (
    lowerBase === '.env.example' ||
    lowerBase.startsWith('.env.example.') ||
    lowerBase === '.env.sample' ||
    lowerBase.startsWith('.env.sample.') ||
    lowerBase === '.env.template' ||
    lowerBase.startsWith('.env.template.') ||
    /\.env\.(example|sample|template)/i.test(lowerBase)
  ) {
    return true;
  }

  return false;
}

/**
 * Lowers confidence by one level (high -> medium -> low).
 */
export function lowerConfidence(conf: Confidence): Confidence {
  if (conf === 'high') {
    return 'medium';
  }
  if (conf === 'medium') {
    return 'low';
  }
  return 'low';
}

/**
 * Replaces lines exceeding maxLineLength with empty lines to:
 * 1. Skip minified or bundled lines prone to high regex cost.
 * 2. Retain 100% exact 1-based line and column numbering for all other lines.
 */
function sanitizeLongLines(text: string, maxLineLength: number): string {
  let hasLongLine = false;
  let currentLen = 0;

  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) { // '\n'
      currentLen = 0;
    } else {
      currentLen++;
      if (currentLen > maxLineLength) {
        hasLongLine = true;
        break;
      }
    }
  }

  if (!hasLongLine) {
    return text;
  }

  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > maxLineLength) {
      lines[i] = '';
    }
  }
  return lines.join('\n');
}

/**
 * Checks whether a finding on a given line is suppressed by a "zawa-ignore" comment
 * on that line or on the line directly above it.
 */
function isLineSuppressed(lines: string[], lineNum1Based: number): boolean {
  // Check the finding's line
  const currentIdx = lineNum1Based - 1;
  if (currentIdx >= 0 && currentIdx < lines.length) {
    if (lines[currentIdx].includes('zawa-ignore')) {
      return true;
    }
  }

  // Check the line directly above
  const prevIdx = lineNum1Based - 2;
  if (prevIdx >= 0 && prevIdx < lines.length) {
    if (lines[prevIdx].includes('zawa-ignore')) {
      return true;
    }
  }

  return false;
}

/**
 * Pre-computes line start offsets for fast O(log N) position lookups.
 */
function computeLineOffsets(text: string): number[] {
  const offsets = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) { // '\n'
      offsets.push(i + 1);
    }
  }
  return offsets;
}

/**
 * Resolves 1-based line and column coordinates from a character offset.
 */
function getPositionFromOffset(lineOffsets: number[], offset: number): { line: number; column: number } {
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const lineStart = lineOffsets[mid];

    if (lineStart <= offset) {
      if (mid === lineOffsets.length - 1 || lineOffsets[mid + 1] > offset) {
        return {
          line: mid + 1,
          column: offset - lineStart + 1,
        };
      }
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return { line: 1, column: 1 };
}

/**
 * Scans a string of text against security rules and returns findings.
 *
 * Guarantees:
 * - Skips lines longer than maxLineLength (2000 chars) to prevent ReDoS / memory spikes.
 * - Suppresses findings marked with "zawa-ignore" on the same line or line above.
 * - Lowers confidence by one level for test / fixture / mock / spec paths,
 *   as well as .md, .txt documentation and .env.example / .env.sample / .env.template files.
 * - Caps findings at maxFindings (50 per file by default).
 * - All regexes execute with the global flag (`g`).
 * - Never loops forever: explicitly advances `regex.lastIndex` on zero-length matches.
 * - Pure TypeScript: zero dependencies on external modules or VS Code.
 *
 * @param text The source code or file content to scan.
 * @param filename Optional filename used for context-aware filtering.
 * @param rules Optional custom rule list; defaults to DEFAULT_RULES.
 * @param maxFindings Optional maximum findings per file; defaults to 50.
 * @param maxLineLength Optional maximum line length; defaults to 2000.
 */
export function scanText(
  text: string,
  filename?: string,
  rules: Rule[] = DEFAULT_RULES,
  maxFindings: number = DEFAULT_MAX_FINDINGS_PER_FILE,
  maxLineLength: number = DEFAULT_MAX_LINE_LENGTH
): Finding[] {
  if (!text || text.length === 0) {
    return [];
  }

  // Keep original lines to inspect "zawa-ignore" comment directives
  const originalLines = text.split('\n');

  // Check if current file is a test/fixture path or doc/template path to lower confidence
  const inTestPath = filename ? isTestOrFixturePath(filename) : false;
  const inDocOrTemplate = filename ? isDocOrTemplatePath(filename) : false;
  const shouldDemoteConfidence = inTestPath || inDocOrTemplate;

  // 1. Skip minified / excessively long lines while preserving line indices
  const sanitizedText = sanitizeLongLines(text, maxLineLength);
  const findings: Finding[] = [];
  const lineOffsets = computeLineOffsets(sanitizedText);

  for (const rule of rules) {
    // Stop early if file finding limit is already reached
    if (findings.length >= maxFindings) {
      break;
    }

    // Ensure global flag 'g'
    const flags = rule.pattern.flags.includes('g')
      ? rule.pattern.flags
      : rule.pattern.flags + 'g';

    // Fresh RegExp instance per scan to ensure thread/re-entrancy safety
    const regex = new RegExp(rule.pattern.source, flags);
    regex.lastIndex = 0;

    let match: RegExpExecArray | null;

    // Loop with safety against infinite loops
    while ((match = regex.exec(sanitizedText)) !== null) {
      const matchIndex = match.index;
      const matchedString = match[0];

      // Anti-infinite loop guarantee:
      // If regex matched an empty string or lastIndex failed to advance, force advance
      if (regex.lastIndex === matchIndex) {
        regex.lastIndex++;
      }

      // Check optional filter
      if (rule.filter && !rule.filter(match, filename)) {
        continue;
      }

      // Compute 1-based positions
      const startPos = getPositionFromOffset(lineOffsets, matchIndex);
      const endPos = getPositionFromOffset(lineOffsets, matchIndex + matchedString.length);

      // Check if this line is suppressed via "zawa-ignore" comment
      if (isLineSuppressed(originalLines, startPos.line)) {
        continue;
      }

      // Format snippet
      const captureGroups = match.slice(1);
      let snippet = rule.formatSnippet
        ? rule.formatSnippet(matchedString, captureGroups)
        : matchedString.slice(0, 60);

      // Findings in test/fixture or doc/template paths have their confidence lowered by one level
      let confidence = shouldDemoteConfidence ? lowerConfidence(rule.confidence) : rule.confidence;

      // Documented example keys: report at low confidence with "documented example key"
      let extraMessage: string | undefined;
      const candidateSecret = captureGroups[0] || matchedString;
      if (isDocumentedExampleKey(matchedString) || isDocumentedExampleKey(candidateSecret)) {
        confidence = 'low';
        extraMessage = 'documented example key';
        snippet = `${snippet} (documented example key)`;
      }

      // JWT expiration check: decode offline and demote by one level if expired
      if (rule.id === 'ZAWA-009' && isJwtExpired(matchedString)) {
        confidence = lowerConfidence(confidence);
        extraMessage = extraMessage ? `${extraMessage}, expired` : 'expired';
        snippet = `${snippet} (expired)`;
      }

      findings.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        confidence,
        cwe: rule.cwe,
        cvss: rule.cvss,
        line: startPos.line,
        column: startPos.column,
        endLine: endPos.line,
        endColumn: endPos.column,
        snippet,
        message: extraMessage,
      });

      // Stop scanning this rule if cap reached
      if (findings.length >= maxFindings) {
        break;
      }
    }
  }

  // Sort findings by line and column for deterministic reporting
  return findings.sort((a, b) => {
    if (a.line !== b.line) {
      return a.line - b.line;
    }
    return (a.column ?? 0) - (b.column ?? 0);
  });
}
