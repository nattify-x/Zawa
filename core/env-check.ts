/**
 * Environment file (.env) detection and gitignore verification utilities.
 * Pure TypeScript: Zero external dependencies.
 */

import { Finding } from './types';

/**
 * Checks whether a given path is an environment (.env) file.
 * Excludes example, sample, template, and distribution placeholder files.
 */
export function isEnvFile(filePath: string): boolean {
  if (!filePath) {
    return false;
  }

  const normalized = filePath.replace(/\\/g, '/');
  const baseName = normalized.split('/').pop() || normalized;
  const lowerBase = baseName.toLowerCase();

  // Must start with '.env' or be named 'env' (e.g. '.env', '.env.local', '.env.prod')
  if (!lowerBase.startsWith('.env')) {
    return false;
  }

  // Exclude example and template files which are designed to be committed
  const templateKeywords = ['example', 'sample', 'template', 'dist', 'mock'];
  for (const kw of templateKeywords) {
    if (lowerBase.includes(kw)) {
      return false;
    }
  }

  return true;
}

/**
 * Verifies if .gitignore file contents contain a pattern that covers an environment file.
 */
export function checkGitignoreMatchesEnv(gitignoreText: string, relPath: string): boolean {
  if (!gitignoreText || gitignoreText.length === 0) {
    return false;
  }

  const normalizedRelPath = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const baseName = normalizedRelPath.split('/').pop() || normalizedRelPath;
  const lowerBase = baseName.toLowerCase();

  const lines = gitignoreText.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Ignore empty lines and comments
    if (!line || line.startsWith('#')) {
      continue;
    }

    // Direct exact matches or common broad patterns
    if (
      line === '.env' ||
      line === '.env*' ||
      line === '*.env' ||
      line === '**/.env' ||
      line === '**/.env*' ||
      line === '/**/.env' ||
      line === '/**/.env*'
    ) {
      return true;
    }

    // Path-specific match (e.g. '/.env', 'config/.env', '.env.local')
    const strippedSlash = line.replace(/^\/+/, '').replace(/\/+$/, '');
    if (strippedSlash === normalizedRelPath || strippedSlash === baseName) {
      return true;
    }

    // Pattern .env.* matches files like .env.local, .env.production
    if (line === '.env.*' && lowerBase.startsWith('.env.')) {
      return true;
    }
  }

  return false;
}

/**
 * Creates a standard ZAWA-021 finding for an unignored .env file.
 */
export function createUnignoredEnvFinding(relPath: string): Finding {
  return {
    ruleId: 'ZAWA-021',
    name: '.env not ignored',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-538',
    cvss: 7.5,
    line: 1,
    column: 1,
    snippet: `${relPath} is not covered by .gitignore`,
    message: '.env file exists and is not covered by .gitignore',
  };
}
