/**
 * Core type definitions for the Zawa security engine.
 * Pure TypeScript: No VS Code imports allowed here.
 */

export type Severity = 'error' | 'warning' | 'info';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  ruleId: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  cvss: number;
  line: number;
  snippet: string;
  // Precise coordinate metadata for IDE highlighting (1-based)
  column?: number;
  endLine?: number;
  endColumn?: number;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  cvss: number;
  pattern: RegExp;
  description: string;
  // Optional validator to reduce false positives
  filter?: (match: RegExpExecArray, filename?: string) => boolean;
  // Optional custom snippet formatter
  formatSnippet?: (rawMatch: string, groups: string[]) => string;
}
