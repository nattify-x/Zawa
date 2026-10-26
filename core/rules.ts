/**
 * Zawa Security Rules
 * Pure TypeScript rule definitions for offline credential and vulnerability detection.
 * All regex patterns MUST include the global ('g') flag and strictly bounded quantifiers.
 */

import { isValidGenericSecret, isPlaceholder, isCodeReference } from './entropy';
import { Rule } from './types';

export function maskSecret(secret: string): string {
  if (secret.length <= 6) {
    return '******';
  }
  const prefix = secret.slice(0, 4);
  const suffix = secret.slice(-3);
  const maskedCount = Math.max(4, secret.length - 7);
  return `${prefix}${'*'.repeat(maskedCount)}${suffix}`;
}

export const DEFAULT_RULES: Rule[] = [
  // 1. AWS Access Key ID
  {
    id: 'ZAWA-001',
    name: 'AWS Access Key ID',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.5,
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    description: 'Exposed AWS Access Key ID. Permits unauthorized access to cloud assets.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 2. GitHub Token (Classic and Fine-Grained)
  {
    id: 'ZAWA-002',
    name: 'GitHub Token',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.1,
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,
    description: 'Exposed GitHub Personal Access Token or service token.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 3. Private Key Block
  {
    id: 'ZAWA-003',
    name: 'Private Key Block',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-312',
    cvss: 9.0,
    pattern: /-----BEGIN (?:[A-Z0-9_-]{1,64}\s+)?PRIVATE KEY-----/g,
    description: 'Exposed cryptographic private key header.',
    formatSnippet: (raw) => raw.trim(),
  },

  // 4. Hardcoded Password (Generic with Entropy & Placeholder Filtering)
  {
    id: 'ZAWA-004',
    name: 'Hardcoded Password',
    severity: 'warning',
    confidence: 'medium',
    cwe: 'CWE-798',
    cvss: 7.5,
    pattern: /(?:password|passwd|pwd|pass)\s*[:=]\s*["']([^"'\r\n\s]{6,128})["']/gi,
    description: 'Hardcoded password literal discovered in source code or configuration.',
    filter: (match) => {
      const value = match[1] || '';
      return isValidGenericSecret(value, 3.0);
    },
    formatSnippet: (raw, groups) => {
      const secret = groups[0] || raw;
      return raw.replace(secret, maskSecret(secret));
    },
  },

  // 5. Generic Secret / API Key (with Entropy & Placeholder Filtering)
  {
    id: 'ZAWA-005',
    name: '.env-Style Secret',
    severity: 'warning',
    confidence: 'medium',
    cwe: 'CWE-798',
    cvss: 7.5,
    pattern: /(?:["']?\b(?:API_KEY|SECRET_KEY|AUTH_TOKEN|JWT_SECRET|ACCESS_TOKEN|PRIVATE_KEY|CLIENT_SECRET|[a-zA-Z0-9_]*(?:ApiKey|apiSecret|secretKey|authToken|accessToken|clientSecret))\b["']?)\s*[:=]\s*["']?([^"'\r\n\s]{8,256})["']?/gi,
    description: 'High-entropy secret or API key assignment in an environment file, configuration, or code.',
    filter: (match) => {
      const value = match[1] || '';
      // Let specialized high-confidence rules handle their specific prefixes
      if (/^(?:sk-(?!ant-)|sk-ant-|hf_|gsk_|r8_|AIza|AKIA|gh[pousr]_|github_pat_|xox[baprs]-)/.test(value)) {
        return false;
      }
      return isValidGenericSecret(value, 3.0);
    },
    formatSnippet: (raw, groups) => {
      const secret = groups[0];
      if (secret) {
        return raw.trim().replace(secret, maskSecret(secret));
      }
      return raw.trim();
    },
  },

  // 6. Stripe Live Secret Key
  {
    id: 'ZAWA-006',
    name: 'Stripe Live Secret Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.5,
    pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Exposed Stripe Live Secret or Restricted API Key.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 7. Slack Token
  {
    id: 'ZAWA-007',
    name: 'Slack Token',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.2,
    pattern: /\b(xox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}(?:-[0-9a-zA-Z]{10,48})?)\b/g,
    description: 'Exposed Slack Bot, User, or App token.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 8. Google API Key (AIza...)
  {
    id: 'ZAWA-008',
    name: 'Google API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(AIza[0-9A-Za-z\-_]{35,40})\b/g,
    description: 'Exposed Google Cloud / Maps / Firebase API key.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 9. JSON Web Token (JWT)
  {
    id: 'ZAWA-009',
    name: 'JSON Web Token (JWT)',
    severity: 'warning',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 7.5,
    pattern: /\b(ey[A-Za-z0-9_-]{10,128}\.ey[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512})\b/g,
    description: 'Exposed JSON Web Token (JWT) containing authentication claims.',
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 10. GCP Service Account JSON
  {
    id: 'ZAWA-010',
    name: 'GCP Service Account Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 9.0,
    pattern: /(?:"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[0-9a-f]{40}")/g,
    description: 'Identifies exposed Google Cloud Platform service account credential JSON structure.',
    formatSnippet: (raw) => raw.trim(),
  },

  // 11. Database URL with an Embedded Password
  {
    id: 'ZAWA-011',
    name: 'Database URL with Password',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.5,
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mariadb):\/\/[a-zA-Z0-9_.-]+:([^@\s\/]{3,128})@[a-zA-Z0-9_.-]+(?::\d+)?\/?[^\s"'`]*\b/gi,
    description: 'Database connection string containing embedded plaintext credentials.',
    filter: (match) => {
      const password = match[1] || '';
      return !isPlaceholder(password);
    },
    formatSnippet: (raw, groups) => {
      const pass = groups[0];
      return pass ? raw.replace(`:${pass}@`, `:${maskSecret(pass)}@`) : raw;
    },
  },

  // 12. SQL Injection by String Concatenation
  {
    id: 'ZAWA-012',
    name: 'SQL Injection via String Concatenation',
    severity: 'error',
    confidence: 'low',
    cwe: 'CWE-89',
    cvss: 8.8,
    pattern: /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[^"'\n\r;]{1,80}\s+WHERE\s+[^"'\n\r;]{0,40}["']\s*\+\s*[a-zA-Z0-9_.]+/gi,
    description: 'Raw SQL statement concatenated with untrusted variable without parameterization.',
    formatSnippet: (raw) => raw.trim().slice(0, 70),
  },

  // 13. Command Injection by String Concatenation
  {
    id: 'ZAWA-013',
    name: 'Command Injection via String Concatenation',
    severity: 'error',
    confidence: 'low',
    cwe: 'CWE-78',
    cvss: 9.8,
    pattern: /\b(?:exec|execSync|spawn|system|popen)\s*\(\s*["'][^"'\n\r]{1,80}["']\s*\+\s*[a-zA-Z0-9_.]+/gi,
    description: 'OS command execution function concatenated with external variable input.',
    formatSnippet: (raw) => raw.trim().slice(0, 70),
  },

  // 14. OpenAI API Key
  {
    id: 'ZAWA-014',
    name: 'OpenAI API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.5,
    pattern: /\b(sk-(?!ant-)(?:proj-|admin-|svcacct-)?[A-Za-z0-9_\-]{32,160})\b/g,
    description: 'Exposed OpenAI API Key or project service credential.',
    filter: (match) => {
      const secret = match[1] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 15. Anthropic API Key
  {
    id: 'ZAWA-015',
    name: 'Anthropic API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.5,
    pattern: /\b(sk-ant-[A-Za-z0-9_\-]{32,128})\b/g,
    description: 'Exposed Anthropic Claude API key.',
    filter: (match) => {
      const secret = match[1] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 16. Hugging Face Token
  {
    id: 'ZAWA-016',
    name: 'Hugging Face Token',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(hf_[A-Za-z0-9]{32,64})\b/g,
    description: 'Exposed Hugging Face User Access Token.',
    filter: (match) => {
      const secret = match[1] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 17. Groq API Key
  {
    id: 'ZAWA-017',
    name: 'Groq API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(gsk_[A-Za-z0-9]{48,64})\b/g,
    description: 'Exposed Groq Cloud API key.',
    filter: (match) => {
      const secret = match[1] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 18. Replicate API Token
  {
    id: 'ZAWA-018',
    name: 'Replicate API Token',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(r8_[A-Za-z0-9]{32,48})\b/g,
    description: 'Exposed Replicate API token.',
    filter: (match) => {
      const secret = match[1] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => maskSecret(groups[0] || raw),
  },

  // 19. Mistral API Key
  {
    id: 'ZAWA-019',
    name: 'Mistral API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(?:(?:mistral[_-](?:api[_-]?)?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,45})["']?|(mis_[a-zA-Z0-9]{32,45}))\b/gi,
    description: 'Exposed Mistral AI API key.',
    filter: (match) => {
      const secret = match[1] || match[2] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => {
      const secret = groups[0] || groups[1] || raw;
      return maskSecret(secret);
    },
  },

  // 20. Cohere API Key
  {
    id: 'ZAWA-020',
    name: 'Cohere API Key',
    severity: 'error',
    confidence: 'high',
    cwe: 'CWE-798',
    cvss: 8.0,
    pattern: /\b(?:(?:(?:cohere[_-](?:api[_-]?)?key)|co_api_key)\s*[:=]\s*["']?([a-zA-Z0-9_-]{40})["']?|(coh_[a-zA-Z0-9_-]{36,50}))\b/gi,
    description: 'Exposed Cohere API key.',
    filter: (match) => {
      const secret = match[1] || match[2] || match[0];
      return !isPlaceholder(secret) && !isCodeReference(secret);
    },
    formatSnippet: (raw, groups) => {
      const secret = groups[0] || groups[1] || raw;
      return maskSecret(secret);
    },
  },
];

/**
 * Metadata definition for unignored .env files (evaluated via filesystem / gitignore inspection).
 */
export const RULE_ENV_NOT_IGNORED: Rule = {
  id: 'ZAWA-021',
  name: '.env not ignored',
  severity: 'error',
  confidence: 'high',
  cwe: 'CWE-538',
  cvss: 7.5,
  pattern: /(?:)/g,
  description: 'A .env file exists and is not covered by .gitignore, creating high risk of secret exposure.',
  formatSnippet: (raw) => raw,
};
