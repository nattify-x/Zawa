/**
 * Shannon entropy, placeholder, and code reference detection utilities.
 * Pure TypeScript: Zero external dependencies.
 */

/**
 * Computes the Shannon entropy of a string in bits per character.
 * H(X) = -SUM( P(x) * log2(P(x)) )
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Checks whether a candidate secret value matches placeholder patterns:
 * - Contains change, replace, todo, fixme, insert, example, your_, xxx, test, dummy, sample (case-insensitive)
 * - Contains '<' or '>' (template angle brackets)
 * - Contains template expressions like ${...} or %...%
 * - Consists entirely of a single repeated character (e.g. 'aaaaaa', '111111', '******')
 */
export function isPlaceholder(val: string): boolean {
  if (!val || val.length === 0) {
    return true;
  }

  const trimmed = val.trim();
  const lower = trimmed.toLowerCase();

  // 1. All same character check (e.g. 'aaaaaa', '111111', '******')
  const firstChar = trimmed[0];
  let allSame = true;
  for (let i = 1; i < trimmed.length; i++) {
    if (trimmed[i] !== firstChar) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    return true;
  }

  // 2. Contains '<' or '>' (explicit angle bracket placeholder check)
  if (trimmed.includes('<') || trimmed.includes('>')) {
    return true;
  }

  // 3. Specific placeholder substrings
  const placeholderTokens = [
    'change',
    'replace',
    'todo',
    'fixme',
    'insert',
    'example',
    'your_',
    'xxx',
    'test',
    'dummy',
    'sample',
  ];
  for (const token of placeholderTokens) {
    if (lower.includes(token)) {
      return true;
    }
  }

  // 4. Template indicators: ${...}, %...%
  if (/\$\{[^}]+\}/.test(trimmed) || /^%[^%]+%$/.test(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Checks whether a candidate secret value is a code reference rather than a literal:
 * - Starting with: var., local., process.env, os.environ, config., this.
 * - Containing "(" or a function call like base64decode(
 */
export function isCodeReference(val: string): boolean {
  if (!val || val.length === 0) {
    return false;
  }

  const trimmed = val.trim().replace(/^["'`]/, '').replace(/["'`]$/, '').trim();
  const lower = trimmed.toLowerCase();

  const codePrefixes = [
    'var.',
    'local.',
    'process.env',
    'os.environ',
    'config.',
    'this.',
  ];

  for (const prefix of codePrefixes) {
    if (lower.startsWith(prefix)) {
      return true;
    }
  }

  // Reject function calls and expressions containing "("
  if (trimmed.includes('(')) {
    return true;
  }

  return false;
}

/**
 * Validates that a credential candidate has adequate Shannon entropy
 * and is not a common dummy placeholder or code reference.
 *
 * @param value The secret string to evaluate.
 * @param minEntropy Minimum entropy threshold (default: 3.0 bits for strings >= 8 chars, 2.4 for shorter).
 */
export function isValidGenericSecret(value: string, minEntropy: number = 3.0): boolean {
  if (!value || value.length === 0) {
    return false;
  }

  // 1. Reject placeholders
  if (isPlaceholder(value)) {
    return false;
  }

  // 2. Reject code references (var., local., process.env, os.environ, config., this., function calls)
  if (isCodeReference(value)) {
    return false;
  }

  // 3. Check Shannon entropy threshold
  const threshold = value.length < 8 ? Math.max(2.4, minEntropy - 0.6) : minEntropy;
  const entropy = calculateShannonEntropy(value);

  return entropy >= threshold;
}
