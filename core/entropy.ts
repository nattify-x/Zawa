/**
 * Shannon entropy, placeholder, code reference, and format detection utilities.
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
 * Checks whether a key is a published / documented example key
 * (such as AWS AKIAIOSFODNN7EXAMPLE).
 */
export function isDocumentedExampleKey(val: string): boolean {
  if (!val) {
    return false;
  }
  const trimmed = val.trim();
  const upper = trimmed.toUpperCase();

  // AWS documented example key: AKIAIOSFODNN7EXAMPLE or any AWS key containing EXAMPLE
  if (/^(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}$/.test(upper) && upper.includes('EXAMPLE')) {
    return true;
  }

  // Other published example token formats ending with EXAMPLE
  if (/(?:AKIA|gh[pousr]_|sk_live_|sk-proj-|xox[baprs]-)[A-Za-z0-9_\-]{10,}EXAMPLE$/i.test(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Checks whether a candidate secret value is a hex address (0x + 40 hex),
 * a standard UUID, or a pure hex hash (32, 40, or 64 hex characters).
 */
export function isHexAddressOrHashOrUuid(val: string): boolean {
  if (!val || val.length === 0) {
    return false;
  }
  const trimmed = val.trim().replace(/^["'`]/, '').replace(/["'`]$/, '');

  // 1. Ethereum / Hex address: 0x + 40 hex characters
  if (/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
    return true;
  }

  // 2. UUID: 8-4-4-4-12 hex characters
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i.test(trimmed)) {
    return true;
  }

  // 3. Pure hex hash: exactly 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters
  if (/^[0-9a-fA-F]{32}$/.test(trimmed) || /^[0-9a-fA-F]{40}$/.test(trimmed) || /^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Decodes a JWT payload offline and checks if its 'exp' claim is in the past.
 */
export function isJwtExpired(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length < 2) {
      return false;
    }
    let base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const jsonStr = typeof Buffer !== 'undefined'
      ? Buffer.from(base64, 'base64').toString('utf-8')
      : atob(base64);
    const payload = JSON.parse(jsonStr);
    if (typeof payload.exp === 'number') {
      const nowSeconds = Math.floor(Date.now() / 1000);
      return payload.exp < nowSeconds;
    }
  } catch {
    // If decoding or parsing fails, treat as not expired
  }
  return false;
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

  // Documented example keys are specially reported at low confidence rather than dropped as placeholders
  if (isDocumentedExampleKey(val)) {
    return false;
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

/**
 * Checks whether a generic rule match (ZAWA-004, ZAWA-005) should be ignored because:
 * - It is a commented-out line (starts with //, #, or *)
 * - It is built with string concatenation or a function call
 * - It is a regular expression pattern containing [ ] { } \ ( ) metacharacters
 */
export function isGenericRuleIgnored(match: RegExpExecArray, value: string): boolean {
  if (!value || value.length === 0) {
    return true;
  }

  // 1. Regular expression metacharacters or function call in the value: [ ] { } \ ( )
  if (/[\[\]{}\\\(\)]/.test(value)) {
    return true;
  }

  // 2. Value contains explicit string concatenation syntax (e.g. "foo" + "bar")
  if (/\s*\+\s*["']/.test(value) || /["']\s*\+/.test(value) || /\s*\.\s*["']/.test(value) || /["']\s*\./.test(value)) {
    return true;
  }

  // 3. Line context inspection
  if (match && match.input) {
    const lineStart = match.input.lastIndexOf('\n', match.index) + 1;
    let lineEnd = match.input.indexOf('\n', match.index);
    if (lineEnd === -1) {
      lineEnd = match.input.length;
    }
    const line = match.input.slice(lineStart, lineEnd);
    const trimmedLine = line.trim();

    // Commented-out line (starts with //, #, or *)
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('*')) {
      return true;
    }

    // Built with string concatenation: line continues with + or . immediately after match
    const restOfLine = match.input.slice(match.index + match[0].length, lineEnd).trim();
    if (restOfLine.startsWith('+') || restOfLine.startsWith('.')) {
      return true;
    }

    // Built with string concatenation: line ends with + or . immediately before match
    const beforeMatch = match.input.slice(lineStart, match.index).trim();
    if (beforeMatch.endsWith('+') || beforeMatch.endsWith('.')) {
      return true;
    }
  }

  return false;
}
