#!/usr/bin/env node
/**
 * Zawa Benchmark Generator
 * Pure Node.js script (zero external dependencies).
 * Generates synthetic benchmark files with true secrets and decoys covering all Zawa rules,
 * including new AI service rules (OpenAI, Anthropic, Hugging Face, Groq, Replicate, Mistral, Cohere)
 * and unignored .env file detection.
 *
 * NOTE: Keys are constructed at runtime from string fragments to prevent
 * triggering GitHub push protection or external secret scanners.
 */

const fs = require('fs');
const path = require('path');

const BENCHMARK_DIR = __dirname;
const PLANTED_DIR = path.join(BENCHMARK_DIR, 'planted');
const GROUND_TRUTH_PATH = path.join(BENCHMARK_DIR, 'ground-truth.json');

// String fragments assembled at runtime
const F = {
  aws: ['A', 'K', 'I', 'A'].join(''),
  ghp: ['g', 'h', 'p', '_'].join(''),
  gho: ['g', 'h', 'o', '_'].join(''),
  ghpat: ['g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_'].join(''),
  skLive: ['s', 'k', '_', 'l', 'i', 'v', 'e', '_'].join(''),
  rkLive: ['r', 'k', '_', 'l', 'i', 'v', 'e', '_'].join(''),
  slackB: ['x', 'o', 'x', 'b', '-'].join(''),
  slackP: ['x', 'o', 'x', 'p', '-'].join(''),
  google: ['A', 'I', 'z', 'a'].join(''),
  jwt: ['e', 'y'].join(''),
  privKey: ['-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '].join(''),
  privKeyEnd: [' ', 'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y', '-', '-', '-', '-', '-'].join(''),
  ignore: ['z', 'a', 'w', 'a', '-', 'i', 'g', 'n', 'o', 'r', 'e'].join(''),
  // AI Service fragments
  openai: ['s', 'k', '-', 'p', 'r', 'o', 'j', '-'].join(''),
  anthropic: ['s', 'k', '-', 'a', 'n', 't', '-'].join(''),
  hf: ['h', 'f', '_'].join(''),
  groq: ['g', 's', 'k', '_'].join(''),
  replicate: ['r', '8', '_'].join(''),
  mistral: ['m', 'i', 's', '_'].join(''),
  cohere: ['c', 'o', 'h', '_'].join(''),
};

function ensureDir(dir) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  fs.mkdirSync(dir, { recursive: true });
}

function generateBenchmark() {
  console.log('[BENCHMARK] Generating benchmark dataset in benchmark/planted/ ...');
  ensureDir(PLANTED_DIR);

  const groundTruth = [];

  // Helper to append a file with lines and track ground truth
  function buildFile(fileName, items) {
    const filePath = path.join(PLANTED_DIR, fileName);
    const lines = [];
    lines.push(`// Benchmark Test File: ${fileName}`);
    lines.push(`// Generated automatically by benchmark/generate.js`);
    lines.push('');

    for (const item of items) {
      if (item.precedingComment) {
        lines.push(item.precedingComment);
      }
      const lineNum = lines.length + 1;
      lines.push(item.code);

      groundTruth.push({
        id: item.id,
        file: fileName,
        line: lineNum,
        type: item.type, // 'secret' | 'decoy'
        expectedRule: item.expectedRule || null,
        description: item.description,
      });

      lines.push(''); // Spacing line
    }

    fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
  }

  // File 1: AWS Services
  buildFile('aws-service.ts', [
    // True Secrets
    {
      id: 'TS-001',
      type: 'secret',
      expectedRule: 'ZAWA-001',
      description: 'AWS Access Key ID 1',
      code: `export const AWS_PRIMARY_KEY = "${F.aws}1234567890ABCDEF";`,
    },
    {
      id: 'TS-002',
      type: 'secret',
      expectedRule: 'ZAWA-001',
      description: 'AWS Access Key ID 2',
      code: `const S3_BUCKET_KEY = "${F.aws}9876543210FEDCBA";`,
    },
    {
      id: 'TS-003',
      type: 'secret',
      expectedRule: 'ZAWA-001',
      description: 'AWS Access Key ID 3',
      code: `process.env.AWS_KEY = "${F.aws}ABCDEF1234567890";`,
    },
    // Decoys
    {
      id: 'DC-001',
      type: 'decoy',
      description: 'Lookalike AWS non-AKIA prefix (AKIB)',
      code: `const FAKE_AWS_PREFIX = "AKIB1234567890ABCDEF";`,
    },
    {
      id: 'DC-002',
      type: 'decoy',
      description: 'Lookalike AWS key with insufficient length',
      code: `const SHORT_AWS_KEY = "${F.aws}12345";`,
    },
    {
      id: 'DC-003',
      type: 'decoy',
      description: 'AWS key suppressed with inline zawa-ignore comment',
      code: `const SUPPRESSED_AWS = "${F.aws}9999999999IGNOR1"; // ${F.ignore}`,
    },
  ]);

  // File 2: GitHub Integrations
  buildFile('github-client.ts', [
    // True Secrets
    {
      id: 'TS-004',
      type: 'secret',
      expectedRule: 'ZAWA-002',
      description: 'GitHub Classic Personal Access Token',
      code: `const GITHUB_PAT = "${F.ghp}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";`,
    },
    {
      id: 'TS-005',
      type: 'secret',
      expectedRule: 'ZAWA-002',
      description: 'GitHub OAuth Access Token',
      code: `const GITHUB_OAUTH = "${F.gho}1234567890abcdefghijklmnopqrstuvwxyz";`,
    },
    {
      id: 'TS-006',
      type: 'secret',
      expectedRule: 'ZAWA-002',
      description: 'GitHub Fine-Grained Personal Access Token (82 chars)',
      code: `const GITHUB_FINE_GRAINED = "${F.ghpat}${'a'.repeat(82)}";`,
    },
    // Decoys
    {
      id: 'DC-004',
      type: 'decoy',
      description: 'Lookalike GitHub token with wrong prefix (ghx_)',
      code: `const INVALID_GH_PREFIX = "ghx_123456789012345678901234567890123456";`,
    },
    {
      id: 'DC-005',
      type: 'decoy',
      description: 'GitHub token with preceding zawa-ignore comment',
      precedingComment: `// ${F.ignore}`,
      code: `const SUPPRESSED_GH = "${F.ghp}999999999999999999999999999999999999";`,
    },
    {
      id: 'DC-006',
      type: 'decoy',
      description: 'Placeholder GitHub token template ${...}',
      code: `const TEMPLATE_GH = "${F.ghp}\${GITHUB_TOKEN_VAR}";`,
    },
  ]);

  // File 3: Stripe Payments
  buildFile('payment-stripe.ts', [
    // True Secrets
    {
      id: 'TS-007',
      type: 'secret',
      expectedRule: 'ZAWA-006',
      description: 'Stripe Live Secret Key 1',
      code: `const STRIPE_SECRET_KEY = "${F.skLive}26CharactersLongSecretVal123";`,
    },
    {
      id: 'TS-008',
      type: 'secret',
      expectedRule: 'ZAWA-006',
      description: 'Stripe Live Secret Key 2',
      code: `const STRIPE_WEBHOOK_LIVE = "${F.skLive}9876543210abcdefghijklmnop";`,
    },
    {
      id: 'TS-009',
      type: 'secret',
      expectedRule: 'ZAWA-006',
      description: 'Stripe Restricted Live Key',
      code: `const STRIPE_RESTRICTED = "${F.rkLive}RestrictedKeyForLiveApiAccess777";`,
    },
    // Decoys
    {
      id: 'DC-007',
      type: 'decoy',
      description: 'Stripe Test Secret Key (sk_test_)',
      code: `const STRIPE_TEST_KEY = "sk_test_1234567890123456789012345678";`,
    },
    {
      id: 'DC-008',
      type: 'decoy',
      description: 'Stripe Live Key suppressed with inline zawa-ignore',
      code: `const STRIPE_SUPPRESSED = "${F.skLive}88888888888888888888888888"; // ${F.ignore}`,
    },
    {
      id: 'DC-009',
      type: 'decoy',
      description: 'Placeholder Stripe template <STRIPE_KEY>',
      code: `const STRIPE_PLACEHOLDER = "${F.skLive}<YOUR_STRIPE_KEY>";`,
    },
  ]);

  // File 4: Slack Notifications
  buildFile('slack-bot.ts', [
    // True Secrets
    {
      id: 'TS-010',
      type: 'secret',
      expectedRule: 'ZAWA-007',
      description: 'Slack Bot Token (xoxb-)',
      code: `const SLACK_BOT = "${F.slackB}123456789012-123456789012-abcdefghijklmnopqrstuvwxyz12";`,
    },
    {
      id: 'TS-011',
      type: 'secret',
      expectedRule: 'ZAWA-007',
      description: 'Slack User Token (xoxp-)',
      code: `const SLACK_USER = "${F.slackP}987654321098-987654321098-zyxwvutsrqponmlkjihgfedcba98";`,
    },
    {
      id: 'TS-012',
      type: 'secret',
      expectedRule: 'ZAWA-007',
      description: 'Slack App Token',
      code: `const SLACK_APP = "${F.slackB}555555555555-444444444444-1111222233334444555566667777";`,
    },
    // Decoys
    {
      id: 'DC-010',
      type: 'decoy',
      description: 'Lookalike Slack invalid prefix (xoxe-)',
      code: `const SLACK_INVALID = "xoxe-123456789012-123456789012-abcdef123456";`,
    },
    {
      id: 'DC-011',
      type: 'decoy',
      description: 'Slack Token with preceding zawa-ignore comment',
      precedingComment: `// ${F.ignore}`,
      code: `const SLACK_SUPPRESSED = "${F.slackB}999999999999-999999999999-99999999999999999999999999";`,
    },
    {
      id: 'DC-012',
      type: 'decoy',
      description: 'Lookalike Slack token with segments too short (5 chars vs min 10)',
      code: `const SLACK_SHORT_LOOKALIKE = "xoxb-12345-abcde";`,
    },
  ]);

  // File 5: Google Cloud API
  buildFile('google-cloud.ts', [
    // True Secrets
    {
      id: 'TS-013',
      type: 'secret',
      expectedRule: 'ZAWA-008',
      description: 'Google API Key 1',
      code: `const GOOGLE_MAPS_KEY = "${F.google}SyA1234567890abcdefghijklmnopqrstuv";`,
    },
    {
      id: 'TS-014',
      type: 'secret',
      expectedRule: 'ZAWA-008',
      description: 'Google API Key 2',
      code: `const FIREBASE_API_KEY = "${F.google}SyD9876543210zyxwvutsrqponmlkjihgfe";`,
    },
    {
      id: 'TS-015',
      type: 'secret',
      expectedRule: 'ZAWA-008',
      description: 'Google API Key 3',
      code: `const TRANSLATE_KEY = "${F.google}SyB55555666667777788888999990000012";`,
    },
    // Decoys
    {
      id: 'DC-013',
      type: 'decoy',
      description: 'Lookalike Google key wrong prefix (AIzb)',
      code: `const INVALID_GOOGLE_KEY = "AIzbSyD1234567890abcdefghijklmnopqrstuv";`,
    },
    {
      id: 'DC-014',
      type: 'decoy',
      description: 'Google API key with inline zawa-ignore comment',
      code: `const SUPPRESSED_GOOGLE = "${F.google}SyZ9999999999999999999999999999999"; // ${F.ignore}`,
    },
    {
      id: 'DC-015',
      type: 'decoy',
      description: 'Google API key placeholder with "your_"',
      code: `const PLACEHOLDER_GOOGLE = "${F.google}your_api_key_here_for_testing";`,
    },
  ]);

  // File 6: JSON Web Tokens
  buildFile('jwt-tokens.ts', [
    // True Secrets
    {
      id: 'TS-016',
      type: 'secret',
      expectedRule: 'ZAWA-009',
      description: 'JSON Web Token (JWT) 1',
      code: `const USER_SESSION_JWT = "${F.jwt}JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${F.jwt}zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`,
    },
    {
      id: 'TS-017',
      type: 'secret',
      expectedRule: 'ZAWA-009',
      description: 'JSON Web Token (JWT) 2',
      code: `const ADMIN_AUTH_JWT = "${F.jwt}JhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${F.jwt}zdWIiOiJ1c2VyNDIiLCJyb2xlIjoiYWRtaW4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";`,
    },
    {
      id: 'TS-018',
      type: 'secret',
      expectedRule: 'ZAWA-009',
      description: 'JSON Web Token (JWT) 3',
      code: `const SERVICE_JWT = "${F.jwt}JhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.${F.jwt}zdWIiOiJzZXJ2aWNlIiwiYXVkIjoiYXBpIn0.TYzp_37WqXFfI46L0y_l7m_vWl6w7-T1r0Fh_7Hj5e4";`,
    },
    // Decoys
    {
      id: 'DC-016',
      type: 'decoy',
      description: 'Lookalike JWT with only 2 segments (truncated)',
      code: `const TRUNCATED_JWT = "${F.jwt}JhbGciOiJIUzI1NiJ9.${F.jwt}zdWIiOiIxMjM0NTY3ODkwIn0";`,
    },
    {
      id: 'DC-017',
      type: 'decoy',
      description: 'JWT with preceding zawa-ignore comment',
      precedingComment: `// ${F.ignore}`,
      code: `const SUPPRESSED_JWT = "${F.jwt}JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${F.jwt}zdWIiOiJpZ25vcmVkIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";`,
    },
    {
      id: 'DC-018',
      type: 'decoy',
      description: 'Plain dot-separated string that is not a JWT',
      code: `const REGULAR_VERSION_STRING = "v1.2.3.4.5";`,
    },
  ]);

  // File 7: Cryptographic Private Keys
  buildFile('crypto-keys.ts', [
    // True Secrets
    {
      id: 'TS-019',
      type: 'secret',
      expectedRule: 'ZAWA-003',
      description: 'RSA Private Key Header Block',
      code: `const RSA_KEY_HEADER = "${F.privKey}RSA${F.privKeyEnd}";`,
    },
    {
      id: 'TS-020',
      type: 'secret',
      expectedRule: 'ZAWA-003',
      description: 'OPENSSH Private Key Header Block',
      code: `const OPENSSH_KEY_HEADER = "${F.privKey}OPENSSH${F.privKeyEnd}";`,
    },
    {
      id: 'TS-021',
      type: 'secret',
      expectedRule: 'ZAWA-003',
      description: 'EC Private Key Header Block',
      code: `const EC_KEY_HEADER = "${F.privKey}EC${F.privKeyEnd}";`,
    },
    // Decoys
    {
      id: 'DC-019',
      type: 'decoy',
      description: 'Public Key Header Block (not private)',
      code: `const PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";`,
    },
    {
      id: 'DC-020',
      type: 'decoy',
      description: 'Certificate Header Block (not private)',
      code: `const CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";`,
    },
    {
      id: 'DC-021',
      type: 'decoy',
      description: 'Private Key header with inline zawa-ignore comment',
      code: `const SUPPRESSED_KEY = "${F.privKey}RSA${F.privKeyEnd}"; // ${F.ignore}`,
    },
  ]);

  // File 8: Database Connection URLs
  buildFile('database-config.ts', [
    // True Secrets
    {
      id: 'TS-022',
      type: 'secret',
      expectedRule: 'ZAWA-011',
      description: 'PostgreSQL URL with embedded high-entropy password',
      code: `const POSTGRES_URL = "postgres://dbuser:V9#qL$2mK!pZ7@database.internal:5432/production";`,
    },
    {
      id: 'TS-023',
      type: 'secret',
      expectedRule: 'ZAWA-011',
      description: 'MySQL URL with embedded high-entropy password',
      code: `const MYSQL_URL = "mysql://app_admin:K9$mX!8pQ#wZ4@mysql.cluster.local:3306/app";`,
    },
    {
      id: 'TS-024',
      type: 'secret',
      expectedRule: 'ZAWA-011',
      description: 'MongoDB URL with embedded high-entropy password',
      code: `const MONGO_URL = "mongodb://mongo_user:R3#yU$9aP!kL6@mongo-primary:27017/analytics";`,
    },
    // Decoys
    {
      id: 'DC-022',
      type: 'decoy',
      description: 'Database URL without password credentials',
      code: `const DB_NO_AUTH = "postgres://localhost:5432/test_db";`,
    },
    {
      id: 'DC-023',
      type: 'decoy',
      description: 'Database URL with placeholder password "changeme"',
      code: `const DB_PLACEHOLDER = "postgres://user:changeme@localhost:5432/local_db";`,
    },
    {
      id: 'DC-024',
      type: 'decoy',
      description: 'Database URL with placeholder "your_password"',
      code: `const DB_YOUR_PASS = "mysql://root:your_password@127.0.0.1:3306/sample_db";`,
    },
  ]);

  // File 9: Authentication Passwords
  buildFile('auth-passwords.ts', [
    // True Secrets
    {
      id: 'TS-025',
      type: 'secret',
      expectedRule: 'ZAWA-004',
      description: 'Hardcoded password with high Shannon entropy (3.52)',
      code: `const DB_PASS_1 = 'password = "V9#qL$2mK!pZ7@wX"';`,
    },
    {
      id: 'TS-026',
      type: 'secret',
      expectedRule: 'ZAWA-004',
      description: 'Hardcoded password with high Shannon entropy (3.58)',
      code: `const ADMIN_PWD = 'password = "X7*kM!4pB#wQ8$zT"';`,
    },
    {
      id: 'TS-027',
      type: 'secret',
      expectedRule: 'ZAWA-004',
      description: 'Hardcoded password with high Shannon entropy (3.65)',
      code: `const SERVICE_PASS = 'password = "s8F!mK9@wQ#zR2$v"';`,
    },
    // Decoys
    {
      id: 'DC-025',
      type: 'decoy',
      description: 'Placeholder password "changeme"',
      code: `const DUMMY_PASS_1 = 'password = "changeme"';`,
    },
    {
      id: 'DC-026',
      type: 'decoy',
      description: 'Placeholder password "sample_password"',
      code: `const DUMMY_PASS_2 = 'password = "sample_password"';`,
    },
    {
      id: 'DC-027',
      type: 'decoy',
      description: 'Low-entropy password with all repeated chars "xxxxxxxxxxxx"',
      code: `const DUMMY_PASS_3 = 'password = "xxxxxxxxxxxx"';`,
    },
  ]);

  // File 10: Environment File (.env-style assignments)
  buildFile('environment.env', [
    // True Secrets
    {
      id: 'TS-028',
      type: 'secret',
      expectedRule: 'ZAWA-005',
      description: '.env-style API key with high Shannon entropy (3.82)',
      code: `API_KEY="q8W!eR#tY$uI%oP&aS*dF"`,
    },
    {
      id: 'TS-029',
      type: 'secret',
      expectedRule: 'ZAWA-005',
      description: '.env-style secret key with high Shannon entropy (3.88)',
      code: `SECRET_KEY="m4K$9xP!2vL#7zQ*1wR&"`,
    },
    {
      id: 'TS-030',
      type: 'secret',
      expectedRule: 'ZAWA-005',
      description: '.env-style auth token with high Shannon entropy (3.91)',
      code: `AUTH_TOKEN="b8N#3vM$9xZ!5pL*2kQ&"`,
    },
    // Decoys
    {
      id: 'DC-028',
      type: 'decoy',
      description: 'Placeholder API key "your_api_key_here"',
      code: `API_KEY="your_api_key_here"`,
    },
    {
      id: 'DC-029',
      type: 'decoy',
      description: 'Placeholder secret with template syntax ${...}',
      code: `SECRET_KEY="\${ENV_SECRET_VARIABLE}"`,
    },
    {
      id: 'DC-030',
      type: 'decoy',
      description: 'High-entropy secret suppressed with preceding zawa-ignore',
      precedingComment: `# ${F.ignore}`,
      code: `AUTH_TOKEN="z9X#4mN$8vB!1pL*7kQ&"`,
    },
  ]);

  // File 11: AI Services (OpenAI, Anthropic, Hugging Face, Groq, Replicate, Mistral, Cohere)
  buildFile('ai-services.ts', [
    // True Secrets
    {
      id: 'TS-031',
      type: 'secret',
      expectedRule: 'ZAWA-014',
      description: 'OpenAI Project Service API Key (sk-proj-)',
      code: `const OPENAI_API_KEY = "${F.openai}A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4";`,
    },
    {
      id: 'TS-032',
      type: 'secret',
      expectedRule: 'ZAWA-015',
      description: 'Anthropic Claude API Key (sk-ant-)',
      code: `const ANTHROPIC_KEY = "${F.anthropic}api03-A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6";`,
    },
    {
      id: 'TS-033',
      type: 'secret',
      expectedRule: 'ZAWA-016',
      description: 'Hugging Face User Access Token (hf_)',
      code: `const HUGGINGFACE_TOKEN = "${F.hf}AbCdEfGhIjKlMnOpQrStUvWxYz01234567";`,
    },
    {
      id: 'TS-034',
      type: 'secret',
      expectedRule: 'ZAWA-017',
      description: 'Groq Cloud API Key (gsk_)',
      code: `const GROQ_API_KEY = "${F.groq}A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6";`,
    },
    {
      id: 'TS-035',
      type: 'secret',
      expectedRule: 'ZAWA-018',
      description: 'Replicate API Token (r8_)',
      code: `const REPLICATE_API_TOKEN = "${F.replicate}AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";`,
    },
    {
      id: 'TS-036',
      type: 'secret',
      expectedRule: 'ZAWA-019',
      description: 'Mistral AI API Key (mis_ prefix)',
      code: `const MISTRAL_API_KEY = "${F.mistral}A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6";`,
    },
    {
      id: 'TS-037',
      type: 'secret',
      expectedRule: 'ZAWA-020',
      description: 'Cohere Platform API Key (coh_ prefix)',
      code: `const COHERE_API_KEY = "${F.cohere}A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0";`,
    },
    // Decoys
    {
      id: 'DC-031',
      type: 'decoy',
      description: 'OpenAI key with placeholder changeme',
      code: `const DUMMY_OPENAI = "${F.openai}changeme_your_api_key_dummy_sample_123456";`,
    },
    {
      id: 'DC-032',
      type: 'decoy',
      description: 'Anthropic key template syntax ${...}',
      code: `const TEMPLATE_ANTHROPIC = "${F.anthropic}\${ANTHROPIC_SECRET_KEY}";`,
    },
    {
      id: 'DC-033',
      type: 'decoy',
      description: 'Hugging Face token suppressed with inline zawa-ignore',
      code: `const SUPPRESSED_HF = "${F.hf}9999999999999999999999999999999999"; // ${F.ignore}`,
    },
    {
      id: 'DC-034',
      type: 'decoy',
      description: 'Groq key placeholder with your_',
      code: `const DUMMY_GROQ = "${F.groq}your_api_key_here_for_groq_service_testing";`,
    },
    {
      id: 'DC-035',
      type: 'decoy',
      description: 'Replicate token with preceding zawa-ignore comment',
      precedingComment: `// ${F.ignore}`,
      code: `const SUPPRESSED_REPLICATE = "${F.replicate}888888888888888888888888888888888888";`,
    },
    {
      id: 'DC-036',
      type: 'decoy',
      description: 'Mistral key referring to process.env code reference',
      code: `const CODE_REF_MISTRAL = 'mistral_api_key = process.env.MISTRAL_KEY';`,
    },
    {
      id: 'DC-037',
      type: 'decoy',
      description: 'Cohere key with placeholder dummy',
      code: `const DUMMY_COHERE = "${F.cohere}dummy_placeholder_token_cohere_1234567";`,
    },
  ]);

  // File 12: Unignored .env check (ZAWA-021)
  // Plant an actual .env file that is NOT covered by any .gitignore in planted/
  const unignoredEnvPath = path.join(PLANTED_DIR, '.env');
  fs.writeFileSync(unignoredEnvPath, '# Production credentials\nDATABASE_PORT=5432\n', 'utf-8');
  groundTruth.push({
    id: 'TS-038',
    file: '.env',
    line: 1,
    type: 'secret',
    expectedRule: 'ZAWA-021',
    description: 'Unignored .env file exposed in workspace root',
  });

  // Decoy 1 for .env: .env.example (template file designed to be committed)
  const envExamplePath = path.join(PLANTED_DIR, '.env.example');
  fs.writeFileSync(envExamplePath, '# Safe environment template\nAPP_PORT=3000\n', 'utf-8');
  groundTruth.push({
    id: 'DC-038',
    file: '.env.example',
    line: 1,
    type: 'decoy',
    expectedRule: null,
    description: '.env.example template file is allowed to be committed',
  });

  // Decoy 2 for .env: .env file covered by local .gitignore
  const ignoredVaultDir = path.join(PLANTED_DIR, 'ignored-vault');
  fs.mkdirSync(ignoredVaultDir, { recursive: true });
  fs.writeFileSync(path.join(ignoredVaultDir, '.gitignore'), '.env\n', 'utf-8');
  fs.writeFileSync(path.join(ignoredVaultDir, '.env'), '# Local ignored environment\nLOCAL_KEY=true\n', 'utf-8');
  groundTruth.push({
    id: 'DC-039',
    file: 'ignored-vault/.env',
    line: 1,
    type: 'decoy',
    expectedRule: null,
    description: '.env file explicitly covered by .gitignore in its directory',
  });

  // Save ground truth JSON
  fs.writeFileSync(GROUND_TRUTH_PATH, JSON.stringify(groundTruth, null, 2), 'utf-8');

  const trueSecretsCount = groundTruth.filter((i) => i.type === 'secret').length;
  const decoysCount = groundTruth.filter((i) => i.type === 'decoy').length;

  console.log(`[BENCHMARK] Dataset generation complete:`);
  console.log(`  - True Secrets Planted: ${trueSecretsCount}`);
  console.log(`  - Decoys Planted:       ${decoysCount}`);
  console.log(`  - Total Items:          ${groundTruth.length}`);
  console.log(`  - Output Folder:        benchmark/planted/`);
  console.log(`  - Ground Truth File:    benchmark/ground-truth.json\n`);
}

generateBenchmark();
