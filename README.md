# Zawa

Zawa is a fast, offline security scanner for VS Code and terminal environments that guards your source code directly on your local machine before it ever leaves your workstation or gets committed to remote repositories. Engineered for privacy, zero cloud telemetry, and low resource overhead, Zawa continuously inspects open files and repositories for leaked credentials, AI service API keys, cryptographic secrets, unignored configuration files, and injection vulnerabilities—highlighting issues with inline editor squiggles, CWE classifications, CVSS severity ratings, and confidence scores.

---

## Features

- **100% Offline & Private:** Zero network requests, zero telemetry, and zero runtime dependencies.
- **Git Pre-Commit Hook:** Installable with `zawa install-hook` to block commits containing high-confidence secrets before they are committed.
- **AI Service Key Protection:** Comprehensive detection of keys from OpenAI, Anthropic, Hugging Face, Groq, Replicate, Mistral, and Cohere.
- **Unignored `.env` Guard:** Automatically flags exposed `.env` files not covered by `.gitignore` (CWE-538).
- **Shannon Entropy Analysis:** Generic secrets and hardcoded passwords are evaluated with Shannon entropy ($H \ge 3.0$) and automatically filtered against dummy placeholders (`changeme`, `your_...`, `example`, `test`, `dummy`, `sample`, repeated characters, and template brackets).
- **Rule Confidence Ratings:** Every finding is classified as `high` (known token formats, AI service keys, unignored env files), `medium` (generic high-entropy credentials), or `low` (heuristic injection patterns).
- **Inline Suppression:** Suppress intentional test secrets or false positives by adding a `// zawa-ignore` comment on the offending line or the line directly above.
- **Full Workspace Audits:** Run `Zawa: Scan Workspace` to recursively audit repository files while skipping `node_modules`, `.git`, build outputs, lock files, and binary assets.
- **Standalone CLI:** Includes a fast, offline CLI with optional JSON output (`--json`) for local pre-commit hooks and CI pipelines.
- **Resource Efficient:** Lightweight and designed for low memory use, running efficiently across any development machine without background overhead.

## Included Detection Rules

| Rule ID | Finding | Severity | Confidence | CWE | CVSS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ZAWA-001` | AWS Access Key ID | Error | High | CWE-798 | 8.5 |
| `ZAWA-002` | GitHub Token (Classic & Fine-Grained) | Error | High | CWE-798 | 8.1 |
| `ZAWA-003` | Private Key Block | Error | High | CWE-312 | 9.0 |
| `ZAWA-004` | Hardcoded Password (Entropy $\ge 3.0$) | Warning | Medium | CWE-798 | 7.5 |
| `ZAWA-005` | .env-Style Secret (Entropy $\ge 3.0$) | Warning | Medium | CWE-798 | 7.5 |
| `ZAWA-006` | Stripe Live Secret Key (`sk_live_...`) | Error | High | CWE-798 | 8.5 |
| `ZAWA-007` | Slack Token (`xoxb-...`) | Error | High | CWE-798 | 8.2 |
| `ZAWA-008` | Google API Key (`AIza...`) | Error | High | CWE-798 | 8.0 |
| `ZAWA-009` | JSON Web Token (JWT) | Warning | High | CWE-798 | 7.5 |
| `ZAWA-010` | GCP Service Account Key | Error | High | CWE-798 | 9.0 |
| `ZAWA-011` | Database URL with Embedded Password | Error | High | CWE-798 | 8.5 |
| `ZAWA-012` | SQL Injection via String Concatenation | Error | Low | CWE-89 | 8.8 |
| `ZAWA-013` | Command Injection via String Concatenation | Error | Low | CWE-78 | 9.8 |
| `ZAWA-014` | OpenAI API Key (`sk-...`, `sk-proj-...`) | Error | High | CWE-798 | 8.5 |
| `ZAWA-015` | Anthropic API Key (`sk-ant-...`) | Error | High | CWE-798 | 8.5 |
| `ZAWA-016` | Hugging Face Token (`hf_...`) | Error | High | CWE-798 | 8.0 |
| `ZAWA-017` | Groq API Key (`gsk_...`) | Error | High | CWE-798 | 8.0 |
| `ZAWA-018` | Replicate API Token (`r8_...`) | Error | High | CWE-798 | 8.0 |
| `ZAWA-019` | Mistral AI API Key (`mis_...` / assignment) | Error | High | CWE-798 | 8.0 |
| `ZAWA-020` | Cohere API Key (`coh_...` / assignment) | Error | High | CWE-798 | 8.0 |
| `ZAWA-021` | .env Not Ignored | Error | High | CWE-538 | 7.5 |

## Git Pre-Commit Hook (Stop Leaks Before Commit)

Zawa integrates directly with Git hooks to inspect staged changes on every commit:

```bash
# Install the hook into .git/hooks/pre-commit
npm run scan -- install-hook

# Uninstall the hook
npm run scan -- uninstall-hook
```

When installed:
- Runs automatically whenever `git commit` is executed.
- Inspects only staged files (`git diff --cached --name-only`).
- Blocks the commit with exit code `1` if any **HIGH-confidence** finding is detected.
- Explains how to resolve or bypass with `// zawa-ignore` or `git commit --no-verify`.

## Running the Standalone CLI

Audit any directory from the terminal without opening VS Code:

```bash
# Human-readable terminal output
npm run scan -- <folder>

# Exclude findings in test / spec / mock / fixture paths
npm run scan -- <folder> --exclude-tests

# JSON output
npm run scan -- <folder> --json
```

## Regression test (self-made, not an independent evaluation)

Zawa includes a reproducible synthetic test suite measuring precision, recall, F1 score, and scan latency across 77 ground-truth test cases (38 true secrets and 39 decoys):

- **38 True Secrets**: Covers cloud providers (AWS, Google), platforms (GitHub, Stripe, Slack, databases), and AI service providers (OpenAI, Anthropic, Hugging Face, Groq, Replicate, Mistral, Cohere), plus unignored `.env` file detection. Built dynamically at runtime from string fragments to prevent triggering external push protection filters.
- **39 Decoys**: Evaluates resilience against placeholders (`changeme`, `your_...`, `${VAR}`), repeated characters (`xxxxxx`), low-entropy strings, code references (`process.env`), lookalikes with invalid prefixes/lengths, `.env.example` templates, locally ignored `.env` files, and `zawa-ignore` comments.

```bash
npm run bench:generate  # Generate synthetic dataset in benchmark/planted/
npm run bench:eval      # Evaluate accuracy against benchmark/ground-truth.json
```

| Metric | Score | Details |
| :--- | :--- | :--- |
| **True Positives (TP)** | **38 / 38** | 100% of format-valid secrets detected |
| **False Positives (FP)** | **0** | Zero decoys or placeholders falsely flagged |
| **False Negatives (FN)** | **0** | Zero secrets missed |
| **True Negatives (TN)** | **39 / 39** | 100% of decoys correctly ignored |
| **Precision** | **100.00 %** | $TP / (TP + FP)$ |
| **Recall** | **100.00 %** | $TP / (TP + FN)$ |
| **F1-Score** | **100.00 %** | Harmonic mean of precision and recall |
| **Accuracy** | **100.00 %** | $(TP + TN) / (TP + TN + FP + FN)$ |
| **Scan Duration** | **~50 ms** | Sub-60ms offline evaluation |

Results are recorded in `benchmark/results-zawa.json`.

## Real-world evaluation

Tested against open-source intentionally vulnerable applications:

| Target | Zawa Findings | Gitleaks Findings | Notes |
| :--- | :--- | :--- | :--- |
| **OWASP Juice Shop** | **127** (before tuning)<br>**15** (with `--exclude-tests`) | 69 | 110 of the original 127 findings were in test files. The 15 retained findings comprise 3 private keys and 12 seed database passwords. |
| **OWASP NodeGoat** | **1** (before round 2)<br>**3** (after round 2) | 3 | Before round 2 Zawa found 1 (a private key) vs Gitleaks 3; after round 2 Zawa finds 3 (including the camelCase `zapApiKey` in `config/env/development.js` and `test.js`) vs Gitleaks 3. |

*Note: NodeGoat was used to tune round 2, so it is no longer an unseen test set.*

## Limitations

- **Regex-based without data-flow analysis:** Matches patterns and assignments statically; does not trace variable propagation, taint, or cross-file imports.
- **Identifier naming:** only a fixed list of names (ApiKey, apiSecret, secretKey, authToken, accessToken, clientSecret and common uppercase names) is recognized; other custom names are missed.
- **Hard file & line bounds:** Skips individual lines over 2,000 characters (minified code) and skips files larger than 1 MB to prevent memory exhaustion and ReDoS.
- **Estimated severity:** CVSS scores are static estimates based on standard vulnerability impacts, not runtime exploitability assessments.
- **Local-only pre-commit hook:** The pre-commit hook lives in `.git/hooks/pre-commit` (which is gitignored by design and not shared when cloning) and can always be bypassed using `git commit --no-verify`.
- Test and documentation files are demoted, not removed; placeholder detection is word-based and can miss unusual placeholders.

## Vision and roadmap

- **Phase 2 (Private Repo Scanning):** GitHub token scanning of private repositories integrated with VS Code `SecretStorage` for secure offline credential caching.
- **Phase 3 (Curated Labeled Dataset):** Expanded labeled benchmark dataset combining synthetic edge cases with verified real-world manual labels.
- **Phase 4 (Local AI Triage):** Fine-tune a small local code model via LoRA as an optional, fully offline secondary classifier to triage ambiguities and minimize false positives without network calls.

## Running the VS Code Extension (F5)

1. Open this repository in VS Code: `code .`
2. Build the project: `npm run compile`
3. Press **`F5`** to launch the Extension Development Host window.
4. Run `Zawa: Scan Workspace` from the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
