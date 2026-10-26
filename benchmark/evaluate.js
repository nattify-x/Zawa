#!/usr/bin/env node
/**
 * Zawa Benchmark Evaluator
 * Runs the compiled Zawa CLI on benchmark/planted/ in JSON mode,
 * verifies against benchmark/ground-truth.json, computes metrics
 * (TP, FP, FN, TN, Precision, Recall, F1, scan time), and outputs
 * results to console and benchmark/results-zawa.json.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const BENCHMARK_DIR = __dirname;
const PLANTED_DIR = path.join(BENCHMARK_DIR, 'planted');
const GROUND_TRUTH_PATH = path.join(BENCHMARK_DIR, 'ground-truth.json');
const RESULTS_PATH = path.join(BENCHMARK_DIR, 'results-zawa.json');
const CLI_PATH = path.resolve(__dirname, '../out/cli/zawa-cli.js');

function runEvaluation() {
  console.log('\n================================================================');
  console.log(' Zawa Benchmark Evaluation');
  console.log('================================================================');

  if (!fs.existsSync(CLI_PATH)) {
    console.error(`Error: Compiled CLI not found at ${CLI_PATH}. Run "npm run compile" first.`);
    process.exit(1);
  }

  if (!fs.existsSync(GROUND_TRUTH_PATH) || !fs.existsSync(PLANTED_DIR)) {
    console.error(`Error: Dataset not found. Run "npm run bench:generate" first.`);
    process.exit(1);
  }

  const groundTruth = JSON.parse(fs.readFileSync(GROUND_TRUTH_PATH, 'utf-8'));

  console.log(`Running Zawa CLI on benchmark/planted/ ...`);
  const startTime = Date.now();
  const runResult = spawnSync(process.execPath, [CLI_PATH, PLANTED_DIR, '--json'], {
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024,
  });

  const durationMs = Date.now() - startTime;

  let cliOutput;
  try {
    cliOutput = JSON.parse(runResult.stdout);
  } catch (err) {
    console.error('Failed to parse CLI output as JSON. Raw output:');
    console.error(runResult.stdout || runResult.stderr);
    process.exit(1);
  }

  const findings = cliOutput.findings || [];
  const engineDurationMs = cliOutput.summary?.durationMs ?? durationMs;

  console.log(`CLI returned ${findings.length} finding(s) in ${engineDurationMs} ms.`);

  // Map findings by "file:line"
  const findingMap = new Map();
  for (const f of findings) {
    const key = `${f.file}:${f.line}`;
    if (!findingMap.has(key)) {
      findingMap.set(key, []);
    }
    findingMap.get(key).push(f);
  }

  const matchedSecrets = [];
  const missedSecrets = [];
  const falsePositives = [];
  const ignoredDecoys = [];

  const matchedFindingKeys = new Set();

  for (const item of groundTruth) {
    const key = `${item.file}:${item.line}`;
    const detected = findingMap.get(key);

    if (item.type === 'secret') {
      if (detected && detected.length > 0) {
        matchedSecrets.push({ item, finding: detected[0] });
        matchedFindingKeys.add(key);
      } else {
        missedSecrets.push(item);
      }
    } else if (item.type === 'decoy') {
      if (detected && detected.length > 0) {
        falsePositives.push({ item, findings: detected });
        matchedFindingKeys.add(key);
      } else {
        ignoredDecoys.push(item);
      }
    }
  }

  // Check for any finding that didn't correspond to any ground-truth item
  for (const f of findings) {
    const key = `${f.file}:${f.line}`;
    if (!matchedFindingKeys.has(key)) {
      falsePositives.push({
        item: { id: 'UNPLANTED', file: f.file, line: f.line, description: 'Unexpected finding' },
        findings: [f],
      });
    }
  }

  const TP = matchedSecrets.length;
  const FN = missedSecrets.length;
  const FP = falsePositives.length;
  const TN = ignoredDecoys.length;

  const precision = TP + FP > 0 ? TP / (TP + FP) : 1.0;
  const recall = TP + FN > 0 ? TP / (TP + FN) : 1.0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = (TP + TN) / (TP + TN + FP + FN);

  const resultsData = {
    timestamp: new Date().toISOString(),
    engineDurationMs,
    totalGroundTruth: groundTruth.length,
    metrics: {
      truePositives: TP,
      falsePositives: FP,
      falseNegatives: FN,
      trueNegatives: TN,
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1Score: Number(f1.toFixed(4)),
      accuracy: Number(accuracy.toFixed(4)),
    },
    details: {
      matchedSecretsCount: matchedSecrets.length,
      missedSecretsCount: missedSecrets.length,
      falsePositivesCount: falsePositives.length,
      ignoredDecoysCount: ignoredDecoys.length,
      missedSecrets,
      falsePositives,
    },
  };

  fs.writeFileSync(RESULTS_PATH, JSON.stringify(resultsData, null, 2), 'utf-8');

  // Print Summary Table
  console.log('\n----------------------------------------------------------------');
  console.log(' BENCHMARK EVALUATION RESULTS');
  console.log('----------------------------------------------------------------');
  console.log(`  True Positives  (TP) : ${TP} / ${groundTruth.filter((i) => i.type === 'secret').length}`);
  console.log(`  False Positives (FP) : ${FP}`);
  console.log(`  False Negatives (FN) : ${FN}`);
  console.log(`  True Negatives  (TN) : ${TN} / ${groundTruth.filter((i) => i.type === 'decoy').length}`);
  console.log('----------------------------------------------------------------');
  console.log(`  Precision            : ${(precision * 100).toFixed(2)} %`);
  console.log(`  Recall               : ${(recall * 100).toFixed(2)} %`);
  console.log(`  F1-Score             : ${(f1 * 100).toFixed(2)} %`);
  console.log(`  Accuracy             : ${(accuracy * 100).toFixed(2)} %`);
  console.log(`  Scan Time            : ${engineDurationMs} ms`);
  console.log('----------------------------------------------------------------');
  console.log(`Detailed metrics saved to: benchmark/results-zawa.json\n`);

  if (FP > 0) {
    console.log('[!] False Positives Detected:');
    for (const fp of falsePositives) {
      console.log(`    - ${fp.item.file}:${fp.item.line} -> ${fp.item.description}`);
    }
  }

  if (FN > 0) {
    console.log('[!] False Negatives (Missed Secrets):');
    for (const fn of missedSecrets) {
      console.log(`    - ${fn.file}:${fn.line} -> ${fn.description} (${fn.expectedRule})`);
    }
  }

  console.log('================================================================\n');

  // Return success exit code if F1 >= 0.95
  process.exit(f1 >= 0.95 ? 0 : 1);
}

runEvaluation();
