import { readFile } from "node:fs/promises";
import { analyzeUri } from "../packages/core/src/index";
import { exitCodeForGate } from "../lib/cli";

const fixtures = [
  { file: "fixtures/cli/pass-shielded.txt", expected: 0 },
  { file: "fixtures/cli/review-missing-amount.txt", expected: 2 },
  { file: "fixtures/cli/block-transparent.txt", expected: 1 },
];

let failures = 0;
async function main(): Promise<void> {
  for (const fixture of fixtures) {
    const analysis = analyzeUri((await readFile(fixture.file, "utf8")).trim());
    const actual = exitCodeForGate(analysis.gate);
    if (actual !== fixture.expected) {
      failures += 1;
      console.error(`${fixture.file}: expected exit ${fixture.expected}, got ${actual}`);
    } else {
      console.log(`${fixture.file}: ${analysis.gate} (${actual})`);
    }
  }

  if (failures > 0) process.exitCode = 1;
}

void main();
