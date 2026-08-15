import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeAddress, analyzeUri } from "../lib/analyzer";
import { exitCodeForGate, renderJson, renderText } from "../lib/cli";

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
const transparentTestnet = "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";

test("maps local policy gates to CI-friendly exit codes", () => {
  assert.equal(exitCodeForGate(analyzeUri(`zcash:${shieldedTestnet}?amount=1`).gate), 0);
  assert.equal(exitCodeForGate(analyzeUri(`zcash:${transparentTestnet}?amount=1`).gate), 1);
  assert.equal(exitCodeForGate(analyzeUri(`zcash:${shieldedTestnet}`).gate), 2);
});

test("renders machine and human CLI output from the same analysis", () => {
  const analysis = analyzeAddress(transparentTestnet);
  assert.match(renderText(analysis), /Transparent receiver/);
  const json = JSON.parse(renderJson(analysis)) as { schema: string; exitCode: number; analysis: { gate: string } };
  assert.equal(json.schema, "shadecheck.cli-result");
  assert.equal(json.exitCode, 1);
  assert.equal(json.analysis.gate, "block");
});
