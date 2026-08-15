import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeUri } from "../lib/analyzer";
import { buildRedactedFixture, buildReport, decodeFixture, encodeFixture, parseFixtureJson } from "../lib/report";

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";

test("builds a report with a stable schema and input hash", async () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  const report = await buildReport(analysis);

  assert.equal(report.schema, "shadecheck.report");
  assert.equal(report.reportVersion, 1);
  assert.equal(report.ruleVersions["zip321.scheme"], 1);
  assert.equal(report.inputSha256.length, 64);
  assert.equal(report.analysis.normalized, analysis.normalized);
});

test("fixture encoding removes raw request, address, and amount data", () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1&memo=VGVzdA`);
  const fixture = buildRedactedFixture(analysis);
  const encoded = encodeFixture(fixture);
  const decoded = decodeFixture(encoded);

  assert.ok(decoded);
  assert.equal(decoded.normalized, "[redacted]");
  assert.equal(decoded.entries[0]?.address, "[redacted]");
  assert.equal(decoded.entries[0]?.amount, "[redacted]");
  assert.equal(JSON.stringify(fixture).includes(shieldedTestnet), false);
  assert.equal(JSON.stringify(fixture).includes("VGVzdA"), false);
  assert.equal(parseFixtureJson(fixture)?.gate, analysis.gate);
  assert.equal(parseFixtureJson({ schema: "shadecheck.report" }), null);
  assert.equal(parseFixtureJson({ ...fixture, analysis: { ...fixture.analysis, entries: [{ ...fixture.analysis.entries[0], address: "zs1raw" }] } }), null);
});
