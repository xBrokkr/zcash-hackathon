import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeAddress, analyzeUri } from "../lib/analyzer";

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
const shieldedMainnet = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
const transparentTestnet = "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";

test("passes a well-formed shielded ZIP-321 request through local policy", () => {
  const result = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  assert.equal(result.gate, "pass");
  assert.equal(result.network, "testnet");
  assert.equal(result.confidence, "shape-only");
});

test("blocks a memo sent to a transparent receiver", () => {
  const result = analyzeUri(`zcash:${transparentTestnet}?amount=1&memo=VGVzdA`);
  assert.equal(result.gate, "block");
  assert.ok(result.findings.some((finding) => finding.id === "zip321.memo-transparent"));
});

test("blocks duplicate parameters", () => {
  const result = analyzeUri(`zcash:${transparentTestnet}?amount=1&amount=2`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.duplicate"));
  assert.equal(result.gate, "block");
});

test("blocks a direct address combined with address= at the same index", () => {
  const result = analyzeUri(`zcash:${transparentTestnet}?address=${transparentTestnet}&amount=1`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.duplicate"));
  assert.equal(result.gate, "block");
});

test("blocks leading-zero parameter indexes", () => {
  const result = analyzeUri(`zcash:?address.01=${shieldedTestnet}&amount.01=1`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.index"));
  assert.equal(result.gate, "block");
});

test("blocks indexed fields without a matching address", () => {
  const result = analyzeUri(`zcash:?address=${transparentTestnet}&amount.1=1`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.address" && finding.scope === "1"));
  assert.equal(result.gate, "block");
});

test("blocks amount and custom asset collisions", () => {
  const result = analyzeUri(`zcash:${shieldedTestnet}?amount=1&req-asset=bad`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.amount-asset"));
  assert.equal(result.gate, "block");
});

test("blocks unknown required parameters", () => {
  const result = analyzeUri(`zcash:${shieldedTestnet}?amount=1&req-future=value`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.required"));
  assert.equal(result.gate, "block");
});

test("blocks mixed networks", () => {
  const result = analyzeUri(`zcash:?address=${transparentTestnet}&amount=1&address.1=${shieldedMainnet}&amount.1=1`);
  assert.ok(result.findings.some((finding) => finding.id === "zip321.network"));
  assert.equal(result.gate, "block");
});

test("labels direct shielded address checks as shape-only", () => {
  const result = analyzeAddress(shieldedTestnet);
  assert.equal(result.gate, "pass");
  assert.equal(result.confidence, "shape-only");
  assert.ok(result.findings.some((finding) => finding.id === "address.shape"));
});

test("does not treat an arbitrary u1 prefix as a verified address", () => {
  const result = analyzeAddress("u1not-a-real-address");
  assert.equal(result.gate, "block");
  assert.equal(result.confidence, "format-error");
});
