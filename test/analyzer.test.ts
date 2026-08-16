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

test("accepts optional unknown parameters without an equals sign but blocks required ones", () => {
  const optional = analyzeUri(`zcash:${shieldedTestnet}?future-flag&amount=1`);
  assert.equal(optional.gate, "pass");
  assert.deepEqual(optional.ignoredParameters, ["future-flag"]);

  const required = analyzeUri(`zcash:${shieldedTestnet}?req-future&amount=1`);
  assert.ok(required.findings.some((finding) => finding.id === "zip321.required"));
  assert.equal(required.gate, "block");

  const recognized = analyzeUri(`zcash:${shieldedTestnet}?amount&amount=1`);
  assert.ok(recognized.findings.some((finding) => finding.id === "zip321.parameter"));
  assert.equal(recognized.gate, "block");
});

test("enforces ZIP-321 qchar syntax for descriptive and unknown parameter values", () => {
  const valid = analyzeUri(`zcash:${shieldedTestnet}?amount=1&label=hello%20world&future=alpha%3Abeta`);
  assert.equal(valid.gate, "pass");

  const invalidLabel = analyzeUri(`zcash:${shieldedTestnet}?amount=1&label=hello world`);
  assert.ok(invalidLabel.findings.some((finding) => finding.id === "zip321.parameter"));
  assert.equal(invalidLabel.gate, "block");

  const invalidUnknown = analyzeUri(`zcash:${shieldedTestnet}?amount=1&future=bad%2G`);
  assert.ok(invalidUnknown.findings.some((finding) => finding.id === "zip321.parameter"));
  assert.equal(invalidUnknown.gate, "block");
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
  assert.equal(result.entries[0]?.validation, "checksum-valid");
  assert.ok(result.findings.some((finding) => finding.id === "address.shape"));
});

test("does not treat an arbitrary u1 prefix as a verified address", () => {
  const result = analyzeAddress("u1not-a-real-address");
  assert.equal(result.gate, "block");
  assert.equal(result.confidence, "format-error");
});

test("recognizes current Unified Address revision prefixes without claiming checksum verification", () => {
  for (const [address, network] of [
    ["zu1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqv4d6g9", "mainnet"],
    ["zutest1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqdqwec3", "testnet"],
    ["tu1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqa2c2lp", "mainnet"],
    ["tutest1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqlxup9h", "testnet"],
  ] as const) {
    const result = analyzeAddress(address);
    assert.equal(result.entries[0]?.classification, "unified");
    assert.equal(result.entries[0]?.network, network);
    assert.equal(result.entries[0]?.validation, "checksum-valid");
    assert.equal(result.confidence, "shape-only");
    assert.ok(result.findings.some((finding) => finding.id === "address.shape"));
    assert.equal(result.findings.some((finding) => finding.id === "address.unknown"), false);
  }
});

test("rejects Bech32 and Bech32m checksum mutations", () => {
  const validUnified = "zu1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqv4d6g9";
  const invalidUnified = `${validUnified.slice(0, -1)}${validUnified.endsWith("q") ? "p" : "q"}`;
  const unifiedResult = analyzeAddress(invalidUnified);
  assert.equal(unifiedResult.entries[0]?.validation, "invalid");
  assert.equal(unifiedResult.confidence, "format-error");

  const invalidSapling = `${shieldedTestnet.slice(0, -1)}${shieldedTestnet.endsWith("q") ? "p" : "q"}`;
  const saplingResult = analyzeAddress(invalidSapling);
  assert.equal(saplingResult.entries[0]?.validation, "invalid");
  assert.equal(saplingResult.confidence, "format-error");
});
