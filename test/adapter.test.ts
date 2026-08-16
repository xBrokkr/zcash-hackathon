import assert from "node:assert/strict";
import { test } from "node:test";
import { FixtureChainAdapter, RemoteChainAdapter, evaluateWithAdapter } from "../adapters/chain";
import { analyzeUri } from "../packages/core/src/index";

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";

test("fixture adapter adds observation without changing the local gate", async () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  const adapter = new FixtureChainAdapter([{ address: shieldedTestnet, network: "testnet", classification: "shielded", detail: "Fixture contains a shielded-capable testnet shape." }]);
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.localGate, "pass");
  assert.equal(result.effectiveGate, "pass");
  assert.equal(result.verification, "not-verified");
  assert.equal(result.trustBoundary, "local-policy-authority");
  assert.equal(result.observations[0]?.status, "match");
  assert.equal(result.observations[0]?.claim, "observation-only");
});

test("adapter failure cannot upgrade or replace a blocked local result", async () => {
  const analysis = analyzeUri("zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1");
  const adapter = { id: "failing-test-adapter", trust: "remote-untrusted" as const, inspect: async () => { throw new Error("offline"); } };
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.localGate, "block");
  assert.equal(result.effectiveGate, "block");
  assert.equal(result.observations[0]?.status, "error");
  assert.match(result.observations[0]?.detail ?? "", /local policy remains/);
});

test("remote adapter requires HTTPS and remains observation-only", async () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  assert.throws(() => new RemoteChainAdapter("http://node.example", { inspect: async () => ({ status: "match", network: "testnet", detail: "unsafe" }) }), /HTTPS/);
  const adapter = new RemoteChainAdapter("https://node.example", { inspect: async () => ({ status: "match", network: "testnet", detail: "Remote observation returned by injected transport." }) });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.effectiveGate, result.localGate);
  assert.equal(result.verification, "not-verified");
  assert.equal(result.observations[0]?.trust, "remote-untrusted");
  assert.equal(result.observations[0]?.claim, "observation-only");
});
