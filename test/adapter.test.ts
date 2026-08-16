import assert from "node:assert/strict";
import { test } from "node:test";
import { FixtureChainAdapter, LightwalletdTransparentAdapter, RemoteChainAdapter, evaluateWithAdapter } from "../adapters/chain";
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
  assert.equal(result.observations[0]?.queryPrivacy, "not-applicable");
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
  assert.throws(() => new RemoteChainAdapter("https://user:pass@node.example", { inspect: async () => ({ status: "not-found", network: "testnet", detail: "unsafe" }) }), /credentials/);
  assert.throws(() => new RemoteChainAdapter("https://node.example/#fixture", { inspect: async () => ({ status: "not-found", network: "testnet", detail: "unsafe" }) }), /fragment/);
  const adapter = new RemoteChainAdapter("https://node.example", { inspect: async () => ({ status: "match", network: "testnet", detail: "Remote observation returned by injected transport." }) });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.effectiveGate, result.localGate);
  assert.equal(result.verification, "not-verified");
  assert.equal(result.observations[0]?.trust, "remote-untrusted");
  assert.equal(result.observations[0]?.claim, "observation-only");
  assert.equal(result.observations[0]?.queryPrivacy, "unspecified");
});

test("remote network mismatch fails closed without changing the local gate", async () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  const adapter = new RemoteChainAdapter("https://node.example", { inspect: async () => ({ status: "match", network: "mainnet", detail: "wrong network" }) });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.localGate, "pass");
  assert.equal(result.effectiveGate, "pass");
  assert.equal(result.observations[0]?.status, "error");
  assert.match(result.observations[0]?.detail ?? "", /local policy remains/);
});

test("lightwalletd transparent adapter discloses address scope and observes only mined records", async () => {
  const analysis = analyzeUri("zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1");
  let query: { address: string; startHeight: number; endHeight: number } | undefined;
  const adapter = new LightwalletdTransparentAdapter("https://lightwalletd.example", "testnet", {
    getAddressTransactions: async (value) => {
      query = value;
      return [
        { txid: "a".repeat(64), height: 0 },
        { txid: "b".repeat(64), height: 123 },
      ];
    },
  }, { startHeight: 100, endHeight: 200 });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.deepEqual(query, { address: "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU", startHeight: 100, endHeight: 200 });
  assert.equal(result.observations[0]?.status, "match");
  assert.equal(result.observations[0]?.queryPrivacy, "address-disclosed");
  assert.equal(result.effectiveGate, result.localGate);
  assert.equal(result.verification, "not-verified");
});

test("lightwalletd transparent adapter does not query shielded entries", async () => {
  const analysis = analyzeUri(`zcash:${shieldedTestnet}?amount=1`);
  let called = false;
  const adapter = new LightwalletdTransparentAdapter("https://lightwalletd.example", "testnet", {
    getAddressTransactions: async () => {
      called = true;
      return [];
    },
  }, { startHeight: 1, endHeight: 2 });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(called, false);
  assert.equal(result.observations[0]?.status, "unsupported");
  assert.equal(result.observations[0]?.queryPrivacy, "not-applicable");
});

test("lightwalletd transparent adapter rejects malformed records and wrong ranges", async () => {
  assert.throws(() => new LightwalletdTransparentAdapter("https://lightwalletd.example", "testnet", { getAddressTransactions: async () => [] }, { startHeight: 3, endHeight: 2 }), /bounded/);
  const analysis = analyzeUri("zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1");
  const adapter = new LightwalletdTransparentAdapter("https://lightwalletd.example", "testnet", {
    getAddressTransactions: async () => [{ txid: "not-a-txid", height: 10 }],
  }, { startHeight: 1, endHeight: 2 });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.observations[0]?.status, "error");
  assert.match(result.observations[0]?.detail ?? "", /local policy remains/);

  const rangeAdapter = new LightwalletdTransparentAdapter("https://lightwalletd.example", "testnet", {
    getAddressTransactions: async () => [{ txid: "c".repeat(64), height: 99 }],
  }, { startHeight: 1, endHeight: 2 });
  const rangeResult = await evaluateWithAdapter(analysis, rangeAdapter);
  assert.equal(rangeResult.observations[0]?.status, "error");
});

test("lightwalletd transparent adapter fails closed on endpoint network mismatch", async () => {
  const analysis = analyzeUri("zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1");
  const adapter = new LightwalletdTransparentAdapter("https://lightwalletd.example", "mainnet", {
    getAddressTransactions: async () => [],
  }, { startHeight: 1, endHeight: 2 });
  const result = await evaluateWithAdapter(analysis, adapter);

  assert.equal(result.observations[0]?.status, "error");
  assert.equal(result.effectiveGate, result.localGate);
});
