import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeUri as analyzePackageUri } from "../packages/core/src/index";
import { analyzeUri as analyzeAppUri } from "../lib/analyzer";

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";

test("the app compatibility export resolves to the extracted core package", () => {
  const input = `zcash:${shieldedTestnet}?amount=1`;
  assert.deepEqual(analyzeAppUri(input), analyzePackageUri(input));
});
