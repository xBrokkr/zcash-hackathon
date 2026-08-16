export type FindingLevel = "block" | "review" | "note" | "pass";
export type AnalysisGate = "pass" | "review" | "block";
export type AddressValidation = "shape-only" | "checksum-valid" | "invalid";

export interface RuleDefinition {
  title: string;
  level: FindingLevel;
  source: string;
  fix: string;
}

export const RULES = {
  "zip321.scheme": { title: "Invalid payment scheme", level: "block", source: "https://zips.z.cash/zip-0321#uri-syntax", fix: "Start the request with zcash:." },
  "zip321.authority": { title: "URI authority is not allowed", level: "block", source: "https://zips.z.cash/zip-0321#uri-syntax", fix: "Remove // and place the address directly after zcash:." },
  "zip321.parameter": { title: "Malformed parameter", level: "block", source: "https://zips.z.cash/zip-0321#uri-syntax", fix: "Use key=value pairs separated by &, with no percent encoding in addresses, amounts, or parameter names." },
  "zip321.duplicate": { title: "Duplicate parameter", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Keep only one value for each parameter and index." },
  "zip321.index": { title: "Invalid parameter index", level: "block", source: "https://zips.z.cash/zip-0321#uri-syntax", fix: "Use an index from 1 to 999 with no leading zero." },
  "zip321.required": { title: "Required parameter is not understood", level: "block", source: "https://zips.z.cash/zip-0321#forward-compatibility", fix: "Add support for the req- parameter before presenting this request to a wallet." },
  "zip321.address": { title: "No payment address found", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Add an address for every indexed payment field." },
  "zip321.address-format": { title: "Address encoding needs correction", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use a valid Zcash transparent, Sapling, or Unified Address encoding." },
  "zip321.transparent": { title: "Transparent payment path", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use a shielded-capable receiver when this payment claims privacy." },
  "zip321.amount": { title: "Invalid payment amount", level: "block", source: "https://zips.z.cash/zip-0321#zec-transfer-amount", fix: "Use a positive decimal with at most eight fractional digits and no more than 21,000,000 ZEC." },
  "zip321.amount-missing": { title: "Payment amount is missing", level: "review", source: "https://zips.z.cash/zip-0321#query-keys", fix: "Include an amount so the wallet does not require manual re-entry." },
  "zip321.amount-asset": { title: "Amount and asset are combined", level: "block", source: "https://zips.z.cash/zip-0321#custom-assets", fix: "Use amount for ZEC or req-asset for a custom asset, never both at one index." },
  "zip321.asset": { title: "Invalid custom asset request", level: "block", source: "https://zips.z.cash/zip-0321#custom-assets", fix: "Use an unpadded base64url version-0 asset payload with 75 decoded bytes." },
  "zip321.memo": { title: "Invalid memo encoding", level: "block", source: "https://zips.z.cash/zip-0321#query-keys", fix: "Use unpadded base64url and keep the decoded memo at or below 512 bytes." },
  "zip321.memo-transparent": { title: "Memo targets a transparent address", level: "block", source: "https://zips.z.cash/zip-0321#query-keys", fix: "Remove the memo or change the payment to a shielded-capable address." },
  "zip321.network": { title: "Network mismatch", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use only mainnet addresses or only testnet addresses in one request." },
  "zip321.mixed-privacy": { title: "Privacy levels are mixed", level: "review", source: "https://zcash.readthedocs.io/en/latest/rtd_pages/ux_wallet_checklist.html", fix: "Review every output. A multi-payment request is only as private as its most revealing output." },
  "address.transparent": { title: "Transparent receiver", level: "block", source: "https://zcash.readthedocs.io/en/latest/rtd_pages/ux_wallet_checklist.html", fix: "Use a shielded-capable address when the product promise requires privacy." },
  "address.shape": { title: "Shielded-capable address shape", level: "pass", source: "https://zips.z.cash/zip-0316", fix: "Still let the wallet validate receiver composition and network context before sending." },
  "address.unknown": { title: "Address shape is not recognized", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use a supported Zcash address encoding and verify it in a wallet." },
  "analysis.pass": { title: "Local policy rules pass", level: "pass", source: "https://zips.z.cash/zip-0321", fix: "A wallet must still perform complete address and transaction validation." },
} as const satisfies Record<string, RuleDefinition>;

export type RuleId = keyof typeof RULES;

export interface Finding {
  id: RuleId;
  title: string;
  detail: string;
  level: FindingLevel;
  source: string;
  fix: string;
  scope?: string;
}

export type AddressClass = "transparent" | "shielded" | "unified" | "unknown";
export type Network = "mainnet" | "testnet" | "unknown";

export interface PaymentEntry {
  index: string;
  address: string;
  classification: AddressClass;
  network: Network;
  validation: AddressValidation;
  amount: string | null;
  hasMemo: boolean;
  hasAssetRequest: boolean;
}

export interface Analysis {
  inputType: "address" | "uri";
  normalized: string;
  network: Network | "mixed";
  score: number;
  gate: AnalysisGate;
  privacyLabel: string;
  confidence: "shape-only" | "format-error";
  entries: PaymentEntry[];
  findings: Finding[];
  ignoredParameters: string[];
}

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function finding(id: RuleId, detail: string, scope?: string): Finding {
  const rule = RULES[id];
  return { id, title: rule.title, detail, level: rule.level, source: rule.source, fix: rule.fix, scope };
}

function bech32Polymod(values: number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < BECH32_GENERATOR.length; index += 1) {
      if ((top >>> index) & 1) checksum ^= BECH32_GENERATOR[index] ?? 0;
    }
  }
  return checksum >>> 0;
}

function bech32HrpExpand(hrp: string): number[] {
  return [...hrp].map((character) => character.charCodeAt(0) >> 5).concat([0], [...hrp].map((character) => character.charCodeAt(0) & 31));
}

function convertBits(values: number[], fromBits: number, toBits: number): Uint8Array | null {
  let accumulator = 0;
  let bits = 0;
  const output: number[] = [];
  const maxValue = (1 << toBits) - 1;
  const maxAccumulator = (1 << (fromBits + toBits - 1)) - 1;
  for (const value of values) {
    if (value < 0 || (value >> fromBits) !== 0) return null;
    accumulator = ((accumulator << fromBits) | value) & maxAccumulator;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      output.push((accumulator >> bits) & maxValue);
    }
  }
  if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue) !== 0) return null;
  return Uint8Array.from(output);
}

function decodeBech32Payload(address: string, expectedHrp: string, variant: number): Uint8Array | null {
  const lower = address.toLowerCase();
  if (address !== lower && address !== address.toUpperCase()) return null;
  const separator = lower.lastIndexOf("1");
  if (separator < 1 || separator + 7 > lower.length || lower.slice(0, separator) !== expectedHrp) return null;
  const values = [...lower.slice(separator + 1)].map((character) => BECH32_CHARSET.indexOf(character));
  if (values.some((value) => value < 0) || bech32Polymod(bech32HrpExpand(expectedHrp).concat(values)) !== variant) return null;
  return convertBits(values.slice(0, -6), 5, 8);
}

function classifyAddress(address: string): { classification: AddressClass; network: Network; validation: AddressValidation } {
  const value = address.trim();
  const lower = value.toLowerCase();
  if (/^(t1|t3)/.test(lower)) return { classification: "transparent", network: "mainnet", validation: BASE58.test(value) && value.length >= 26 && value.length <= 40 ? "shape-only" : "invalid" };
  if (/^(tm|t2)/.test(lower)) return { classification: "transparent", network: "testnet", validation: BASE58.test(value) && value.length >= 26 && value.length <= 40 ? "shape-only" : "invalid" };
  if (lower.startsWith("zs1")) {
    const payload = decodeBech32Payload(value, "zs", 1);
    return { classification: "shielded", network: "mainnet", validation: payload?.length === 43 ? "checksum-valid" : "invalid" };
  }
  if (lower.startsWith("ztestsapling1")) {
    const payload = decodeBech32Payload(value, "ztestsapling", 1);
    return { classification: "shielded", network: "testnet", validation: payload?.length === 43 ? "checksum-valid" : "invalid" };
  }
  const unifiedMainnetPrefix = ["u1", "zu1", "tu1"].find((prefix) => lower.startsWith(prefix));
  if (unifiedMainnetPrefix) {
    const payload = decodeBech32Payload(value, unifiedMainnetPrefix.slice(0, -1), 0x2bc830a3);
    return { classification: "unified", network: "mainnet", validation: payload && payload.length >= 16 ? "checksum-valid" : "invalid" };
  }
  const unifiedTestnetPrefix = ["utest1", "zutest1", "tutest1"].find((prefix) => lower.startsWith(prefix));
  if (unifiedTestnetPrefix) {
    const payload = decodeBech32Payload(value, unifiedTestnetPrefix.slice(0, -1), 0x2bc830a3);
    return { classification: "unified", network: "testnet", validation: payload && payload.length >= 16 ? "checksum-valid" : "invalid" };
  }
  return { classification: "unknown", network: "unknown", validation: "invalid" };
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function isQchar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? "";
    if (/^[A-Za-z0-9\-._~!$'()*+,;:@]$/.test(character)) continue;
    if (character === "%" && /^[0-9A-Fa-f]{2}$/.test(value.slice(index + 1, index + 3))) {
      index += 2;
      continue;
    }
    return false;
  }
  return true;
}

function amountIsValid(value: string): boolean {
  if (!/^\d+(\.\d{1,8})?$/.test(value)) return false;
  const number = Number(value);
  return Number.isFinite(number) && number > 0 && number <= 21_000_000;
}

function indexIsValid(index: string): boolean {
  return index === "" || /^[1-9]\d{0,2}$/.test(index);
}

function labelForGate(gate: AnalysisGate): string {
  if (gate === "pass") return "Local rules pass";
  if (gate === "review") return "Review required";
  return "Blocked";
}

function gateForFindings(findings: Finding[]): AnalysisGate {
  if (findings.some((item) => item.level === "block")) return "block";
  if (findings.some((item) => item.level === "review")) return "review";
  return "pass";
}

function scoreForFindings(findings: Finding[], entries: PaymentEntry[]): number {
  let score = 100;
  score -= findings.filter((item) => item.level === "block").length * 22;
  score -= findings.filter((item) => item.level === "review").length * 8;
  score -= entries.filter((item) => item.validation === "invalid").length * 20;
  return Math.max(0, Math.min(100, score));
}

function makeAnalysis(inputType: Analysis["inputType"], normalized: string, entries: PaymentEntry[], findings: Finding[], ignoredParameters: string[] = []): Analysis {
  const knownNetworks = new Set(entries.map((entry) => entry.network).filter((network) => network !== "unknown"));
  const network: Analysis["network"] = knownNetworks.size > 1 ? "mixed" : knownNetworks.values().next().value ?? "unknown";
  if (network === "mixed") findings.push(finding("zip321.network", "The request contains both mainnet and testnet address prefixes."));
  if (entries.length > 1 && entries.some((entry) => entry.classification === "transparent")) findings.push(finding("zip321.mixed-privacy", "At least one output is transparent while another output may be shielded-capable."));
  if (findings.length === 0) findings.push(finding("analysis.pass", "No blocking or review-level findings were generated."));
  const gate = gateForFindings(findings);
  return { inputType, normalized, network, score: scoreForFindings(findings, entries), gate, privacyLabel: labelForGate(gate), confidence: entries.some((entry) => entry.validation === "invalid") ? "format-error" : "shape-only", entries, findings, ignoredParameters };
}

export function analyzeAddress(address: string): Analysis {
  const normalized = address.trim();
  if (!normalized) return makeAnalysis("address", normalized, [], [finding("zip321.address", "Paste a mainnet or testnet transparent, Sapling, or Unified Address.")]);
  const classified = classifyAddress(normalized);
  const entries: PaymentEntry[] = [{ index: "", address: normalized, ...classified, amount: null, hasMemo: false, hasAssetRequest: false }];
  const findings: Finding[] = [];
  if (classified.validation === "invalid") findings.push(finding("zip321.address-format", "The prefix is known, but the address body does not match the expected encoding character set or length."));
  if (classified.classification === "transparent") findings.push(finding("address.transparent", "The receiver is transparent, so sender, receiver, and value can be publicly visible."));
  if (classified.classification === "unknown") findings.push(finding("address.unknown", "The string does not match a supported Zcash address prefix."));
  if (classified.classification === "shielded" || classified.classification === "unified") findings.push(finding("address.shape", "The address has a shielded-capable shape and a valid outer checksum. This browser release does not decode every Unified receiver item or prove wallet-level network context."));
  return makeAnalysis("address", normalized, entries, findings);
}

export function analyzeUri(input: string): Analysis {
  const normalized = input.trim();
  const findings: Finding[] = [];
  const ignoredParameters: string[] = [];
  if (!/^zcash:/i.test(normalized)) return makeAnalysis("uri", normalized, [], [finding("zip321.scheme", "A payment request must start with the zcash: scheme.")]);

  const body = normalized.slice(6);
  if (body.startsWith("//")) findings.push(finding("zip321.authority", "ZIP-321 does not use a URI authority component."));
  const queryIndex = body.indexOf("?");
  const head = queryIndex === -1 ? body : body.slice(0, queryIndex);
  const rawQuery = queryIndex === -1 ? "" : body.slice(queryIndex + 1);
  const payments = new Map<string, { address?: string; amount?: string; memo?: string; asset?: string; memoPresent: boolean; assetPresent: boolean }>();
  const seenKeys = new Set<string>();

  if (head) {
    if (!/^[A-Za-z0-9]+$/.test(head)) findings.push(finding("zip321.parameter", "The direct address component contains characters that are not allowed by the ZIP-321 grammar."));
    payments.set("", { address: head, memoPresent: false, assetPresent: false });
  }

  if (rawQuery) {
    for (const rawPair of rawQuery.split("&")) {
      const equals = rawPair.indexOf("=");
      const key = equals === -1 ? rawPair : rawPair.slice(0, equals);
      const rawValue = equals === -1 ? "" : rawPair.slice(equals + 1);
      if (key.length === 0) {
        findings.push(finding("zip321.parameter", `The query item ${rawPair || "<empty>"} does not have a parameter name.`));
        continue;
      }
      if (key.includes("%") || seenKeys.has(key)) {
        findings.push(finding(seenKeys.has(key) ? "zip321.duplicate" : "zip321.parameter", `The parameter ${key} is repeated or percent-encoded in a position where ZIP-321 forbids it.`));
        continue;
      }
      seenKeys.add(key);
      const parsedKey = /^(address|amount|memo|req-asset|label|message)(?:\.(\d+))?$/.exec(key);
      const genericKey = /^([A-Za-z][A-Za-z0-9+-]*)(?:\.(\d+))?$/.exec(key);
      if (!genericKey) {
        findings.push(finding("zip321.parameter", `The parameter name ${key} is not valid.`));
        continue;
      }
      const name = genericKey[1];
      const index = genericKey[2] ?? "";
      if (!indexIsValid(index)) {
        findings.push(finding("zip321.index", `The parameter ${key} uses a forbidden index.`));
        continue;
      }
      if (!isQchar(rawValue)) {
        findings.push(finding("zip321.parameter", `${key} contains characters outside the ZIP-321 qchar grammar.`));
        continue;
      }
      if (!parsedKey) {
        if (name.startsWith("req-")) findings.push(finding("zip321.required", `${name} is required by forward compatibility and is not supported by this analyzer.`));
        else ignoredParameters.push(key);
        continue;
      }
      if (equals === -1) {
        findings.push(finding("zip321.parameter", `The recognized parameter ${key} must use key=value syntax.`));
        continue;
      }
      if (head && name === "address" && index === "") {
        findings.push(finding("zip321.duplicate", "The direct address component and address= both target payment 0."));
        continue;
      }
      if (["address", "amount", "memo", "req-asset"].includes(name) && rawValue.includes("%")) {
        findings.push(finding("zip321.parameter", `${key} uses percent encoding where ZIP-321 does not allow it.`));
        continue;
      }
      if (name === "label" || name === "message") {
        try { decodeURIComponent(rawValue); } catch { findings.push(finding("zip321.parameter", `${key} contains invalid percent encoding.`)); }
      }
      const current = payments.get(index) ?? { memoPresent: false, assetPresent: false };
      if (name === "address") current.address = rawValue;
      if (name === "amount") current.amount = rawValue;
      if (name === "memo") { current.memo = rawValue; current.memoPresent = true; }
      if (name === "req-asset") { current.asset = rawValue; current.assetPresent = true; }
      payments.set(index, current);
    }
  }

  const entries: PaymentEntry[] = [];
  for (const [index, payment] of [...payments.entries()].sort(([left], [right]) => Number(left || 0) - Number(right || 0))) {
    if (!payment.address) {
      if (payment.amount || payment.memoPresent || payment.assetPresent) findings.push(finding("zip321.address", `Payment ${index || "0"} has fields but no address.`, index || "0"));
      continue;
    }
    const classified = classifyAddress(payment.address);
    const entry: PaymentEntry = { index, address: payment.address, ...classified, amount: payment.amount ?? null, hasMemo: payment.memoPresent, hasAssetRequest: payment.assetPresent };
    entries.push(entry);
    if (classified.validation === "invalid") findings.push(finding("zip321.address-format", `Payment ${index || "0"} has a malformed ${classified.classification} address body or checksum.`, index || "0"));
    if (classified.classification === "unknown") findings.push(finding("address.unknown", `Payment ${index || "0"} uses an address shape that this release does not recognize.`, index || "0"));
    if (classified.classification === "transparent") findings.push(finding("zip321.transparent", `Payment ${index || "0"} is sent to a transparent receiver.`, index || "0"));
    if (!payment.amount && !payment.assetPresent) findings.push(finding("zip321.amount-missing", `Payment ${index || "0"} has no amount.`, index || "0"));
    if (payment.amount && !amountIsValid(payment.amount)) findings.push(finding("zip321.amount", `Payment ${index || "0"} uses ${payment.amount}, which is outside the ZIP-321 amount grammar.`, index || "0"));
    if (payment.assetPresent && payment.amount) findings.push(finding("zip321.amount-asset", `Payment ${index || "0"} includes both amount and req-asset.`, index || "0"));
    if (payment.assetPresent) {
      const assetBytes = decodeBase64Url(payment.asset ?? "");
      if (!assetBytes || assetBytes.length !== 75 || assetBytes[0] !== 0) findings.push(finding("zip321.asset", `Payment ${index || "0"} does not contain a valid version-0 asset payload.`, index || "0"));
      if (classified.classification !== "unified") findings.push(finding("zip321.asset", `Payment ${index || "0"} requests a custom asset without a Unified Address receiver.`, index || "0"));
    }
    if (payment.memoPresent) {
      const memoBytes = decodeBase64Url(payment.memo ?? "");
      if (!memoBytes || memoBytes.length > 512) findings.push(finding("zip321.memo", `Payment ${index || "0"} has an invalid or oversized memo.`, index || "0"));
      if (classified.classification === "transparent") findings.push(finding("zip321.memo-transparent", `Payment ${index || "0"} places a memo on a transparent receiver.`, index || "0"));
    }
  }
  if (entries.length === 0) findings.push(finding("zip321.address", "The request contains no usable payment address."));
  return makeAnalysis("uri", normalized, entries, findings, ignoredParameters);
}
