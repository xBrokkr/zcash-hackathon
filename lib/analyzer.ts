export type FindingLevel = "good" | "warning" | "critical" | "info";

export type AddressClass = "transparent" | "shielded" | "unified" | "unknown";

export interface Finding {
  id: string;
  title: string;
  detail: string;
  level: FindingLevel;
}

export interface PaymentEntry {
  index: string;
  address: string;
  classification: AddressClass;
  network: "mainnet" | "testnet" | "unknown";
  amount: string | null;
  hasMemo: boolean;
  hasAssetRequest: boolean;
}

export interface Analysis {
  inputType: "address" | "uri";
  normalized: string;
  network: "mainnet" | "testnet" | "mixed" | "unknown";
  score: number;
  privacyLabel: string;
  entries: PaymentEntry[];
  findings: Finding[];
}

function classifyAddress(address: string): { classification: AddressClass; network: PaymentEntry["network"] } {
  const value = address.trim().toLowerCase();
  if (/^(t1|t3)/.test(value)) return { classification: "transparent", network: "mainnet" };
  if (/^(tm|t2)/.test(value)) return { classification: "transparent", network: "testnet" };
  if (value.startsWith("zs1")) return { classification: "shielded", network: "mainnet" };
  if (value.startsWith("ztestsapling1")) return { classification: "shielded", network: "testnet" };
  if (value.startsWith("u1")) return { classification: "unified", network: "mainnet" };
  if (value.startsWith("utest1")) return { classification: "unified", network: "testnet" };
  return { classification: "unknown", network: "unknown" };
}

function base64UrlMemo(value: string): boolean {
  return /^[A-Za-z0-9_-]*$/.test(value) && value.length > 0;
}

function scoreAnalysis(entries: PaymentEntry[], findings: Finding[]): number {
  let score = 100;
  for (const entry of entries) {
    if (entry.classification === "transparent") score -= 35;
    if (entry.classification === "unknown") score -= 25;
    if (!entry.amount) score -= 8;
    if (entry.hasMemo) score -= 3;
  }
  for (const finding of findings) {
    if (finding.id === "missing-address" || finding.id === "invalid-amount" || finding.id === "unsupported-required") score -= 15;
    if (finding.id === "missing-index-address") score -= 10;
  }
  return Math.max(0, Math.min(100, score));
}

function labelForScore(score: number): string {
  if (score >= 85) return "Strong shielded path";
  if (score >= 60) return "Needs review";
  return "Privacy risk";
}

function invalidAnalysis(inputType: Analysis["inputType"], normalized: string, finding: Finding): Analysis {
  return {
    inputType,
    normalized,
    network: "unknown",
    score: 0,
    privacyLabel: "Cannot analyze",
    entries: [],
    findings: [finding],
  };
}

export function analyzeAddress(address: string): Analysis {
  const normalized = address.trim();
  const classification = classifyAddress(normalized);
  const findings: Finding[] = [];

  if (!normalized) {
    return invalidAnalysis("address", normalized, {
      id: "missing-address",
      title: "Add a Zcash address",
      detail: "Paste a mainnet or testnet transparent, Sapling, or Unified Address to begin.",
      level: "critical",
    });
  }

  if (classification.classification === "transparent") {
    findings.push({ id: "transparent-address", title: "Transparent receiver", detail: "The address shape indicates that the receiver and transaction value can be publicly visible. Use a shielded-capable address when privacy is required.", level: "critical" });
  } else if (classification.classification === "unknown") {
    findings.push({ id: "unknown-address", title: "Address shape is not recognized", detail: "This string-only release does not recognize the prefix. It does not perform checksum validation or claim that the address is safe to use.", level: "critical" });
  } else {
    findings.push({ id: "shielded-capable", title: "Shielded-capable receiver", detail: "The prefix indicates a Sapling or Unified Address that can support a shielded payment path.", level: "good" });
  }

  const entry: PaymentEntry = { index: "", address: normalized, ...classification, amount: null, hasMemo: false, hasAssetRequest: false };
  const score = scoreAnalysis([entry], findings);
  return { inputType: "address", normalized, network: classification.network, score, privacyLabel: labelForScore(score), entries: [entry], findings };
}

export function analyzeUri(input: string): Analysis {
  const normalized = input.trim();
  if (!normalized.toLowerCase().startsWith("zcash:")) {
    return invalidAnalysis("uri", normalized, { id: "missing-scheme", title: "Not a ZIP-321 URI", detail: "A payment request must start with the zcash: scheme.", level: "critical" });
  }

  const withoutScheme = normalized.slice(6);
  const questionMark = withoutScheme.indexOf("?");
  const head = questionMark === -1 ? withoutScheme : withoutScheme.slice(0, questionMark);
  const query = questionMark === -1 ? "" : withoutScheme.slice(questionMark + 1);
  const params = new URLSearchParams(query);
  const payments = new Map<string, { address?: string; amount?: string; memo?: string; hasMemo: boolean; hasAssetRequest: boolean }>();
  const requiredUnknown: string[] = [];

  if (head) payments.set("", { address: head, hasMemo: false, hasAssetRequest: false });

  for (const [key, value] of params.entries()) {
    const match = /^(address|amount|memo|req-asset|label|message)(?:\.(\d+))?$/.exec(key);
    if (!match) {
      if (key.startsWith("req-")) requiredUnknown.push(key);
      continue;
    }
    const field = match[1];
    const index = match[2] ?? "";
    const current = payments.get(index) ?? { hasMemo: false, hasAssetRequest: false };
    if (field === "address") current.address = value;
    if (field === "amount") current.amount = value;
    if (field === "memo") { current.memo = value; current.hasMemo = true; }
    if (field === "req-asset") current.hasAssetRequest = true;
    payments.set(index, current);
  }

  const findings: Finding[] = [];
  if (requiredUnknown.length > 0) findings.push({ id: "unsupported-required", title: "Required parameter is not understood", detail: `${requiredUnknown.join(", ")} must be understood by a conformant wallet. This analyzer cannot safely interpret it.`, level: "critical" });

  const entries: PaymentEntry[] = [];
  for (const [index, payment] of [...payments.entries()].sort(([a], [b]) => (Number(a || 0) - Number(b || 0)))) {
    if (!payment.address) {
      findings.push({ id: "missing-index-address", title: `Payment ${index || "0"} has no address`, detail: "Every indexed amount, memo, or required parameter must have an address with the same index.", level: "critical" });
      continue;
    }
    const classified = classifyAddress(payment.address);
    entries.push({ index, address: payment.address, ...classified, amount: payment.amount ?? null, hasMemo: payment.hasMemo, hasAssetRequest: payment.hasAssetRequest });
    if (classified.classification === "transparent") findings.push({ id: `transparent-${index}`, title: `Payment ${index || "0"} is transparent`, detail: "This recipient does not preserve shielded receiver privacy. The payment path can expose public transaction details.", level: "critical" });
    if (classified.classification === "unknown") findings.push({ id: `unknown-${index}`, title: `Payment ${index || "0"} has an unknown address shape`, detail: "Do not treat an unrecognized address as shielded. Add an explicit parser for any new address type before shipping.", level: "critical" });
    if (!payment.amount) findings.push({ id: `amount-${index}`, title: `Payment ${index || "0"} has no amount`, detail: "The wallet will need the payer to enter the amount manually, which creates avoidable checkout friction and error risk.", level: "warning" });
    if (payment.amount && (!/^\d+(\.\d{1,8})?$/.test(payment.amount) || Number(payment.amount) <= 0)) findings.push({ id: "invalid-amount", title: `Payment ${index || "0"} has an invalid amount`, detail: "Use a positive decimal with no more than eight fractional digits.", level: "critical" });
    if (payment.hasMemo) {
      const memoIsEncoded = base64UrlMemo(payment.memo ?? "");
      findings.push({ id: `memo-${index}`, title: `Payment ${index || "0"} includes a memo`, detail: memoIsEncoded ? "The memo is encoded for the URI. It remains visible to the recipient, so avoid putting secrets or unnecessary personal data in it." : "Review the memo encoding before shipping. Memo contents should be intentional and recipient-visible.", level: "info" });
    }
    if (payment.hasAssetRequest && classified.classification !== "unified") findings.push({ id: "asset-on-non-unified", title: `Payment ${index || "0"} requests an asset on a non-Unified address`, detail: "Custom asset requests require a compatible Unified Address receiver. Reject this request until the receiver is checked.", level: "critical" });
  }

  if (entries.length === 0) findings.unshift({ id: "missing-address", title: "No payment address found", detail: "Add an address in the URI or use the Address tab for a direct address check.", level: "critical" });
  const networks = new Set(entries.map((entry) => entry.network).filter((network) => network !== "unknown"));
  const network: Analysis["network"] = networks.size > 1 ? "mixed" : networks.values().next().value ?? "unknown";
  if (network === "mixed") findings.push({ id: "mixed-network", title: "Mainnet and testnet addresses are mixed", detail: "Do not let a payment request cross networks. Generate a request for one network only.", level: "critical" });
  if (entries.length > 1 && entries.some((entry) => entry.classification === "transparent")) findings.push({ id: "mixed-privacy", title: "The request mixes privacy levels", detail: "A multi-payment request is only as private as its most revealing output. Review every recipient before presenting the QR code.", level: "warning" });
  if (entries.length > 0 && findings.every((finding) => finding.level === "good" || finding.level === "info")) findings.unshift({ id: "review-passed", title: "No obvious privacy mismatch found", detail: "The request is shielded-capable by address shape. A real wallet should still perform full address and transaction validation before sending.", level: "good" });

  const score = scoreAnalysis(entries, findings);
  return { inputType: "uri", normalized, network, score, privacyLabel: labelForScore(score), entries, findings };
}
