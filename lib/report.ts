import { Analysis, Finding, PaymentEntry, RULES } from "./analyzer";

export const TOOL_VERSION = "0.1.0";
export const REPORT_VERSION = 1;

export interface ReportArtifact {
  schema: "shadecheck.report";
  reportVersion: number;
  toolVersion: string;
  ruleVersions: Record<string, number>;
  inputSha256: string;
  analysis: Analysis;
}

type RedactedEntry = Omit<PaymentEntry, "address" | "amount"> & {
  address: "[redacted]";
  amount: null | "[redacted]";
};

type RedactedFinding = Omit<Finding, "detail"> & {
  detail: string;
};

export interface RedactedFixture {
  schema: "shadecheck.fixture";
  fixtureVersion: number;
  toolVersion: string;
  ruleVersions: Record<string, number>;
  analysis: Omit<Analysis, "normalized" | "entries" | "findings" | "ignoredParameters"> & {
    normalized: "[redacted]";
    entries: RedactedEntry[];
    findings: RedactedFinding[];
    ignoredParameters: [];
  };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToText(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function sha256(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is unavailable in this browser.");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function ruleVersions(): Record<string, number> {
  return Object.fromEntries(Object.keys(RULES).sort().map((ruleId) => [ruleId, 1]));
}

export async function buildReport(analysis: Analysis): Promise<ReportArtifact> {
  return {
    schema: "shadecheck.report",
    reportVersion: REPORT_VERSION,
    toolVersion: TOOL_VERSION,
    ruleVersions: ruleVersions(),
    inputSha256: await sha256(analysis.normalized),
    analysis,
  };
}

export function buildRedactedFixture(analysis: Analysis): RedactedFixture {
  return {
    schema: "shadecheck.fixture",
    fixtureVersion: REPORT_VERSION,
    toolVersion: TOOL_VERSION,
    ruleVersions: ruleVersions(),
    analysis: {
      inputType: analysis.inputType,
      normalized: "[redacted]",
      network: analysis.network,
      score: analysis.score,
      gate: analysis.gate,
      privacyLabel: analysis.privacyLabel,
      confidence: analysis.confidence,
      entries: analysis.entries.map((entry) => ({
        index: entry.index,
        address: "[redacted]",
        classification: entry.classification,
        network: entry.network,
        validation: entry.validation,
        amount: entry.amount ? "[redacted]" : null,
        hasMemo: entry.hasMemo,
        hasAssetRequest: entry.hasAssetRequest,
      })),
      findings: analysis.findings.map((item) => ({
        id: item.id,
        title: item.title,
        detail: `Redacted ${item.level} finding${item.scope ? ` for payment ${item.scope}` : " for this request"}.`,
        level: item.level,
        source: item.source,
        fix: item.fix,
        scope: item.scope,
      })),
      ignoredParameters: [],
    },
  };
}

export function encodeFixture(fixture: RedactedFixture): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(fixture)));
}

export function decodeFixture(value: string): Analysis | null {
  if (!value || value.length > 12000) return null;
  try {
    const fixture = JSON.parse(base64UrlToText(value)) as RedactedFixture;
    if (fixture.schema !== "shadecheck.fixture" || fixture.fixtureVersion !== REPORT_VERSION || fixture.analysis?.normalized !== "[redacted]") return null;
    if (!Array.isArray(fixture.analysis.entries) || !Array.isArray(fixture.analysis.findings)) return null;
    return fixture.analysis as Analysis;
  } catch {
    return null;
  }
}

export function fixtureUrl(fixture: RedactedFixture): string {
  return `${window.location.origin}${window.location.pathname}#fixture=${encodeFixture(fixture)}`;
}
