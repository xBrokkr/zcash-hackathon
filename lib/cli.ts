import { Analysis, FindingLevel } from "./analyzer";

export const CLI_TOOL_VERSION = "0.1.0";

export function exitCodeForGate(gate: Analysis["gate"]): 0 | 1 | 2 {
  if (gate === "pass") return 0;
  if (gate === "block") return 1;
  return 2;
}

function levelLabel(level: FindingLevel): string {
  return level.toUpperCase().padEnd(6, " ");
}

export function renderText(analysis: Analysis): string {
  const lines = [
    `ShadeCheck ${analysis.privacyLabel} · ${analysis.gate}`,
    `Input: ${analysis.inputType === "uri" ? "ZIP-321" : "Address"} · Network: ${analysis.network} · Payments: ${analysis.entries.length}`,
    `Confidence: ${analysis.confidence} · Local signal score: ${analysis.score}/100`,
    "",
  ];

  for (const item of analysis.findings) {
    lines.push(`[${levelLabel(item.level)}] ${item.title}`);
    lines.push(`  ${item.detail}`);
    lines.push(`  Next: ${item.fix}`);
  }

  return lines.join("\n");
}

export function renderJson(analysis: Analysis): string {
  return JSON.stringify({
    schema: "shadecheck.cli-result",
    toolVersion: CLI_TOOL_VERSION,
    exitCode: exitCodeForGate(analysis.gate),
    analysis,
  }, null, 2);
}
