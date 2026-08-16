"use client";

import { ChangeEvent, FormEvent, useEffect, useRef, useState } from "react";
import { AlertTriangle, ArrowUpRight, CheckCircle2, ClipboardList, Copy, Download, FileCheck2, Info, Link2, LockKeyhole, ScanLine, ShieldCheck, TerminalSquare, Upload } from "lucide-react";
import { Analysis, Finding, analyzeAddress, analyzeUri } from "@/lib/analyzer";
import { buildRedactedFixture, buildReport, decodeFixture, encodeFixture, fixtureUrl, parseFixtureJson } from "@/lib/report";

type Mode = "uri" | "address";
type FindingFilter = "all" | "block" | "review" | "informational";
type InputExample = { label: string; value: string };
type CheckoutScenario = InputExample & { eyebrow: string; description: string; expected: string };

const shieldedTestnet = "ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
const transparentTestnet = "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
const unifiedMainnet = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

const examplesByMode: Record<Mode, InputExample[]> = {
  uri: [
    { label: "Shielded request", value: `zcash:${shieldedTestnet}?amount=1` },
    { label: "Transparent request", value: `zcash:${transparentTestnet}?amount=1` },
    { label: "Missing amount", value: `zcash:${shieldedTestnet}` },
  ],
  address: [
    { label: "Shielded address", value: shieldedTestnet },
    { label: "Transparent address", value: transparentTestnet },
    { label: "Unified address", value: unifiedMainnet },
  ],
};

const checkoutScenarios: CheckoutScenario[] = [
  {
    label: "Transparent fallback",
    eyebrow: "Common integration mistake",
    description: "A checkout promises privacy but falls back to a transparent receiver.",
    expected: "Should block",
    value: `zcash:${transparentTestnet}?amount=0.25`,
  },
  {
    label: "Shielded checkout",
    eyebrow: "Safer starting point",
    description: "A payment request uses a shielded-capable receiver and includes the amount.",
    expected: "Should pass",
    value: `zcash:${shieldedTestnet}?amount=0.25`,
  },
];

const publicFixtures: Array<{ label: string; description: string; analysis: Analysis }> = [
  {
    label: "Transparent output",
    description: "A payment request routes value to a transparent receiver.",
    analysis: {
      inputType: "uri",
      normalized: "[redacted]",
      network: "testnet",
      score: 78,
      gate: "block",
      privacyLabel: "Blocked",
      confidence: "shape-only",
      entries: [{ index: "", address: "[redacted]", classification: "transparent", network: "testnet", validation: "shape-only", amount: "[redacted]", hasMemo: false, hasAssetRequest: false }],
      findings: [{ id: "zip321.transparent", title: "Transparent payment path", detail: "Redacted block finding for this request.", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use a shielded-capable receiver when this payment claims privacy." }],
      ignoredParameters: [],
    },
  },
  {
    label: "Amount missing",
    description: "A shielded-capable request leaves the wallet to ask for the amount.",
    analysis: {
      inputType: "uri",
      normalized: "[redacted]",
      network: "testnet",
      score: 92,
      gate: "review",
      privacyLabel: "Review required",
      confidence: "shape-only",
      entries: [{ index: "", address: "[redacted]", classification: "shielded", network: "testnet", validation: "shape-only", amount: null, hasMemo: false, hasAssetRequest: false }],
      findings: [{ id: "zip321.amount-missing", title: "Payment amount is missing", detail: "Redacted review finding for this request.", level: "review", source: "https://zips.z.cash/zip-0321#query-keys", fix: "Include an amount so the wallet does not require manual re-entry." }],
      ignoredParameters: [],
    },
  },
  {
    label: "Mixed network",
    description: "One request contains payment targets from different Zcash networks.",
    analysis: {
      inputType: "uri",
      normalized: "[redacted]",
      network: "mixed",
      score: 56,
      gate: "block",
      privacyLabel: "Blocked",
      confidence: "shape-only",
      entries: [
        { index: "", address: "[redacted]", classification: "transparent", network: "testnet", validation: "shape-only", amount: "[redacted]", hasMemo: false, hasAssetRequest: false },
        { index: "1", address: "[redacted]", classification: "shielded", network: "mainnet", validation: "shape-only", amount: "[redacted]", hasMemo: false, hasAssetRequest: false },
      ],
      findings: [{ id: "zip321.network", title: "Network mismatch", detail: "Redacted block finding for this request.", level: "block", source: "https://zips.z.cash/zip-0321#uri-semantics", fix: "Use only mainnet addresses or only testnet addresses in one request." }],
      ignoredParameters: [],
    },
  },
];

function FindingIcon({ level }: { level: Finding["level"] }) {
  if (level === "block" || level === "review") return <AlertTriangle size={16} aria-hidden="true" />;
  if (level === "pass") return <CheckCircle2 size={16} aria-hidden="true" />;
  return <Info size={16} aria-hidden="true" />;
}

function buildPrivacyImpact(analysis: Analysis) {
  const hasTransparent = analysis.entries.some((entry) => entry.classification === "transparent");
  const hasInvalid = analysis.entries.some((entry) => entry.validation === "invalid");
  const hasMixedNetwork = analysis.network === "mixed";

  if (hasInvalid) {
    return {
      title: "Correct the request before reviewing privacy.",
      description: "At least one address or payment field failed local format validation, so the privacy result is not reliable yet.",
      publicView: "Not assessed",
      action: "Fix the format finding first, then run the review again.",
    };
  }

  if (hasMixedNetwork) {
    return {
      title: "Do not ship this checkout yet.",
      description: "This request combines networks. A wallet or product flow could interpret the payment differently than intended.",
      publicView: "Network path is ambiguous",
      action: "Use one network consistently across every payment target.",
    };
  }

  if (hasTransparent) {
    return {
      title: "Do not ship this checkout yet.",
      description: "A transparent receiver is part of this request. The public transaction path can expose the receiver and value; linkability depends on the full transaction.",
      publicView: "Receiver and value may be public",
      action: "Replace the transparent path with a shielded-capable receiver, then review again.",
    };
  }

  if (analysis.gate === "block") {
    return {
      title: "Do not ship this checkout yet.",
      description: "A local policy rule blocked this request before it can be treated as a privacy-safe checkout.",
      publicView: "Privacy result is blocked",
      action: analysis.findings.find((item) => item.level === "block")?.fix ?? "Resolve the blocking finding and run the review again.",
    };
  }

  if (analysis.gate === "review") {
    return {
      title: "Review this checkout before release.",
      description: "The request is not blocked by the local policy, but it still needs a product decision before it can claim a complete privacy-preserving flow.",
      publicView: "No transparent path detected",
      action: analysis.findings.find((item) => item.level === "review")?.fix ?? "Resolve the review finding before release.",
    };
  }

  return {
    title: "This checkout passes the local privacy gate.",
    description: "No transparent payment path was detected and the request includes the fields required for this local policy check.",
    publicView: "No transparent path detected",
    action: "Keep this rule check in CI and let the wallet perform complete validation before sending.",
  };
}

function downloadJson(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function HomePage() {
  const [mode, setMode] = useState<Mode>("uri");
  const [value, setValue] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copyState, setCopyState] = useState("Copy request");
  const [checklistState, setChecklistState] = useState("Copy fixes");
  const [reportState, setReportState] = useState("Download report");
  const [shareState, setShareState] = useState("Share redacted fixture");
  const [findingFilter, setFindingFilter] = useState<FindingFilter>("all");
  const [isFixture, setIsFixture] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const fixtureInputRef = useRef<HTMLInputElement>(null);
  const analysisPanelRef = useRef<HTMLDivElement>(null);

  function scrollToReview() {
    const behavior: ScrollBehavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
    window.requestAnimationFrame(() => analysisPanelRef.current?.scrollIntoView({ behavior, block: "start" }));
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const encodedFixture = window.location.hash.startsWith("#fixture=") ? window.location.hash.slice("#fixture=".length) : "";
      if (!encodedFixture) return;
      const fixture = decodeFixture(encodedFixture);
      if (!fixture) {
        setError("This fixture link is invalid or incomplete. Paste the original request to run a fresh review.");
        return;
      }
      setMode(fixture.inputType);
      setAnalysis(fixture);
      setIsFixture(true);
      setFindingFilter("all");
      scrollToReview();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  function runAnalysis(nextValue = value, nextMode = mode, shouldScroll = false) {
    setError("");
    if (!nextValue.trim()) {
      setAnalysis(null);
      setError("Paste a ZIP-321 request or a Zcash address before analyzing.");
      return;
    }
    setIsFixture(false);
    setFindingFilter("all");
    setReportState("Download report");
    setShareState("Share redacted fixture");
    setIsAnalyzing(true);
    window.setTimeout(() => {
      setAnalysis(nextMode === "uri" ? analyzeUri(nextValue) : analyzeAddress(nextValue));
      setIsAnalyzing(false);
      if (shouldScroll) scrollToReview();
    }, 160);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    runAnalysis();
  }

  function runExample(example: InputExample, exampleMode: Mode) {
    setMode(exampleMode);
    setValue(example.value);
    runAnalysis(example.value, exampleMode, true);
  }

  function runScenario(scenario: CheckoutScenario) {
    runExample(scenario, "uri");
  }

  function chooseMode(nextMode: Mode) {
    setMode(nextMode);
    setAnalysis(null);
    setError("");
    setCopyState("Copy request");
    setChecklistState("Copy fixes");
    setReportState("Download report");
    setShareState("Share redacted fixture");
    setFindingFilter("all");
    setIsFixture(false);
  }

  function loadFixture(fixture: Analysis) {
    window.history.replaceState(null, "", `#fixture=${encodeFixture(buildRedactedFixture(fixture))}`);
    setMode(fixture.inputType);
    setValue("");
    setAnalysis(fixture);
    setError("");
    setIsFixture(true);
    setFindingFilter("all");
    setCopyState("Copy request");
    setChecklistState("Copy fixes");
    setReportState("Download fixture");
    setShareState("Share redacted fixture");
    scrollToReview();
  }

  function importFixture(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setIsImporting(true);
    file.text().then((text) => {
      const fixture = parseFixtureJson(JSON.parse(text));
      if (!fixture) throw new Error("invalid fixture");
      loadFixture(fixture);
      setError("");
    }).catch(() => {
      setError("That file is not a valid ShadeCheck redacted fixture. Download a fixture from ShadeCheck and try again.");
    }).finally(() => setIsImporting(false));
  }

  async function copyRequest() {
    if (!analysis?.normalized || isFixture) return;
    try {
      await navigator.clipboard.writeText(analysis.normalized);
      setCopyState("Copied");
      window.setTimeout(() => setCopyState("Copy request"), 1800);
    } catch {
      setError("Clipboard access is unavailable. Select the request manually to copy it.");
    }
  }

  async function copyFixChecklist() {
    if (!analysis) return;
    const fixes = analysis.findings.filter((item) => item.level !== "pass").map((item) => `- ${item.title}: ${item.fix}`);
    const checklist = fixes.length > 0 ? `ShadeCheck fix checklist\n\n${fixes.join("\n")}` : "ShadeCheck fix checklist\n\nNo blocking or review-level fixes.";
    try {
      await navigator.clipboard.writeText(checklist);
      setChecklistState("Fixes copied");
      window.setTimeout(() => setChecklistState("Copy fixes"), 1800);
    } catch {
      setError("Clipboard access is unavailable. Open the downloaded report to copy the fixes manually.");
    }
  }

  async function downloadReportArtifact() {
    if (!analysis) return;
    setReportState("Preparing…");
    try {
      if (isFixture) {
        downloadJson("shadecheck-fixture.json", buildRedactedFixture(analysis));
      } else {
        downloadJson("shadecheck-report.json", await buildReport(analysis));
      }
      setReportState(isFixture ? "Fixture downloaded" : "Report downloaded");
      window.setTimeout(() => setReportState(isFixture ? "Download fixture" : "Download report"), 2200);
    } catch {
      setError("The report could not be prepared in this browser. Try the review again or use the fix checklist.");
      setReportState(isFixture ? "Download fixture" : "Download report");
    }
  }

  async function shareRedactedFixture() {
    if (!analysis) return;
    setShareState("Preparing…");
    try {
      const link = fixtureUrl(buildRedactedFixture(analysis));
      await navigator.clipboard.writeText(link);
      setShareState("Link copied");
      window.setTimeout(() => setShareState("Share redacted fixture"), 2200);
    } catch {
      setError("The redacted link could not be copied. Download the fixture instead and share that file.");
      setShareState("Share redacted fixture");
    }
  }

  const visibleFindings = analysis?.findings.filter((item) => {
    if (findingFilter === "all") return true;
    if (findingFilter === "informational") return item.level === "pass" || item.level === "note";
    return item.level === findingFilter;
  }) ?? [];
  const privacyImpact = analysis ? buildPrivacyImpact(analysis) : null;

  const findingFilters: Array<{ value: FindingFilter; label: string }> = [
    { value: "all", label: "All" },
    { value: "block", label: "Block" },
    { value: "review", label: "Review" },
    { value: "informational", label: "Pass / note" },
  ];
  const findingCounts: Record<FindingFilter, number> = {
    all: analysis?.findings.length ?? 0,
    block: analysis?.findings.filter((item) => item.level === "block").length ?? 0,
    review: analysis?.findings.filter((item) => item.level === "review").length ?? 0,
    informational: analysis?.findings.filter((item) => item.level === "pass" || item.level === "note").length ?? 0,
  };

  return (
    <div className="app-shell">
      <header className="container topbar">
        <a className="brand" href="#top" aria-label="ShadeCheck home"><span className="brand-mark"><ShieldCheck size={17} aria-hidden="true" /></span><span>SHADECHECK</span></a>
        <div className="topbar-meta"><span className="status-dot" aria-hidden="true" />Client-only analysis</div>
      </header>

      <main id="top" className="container">
        <section className="hero">
          <div className="eyebrow">Zcash privacy tooling</div>
          <h1>Catch privacy leaks before they ship.</h1>
          <p className="hero-copy">Inspect a Zcash payment request or address and get a plain-language policy review. ShadeCheck runs in your browser and never asks for keys or funds.</p>
          <div className="hero-note"><LockKeyhole size={15} aria-hidden="true" />Nothing is uploaded or stored.</div>
        </section>

        <section className="lab-section" aria-labelledby="lab-heading">
          <div className="lab-heading">
            <div>
              <div className="eyebrow">Guided demo</div>
              <h2 id="lab-heading">See a privacy leak before it ships.</h2>
              <p className="lab-copy">Choose a realistic checkout path. ShadeCheck turns the request into a policy gate, an exposure explanation, and a fix you can act on.</p>
            </div>
            <div className="lab-steps" aria-label="Privacy Checkout Lab steps">
              <span><b>1</b> Choose</span>
              <span><b>2</b> Review</span>
              <span><b>3</b> Fix</span>
            </div>
          </div>
          <div className="lab-grid">
            {checkoutScenarios.map((scenario) => <article className="panel lab-card" key={scenario.label}>
              <div className="lab-card-kicker">{scenario.eyebrow}</div>
              <div className="lab-card-topline"><h3>{scenario.label}</h3><span>{scenario.expected}</span></div>
              <p>{scenario.description}</p>
              <button type="button" className="secondary-button" onClick={() => runScenario(scenario)}>Run scenario <ArrowUpRight size={15} aria-hidden="true" /></button>
            </article>)}
          </div>
        </section>

        <section className="workspace" aria-label="ShadeCheck analyzer">
          <div className="panel">
            <div className="panel-header">
              <div><h2 className="panel-title">Analyze an input</h2><p className="panel-subtitle">Start with a ZIP-321 payment request or a single address.</p></div>
              <div className="mode-switch" aria-label="Input type">
                <button type="button" className="mode-button" aria-pressed={mode === "uri"} onClick={() => chooseMode("uri")}>ZIP-321 URI</button>
                <button type="button" className="mode-button" aria-pressed={mode === "address"} onClick={() => chooseMode("address")}>Address</button>
              </div>
            </div>
            <form className="input-area" onSubmit={submit}>
              <label className="field-label" htmlFor="analysis-input">{mode === "uri" ? "Payment request" : "Zcash address"}</label>
              <div className="input-wrap">
              <textarea id="analysis-input" value={value} onChange={(event) => { setValue(event.target.value); setError(""); setIsFixture(false); }} placeholder={mode === "uri" ? "zcash:<address>?amount=1" : "u1... / zs1... / t1..."} aria-describedby="analysis-help analysis-format" spellCheck={false} autoCapitalize="none" />
              </div>
              <p id="analysis-help" className="input-help">{mode === "uri" ? "Paste a complete ZIP-321 payment request, including the zcash: prefix, address, and amount. Use the examples below if you are unsure what belongs here." : "Paste one Zcash address, such as a shielded, transparent, or Unified address. Use the examples below to compare the supported formats."}</p>
              <div id="analysis-format" className="input-format"><span>Expected format</span><code>{mode === "uri" ? "zcash:<address>?amount=1" : "u1... / zs1... / ztestsapling... / t1... / tm..."}</code></div>
              <div className="form-actions">
                <div className="sample-group">
                  <span className="sample-label">Use a starting example</span>
                  <div className="sample-row" aria-label={`${mode === "uri" ? "Payment request" : "Address"} examples`}>
                    {examplesByMode[mode].map((example) => <button type="button" key={example.label} className="sample-button" onClick={() => runExample(example, mode)}>{example.label}</button>)}
                  </div>
                </div>
                <button type="submit" className="primary-button" disabled={isAnalyzing} aria-busy={isAnalyzing}>{isAnalyzing ? "Analyzing" : "Run review"}<ArrowUpRight size={16} aria-hidden="true" /></button>
              </div>
              {error ? <div className="error-state" role="alert"><AlertTriangle size={17} aria-hidden="true" /><div><div className="error-title">Review needs attention</div><div className="error-copy">{error}</div></div></div> : null}
            </form>
          </div>

          <div ref={analysisPanelRef} className="panel analysis-panel">
            <div className="panel-header"><div><h2 className="panel-title">Privacy review</h2><p className="panel-subtitle">Every finding includes a source and an action.</p></div><ScanLine size={20} color="var(--accent)" aria-hidden="true" /></div>
            {!analysis ? <div className="idle-state"><div><div className="idle-icon"><FileCheck2 size={22} aria-hidden="true" /></div><div className="idle-title">Nothing reviewed yet</div><p className="idle-copy">Paste an input or use a sample to see the policy gate, request anatomy, and next actions.</p></div></div> :
              <div className="analysis-body">
                <div className="analysis-summary"><div className="gate-block"><div className="gate-label">Policy gate</div><div className={`summary-tag ${analysis.gate}`} aria-label={`Policy gate: ${analysis.privacyLabel}`}>{analysis.privacyLabel}</div></div><div className="score-summary"><div className="score-block"><span className="score-number">{analysis.score}</span><span className="score-denominator">/ 100</span></div><div className="score-label">Secondary signal score</div></div></div>
                <div className="confidence-note"><Info size={15} aria-hidden="true" /><span>{analysis.confidence === "shape-only" ? "Confidence: shape-only. Supported outer checksums are checked; full receiver composition and wallet-level context are not verified here." : "Confidence: format error. At least one address failed the local encoding or checksum check."}</span></div>
                {privacyImpact ? <div className={`impact-card ${analysis.gate}`} aria-live="polite"><div className="impact-kicker">Privacy impact</div><h3>{privacyImpact.title}</h3><p>{privacyImpact.description}</p><div className="impact-grid"><div><span>Public transaction view</span><strong>{privacyImpact.publicView}</strong></div><div><span>Next action</span><strong>{privacyImpact.action}</strong></div></div></div> : null}
                <div className="section-label">Request anatomy</div>
                <div className="anatomy-grid">
                  <div><span>Network</span><strong>{analysis.network}</strong></div>
                  <div><span>Payments</span><strong>{analysis.entries.length}</strong></div>
                  <div><span>Input</span><strong>{analysis.inputType === "uri" ? "ZIP-321" : "Address"}</strong></div>
                </div>
                <div className="entry-list">{analysis.entries.map((entry) => <div className="entry-row" key={`${entry.index}-${entry.address}`}><div><span className="entry-index">Payment {entry.index || "0"}</span><strong>{entry.classification}</strong><small>{entry.network} · {entry.validation}</small></div><div className="entry-flags"><span>{entry.amount === "[redacted]" ? "amount redacted" : entry.amount ? `${entry.amount} ZEC` : entry.hasAssetRequest ? "custom asset" : "amount missing"}</span>{entry.hasMemo ? <span>memo</span> : null}</div></div>)}</div>
                <div className="section-label">Findings</div>
                <div className="finding-toolbar" aria-label="Finding filters">
                  <div className="filter-list">
                    {findingFilters.map((filter) => <button type="button" key={filter.value} className="filter-button" aria-pressed={findingFilter === filter.value} disabled={filter.value !== "all" && findingCounts[filter.value] === 0} onClick={() => setFindingFilter(filter.value)}>{filter.label}<span className="filter-count">{findingCounts[filter.value]}</span></button>)}
                  </div>
                  <span className="finding-count" aria-live="polite">{visibleFindings.length} {visibleFindings.length === 1 ? "finding" : "findings"}</span>
                </div>
                {visibleFindings.length > 0 ? <div className="finding-list">{visibleFindings.map((item) => <div className={`finding ${item.level}`} key={`${item.id}-${item.scope ?? "global"}`}><FindingIcon level={item.level} /><div><div className="finding-title">{item.title}</div><div className="finding-detail">{item.detail}</div><div className="finding-fix"><strong>Next:</strong> {item.fix}</div><a className="finding-source" href={item.source} target="_blank" rel="noreferrer">Source <ArrowUpRight size={12} aria-hidden="true" /></a></div></div>)}</div> : findingFilter === "all" ? <div className="empty-findings"><CheckCircle2 size={16} aria-hidden="true" /><div><div className="empty-title">Review complete</div><p>No policy findings were generated for this input.</p></div></div> : <div className="filter-empty"><CheckCircle2 size={16} aria-hidden="true" /><span>This view is clear. <button type="button" className="filter-reset" onClick={() => setFindingFilter("all")}>View all results</button></span></div>}
                {analysis.ignoredParameters.length > 0 ? <div className="ignored-note"><Info size={15} aria-hidden="true" /><span>Ignored optional parameters: {analysis.ignoredParameters.join(", ")}</span></div> : null}
                <div className="report-actions">{!isFixture ? <button type="button" className="secondary-button" onClick={copyRequest}><Copy size={15} aria-hidden="true" />{copyState}</button> : <span className="redacted-badge"><LockKeyhole size={14} aria-hidden="true" />Raw input redacted</span>}<button type="button" className="secondary-button" onClick={copyFixChecklist}><ClipboardList size={15} aria-hidden="true" />{checklistState}</button><button type="button" className="secondary-button" onClick={downloadReportArtifact}><Download size={15} aria-hidden="true" />{isFixture ? reportState.replace("report", "fixture") : reportState}</button><button type="button" className="secondary-button" onClick={shareRedactedFixture}><Link2 size={15} aria-hidden="true" />{shareState}</button></div>
                <div className="report-note"><LockKeyhole size={15} aria-hidden="true" /><span>{isFixture ? "This is a redacted fixture. Addresses, amounts, and raw request text are not included." : "The report is generated locally. Downloaded reports include a SHA-256 input hash; ShadeCheck does not query the chain, sign a transaction, or broadcast funds."}</span></div>
              </div>}
          </div>
        </section>

        <section className="below-grid" aria-label="How ShadeCheck works">
          <article className="panel info-card"><h2><ScanLine size={17} aria-hidden="true" />Parse the request</h2><p>Read ZIP-321 addresses, amounts, memos, assets, and indexed payments without sending input to a server.</p></article>
          <article className="panel info-card"><h2><ShieldCheck size={17} aria-hidden="true" />Explain exposure</h2><p>Separate transparent, shielded-capable, mixed, unknown, and cross-network paths in language a product team can use.</p></article>
          <article className="panel info-card"><h2><TerminalSquare size={17} aria-hidden="true" />Ship with confidence</h2><p>The next phase keeps any chain-aware adapters opt-in and separate from local policy rules.</p></article>
        </section>

        <section className="fixture-section" aria-labelledby="fixture-heading">
          <div className="fixture-heading"><div><div className="eyebrow">Public fixtures</div><h2 id="fixture-heading">Review common integration mistakes.</h2></div><div className="fixture-heading-actions"><p>These examples contain no wallet data. Open one to see the same rules, sources, and redacted sharing path.</p><button type="button" className="secondary-button" onClick={() => fixtureInputRef.current?.click()} disabled={isImporting} aria-busy={isImporting}><Upload size={15} aria-hidden="true" />{isImporting ? "Importing…" : "Import fixture"}</button><input ref={fixtureInputRef} className="visually-hidden" type="file" accept="application/json,.json" onChange={importFixture} /></div></div>
          <div className="fixture-grid">{publicFixtures.map((fixture) => <article className="panel fixture-card" key={fixture.label}><div className="fixture-card-header"><span className={`fixture-gate ${fixture.analysis.gate}`}>{fixture.analysis.privacyLabel}</span><span>{fixture.analysis.entries.length} payment{fixture.analysis.entries.length === 1 ? "" : "s"}</span></div><h3>{fixture.label}</h3><p>{fixture.description}</p><button type="button" className="secondary-button" onClick={() => loadFixture(fixture.analysis)}>Open fixture <ArrowUpRight size={15} aria-hidden="true" /></button></article>)}</div>
        </section>

        <footer className="footer"><span>ShadeCheck is an early privacy linting prototype.</span><a href="https://zips.z.cash/zip-0321" target="_blank" rel="noreferrer">Read ZIP-321 <ArrowUpRight size={12} aria-hidden="true" /></a></footer>
      </main>
    </div>
  );
}
