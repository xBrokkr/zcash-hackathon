"use client";

import { FormEvent, useState } from "react";
import { AlertTriangle, ArrowUpRight, CheckCircle2, Copy, Download, FileCheck2, Info, LockKeyhole, ScanLine, ShieldCheck, TerminalSquare } from "lucide-react";
import { Analysis, Finding, analyzeAddress, analyzeUri } from "@/lib/analyzer";

type Mode = "uri" | "address";

const samples = [
  { label: "Shielded testnet", value: "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=1" },
  { label: "Transparent testnet", value: "zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1" },
];

function FindingIcon({ level }: { level: Finding["level"] }) {
  if (level === "block" || level === "review") return <AlertTriangle size={16} aria-hidden="true" />;
  if (level === "pass") return <CheckCircle2 size={16} aria-hidden="true" />;
  return <Info size={16} aria-hidden="true" />;
}

function downloadReport(analysis: Analysis) {
  const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "shadecheck-report.json";
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

  function runAnalysis(nextValue = value, nextMode = mode) {
    setError("");
    if (!nextValue.trim()) {
      setAnalysis(null);
      setError("Paste a ZIP-321 request or a Zcash address before analyzing.");
      return;
    }
    setIsAnalyzing(true);
    window.setTimeout(() => {
      setAnalysis(nextMode === "uri" ? analyzeUri(nextValue) : analyzeAddress(nextValue));
      setIsAnalyzing(false);
    }, 160);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    runAnalysis();
  }

  function chooseMode(nextMode: Mode) {
    setMode(nextMode);
    setAnalysis(null);
    setError("");
    setCopyState("Copy request");
  }

  async function copyRequest() {
    if (!analysis?.normalized) return;
    try {
      await navigator.clipboard.writeText(analysis.normalized);
      setCopyState("Copied");
      window.setTimeout(() => setCopyState("Copy request"), 1800);
    } catch {
      setError("Clipboard access is unavailable. Select the request manually to copy it.");
    }
  }

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
                <textarea id="analysis-input" value={value} onChange={(event) => { setValue(event.target.value); setError(""); }} placeholder={mode === "uri" ? "zcash:ztestsapling1...?amount=1" : "u1... or zs1..."} aria-describedby="analysis-help" spellCheck={false} autoCapitalize="none" />
              </div>
              <p id="analysis-help" className="input-help">Local policy and encoding-shape analysis only. Full checksum, receiver composition, and transaction verification stay in the wallet.</p>
              <div className="form-actions">
                <div className="sample-row" aria-label="Sample inputs">
                  {samples.map((sample) => <button type="button" key={sample.label} className="sample-button" onClick={() => { setMode("uri"); setValue(sample.value); runAnalysis(sample.value, "uri"); }}>{sample.label}</button>)}
                </div>
                <button type="submit" className="primary-button" disabled={isAnalyzing} aria-busy={isAnalyzing}>{isAnalyzing ? "Analyzing" : "Run review"}<ArrowUpRight size={16} aria-hidden="true" /></button>
              </div>
              {error ? <div className="error-state" role="alert"><AlertTriangle size={17} aria-hidden="true" /><div><div className="error-title">Review needs attention</div><div className="error-copy">{error}</div></div></div> : null}
            </form>
          </div>

          <div className="panel analysis-panel">
            <div className="panel-header"><div><h2 className="panel-title">Privacy review</h2><p className="panel-subtitle">Every finding includes a source and an action.</p></div><ScanLine size={20} color="var(--accent)" aria-hidden="true" /></div>
            {!analysis ? <div className="idle-state"><div><div className="idle-icon"><FileCheck2 size={22} aria-hidden="true" /></div><div className="idle-title">Nothing reviewed yet</div><p className="idle-copy">Paste an input or use a sample to see the policy gate, request anatomy, and next actions.</p></div></div> :
              <div className="analysis-body">
                <div className="analysis-summary"><div><div className="score-block"><span className="score-number">{analysis.score}</span><span className="score-denominator">/ 100</span></div><div className="score-label">Local signal score</div></div><div className={`summary-tag ${analysis.gate}`}>{analysis.privacyLabel}</div></div>
                <div className="confidence-note"><Info size={15} aria-hidden="true" /><span>{analysis.confidence === "shape-only" ? "Confidence: shape-only. Address checksum and full receiver composition are not verified here." : "Confidence: format error. At least one address failed the local encoding-shape check."}</span></div>
                <div className="section-label">Request anatomy</div>
                <div className="anatomy-grid">
                  <div><span>Network</span><strong>{analysis.network}</strong></div>
                  <div><span>Payments</span><strong>{analysis.entries.length}</strong></div>
                  <div><span>Input</span><strong>{analysis.inputType === "uri" ? "ZIP-321" : "Address"}</strong></div>
                </div>
                <div className="entry-list">{analysis.entries.map((entry) => <div className="entry-row" key={`${entry.index}-${entry.address}`}><div><span className="entry-index">Payment {entry.index || "0"}</span><strong>{entry.classification}</strong><small>{entry.network} · {entry.validation}</small></div><div className="entry-flags"><span>{entry.amount ? `${entry.amount} ZEC` : entry.hasAssetRequest ? "custom asset" : "amount missing"}</span>{entry.hasMemo ? <span>memo</span> : null}</div></div>)}</div>
                <div className="section-label">Findings</div>
                <div className="finding-list">{analysis.findings.map((item) => <div className={`finding ${item.level}`} key={`${item.id}-${item.scope ?? "global"}`}><FindingIcon level={item.level} /><div><div className="finding-title">{item.title}</div><div className="finding-detail">{item.detail}</div><div className="finding-fix"><strong>Next:</strong> {item.fix}</div><a className="finding-source" href={item.source} target="_blank" rel="noreferrer">Source <ArrowUpRight size={12} aria-hidden="true" /></a></div></div>)}</div>
                {analysis.ignoredParameters.length > 0 ? <div className="ignored-note"><Info size={15} aria-hidden="true" /><span>Ignored optional parameters: {analysis.ignoredParameters.join(", ")}</span></div> : null}
                <div className="report-actions"><button type="button" className="secondary-button" onClick={copyRequest}><Copy size={15} aria-hidden="true" />{copyState}</button><button type="button" className="secondary-button" onClick={() => downloadReport(analysis)}><Download size={15} aria-hidden="true" />Download report</button></div>
                <div className="report-note"><LockKeyhole size={15} aria-hidden="true" /><span>The report is generated locally. ShadeCheck does not query the chain, sign a transaction, or broadcast funds.</span></div>
              </div>}
          </div>
        </section>

        <section className="below-grid" aria-label="How ShadeCheck works">
          <article className="panel info-card"><h2><ScanLine size={17} aria-hidden="true" />Parse the request</h2><p>Read ZIP-321 addresses, amounts, memos, assets, and indexed payments without sending input to a server.</p></article>
          <article className="panel info-card"><h2><ShieldCheck size={17} aria-hidden="true" />Explain exposure</h2><p>Separate transparent, shielded-capable, mixed, unknown, and cross-network paths in language a product team can use.</p></article>
          <article className="panel info-card"><h2><TerminalSquare size={17} aria-hidden="true" />Ship with confidence</h2><p>The next phase extracts these rules into a CLI and CI check for Zcash checkout integrations.</p></article>
        </section>

        <footer className="footer"><span>ShadeCheck is an early privacy linting prototype.</span><a href="https://zips.z.cash/zip-0321" target="_blank" rel="noreferrer">Read ZIP-321 <ArrowUpRight size={12} aria-hidden="true" /></a></footer>
      </main>
    </div>
  );
}
