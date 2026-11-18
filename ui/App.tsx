import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Download,
  FileCode2,
  GitPullRequest,
  KeyRound,
  Network,
  Play,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type { ReachabilityFinding, ScanReport } from '../src/core/types';

interface SampleItem {
  id: string;
  name: string;
  path: string;
  description: string;
}

interface SourceSnippetResponse {
  file: string;
  focusLine: number;
  snippet: Array<{ lineNumber: number; content: string; isFocus: boolean }>;
}

interface VerifyResponse {
  valid: boolean;
  recomputedSha256: string;
  claimedSha256: string;
  statementCount: number;
  reason: string;
}

type TabKey = 'triage' | 'graph' | 'vex' | 'patch';

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function App() {
  const [samples, setSamples] = useState<SampleItem[]>([]);
  const [targetInput, setTargetInput] = useState<string>('examples/acme-eu-gateway');
  const [offlineOnly, setOfflineOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('triage');
  const [statusFilter, setStatusFilter] = useState<'all' | ReachabilityFinding['status']>('all');
  const [selectedIdx, setSelectedIdx] = useState<number>(0);
  const [snippet, setSnippet] = useState<SourceSnippetResponse | null>(null);

  const [vexEditorText, setVexEditorText] = useState<string>('');
  const [verifyVerdict, setVerifyVerdict] = useState<VerifyResponse | null>(null);

  async function runScan(pathOrUrl: string, forceOffline = offlineOnly) {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetPathOrUrl: pathOrUrl, offlineOnly: forceOffline }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      const typed = data as ScanReport;
      setReport(typed);
      setSelectedIdx(0);
      setVexEditorText(JSON.stringify(typed.signedVex, null, 2));
      setVerifyVerdict(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetch('/api/samples')
      .then((r) => r.json())
      .then((d: { samples?: SampleItem[] }) => {
        if (d.samples) setSamples(d.samples);
      })
      .catch(() => {
        // Ignore sample list failure
      });
    void runScan('examples/acme-eu-gateway', false);
  }, []);

  const filteredFindings = useMemo(() => {
    if (!report) return [];
    if (statusFilter === 'all') return report.findings;
    return report.findings.filter((f) => f.status === statusFilter);
  }, [report, statusFilter]);

  const activeFinding = filteredFindings[selectedIdx] ?? filteredFindings[0] ?? null;

  useEffect(() => {
    if (!report || !activeFinding) {
      setSnippet(null);
      return;
    }
    const site = activeFinding.callSites[0];
    if (!site || report.targetPath.startsWith('https://')) {
      setSnippet(null);
      return;
    }
    const params = new URLSearchParams({
      repoPath: report.targetPath,
      file: site.file,
      line: String(site.line),
    });
    fetch(`/api/source-snippet?${params.toString()}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setSnippet(data))
      .catch(() => setSnippet(null));
  }, [report, activeFinding]);

  async function verifyEditedVex() {
    setVerifyVerdict(null);
    try {
      const parsed = JSON.parse(vexEditorText);
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bundle: parsed }),
      });
      const verdict = (await res.json()) as VerifyResponse;
      setVerifyVerdict(verdict);
    } catch (err) {
      setVerifyVerdict({
        valid: false,
        recomputedSha256: '',
        claimedSha256: '',
        statementCount: 0,
        reason: err instanceof Error ? `JSON Parse Error: ${err.message}` : 'Invalid JSON',
      });
    }
  }

  function simulateTamper() {
    if (!report) return;
    try {
      const clone = JSON.parse(vexEditorText);
      if (clone?.document?.statements?.[0]) {
        clone.document.statements[0].status =
          clone.document.statements[0].status === 'affected' ? 'not_affected' : 'affected';
        setVexEditorText(JSON.stringify(clone, null, 2));
        setVerifyVerdict(null);
      }
    } catch {
      // Ignore if malformed
    }
  }

  return (
    <div className="app-shell">
      <header className="header">
        <div className="brand">
          <div className="brand-badge">VP</div>
          <div>
            <h1>VEXProof — Reachability &amp; Signed OpenVEX Compiler</h1>
            <p>
              Real TypeScript AST Call-Graph + Live OSV.dev / CISA KEV / EPSS + Ed25519 EU CRA Attestation
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <span className="pill-tag live">
            <Activity size={13} />
            {report ? `Intel: ${report.metrics.intelMode.toUpperCase()}` : 'Ready'}
          </span>
          <span className="pill-tag">Kiroween 2026 • Frankenstein</span>
        </div>
      </header>

      <section className="scan-bar">
        <div className="scan-input-row">
          <input
            className="input"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="Local repository path (e.g. examples/acme-eu-gateway or C:\...) or https://github.com/org/repo"
          />
          <label className="btn" style={{ fontWeight: 500 }}>
            <input
              type="checkbox"
              checked={offlineOnly}
              onChange={(e) => setOfflineOnly(e.target.checked)}
            />
            Cache-Only Mode
          </label>
          <button
            className="btn btn-primary"
            disabled={loading || !targetInput.trim()}
            onClick={() => runScan(targetInput)}
          >
            <Play size={15} />
            {loading ? 'Analyzing AST + Querying OSV.dev...' : 'Scan & Compile Signed VEX'}
          </button>
        </div>
        <div className="sample-chips">
          <span>Real Sample Targets:</span>
          {samples.map((s) => {
            const rel = `examples/${s.id}`;
            const active = targetInput === rel || targetInput === s.path;
            return (
              <button
                key={s.id}
                className={`chip ${active ? 'active' : ''}`}
                onClick={() => {
                  setTargetInput(rel);
                  void runScan(rel);
                }}
                title={s.description}
              >
                {s.name}
              </button>
            );
          })}
        </div>
      </section>

      {error && <div className="error-banner">Scan Error: {error}</div>}

      {report && (
        <>
          <section className="kpi-grid">
            <div className="kpi-card">
              <div className="kpi-label">SBOM Components</div>
              <div className="kpi-value">{report.metrics.totalDependencies}</div>
              <div className="kpi-sub">
                {report.metrics.directDependencies} direct • {report.astSummary.filesScanned} source files
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Raw OSV.dev Alerts</div>
              <div className="kpi-value">{report.metrics.totalVulnerabilities}</div>
              <div className="kpi-sub">Matched from lockfile versions</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Reachable (Affected)</div>
              <div className="kpi-value" style={{ color: '#f87171' }}>
                {report.metrics.affectedCount}
              </div>
              <div className="kpi-sub">Actionable call-path proven</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Dynamic Uncertain</div>
              <div className="kpi-value" style={{ color: '#fbbf24' }}>
                {report.metrics.underInvestigationCount}
              </div>
              <div className="kpi-sub">
                {report.astSummary.dynamicHazards.length} eval/dynamic require guard(s)
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Suppressed by VEX</div>
              <div className="kpi-value" style={{ color: '#34d399' }}>
                {report.metrics.notAffectedCount}
              </div>
              <div className="kpi-sub">
                {report.metrics.noiseReductionPercent}% false-alarm reduction ({report.metrics.durationMs} ms)
              </div>
            </div>
          </section>

          <nav className="tabs">
            <button
              className={`tab-btn ${activeTab === 'triage' ? 'active' : ''}`}
              onClick={() => setActiveTab('triage')}
            >
              <ShieldAlert size={15} />
              Reachability Triage ({report.findings.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
              onClick={() => setActiveTab('graph')}
            >
              <Network size={15} />
              AST Call-Graph ({report.astSummary.nodes.length} nodes)
            </button>
            <button
              className={`tab-btn ${activeTab === 'vex' ? 'active' : ''}`}
              onClick={() => setActiveTab('vex')}
            >
              <KeyRound size={15} />
              Signed OpenVEX &amp; Tamper Test
            </button>
            <button
              className={`tab-btn ${activeTab === 'patch' ? 'active' : ''}`}
              onClick={() => setActiveTab('patch')}
            >
              <GitPullRequest size={15} />
              Minimal Upgrade PR ({report.patchPlan.actions.length})
            </button>
          </nav>

          {activeTab === 'triage' && (
            <section className="split-grid">
              <div className="panel">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: 12,
                    gap: 8,
                    flexWrap: 'wrap',
                  }}
                >
                  <h2 style={{ margin: 0 }}>CVE Reachability Findings</h2>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {(['all', 'affected', 'under_investigation', 'not_affected'] as const).map((k) => (
                      <button
                        key={k}
                        className={`chip ${statusFilter === k ? 'active' : ''}`}
                        onClick={() => {
                          setStatusFilter(k);
                          setSelectedIdx(0);
                        }}
                      >
                        {k}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="finding-list">
                  {filteredFindings.map((f, idx) => (
                    <button
                      key={`${f.vuln.id}-${f.vuln.packageName}`}
                      className={`finding-item ${idx === selectedIdx ? 'selected' : ''}`}
                      onClick={() => setSelectedIdx(idx)}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: 8,
                          flexWrap: 'wrap',
                        }}
                      >
                        <strong style={{ fontSize: '0.9rem' }}>
                          {f.vuln.cveId ?? f.vuln.id}{' '}
                          <span style={{ color: 'var(--muted)', fontWeight: 500 }}>
                            • {f.vuln.packageName}@{f.vuln.installedVersion}
                          </span>
                        </strong>
                        <span className={`badge ${f.status}`}>{f.status}</span>
                      </div>
                      <div style={{ marginTop: 6, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <span className="badge info">{f.craPriority}</span>
                        {f.vuln.inCisaKev && <span className="badge kev">CISA KEV</span>}
                        {f.vuln.epssScore !== null && (
                          <span className="badge info">
                            EPSS {(f.vuln.epssScore * 100).toFixed(1)}%
                          </span>
                        )}
                        <span className="badge info">{f.vuln.severityLabel}</span>
                      </div>
                      <p style={{ margin: '7px 0 0', fontSize: '0.8rem', color: 'var(--muted)' }}>
                        {f.vuln.summary}
                      </p>
                    </button>
                  ))}
                  {filteredFindings.length === 0 && (
                    <p style={{ color: 'var(--muted)' }}>No vulnerabilities match this filter.</p>
                  )}
                </div>
              </div>

              <div className="panel">
                {activeFinding ? (
                  <>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: 8,
                        flexWrap: 'wrap',
                      }}
                    >
                      <h2 style={{ margin: 0 }}>
                        {activeFinding.vuln.cveId ?? activeFinding.vuln.id} Provenance
                      </h2>
                      <span className={`badge ${activeFinding.status}`}>{activeFinding.status}</span>
                    </div>
                    <p style={{ fontSize: '0.88rem', color: 'var(--text)', marginTop: 10 }}>
                      {activeFinding.rationale}
                    </p>
                    {activeFinding.justification && (
                      <div className="pill-tag live" style={{ marginBottom: 10 }}>
                        OpenVEX Justification: <code>{activeFinding.justification}</code>
                      </div>
                    )}

                    <h3 style={{ marginTop: 14 }}>
                      <Terminal size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                      Call-Graph Path from Entrypoint
                    </h3>
                    {activeFinding.callPath.length > 0 ? (
                      <div className="call-chain">
                        {activeFinding.callPath.map((step, i) => (
                          <React.Fragment key={step}>
                            <span className="chain-step">{step}</span>
                            {i < activeFinding.callPath.length - 1 && (
                              <ArrowRight size={14} color="#8b9bb4" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    ) : (
                      <p style={{ fontSize: '0.84rem', color: 'var(--muted)' }}>
                        Zero reachable execution paths from any runtime entrypoint.
                      </p>
                    )}

                    {snippet && (
                      <>
                        <h3 style={{ marginTop: 16 }}>
                          <FileCode2 size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                          Real Source Evidence: <code>{snippet.file}:{snippet.focusLine}</code>
                        </h3>
                        <div className="code-box">
                          {snippet.snippet.map((line) => (
                            <div
                              key={line.lineNumber}
                              className={`code-line ${line.isFocus ? 'focus' : ''}`}
                            >
                              <span className="code-ln">{line.lineNumber}</span>
                              <span>{line.content || ' '}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    <div style={{ marginTop: 14, fontSize: '0.8rem', color: 'var(--muted)' }}>
                      OSV ID: <code>{activeFinding.vuln.id}</code> • PURL:{' '}
                      <code>{activeFinding.vuln.purl}</code> • Fixed versions:{' '}
                      <code>{activeFinding.vuln.fixedVersions.join(', ') || 'None published'}</code>
                    </div>
                  </>
                ) : (
                  <p style={{ color: 'var(--muted)' }}>Select a finding to inspect call provenance.</p>
                )}
              </div>
            </section>
          )}

          {activeTab === 'graph' && (
            <section className="panel" style={{ marginTop: 16 }}>
              <h2>AST Call-Graph Topology ({report.astSummary.edgesMapped} edges)</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--muted)' }}>
                Real entrypoints, internal functions, external package symbol sinks, and dynamic
                eval/require hazards extracted by the TypeScript Compiler AST engine.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginTop: 12 }}>
                {(['entrypoint', 'function', 'external-symbol'] as const).map((kind) => {
                  const nodes = report.astSummary.nodes.filter((n) => n.kind === kind);
                  return (
                    <div key={kind} className="panel" style={{ background: 'var(--surface-2)' }}>
                      <h3 style={{ textTransform: 'uppercase', fontSize: '0.8rem', color: 'var(--muted)' }}>
                        {kind} ({nodes.length})
                      </h3>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {nodes.map((n) => (
                          <div key={n.id} className="chain-step">
                            <div><strong>{n.label}</strong></div>
                            <div style={{ color: 'var(--muted)', fontSize: '0.72rem' }}>
                              {n.file}:{n.line}
                            </div>
                          </div>
                        ))}
                        {nodes.length === 0 && <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>None</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
              {report.astSummary.dynamicHazards.length > 0 && (
                <div className="error-banner" style={{ background: 'var(--amber-soft)', borderColor: 'rgba(245,158,11,0.4)', color: '#fde68a' }}>
                  <strong>Dynamic Hazards Triggering Soundness Guard:</strong>
                  {report.astSummary.dynamicHazards.map((h) => (
                    <div key={`${h.file}:${h.line}`} style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', marginTop: 4 }}>
                      [{h.kind}] {h.file}:{h.line} — {h.snippet}
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {activeTab === 'vex' && (
            <section className="panel" style={{ marginTop: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
                <div>
                  <h2 style={{ margin: 0 }}>Ed25519 Signed OpenVEX v0.2.0 Bundle</h2>
                  <p style={{ margin: '4px 0 10px', fontSize: '0.82rem', color: 'var(--muted)' }}>
                    Canonical SHA-256: <code>{report.signedVex.canonicalDigestSha256}</code>
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn"
                    onClick={() => downloadJson('vex.signed.json', report.signedVex)}
                  >
                    <Download size={14} /> Download vex.signed.json
                  </button>
                  <button className="btn" onClick={() => downloadJson('bom.json', report.sbom)}>
                    <Download size={14} /> Download CycloneDX bom.json
                  </button>
                  <button className="btn btn-danger" onClick={simulateTamper}>
                    <AlertTriangle size={14} /> Tamper 1 Statement (Test Integrity)
                  </button>
                  <button className="btn btn-primary" onClick={verifyEditedVex}>
                    <ShieldCheck size={14} /> Verify Ed25519 Signature
                  </button>
                </div>
              </div>

              {verifyVerdict && (
                <div
                  className="error-banner"
                  style={{
                    marginBottom: 12,
                    background: verifyVerdict.valid ? 'var(--emerald-soft)' : 'var(--crimson-soft)',
                    borderColor: verifyVerdict.valid ? 'rgba(16,185,129,0.45)' : 'rgba(239,68,68,0.45)',
                    color: verifyVerdict.valid ? '#a7f3d0' : '#fecaca',
                  }}
                >
                  {verifyVerdict.valid ? (
                    <CheckCircle2 size={16} style={{ verticalAlign: 'middle', marginRight: 8 }} />
                  ) : (
                    <AlertTriangle size={16} style={{ verticalAlign: 'middle', marginRight: 8 }} />
                  )}
                  <strong>{verifyVerdict.valid ? 'VERIFIED:' : 'TAMPER DETECTED:'}</strong>{' '}
                  {verifyVerdict.reason}
                </div>
              )}

              <textarea
                className="textarea-vex"
                value={vexEditorText}
                onChange={(e) => setVexEditorText(e.target.value)}
              />
            </section>
          )}

          {activeTab === 'patch' && (
            <section className="split-grid">
              <div className="panel">
                <h2>Minimal Safe-Upgrade Actions ({report.patchPlan.actions.length})</h2>
                <p style={{ fontSize: '0.84rem', color: 'var(--muted)' }}>
                  Only targets dependencies with reachable or dynamic-uncertain findings. Suppressed{' '}
                  <code>not_affected</code> packages are excluded from urgent upgrade churn.
                </p>
                {report.patchPlan.actions.map((act) => (
                  <div
                    key={act.packageName}
                    className="panel"
                    style={{ background: 'var(--surface-2)', marginTop: 10 }}
                  >
                    <strong>
                      {act.packageName}: {act.currentVersion} &rarr; {act.targetVersion}
                    </strong>
                    <div style={{ fontSize: '0.78rem', color: 'var(--muted)', marginTop: 4 }}>
                      Fixes: {act.triggeredByVuls.join(', ')}
                    </div>
                    <div className="code-box" style={{ marginTop: 8 }}>
                      {act.npmCommand}
                    </div>
                  </div>
                ))}
                {report.patchPlan.actions.length === 0 && (
                  <div className="pill-tag live">Zero reachable upgrades required.</div>
                )}
              </div>
              <div className="panel">
                <h2>Generated package.json Diff &amp; CRA PR Summary</h2>
                <div className="code-box">{report.patchPlan.packageJsonDiff}</div>
                <h3 style={{ marginTop: 14 }}>PR Description Markdown</h3>
                <div className="code-box" style={{ whiteSpace: 'pre-wrap' }}>
                  {report.patchPlan.prMarkdown}
                </div>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
