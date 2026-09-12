import { useState } from 'react';
import './Dashboard.css';

/*
Expected props shape:

repos: [
  { id: string, name: string, branch: string, language: string }
]
selectedRepoId: string          // id of the currently active repo, or 'all'
onSelectRepo: (id) => void

scanMeta: {
  lastScanTime: string,         // e.g. "02:14:32"
  systemOnline: boolean,
  filesAnalyzed: number,
  lastSyncLabel: string         // e.g. "00:02 AGO"
}
onTriggerScan: () => void
scanning: boolean               // true while a scan is in progress, disables the button

surfaceTitle: string            // e.g. "ALL SURFACES" or a specific repo name

findings: [
  {
    id: string,
    severity: 'critical' | 'high' | 'medium' | 'low',
    name: string,
    repository: string,
    file: string,
    line: number,
    status: 'OPEN' | 'REVIEW' | 'RESOLVED',
    context: string,            // the flagged code snippet
    aiExplanation: string,
    suggestedFix: string,
    feedback: 'up' | 'down' | null
  }
]
selectedFindingId: string | null
onSelectFinding: (id) => void
onFeedback: (findingId, vote) => void   // vote is 'up' | 'down'
*/

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const SEVERITY_TAG = { critical: 'BLOCK', high: 'REVIEW', medium: 'REVIEW', low: 'TRACE' };

export default function Dashboard({
  repos = [],
  selectedRepoId,
  onSelectRepo,
  scanMeta = {},
  onTriggerScan,
  scanning = false,
  surfaceTitle = 'ALL SURFACES',
  findings = [],
  selectedFindingId,
  onSelectFinding,
  onFeedback,
  onClose,
}) {
  const [copied, setCopied] = useState(false);

  const selectedFinding = findings.find(f => f.id === selectedFindingId) || null;

  const counts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev).length;
    return acc;
  }, {});
  const totalFindings = findings.length;
  const maxCount = Math.max(1, ...SEVERITY_ORDER.map(s => counts[s]));

  const handleCopyFix = () => {
    if (!selectedFinding) return;
    navigator.clipboard.writeText(selectedFinding.suggestedFix || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="virgo-dashboard">
      <div className="app">

        {/* SIDEBAR */}
        <div className="sidebar">
          <div className="brand-row">
            <div className="brand">VIRGO</div>
            {onClose && <div className="close-x" onClick={onClose}>&times;</div>}
          </div>
          <div className="section-label">Repositories</div>
          <div className="section-label" style={{ color: 'var(--dim-2)', fontSize: 10, marginBottom: 8 }}>
            // Indexed Surfaces
          </div>
          <ul className="repo-list">
            <li
              className={`repo-item${selectedRepoId === 'all' ? ' active' : ''}`}
              onClick={() => onSelectRepo && onSelectRepo('all')}
            >
              <div className="repo-name">
                <span className="diamond" />
                {selectedRepoId === 'all' ? '> ' : ''}ALL SURFACES
              </div>
              <div className="repo-sub">workspace // mixed</div>
            </li>
            {repos.map(repo => (
              <li
                key={repo.id}
                className={`repo-item${selectedRepoId === repo.id ? ' active' : ''}`}
                onClick={() => onSelectRepo && onSelectRepo(repo.id)}
              >
                <div className="repo-name">
                  <span className="diamond" />
                  {selectedRepoId === repo.id ? '> ' : ''}{repo.name}
                </div>
                <div className="repo-sub">{repo.branch} // {repo.language}</div>
              </li>
            ))}
          </ul>
          <div className="sidebar-footer">
            <span className="status">SECURITY ENGINE ONLINE</span>
            <span>MEM: 64K &nbsp; NODE: 04</span>
          </div>
        </div>

        {/* MAIN */}
        <div className="main">
          <div className="main-topbar">
            <div>
              <h1>VIRGO // SECURITY ANALYSIS</h1>
              <div className="sub">REPOSITORY INTELLIGENCE CONSOLE</div>
            </div>
            <div className="topbar-right">
              <div className="topbar-meta">
                <div>LAST SCAN: {scanMeta.lastScanTime || '—'}</div>
                <div className="online">
                  &#9678; {scanMeta.systemOnline ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'}
                </div>
              </div>
              <button className="scan-btn" onClick={onTriggerScan} disabled={scanning}>
                &#9654; {scanning ? 'SCANNING...' : 'INITIATE SCAN'}
              </button>
            </div>
          </div>

          <div className="surface-label">SECURITY SURFACE</div>
          <div className="surface-title">{surfaceTitle}</div>
          <div className="surface-meta">
            <span>// LIVE INDEX &middot; LAST SYNC {scanMeta.lastSyncLabel || '—'}</span>
            <span>FILES ANALYZED: {scanMeta.filesAnalyzed ?? '—'}</span>
          </div>

          <div className="stat-grid">
            <div className="stat-card pink">
              <div className="label">Total Findings</div>
              <div className="value">{totalFindings} <span className="tag">INDEX</span></div>
              <div className="track"><div className="fill" style={{ width: '100%' }} /></div>
            </div>
            {SEVERITY_ORDER.map(sev => (
              <div className={`stat-card ${sev === 'critical' ? 'crimson' : sev}`} key={sev}>
                <div className="label">{SEVERITY_LABEL[sev]}</div>
                <div className="value">{counts[sev]} <span className="tag">{SEVERITY_TAG[sev]}</span></div>
                <div className="track">
                  <div className="fill" style={{ width: `${(counts[sev] / maxCount) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>

          <div className="table-header">
            <div>
              <div className="t1">FINDINGS TABLE</div>
              <div className="t2">DETECTION REGISTER</div>
            </div>
            <div className="hint">SELECT ROW FOR ANALYSIS</div>
          </div>

          <table>
            <thead>
              <tr>
                <th>Severity</th><th>Finding</th><th>Repository</th>
                <th>File</th><th>Line</th><th>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr
                  key={f.id}
                  className={f.id === selectedFindingId ? 'selected' : ''}
                  onClick={() => onSelectFinding && onSelectFinding(f.id)}
                >
                  <td>
                    <span className={`badge ${f.severity}`}>
                      <span className="dot" />{SEVERITY_LABEL[f.severity]}
                    </span>
                  </td>
                  <td className="finding-name">{f.name}</td>
                  <td className="mono-dim">{f.repository}</td>
                  <td className="mono-dim">{f.file}</td>
                  <td className="mono-dim">L{f.line}</td>
                  <td>
                    <span className={`status-tag${f.status === 'OPEN' ? ' open' : ''}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="chevron">&rsaquo;</td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr>
                  <td colSpan={7} className="mono-dim" style={{ padding: '24px 12px' }}>
                    No findings yet — run a scan to populate this table.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* DETAILS PANEL */}
        <div className="details">
          {!selectedFinding && (
            <div className="details-empty">SELECT A FINDING TO VIEW ANALYSIS</div>
          )}

          {selectedFinding && (
            <>
              <div className="details-label">FINDING // {SEVERITY_LABEL[selectedFinding.severity].toUpperCase()}</div>
              <h2>{selectedFinding.name.toUpperCase()}</h2>

              <div className="meta-row">
                <div className="meta-cell"><div className="k">Repository</div><div className="v">{selectedFinding.repository}</div></div>
                <div className="meta-cell"><div className="k">File</div><div className="v">{selectedFinding.file}</div></div>
                <div className="meta-cell"><div className="k">Line</div><div className="v">{selectedFinding.line}</div></div>
              </div>

              <div className="section-block">
                <div className="h">Context</div>
                <div className="code-block">{selectedFinding.context}</div>
              </div>

              <div className="section-block">
                <div className="h">AI Analysis</div>
                <p className="ai-text">{selectedFinding.aiExplanation}</p>
                <span className="ai-tag">AI-generated — review before applying</span>
              </div>

              <div className="section-block">
                <div className="patch-header">
                  <div className="h" style={{ marginBottom: 0 }}>Patch // Suggested Fix</div>
                  <button className="copy-btn" onClick={handleCopyFix}>
                    {copied ? 'COPIED' : 'COPY'}
                  </button>
                </div>
                <div className="patch-code">{selectedFinding.suggestedFix}</div>
              </div>

              <div className="feedback-row">
                <span className="feedback-label">Was this useful?</span>
                <button
                  className={`fb-btn up${selectedFinding.feedback === 'up' ? ' active' : ''}`}
                  onClick={() => onFeedback && onFeedback(selectedFinding.id, 'up')}
                >
                  <svg viewBox="0 0 24 24"><path d="M7 22V11l5-8 1 1-1 6h7a2 2 0 0 1 2 2.3l-1.4 8A2 2 0 0 1 17.6 22H7z"/><path d="M7 11H3v11h4"/></svg>
                </button>
                <button
                  className={`fb-btn down${selectedFinding.feedback === 'down' ? ' active' : ''}`}
                  onClick={() => onFeedback && onFeedback(selectedFinding.id, 'down')}
                >
                  <svg viewBox="0 0 24 24"><path d="M17 2v11l-5 8-1-1 1-6H5a2 2 0 0 1-2-2.3l1.4-8A2 2 0 0 1 6.4 2H17z"/><path d="M17 13h4V2h-4"/></svg>
                </button>
              </div>
            </>
          )}
        </div>

      </div>
    </div>
  );
}
