import React, { useState, useEffect, useMemo } from 'react';
import { 
  Search, Globe, Activity, Brain, Crosshair, 
  TrendingUp, Network, Lock, Eye, Building2,
  AlertTriangle, Shield, ExternalLink, ChevronDown, ChevronUp
} from 'lucide-react';
import PaginationControls, { usePagination } from '../components/PaginationControls';

// Helper to build auth headers
function getAuthHeaders(authData) {
  const headers = {};
  if (authData?.token) {
    headers['Authorization'] = `Bearer ${authData.token}`;
  } else if (authData?.basic) {
    headers['Authorization'] = `Basic ${btoa(authData.basic.user + ':' + authData.basic.pass)}`;
  }
  return headers;
}

function PaginatedTable({ items, headers, renderRow, initialPageSize = 100 }) {
  const pagination = usePagination(items || [], initialPageSize);
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>{headers.map(header => <th key={header}>{header}</th>)}</tr>
        </thead>
        <tbody>
          {pagination.pagedItems.map(renderRow)}
        </tbody>
      </table>
      <PaginationControls pagination={pagination} />
    </div>
  );
}

// ============ Threat Hunting ============
export function ThreatHunting({ authData }) {
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState('cve');
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    try {
      const headers = getAuthHeaders(authData);
      const res = await fetch(`/api/alerts?search=${encodeURIComponent(query.trim())}`, { headers });
      if (res.ok) {
        const data = await res.json();
        // Client-side filter for more specific matching
        const filtered = data.filter(a => {
          const q = query.toLowerCase();
          return (a.title && a.title.toLowerCase().includes(q)) ||
                 (a.externalId && a.externalId.toLowerCase().includes(q)) ||
                 (a.source && a.source.toLowerCase().includes(q));
        });
        setResults(filtered.slice(0, 100));
      }
    } catch (err) {
      console.error('Hunt error:', err);
    }
    setSearching(false);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Hunting</h1>
          <p className="page-subtitle">Proactively search across multiple intelligence sources for specific IOCs, CVEs, and threats.</p>
        </div>
      </div>

      <div className="card">
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: '1', minWidth: '250px' }}>
            <label className="form-label">Search Query</label>
            <input className="form-input" type="text" value={query} onChange={e => setQuery(e.target.value)} placeholder="CVE-2026-XXXXX, malware name, IOC..." />
          </div>
          <div className="form-group" style={{ minWidth: '150px' }}>
            <label className="form-label">Type</label>
            <select className="form-input" value={queryType} onChange={e => setQueryType(e.target.value)}>
              <option value="cve">CVE ID</option>
              <option value="ioc">IOC / Hash</option>
              <option value="keyword">Keyword</option>
              <option value="source">Source</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary" disabled={searching} style={{ height: '42px' }}>
            <Search size={16} /> {searching ? 'Searching...' : 'Hunt'}
          </button>
        </form>
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>
          Results {results.length > 0 && `(${results.length})`}
        </h2>
        {results.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            <Search size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
            <p>Enter a query above to begin hunting.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Source</th><th>ID</th><th>Severity</th><th>Title</th><th>Date</th></tr></thead>
              <tbody>
                {results.map(a => (
                  <tr key={a.id}>
                    <td style={{ fontWeight: 600, color: 'var(--primary-color)' }}>{a.source}</td>
                    <td><code style={{ fontSize: '0.8rem' }}>{a.externalId}</code></td>
                    <td><span className={`severity-badge severity-${a.severity || 'Unknown'}`}>{a.severity}</span></td>
                    <td>{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="alert-link">{a.title}</a> : a.title}</td>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)', fontSize: '0.85rem' }}>{a.date ? new Date(a.date).toLocaleDateString() : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ============ Asset Discovery ============
export function AssetDiscovery({ authData }) {
  const [assets, setAssets] = useState([]);
  const [newAsset, setNewAsset] = useState({ domain: '', ip: '', port: '', service: '' });
  const [scanTarget, setScanTarget] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    fetchAssets();
  }, []);

  const fetchAssets = async () => {
    try {
      const res = await fetch('/api/assets', { headers: getAuthHeaders(authData) });
      if (res.ok) setAssets(await res.json());
    } catch (e) { console.error(e); }
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify(newAsset)
      });
      if (res.ok) {
        setNewAsset({ domain: '', ip: '', port: '', service: '' });
        fetchAssets();
      }
    } catch (e) { console.error(e); }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!scanTarget.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/assets/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify({ target: scanTarget.trim() })
      });
      const data = await res.json();
      setScanResult(data);
      if (res.ok) fetchAssets();
    } catch (err) {
      setScanResult({ error: err.message });
    }
    setScanning(false);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">External Asset Discovery</h1>
          <p className="page-subtitle">Discover and catalog external-facing assets (domains, IPs, services).</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Scan Public Asset</h2>
        <form onSubmit={handleScan} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '240px' }}>
            <label className="form-label">Domain or Host</label>
            <input className="form-input" value={scanTarget} onChange={e => setScanTarget(e.target.value)} placeholder="example.com" />
          </div>
          <button type="submit" className="btn btn-primary" disabled={scanning} style={{ height: '42px' }}>
            <Search size={16} /> {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </form>
        {scanResult && (
          <div style={{ marginTop: '1rem', color: scanResult.error ? 'var(--danger)' : 'var(--text-muted)', fontSize: '0.875rem' }}>
            {scanResult.error ? scanResult.error : (
              <>
                <div>IPs: {(scanResult.ips || []).join(', ') || '-'}</div>
                <div>Open ports: {(scanResult.openPorts || []).join(', ') || '-'}</div>
                <div>Saved assets: {(scanResult.saved || []).length}</div>
              </>
            )}
          </div>
        )}
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Add Asset</h2>
        <form onSubmit={handleAdd} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '150px' }}>
            <label className="form-label">Domain</label>
            <input className="form-input" value={newAsset.domain} onChange={e => setNewAsset({...newAsset, domain: e.target.value})} placeholder="example.com" />
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: '120px' }}>
            <label className="form-label">IP</label>
            <input className="form-input" value={newAsset.ip} onChange={e => setNewAsset({...newAsset, ip: e.target.value})} placeholder="192.168.1.1" />
          </div>
          <div className="form-group" style={{ width: '100px' }}>
            <label className="form-label">Port</label>
            <input className="form-input" type="number" value={newAsset.port} onChange={e => setNewAsset({...newAsset, port: e.target.value})} placeholder="443" />
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: '120px' }}>
            <label className="form-label">Service</label>
            <input className="form-input" value={newAsset.service} onChange={e => setNewAsset({...newAsset, service: e.target.value})} placeholder="HTTPS" />
          </div>
          <button type="submit" className="btn btn-primary" style={{ height: '42px' }}>Add Asset</button>
        </form>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Discovered Assets ({assets.length})</h2>
        {assets.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <Globe size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} /><p>No assets discovered yet. Add assets above to begin tracking.</p>
          </div>
        ) : (
          <PaginatedTable
            items={assets}
            headers={['Domain', 'IP', 'Port', 'Service', 'Status', 'Risk']}
            renderRow={(a) => (
              <tr key={a.id}>
                <td style={{ fontWeight: 600 }}>{a.domain || '-'}</td>
                <td><code>{a.ip || '-'}</code></td>
                <td>{a.port || '-'}</td>
                <td>{a.service || '-'}</td>
                <td><span className={`severity-badge severity-${a.status === 'Active' ? 'High' : 'Low'}`}>{a.status}</span></td>
                <td>{a.risk_score}</td>
              </tr>
            )}
          />
        )}
      </div>
    </div>
  );
}

// ============ Exposure Monitoring ============
export function ExposureMonitoring({ alerts }) {
  const exposureData = useMemo(() => {
    const bySource = {};
    alerts.forEach(a => {
      if (!bySource[a.source]) bySource[a.source] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      bySource[a.source].total++;
      const sev = (a.severity || '').toLowerCase();
      if (sev === 'critical') bySource[a.source].critical++;
      else if (sev === 'high') bySource[a.source].high++;
      else if (sev === 'medium') bySource[a.source].medium++;
      else if (sev === 'low') bySource[a.source].low++;
    });
    return Object.entries(bySource).sort((a, b) => b[1].total - a[1].total);
  }, [alerts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Exposure Monitoring</h1>
          <p className="page-subtitle">Continuous monitoring of exposed services, certificates, and misconfigurations.</p>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid var(--primary-color)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Exposures</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, marginTop: '0.25rem' }}>{alerts.length}</div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical Exposure</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, marginTop: '0.25rem', color: '#f87171' }}>
            {alerts.filter(a => a.severity === 'Critical').length}
          </div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>High Risk</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, marginTop: '0.25rem', color: '#fb923c' }}>
            {alerts.filter(a => a.severity === 'High').length}
          </div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #10b981' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sources Tracked</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, marginTop: '0.25rem', color: '#34d399' }}>{exposureData.length}</div>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Exposure by Source</h2>
        <div className="table-container">
          <table>
            <thead><tr><th>Source</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
            <tbody>
              {exposureData.map(([source, data]) => (
                <tr key={source}>
                  <td style={{ fontWeight: 600 }}>{source}</td>
                  <td>{data.total}</td>
                  <td style={{ color: '#f87171' }}>{data.critical}</td>
                  <td style={{ color: '#fb923c' }}>{data.high}</td>
                  <td style={{ color: '#fbbf24' }}>{data.medium}</td>
                  <td style={{ color: '#60a5fa' }}>{data.low}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============ Asset Intelligence ============
export function AssetIntelligence({ alerts }) {
  const recentCritical = useMemo(() => {
    return alerts
      .filter(a => a.severity === 'Critical' || a.severity === 'High')
      .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
      .slice(0, 20);
  }, [alerts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Contextual Asset Intelligence</h1>
          <p className="page-subtitle">Enriched context for assets including CVE mapping and historical data.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Recent Critical & High Alerts ({recentCritical.length})</h2>
        <div className="table-container">
          <table>
            <thead><tr><th>Source</th><th>ID</th><th>Severity</th><th>Title</th><th>Date</th></tr></thead>
            <tbody>
              {recentCritical.map(a => (
                <tr key={a.id}>
                  <td style={{ fontWeight: 600, color: 'var(--primary-color)' }}>{a.source}</td>
                  <td><code style={{ fontSize: '0.8rem' }}>{a.externalId}</code></td>
                  <td><span className={`severity-badge severity-${a.severity}`}>{a.severity}</span></td>
                  <td>{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="alert-link">{a.title?.substring(0, 80)}</a> : a.title?.substring(0, 80)}</td>
                  <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>{a.date ? new Date(a.date).toLocaleDateString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============ Vulnerability Prioritization ============
export function VulnPrioritization({ alerts }) {
  const prioritized = useMemo(() => {
    const sevOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4 };
    return [...alerts]
      .sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4))
      .slice(0, 50);
  }, [alerts]);

  const stats = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    alerts.forEach(a => { counts[a.severity || 'Unknown']++; });
    return counts;
  }, [alerts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat-Based Vulnerability Prioritization</h1>
          <p className="page-subtitle">Prioritize remediation based on severity and active exploitation intelligence.</p>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem' }}>
        {Object.entries(stats).filter(([, v]) => v > 0).map(([sev, count]) => (
          <div className="card" key={sev} style={{ padding: '1rem', borderLeft: `4px solid ${sev === 'Critical' ? '#ef4444' : sev === 'High' ? '#f97316' : sev === 'Medium' ? '#f59e0b' : sev === 'Low' ? '#3b82f6' : '#64748b'}` }}>
            <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{sev}</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800 }}>{count}</div>
          </div>
        ))}
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Top 50 Priority Vulnerabilities</h2>
        <div className="table-container">
          <table>
            <thead><tr><th>#</th><th>Source</th><th>ID</th><th>Severity</th><th>Title</th><th>Status</th></tr></thead>
            <tbody>
              {prioritized.map((a, i) => (
                <tr key={a.id}>
                  <td style={{ fontWeight: 700, color: 'var(--text-muted)' }}>{i + 1}</td>
                  <td style={{ fontWeight: 600 }}>{a.source}</td>
                  <td><code style={{ fontSize: '0.8rem' }}>{a.externalId}</code></td>
                  <td><span className={`severity-badge severity-${a.severity || 'Unknown'}`}>{a.severity}</span></td>
                  <td>{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="alert-link">{a.title?.substring(0, 70)}</a> : a.title?.substring(0, 70)}</td>
                  <td>{a.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============ Predictive Intel ============
export function PredictiveIntel({ alerts }) {
  const trendData = useMemo(() => {
    const byDate = {};
    alerts.forEach(a => {
      if (!a.date) return;
      const d = new Date(a.date);
      if (isNaN(d)) return;
      const key = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
      if (!byDate[key]) byDate[key] = { total: 0, critical: 0 };
      byDate[key].total++;
      if (a.severity === 'Critical' || a.severity === 'High') byDate[key].critical++;
    });
    return Object.entries(byDate).slice(-14); // last 14 days
  }, [alerts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Predictive Threat Intelligence</h1>
          <p className="page-subtitle">Forecast emerging threats and attack vectors based on historical trends.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Alert Trend (Last 14 Days)</h2>
        {trendData.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2rem' }}>No date-based trend data available.</p>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Date</th><th>Total Alerts</th><th>Critical/High</th><th>Trend</th></tr></thead>
              <tbody>
                {trendData.map(([date, data], i) => (
                  <tr key={date}>
                    <td style={{ fontWeight: 600 }}>{date}</td>
                    <td>{data.total}</td>
                    <td style={{ color: '#f87171' }}>{data.critical}</td>
                    <td>
                      {i > 0 && data.total > trendData[i-1][1].total ? <ChevronUp size={16} style={{ color: '#ef4444' }} /> : 
                       i > 0 && data.total < trendData[i-1][1].total ? <ChevronDown size={16} style={{ color: '#10b981' }} /> : 
                       <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ============ Threat Analysis ============
export function ThreatAnalysis({ alerts }) {
  const phaseData = useMemo(() => {
    const byPhase = {};
    alerts.forEach(a => {
      const phase = a.attack_phase || 'Unknown';
      if (!byPhase[phase]) byPhase[phase] = { total: 0, critical: 0, high: 0 };
      byPhase[phase].total++;
      if (a.severity === 'Critical') byPhase[phase].critical++;
      if (a.severity === 'High') byPhase[phase].high++;
    });
    return Object.entries(byPhase).sort((a, b) => b[1].total - a[1].total);
  }, [alerts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Context-Rich Threat Analysis</h1>
          <p className="page-subtitle">Deep dive into alerts with MITRE ATT&CK mapping and IOC correlation.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>MITRE ATT&CK Phase Distribution</h2>
        <div className="table-container">
          <table>
            <thead><tr><th>Attack Phase</th><th>Total</th><th>Critical</th><th>High</th></tr></thead>
            <tbody>
              {phaseData.map(([phase, data]) => (
                <tr key={phase}>
                  <td style={{ fontWeight: 600 }}>{phase}</td>
                  <td>{data.total}</td>
                  <td style={{ color: '#f87171' }}>{data.critical}</td>
                  <td style={{ color: '#fb923c' }}>{data.high}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============ Digital Risk ============
export function DigitalRisk({ alerts, authData }) {
  const [keyword, setKeyword] = useState('');
  const [results, setResults] = useState([]);
  const [notes, setNotes] = useState([]);
  const [searching, setSearching] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!keyword.trim()) return;
    setSearching(true);
    try {
      const res = await fetch('/api/osint/digital-risk/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify({ keyword: keyword.trim() })
      });
      const data = await res.json();
      setResults(data.results || []);
      setNotes(data.notes || []);
    } catch (err) {
      setResults([{ provider: 'ThreatDock', type: 'Error', severity: 'Low', title: err.message }]);
    }
    setSearching(false);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Digital Risk & Identity Protection</h1>
          <p className="page-subtitle">Monitor credential leaks, dark web mentions, and identity exposures.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Identity Exposure Search</h2>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '260px' }}>
            <label className="form-label">Keyword, Email, Username, or Identity</label>
            <input className="form-input" value={keyword} onChange={e => setKeyword(e.target.value)} placeholder="name, email@domain.com, brand identity..." />
          </div>
          <button type="submit" className="btn btn-primary" disabled={searching} style={{ height: '42px' }}>
            <Search size={16} /> {searching ? 'Searching...' : 'Search Exposure'}
          </button>
        </form>
        {notes.length > 0 && <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '1rem' }}>{notes.join(' ')}</p>}
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Exposure Results ({results.length})</h2>
        {results.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <Lock size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} /><p>Search for an identity to monitor leaks, mentions, and exposures.</p>
          </div>
        ) : (
          <PaginatedTable
            items={results}
            headers={['Provider', 'Type', 'Severity', 'Title', 'Date', 'Link']}
            renderRow={(a, idx) => (
              <tr key={`${a.provider}-${a.title}-${idx}`}>
                <td style={{ fontWeight: 600, color: 'var(--primary-color)' }}>{a.provider}</td>
                <td>{a.type || '-'}</td>
                <td><span className={`severity-badge severity-${a.severity || 'Unknown'}`}>{a.severity || 'Unknown'}</span></td>
                <td>{a.title?.substring(0, 80)}</td>
                <td>{a.date ? new Date(a.date).toLocaleDateString() : '-'}</td>
                <td>{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /></a> : '-'}</td>
              </tr>
            )}
          />
        )}
      </div>
    </div>
  );
}

// ============ Brand Exposure ============
export function BrandExposure({ alerts, authData }) {
  const [brand, setBrand] = useState('');
  const [results, setResults] = useState([]);
  const [notes, setNotes] = useState([]);
  const [searching, setSearching] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!brand.trim()) return;
    setSearching(true);
    try {
      const res = await fetch('/api/osint/brand/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify({ brand: brand.trim() })
      });
      const data = await res.json();
      setResults(data.results || []);
      setNotes(data.notes || []);
    } catch (err) {
      setResults([{ provider: 'ThreatDock', type: 'Error', severity: 'Low', title: err.message }]);
    }
    setSearching(false);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Brand & Online Exposure Management</h1>
          <p className="page-subtitle">Track brand mentions, phishing domains, and typosquatting across intelligence feeds.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Brand Exposure Search</h2>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '260px' }}>
            <label className="form-label">Brand, Domain, or Product</label>
            <input className="form-input" value={brand} onChange={e => setBrand(e.target.value)} placeholder="example.com, product name, company name..." />
          </div>
          <button type="submit" className="btn btn-primary" disabled={searching} style={{ height: '42px' }}>
            <Search size={16} /> {searching ? 'Searching...' : 'Search Brand'}
          </button>
        </form>
        {notes.length > 0 && <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '1rem' }}>{notes.join(' ')}</p>}
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Brand Exposure Results ({results.length})</h2>
        {results.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <Eye size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} /><p>Search a brand or domain to find mentions, certificates, phishing indicators, and online exposure.</p>
          </div>
        ) : (
          <PaginatedTable
            items={results}
            headers={['Provider', 'Type', 'Severity', 'Title', 'Date', 'Link']}
            renderRow={(item, idx) => (
              <tr key={`${item.provider}-${item.title}-${idx}`}>
                <td style={{ fontWeight: 600, color: 'var(--primary-color)' }}>{item.provider}</td>
                <td>{item.type || '-'}</td>
                <td><span className={`severity-badge severity-${item.severity || 'Unknown'}`}>{item.severity || 'Unknown'}</span></td>
                <td>{item.title?.substring(0, 100)}</td>
                <td>{item.date ? new Date(item.date).toLocaleDateString() : '-'}</td>
                <td>{item.url ? <a href={item.url} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /></a> : '-'}</td>
              </tr>
            )}
          />
        )}
      </div>
    </div>
  );
}

// ============ Third-Party Risk ============
export function ThirdPartyRisk({ authData }) {
  const [vendors, setVendors] = useState([]);
  const [newVendor, setNewVendor] = useState({ name: '', category: '', risk_score: 0, contact: '' });
  const [assessment, setAssessment] = useState(null);

  useEffect(() => {
    fetchVendors();
  }, []);

  const fetchVendors = async () => {
    try {
      const res = await fetch('/api/vendors', { headers: getAuthHeaders(authData) });
      if (res.ok) setVendors(await res.json());
    } catch (e) { console.error(e); }
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/vendors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify(newVendor)
      });
      if (res.ok) {
        setNewVendor({ name: '', category: '', risk_score: 0, contact: '' });
        fetchVendors();
      }
    } catch (e) { console.error(e); }
  };

  const handleAssess = async (id) => {
    try {
      const res = await fetch(`/api/vendors/${id}/assess`, {
        method: 'POST',
        headers: getAuthHeaders(authData)
      });
      const data = await res.json();
      setAssessment(data);
      if (res.ok) fetchVendors();
    } catch (err) {
      setAssessment({ error: err.message });
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Third-Party Risk Management</h1>
          <p className="page-subtitle">Assess and monitor the security posture of vendors and partners.</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Add Vendor</h2>
        <form onSubmit={handleAdd} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '150px' }}>
            <label className="form-label">Vendor Name</label>
            <input className="form-input" required value={newVendor.name} onChange={e => setNewVendor({...newVendor, name: e.target.value})} />
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: '120px' }}>
            <label className="form-label">Category</label>
            <input className="form-input" value={newVendor.category} onChange={e => setNewVendor({...newVendor, category: e.target.value})} placeholder="SaaS, Cloud, etc." />
          </div>
          <div className="form-group" style={{ width: '100px' }}>
            <label className="form-label">Risk (0-100)</label>
            <input className="form-input" type="number" min="0" max="100" value={newVendor.risk_score} onChange={e => setNewVendor({...newVendor, risk_score: parseInt(e.target.value) || 0})} />
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: '150px' }}>
            <label className="form-label">Contact</label>
            <input className="form-input" value={newVendor.contact} onChange={e => setNewVendor({...newVendor, contact: e.target.value})} />
          </div>
          <button type="submit" className="btn btn-primary" style={{ height: '42px' }}>Add Vendor</button>
        </form>
      </div>
      {assessment && (
        <div className="card">
          <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Latest Assessment</h2>
          <p style={{ color: assessment.error ? 'var(--danger)' : 'var(--text-muted)' }}>
            {assessment.error || assessment.notes}
          </p>
          {assessment.matches && assessment.matches.length > 0 && (
            <div className="table-container" style={{ marginTop: '1rem' }}>
              <table>
                <thead><tr><th>Source</th><th>Severity</th><th>Title</th><th>Date</th></tr></thead>
                <tbody>
                  {assessment.matches.slice(0, 10).map(match => (
                    <tr key={`${match.source}-${match.externalId}-${match.id}`}>
                      <td>{match.source}</td>
                      <td><span className={`severity-badge severity-${match.severity || 'Unknown'}`}>{match.severity || 'Unknown'}</span></td>
                      <td>{match.title?.substring(0, 100)}</td>
                      <td>{match.date ? new Date(match.date).toLocaleDateString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Vendor Registry ({vendors.length})</h2>
        {vendors.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <Building2 size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} /><p>No vendors registered yet.</p>
          </div>
        ) : (
          <PaginatedTable
            items={vendors}
            headers={['Vendor', 'Category', 'Risk Score', 'Status', 'Contact', 'Last Assessment', 'Actions']}
            renderRow={(v) => (
              <tr key={v.id}>
                <td style={{ fontWeight: 600 }}>{v.name}</td>
                <td>{v.category || '-'}</td>
                <td><span className={`severity-badge severity-${v.risk_score >= 75 ? 'Critical' : v.risk_score >= 50 ? 'High' : v.risk_score >= 25 ? 'Medium' : 'Low'}`}>{v.risk_score}</span></td>
                <td>{v.status}</td>
                <td>{v.contact || '-'}</td>
                <td>{v.last_assessment ? new Date(v.last_assessment).toLocaleString() : '-'}</td>
                <td><button className="btn btn-outline" onClick={() => handleAssess(v.id)}>Assess</button></td>
              </tr>
            )}
          />
        )}
      </div>
    </div>
  );
}
