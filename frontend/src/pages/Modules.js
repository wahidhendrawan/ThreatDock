import React, { useState, useEffect, useMemo } from 'react';
import { 
  Search, Globe, Activity, Brain, Crosshair, 
  TrendingUp, Network, Lock, Eye, Building2,
  AlertTriangle, Shield, ExternalLink, ChevronDown, ChevronUp
} from 'lucide-react';

function safeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  if (url.startsWith('https://') || url.startsWith('http://')) return url;
  return '';
}
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

function severityRank(severity) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 }[severity || 'Unknown'] || 0;
}

function normalizeSeverity(score) {
  if (score >= 85) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function matchesAsset(alert, asset) {
  const haystack = `${alert.title || ''} ${alert.externalId || ''} ${alert.url || ''}`.toLowerCase();
  return [asset.domain, asset.ip, asset.service].filter(Boolean).some(value => haystack.includes(String(value).toLowerCase()));
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
                    <td>{a.url ? <a href={safeUrl(a.url)} target="_blank" rel="noopener noreferrer" className="alert-link">{a.title}</a> : a.title}</td>
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
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                  <Globe size={14} style={{ color: 'var(--primary-color)' }} />
                  <strong style={{ color: 'var(--text-main)' }}>DNS Resolver (Public):</strong> {(scanResult.dnsServers || []).join(', ') || '1.1.1.1, 8.8.8.8'}
                </div>
                <div>IPs Resolved: {(scanResult.ips || []).join(', ') || '-'}</div>
                <div>Open Ports: {(scanResult.openPorts || []).join(', ') || '-'}</div>
                <div>Saved Assets: {(scanResult.saved || []).length}</div>
                {(scanResult.enrichments || []).length > 0 && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <strong style={{ color: 'var(--text-main)' }}>Enrichment Results:</strong>
                    {(scanResult.enrichments || []).map((item, index) => (
                      <div key={`${item.provider}-${index}`} style={{ marginLeft: '0.5rem' }}>
                        • {item.provider}: {item.error ? <span style={{ color: 'var(--danger)' }}>{item.error}</span> : `${item.count || 0} ${item.type || 'result'} found`}
                      </div>
                    ))}
                  </div>
                )}
                {(scanResult.recommendations || []).length > 0 && (
                  <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', borderRadius: '6px', background: 'rgba(99, 102, 241, 0.08)', border: '1px solid rgba(99, 102, 241, 0.15)' }}>
                    {scanResult.recommendations.join(' ')}
                  </div>
                )}
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
export function AssetIntelligence({ alerts, authData }) {
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [vendors, setVendors] = useState([]);
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    const headers = getAuthHeaders(authData);
    fetch('/api/assets', { headers }).then(res => res.ok ? res.json() : []).then(setAssets).catch(console.error);
    fetch('/api/osint/findings', { headers }).then(res => res.ok ? res.json() : []).then(setFindings).catch(console.error);
    fetch('/api/vendors', { headers }).then(res => res.ok ? res.json() : []).then(setVendors).catch(console.error);
  }, [authData]);

  const assetContext = useMemo(() => {
    return assets.map(asset => {
      const relatedAlerts = alerts.filter(alert => matchesAsset(alert, asset));
      const relatedFindings = findings.filter(finding => {
        const haystack = `${finding.keyword || ''} ${finding.title || ''} ${finding.description || ''}`.toLowerCase();
        return [asset.domain, asset.ip].filter(Boolean).some(value => haystack.includes(String(value).toLowerCase()));
      });

      // Categorize alerts by type
      const cveAlerts = relatedAlerts.filter(a => (a.source === 'NVD' || a.source === 'GitHub' || a.source === 'Red Hat'));
      const iocAlerts = relatedAlerts.filter(a => (a.source === 'ThreatFox' || a.source === 'OTX'));
      const otherAlerts = relatedAlerts.filter(a => !['NVD', 'GitHub', 'Red Hat', 'ThreatFox', 'OTX'].includes(a.source));

      // Find related vendors
      const relatedVendors = vendors.filter(v => {
        const assetStr = `${asset.domain || ''} ${asset.service || ''} ${asset.notes || ''}`.toLowerCase();
        return assetStr.includes(v.name.toLowerCase());
      });

      // Enriched score calculation
      const cveWeight = cveAlerts.reduce((sum, a) => sum + severityRank(a.severity) * 10, 0);
      const iocWeight = iocAlerts.length * 15;
      const findingWeight = relatedFindings.length * 5;
      const vendorRisk = relatedVendors.reduce((sum, v) => sum + (v.risk_score || 0), 0) / Math.max(relatedVendors.length, 1);
      const portRisk = asset.port && ![80, 443].includes(asset.port) ? 10 : 0;
      const score = Math.min(100, (asset.risk_score || 0) + cveWeight + iocWeight + findingWeight + portRisk + Math.round(vendorRisk / 5));

      // Generate recommendations
      const recommendations = [];
      if (cveAlerts.filter(a => severityRank(a.severity) >= 3).length > 0) recommendations.push('Patch critical/high CVEs immediately');
      if (iocAlerts.length > 0) recommendations.push('Investigate active IOC matches');
      if (asset.port && ![80, 443].includes(asset.port)) recommendations.push(`Review non-standard port ${asset.port}`);
      if (relatedFindings.filter(f => f.category === 'digital-risk').length > 0) recommendations.push('Check digital risk exposure findings');
      if (recommendations.length === 0) recommendations.push('Continue monitoring');

      return {
        asset, relatedAlerts, relatedFindings, relatedVendors,
        cveAlerts, iocAlerts, otherAlerts,
        score, severity: normalizeSeverity(score),
        recommendations
      };
    }).sort((a, b) => b.score - a.score);
  }, [assets, alerts, findings, vendors]);

  const summaryStats = useMemo(() => {
    const total = assetContext.length;
    const critical = assetContext.filter(a => a.severity === 'Critical').length;
    const high = assetContext.filter(a => a.severity === 'High').length;
    const withCve = assetContext.filter(a => a.cveAlerts.length > 0).length;
    const withIoc = assetContext.filter(a => a.iocAlerts.length > 0).length;
    return { total, critical, high, withCve, withIoc };
  }, [assetContext]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Contextual Asset Intelligence</h1>
          <p className="page-subtitle">Enriched asset context with CVE mapping, IOC correlation, vendor risk, and OSINT findings per asset.</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid var(--primary-color)' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Assets</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800 }}>{summaryStats.total}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical Risk</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#f87171' }}>{summaryStats.critical}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>High Risk</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fb923c' }}>{summaryStats.high}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>With CVEs</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fbbf24' }}>{summaryStats.withCve}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #8b5cf6' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>With IOCs</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#a78bfa' }}>{summaryStats.withIoc}</div>
        </div>
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Asset Intelligence Context ({assetContext.length})</h2>
        {assetContext.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', padding: '2rem', textAlign: 'center' }}>Add or scan external assets in External Asset Discovery to build contextual intelligence.</p>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th></th>
                  <th>Asset</th>
                  <th>IP</th>
                  <th>Service</th>
                  <th>Risk Score</th>
                  <th>CVEs</th>
                  <th>IOCs</th>
                  <th>OSINT</th>
                  <th>Recommendation</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {assetContext.map(item => (
                  <React.Fragment key={item.asset.id}>
                    <tr onClick={() => setExpandedId(expandedId === item.asset.id ? null : item.asset.id)} style={{ cursor: 'pointer' }}>
                      <td style={{ width: '30px' }}>{expandedId === item.asset.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                      <td style={{ fontWeight: 600 }}>{item.asset.domain || '-'}</td>
                      <td><code>{item.asset.ip || '-'}</code></td>
                      <td>{item.asset.service || '-'}</td>
                      <td><span className={`severity-badge severity-${item.severity}`}>{item.score}</span></td>
                      <td style={{ color: item.cveAlerts.length > 0 ? '#f87171' : 'var(--text-muted)' }}>{item.cveAlerts.length}</td>
                      <td style={{ color: item.iocAlerts.length > 0 ? '#a78bfa' : 'var(--text-muted)' }}>{item.iocAlerts.length}</td>
                      <td>{item.relatedFindings.length}</td>
                      <td style={{ fontSize: '0.8rem' }}>{item.recommendations[0]}</td>
                      <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{item.asset.last_seen ? new Date(item.asset.last_seen).toLocaleString() : '-'}</td>
                    </tr>
                    {expandedId === item.asset.id && (
                      <tr>
                        <td colSpan="10" style={{ padding: '1rem 1.5rem', background: 'rgba(99, 102, 241, 0.03)' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                            {/* CVE Details */}
                            <div>
                              <h4 style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>CVE / Vulnerability Alerts ({item.cveAlerts.length})</h4>
                              {item.cveAlerts.length === 0 ? <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No CVEs mapped</p> : (
                                item.cveAlerts.slice(0, 5).map(a => (
                                  <div key={a.id} style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                                    <span className={`severity-badge severity-${a.severity}`} style={{ fontSize: '0.65rem', marginRight: '0.5rem' }}>{a.severity}</span>
                                    {a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="alert-link">{a.externalId || a.title?.substring(0, 60)}</a> : (a.externalId || a.title?.substring(0, 60))}
                                  </div>
                                ))
                              )}
                            </div>
                            {/* IOC Details */}
                            <div>
                              <h4 style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>IOC Indicators ({item.iocAlerts.length})</h4>
                              {item.iocAlerts.length === 0 ? <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No IOCs matched</p> : (
                                item.iocAlerts.slice(0, 5).map(a => (
                                  <div key={a.id} style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                                    <span style={{ color: '#a78bfa', fontWeight: 600 }}>{a.source}</span>: {a.title?.substring(0, 60)}
                                  </div>
                                ))
                              )}
                            </div>
                            {/* OSINT & Vendor */}
                            <div>
                              <h4 style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>OSINT Findings ({item.relatedFindings.length})</h4>
                              {item.relatedFindings.length === 0 ? <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No OSINT findings</p> : (
                                item.relatedFindings.slice(0, 5).map((f, i) => (
                                  <div key={i} style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                                    <span style={{ color: 'var(--primary-color)', fontWeight: 600 }}>{f.provider}</span>: {f.title?.substring(0, 60)}
                                  </div>
                                ))
                              )}
                              {item.relatedVendors.length > 0 && (
                                <div style={{ marginTop: '0.5rem' }}>
                                  <h4 style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Related Vendors</h4>
                                  {item.relatedVendors.map(v => (
                                    <div key={v.id} style={{ fontSize: '0.8rem' }}>• {v.name} (Risk: {v.risk_score})</div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                          {/* All Recommendations */}
                          {item.recommendations.length > 1 && (
                            <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', borderRadius: '6px', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.15)', fontSize: '0.8rem' }}>
                              <strong>Recommendations:</strong> {item.recommendations.join(' • ')}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ============ Vulnerability Prioritization ============
export function VulnPrioritization({ alerts, authData }) {
  const [assets, setAssets] = useState([]);
  const [vendors, setVendors] = useState([]);
  const [findings, setFindings] = useState([]);
  const [moduleFilter, setModuleFilter] = useState('');

  useEffect(() => {
    const headers = getAuthHeaders(authData);
    fetch('/api/assets', { headers }).then(res => res.ok ? res.json() : []).then(setAssets).catch(console.error);
    fetch('/api/vendors', { headers }).then(res => res.ok ? res.json() : []).then(setVendors).catch(console.error);
    fetch('/api/osint/findings', { headers }).then(res => res.ok ? res.json() : []).then(setFindings).catch(console.error);
  }, [authData]);

  const prioritized = useMemo(() => {
    // External Asset Discovery items
    const assetItems = assets.map(asset => {
      const relatedAlerts = alerts.filter(alert => matchesAsset(alert, asset));
      const cveAlerts = relatedAlerts.filter(a => ['NVD', 'GitHub', 'Red Hat'].includes(a.source));
      const iocAlerts = relatedAlerts.filter(a => ['ThreatFox', 'OTX'].includes(a.source));
      const maxAlertRisk = relatedAlerts.reduce((max, alert) => Math.max(max, severityRank(alert.severity) * 20), 0);
      const score = Math.min(100, (asset.risk_score || 0) + maxAlertRisk + relatedAlerts.length * 3 + (iocAlerts.length * 10));
      const contextParts = [];
      if (cveAlerts.length > 0) contextParts.push(`${cveAlerts.length} CVE(s)`);
      if (iocAlerts.length > 0) contextParts.push(`${iocAlerts.length} IOC match(es)`);
      if (asset.service) contextParts.push(`Service: ${asset.service}`);
      if (asset.port && ![80, 443].includes(asset.port)) contextParts.push(`Non-std port: ${asset.port}`);
      return {
        id: `asset-${asset.id}`,
        sourceModule: 'External Asset Discovery',
        type: 'External Asset',
        name: asset.domain || asset.ip || `Asset #${asset.id}`,
        severity: normalizeSeverity(score),
        score,
        driver: `${relatedAlerts.length} alert(s), service ${asset.service || '-'}`,
        context: contextParts.join(' • ') || 'No active threats detected',
        link: null
      };
    });

    // Digital Risk & Identity Protection items
    const digitalRiskFindings = findings.filter(f => f.category === 'digital-risk');
    const digitalRiskItems = digitalRiskFindings.map(finding => {
      const sevScore = severityRank(finding.severity) * 25;
      return {
        id: `dr-${finding.id}`,
        sourceModule: 'Digital Risk & Identity Protection',
        type: 'Digital Risk',
        name: finding.keyword || finding.title,
        severity: finding.severity || 'Unknown',
        score: sevScore,
        driver: `${finding.provider} - ${finding.type}`,
        context: finding.description?.substring(0, 80) || finding.type || 'Identity exposure finding',
        link: finding.url
      };
    });

    // Brand & Online Exposure Management items
    const brandFindings = findings.filter(f => f.category === 'brand-exposure');
    const brandItems = brandFindings.map(finding => {
      const sevScore = severityRank(finding.severity) * 25;
      return {
        id: `brand-${finding.id}`,
        sourceModule: 'Brand & Online Exposure',
        type: 'Brand Exposure',
        name: finding.keyword || finding.title,
        severity: finding.severity || 'Unknown',
        score: sevScore,
        driver: `${finding.provider} - ${finding.type}`,
        context: finding.description?.substring(0, 80) || finding.type || 'Brand exposure finding',
        link: finding.url
      };
    });

    // Third-Party Risk Management items
    const vendorItems = vendors.map(vendor => {
      const vendorAlerts = alerts.filter(a => `${a.title || ''} ${a.source || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const vendorFindings = findings.filter(f => `${f.keyword || ''} ${f.title || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const adjustedScore = Math.min(100, (vendor.risk_score || 0) + vendorAlerts.length * 5 + vendorFindings.length * 3);
      return {
        id: `vendor-${vendor.id}`,
        sourceModule: 'Third-Party Risk Management',
        type: 'Third Party',
        name: vendor.name,
        severity: normalizeSeverity(adjustedScore),
        score: adjustedScore,
        driver: vendor.notes || 'Vendor assessment score',
        context: `${vendorAlerts.length} alert(s), ${vendorFindings.length} OSINT finding(s), category: ${vendor.category || '-'}`,
        link: null
      };
    });

    const all = [...assetItems, ...digitalRiskItems, ...brandItems, ...vendorItems].sort((a, b) => b.score - a.score);
    if (moduleFilter) return all.filter(item => item.sourceModule === moduleFilter);
    return all;
  }, [assets, vendors, findings, alerts, moduleFilter]);

  const stats = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    prioritized.forEach(a => { counts[a.severity || 'Unknown']++; });
    return counts;
  }, [prioritized]);

  const sourceModules = ['External Asset Discovery', 'Digital Risk & Identity Protection', 'Brand & Online Exposure', 'Third-Party Risk Management'];

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat-Based Vulnerability Prioritization</h1>
          <p className="page-subtitle">Unified remediation priority from External Asset Discovery, Digital Risk, Brand Exposure, and Third-Party Risk data.</p>
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
          <h2 className="section-title" style={{ fontSize: '1rem', margin: 0 }}>Unified Risk Prioritization ({prioritized.length})</h2>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button className={`btn ${!moduleFilter ? 'btn-primary' : 'btn-outline'}`} onClick={() => setModuleFilter('')} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>All</button>
            {sourceModules.map(mod => (
              <button key={mod} className={`btn ${moduleFilter === mod ? 'btn-primary' : 'btn-outline'}`} onClick={() => setModuleFilter(moduleFilter === mod ? '' : mod)} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                {mod.split(' ').slice(0, 2).join(' ')}
              </button>
            ))}
          </div>
        </div>
        <PaginatedTable
          items={prioritized}
          headers={['#', 'Source Module', 'Type', 'Asset / Entity', 'Severity', 'Score', 'Context', 'Link']}
          renderRow={(item, i) => (
            <tr key={item.id}>
              <td style={{ fontWeight: 700, color: 'var(--text-muted)' }}>{i + 1}</td>
              <td style={{ fontSize: '0.75rem', color: 'var(--primary-color)', fontWeight: 600 }}>{item.sourceModule.split(' ').slice(0, 2).join(' ')}</td>
              <td>{item.type}</td>
              <td style={{ fontWeight: 600 }}>{item.name}</td>
              <td><span className={`severity-badge severity-${item.severity || 'Unknown'}`}>{item.severity}</span></td>
              <td>{item.score}</td>
              <td style={{ fontSize: '0.8rem', maxWidth: '250px' }}>{item.context}</td>
              <td>{item.link ? <a href={item.link} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /></a> : '-'}</td>
            </tr>
          )}
        />
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
export function ThreatAnalysis({ alerts, authData }) {
  const [assets, setAssets] = useState([]);
  const [vendors, setVendors] = useState([]);
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    const headers = getAuthHeaders(authData);
    fetch('/api/assets', { headers }).then(res => res.ok ? res.json() : []).then(setAssets).catch(console.error);
    fetch('/api/vendors', { headers }).then(res => res.ok ? res.json() : []).then(setVendors).catch(console.error);
    fetch('/api/osint/findings', { headers }).then(res => res.ok ? res.json() : []).then(setFindings).catch(console.error);
  }, [authData]);

  const phaseData = useMemo(() => {
    const byPhase = {};
    alerts.forEach(a => {
      const phase = a.attack_phase || 'Unknown';
      if (!byPhase[phase]) byPhase[phase] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      byPhase[phase].total++;
      if (a.severity === 'Critical') byPhase[phase].critical++;
      else if (a.severity === 'High') byPhase[phase].high++;
      else if (a.severity === 'Medium') byPhase[phase].medium++;
      else byPhase[phase].low++;
    });
    return Object.entries(byPhase).sort((a, b) => b[1].total - a[1].total);
  }, [alerts]);

  const totalAlerts = alerts.length || 1;

  const correlations = useMemo(() => {
    const assetCorrelations = assets.map(asset => {
      const relAlerts = alerts.filter(alert => matchesAsset(alert, asset));
      const cveAlerts = relAlerts.filter(a => ['NVD', 'GitHub', 'Red Hat'].includes(a.source));
      const iocAlerts = relAlerts.filter(a => ['ThreatFox', 'OTX'].includes(a.source));
      const relFindings = findings.filter(finding => {
        const haystack = `${finding.keyword || ''} ${finding.title || ''} ${finding.description || ''}`.toLowerCase();
        return [asset.domain, asset.ip].filter(Boolean).some(v => haystack.includes(String(v).toLowerCase()));
      });
      const riskScore = Math.min(100, (asset.risk_score || 0) + cveAlerts.reduce((s, a) => s + severityRank(a.severity) * 10, 0) + iocAlerts.length * 15 + relFindings.length * 5);

      // Contextual recommended action
      let action = 'Continue monitoring';
      if (iocAlerts.length > 0) action = `Investigate ${iocAlerts.length} active IOC(s) on ${asset.service || 'service'}`;
      else if (cveAlerts.filter(a => severityRank(a.severity) >= 3).length > 0) action = `Patch ${cveAlerts.filter(a => severityRank(a.severity) >= 3).length} critical/high CVE(s)`;
      else if (asset.port && ![80, 443].includes(asset.port)) action = `Review non-standard port ${asset.port} exposure`;
      else if (relFindings.length > 0) action = `Review ${relFindings.length} OSINT finding(s)`;
      else if (asset.service) action = `Review exposed ${asset.service} service`;

      return {
        id: `asset-${asset.id}`,
        entity: asset.domain || asset.ip || `Asset #${asset.id}`,
        type: 'External Asset',
        alertCount: relAlerts.length,
        cveCount: cveAlerts.length,
        iocCount: iocAlerts.length,
        findingCount: relFindings.length,
        risk: riskScore,
        severity: normalizeSeverity(riskScore),
        action,
        topThreats: relAlerts.slice(0, 3).map(a => ({ source: a.source, severity: a.severity, title: a.externalId || a.title?.substring(0, 40) }))
      };
    });

    const vendorCorrelations = vendors.map(vendor => {
      const vendorAlerts = alerts.filter(alert => `${alert.title || ''} ${alert.source || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const vendorFindings = findings.filter(finding => `${finding.keyword || ''} ${finding.title || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const riskScore = Math.min(100, (vendor.risk_score || 0) + vendorAlerts.length * 5 + vendorFindings.length * 3);

      let action = 'Review vendor exposure and remediation status';
      if (vendorAlerts.filter(a => severityRank(a.severity) >= 3).length > 0) action = `Escalate: ${vendorAlerts.filter(a => severityRank(a.severity) >= 3).length} critical/high alert(s) linked to ${vendor.name}`;
      else if (vendorFindings.length > 0) action = `Review ${vendorFindings.length} OSINT finding(s) for ${vendor.name}`;

      return {
        id: `vendor-${vendor.id}`,
        entity: vendor.name,
        type: 'Third Party',
        alertCount: vendorAlerts.length,
        cveCount: vendorAlerts.filter(a => ['NVD', 'GitHub', 'Red Hat'].includes(a.source)).length,
        iocCount: vendorAlerts.filter(a => ['ThreatFox', 'OTX'].includes(a.source)).length,
        findingCount: vendorFindings.length,
        risk: riskScore,
        severity: normalizeSeverity(riskScore),
        action,
        topThreats: vendorAlerts.slice(0, 3).map(a => ({ source: a.source, severity: a.severity, title: a.externalId || a.title?.substring(0, 40) }))
      };
    });

    return [...assetCorrelations, ...vendorCorrelations]
      .filter(c => c.alertCount > 0 || c.findingCount > 0 || c.risk > 0)
      .sort((a, b) => b.risk - a.risk);
  }, [assets, vendors, findings, alerts]);

  const summaryStats = useMemo(() => ({
    totalEntities: correlations.length,
    highRisk: correlations.filter(c => c.severity === 'Critical' || c.severity === 'High').length,
    avgRisk: correlations.length > 0 ? Math.round(correlations.reduce((s, c) => s + c.risk, 0) / correlations.length) : 0,
    totalIocs: correlations.reduce((s, c) => s + c.iocCount, 0),
    totalCves: correlations.reduce((s, c) => s + c.cveCount, 0)
  }), [correlations]);

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Context-Rich Threat Analysis</h1>
          <p className="page-subtitle">Deep correlation of alerts, IOCs, and OSINT findings per entity with MITRE ATT&CK mapping.</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid var(--primary-color)' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Entities Analyzed</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800 }}>{summaryStats.totalEntities}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>High-Risk Entities</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#f87171' }}>{summaryStats.highRisk}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Avg Risk Score</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fbbf24' }}>{summaryStats.avgRisk}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #8b5cf6' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>IOC Matches</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#a78bfa' }}>{summaryStats.totalIocs}</div>
        </div>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>CVE Correlations</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fb923c' }}>{summaryStats.totalCves}</div>
        </div>
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Entity Threat Correlation</h2>
        {correlations.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2rem' }}>Add assets, vendors, and run OSINT searches to build contextual threat analysis.</p>
        ) : (
          <PaginatedTable
            items={correlations}
            headers={['Entity', 'Type', 'Risk', 'Alerts', 'CVEs', 'IOCs', 'OSINT', 'Top Threats', 'Recommended Action']}
            renderRow={(row) => (
              <tr key={row.id}>
                <td style={{ fontWeight: 600 }}>{row.entity}</td>
                <td>{row.type}</td>
                <td><span className={`severity-badge severity-${row.severity}`}>{row.risk}</span></td>
                <td>{row.alertCount}</td>
                <td style={{ color: row.cveCount > 0 ? '#f87171' : 'var(--text-muted)' }}>{row.cveCount}</td>
                <td style={{ color: row.iocCount > 0 ? '#a78bfa' : 'var(--text-muted)' }}>{row.iocCount}</td>
                <td>{row.findingCount}</td>
                <td style={{ fontSize: '0.75rem', maxWidth: '180px' }}>
                  {row.topThreats.length > 0 ? row.topThreats.map((t, i) => (
                    <div key={i}><span className={`severity-badge severity-${t.severity}`} style={{ fontSize: '0.6rem', marginRight: '0.25rem' }}>{t.severity?.charAt(0)}</span>{t.title}</div>
                  )) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                </td>
                <td style={{ fontSize: '0.8rem' }}>{row.action}</td>
              </tr>
            )}
          />
        )}
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>MITRE ATT&CK Phase Distribution</h2>
        <div className="table-container">
          <table>
            <thead><tr><th>Attack Phase</th><th>Total</th><th style={{ width: '40%' }}>Distribution</th><th>Critical</th><th>High</th><th>Medium</th></tr></thead>
            <tbody>
              {phaseData.map(([phase, data]) => (
                <tr key={phase}>
                  <td style={{ fontWeight: 600 }}>{phase}</td>
                  <td>{data.total}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{ flex: 1, background: 'rgba(255,255,255,0.05)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
                        <div style={{
                          display: 'flex', height: '100%',
                        }}>
                          {data.critical > 0 && <div style={{ width: `${(data.critical / data.total) * 100}%`, background: '#ef4444' }} />}
                          {data.high > 0 && <div style={{ width: `${(data.high / data.total) * 100}%`, background: '#f97316' }} />}
                          {data.medium > 0 && <div style={{ width: `${(data.medium / data.total) * 100}%`, background: '#f59e0b' }} />}
                          {data.low > 0 && <div style={{ width: `${(data.low / data.total) * 100}%`, background: '#3b82f6' }} />}
                        </div>
                      </div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{Math.round((data.total / totalAlerts) * 100)}%</span>
                    </div>
                  </td>
                  <td style={{ color: '#f87171' }}>{data.critical}</td>
                  <td style={{ color: '#fb923c' }}>{data.high}</td>
                  <td style={{ color: '#fbbf24' }}>{data.medium}</td>
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
                <thead><tr><th>Source</th><th>Severity</th><th>Title</th><th>Date</th><th>Link</th></tr></thead>
                <tbody>
                  {assessment.matches.slice(0, 10).map(match => (
                    <tr key={`${match.source}-${match.externalId}-${match.id}`}>
                      <td>{match.source}</td>
                      <td><span className={`severity-badge severity-${match.severity || 'Unknown'}`}>{match.severity || 'Unknown'}</span></td>
                      <td>{match.title?.substring(0, 100)}</td>
                      <td>{match.date ? new Date(match.date).toLocaleDateString() : '-'}</td>
                      <td>{match.url ? <a href={safeUrl(match.url)} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /></a> : '-'}</td>
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
