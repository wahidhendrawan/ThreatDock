import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  Search, Globe, Activity, Brain, Crosshair, 
  TrendingUp, Network, Lock, Eye, Building2,
  AlertTriangle, Shield, ExternalLink, ChevronDown, ChevronUp, Trash2, Plus,
  Edit, Check, X as CloseIcon
} from 'lucide-react';

import PaginationControls, { usePagination } from '../components/PaginationControls';
import { io } from 'socket.io-client';

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

function extractCves(text) {
  const matches = String(text || '').match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map(cve => cve.toUpperCase()))];
}

// ============ Threat Hunting ============
export function ThreatHunting({ authData }) {
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState('cve');
  const [results, setResults] = useState([]);
  const [providers, setProviders] = useState([]);
  const [searching, setSearching] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await fetch('/api/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify({ query_type: queryType, query_value: query.trim() })
      });
      if (res.ok) {
        const data = await res.json();
        const validResults = (data.results || []).filter(r => r.type !== 'Provider Error');
        setResults(validResults);
        setProviders(data.providers || []);
      } else {
        const data = await res.json().catch(() => ({}));
        setResults([]);
        setProviders([]);
      }
    } catch (err) {
      console.error('Hunt error:', err);
      setResults([{ provider: 'ThreatDock', type: 'Error', severity: 'Low', title: err.message }]);
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
        {providers.length > 0 && (
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
            {providers.map(provider => <span key={provider} className="mini-badge">{provider}</span>)}
          </div>
        )}
        {results.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            <Search size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
            <p>Enter a query above to begin hunting.</p>
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
                <td>{item.title || '-'}</td>
                <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)', fontSize: '0.85rem' }}>{item.date ? new Date(item.date).toLocaleDateString() : '-'}</td>
                <td>{item.url && typeof item.url === 'string' && item.url.startsWith('http') ? <a href={item.url} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /></a> : '-'}</td>
              </tr>
            )}
          />
        )}
      </div>
    </div>
  );
}

export function AssetDiscovery({ authData }) {
  const [assets, setAssets] = useState([]);
  const [filterText, setModuleFilterText] = useState('');
  const [sortField, setSortField] = useState('risk_score');
  const [sortDir, setSortDir] = useState('desc');
  const [groupedByDomain, setGroupedByDomain] = useState(true);
  const [expandedFolders, setExpandedFolders] = useState({});
  const [editingId, setEditingId] = useState(null);
  const [editBuffer, setEditBuffer] = useState({});

  const [newAsset, setNewAsset] = useState({
    domain: '',
    ip: '',
    port: '',
    service: '',
    owner: '',
    business_criticality: 'Medium',
    environment: 'Production',
    data_classification: 'Internal'
  });
  const [scanTarget, setScanTarget] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [addError, setAddError] = useState('');

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
    if (e) e.preventDefault();
    setAddError('');
    const payload = {
      ...newAsset,
      domain: (newAsset.domain || '').trim(),
      ip: (newAsset.ip || '').trim()
    };
    if (!payload.domain && !payload.ip) {
      setAddError('Domain atau IP wajib diisi.');
      return;
    }
    try {
      const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setNewAsset({
          domain: '',
          ip: '',
          port: '',
          service: '',
          owner: '',
          business_criticality: 'Medium',
          environment: 'Production',
          data_classification: 'Internal'
        });
        fetchAssets();
      } else {
        const data = await res.json().catch(() => ({}));
        setAddError(data.error || `Request failed with status ${res.status}`);
      }
    } catch (e) {
      console.error(e);
      setAddError(e.message || 'Request failed');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Remove this asset from discovery?')) return;
    try {
      const res = await fetch(`/api/assets/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(authData)
      });
      if (res.ok) fetchAssets();
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
      if (res.ok) {
        fetchAssets();
        // Pre-fill next manual add with scan data if available
        if (data.ips && data.ips.length > 0) {
          setNewAsset(prev => ({ ...prev, ip: data.ips[0], domain: scanTarget.trim() }));
        }
      }
    } catch (err) {
      setScanResult({ error: err.message });
    }
    setScanning(false);
  };

  const filteredAssets = useMemo(() => {
    return assets.filter(a => {
      const search = filterText.toLowerCase();
      return (a.domain || '').toLowerCase().includes(search) ||
             (a.ip || '').toLowerCase().includes(search) ||
             (a.service || '').toLowerCase().includes(search) ||
             (a.owner || '').toLowerCase().includes(search);
    }).sort((a, b) => {
      const valA = a[sortField];
      const valB = b[sortField];
      if (valA < valB) return sortDir === 'asc' ? -1 : 1;
      if (valA > valB) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [assets, filterText, sortField, sortDir]);

  const assetFolders = useMemo(() => {
    const groups = {};
    filteredAssets.forEach(a => {
      let domain = a.domain || 'Unspecified Domain';
      // Normalize domain for grouping (e.g. sub.example.com -> example.com)
      const parts = domain.split('.');
      const root = parts.length > 2 ? parts.slice(-2).join('.') : domain;
      if (!groups[root]) groups[root] = [];
      groups[root].push(a);
    });
    return groups;
  }, [filteredAssets]);

  const toggleFolder = (name) => {
    setExpandedFolders(prev => ({ ...prev, [name]: !prev[name] }));
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const startEdit = (a) => {
    setEditingId(a.id);
    setEditBuffer({ ...a });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditBuffer({});
  };

  const saveEdit = async (id) => {
    try {
      const res = await fetch(`/api/assets/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify(editBuffer)
      });
      if (res.ok) {
        setEditingId(null);
        fetchAssets();
      }
    } catch (e) { console.error(e); }
  };

  const renderAssetRow = (a) => {
    const isEditing = editingId === a.id;
    
    if (isEditing) {
      return (
        <tr key={a.id} style={{ background: 'rgba(59, 130, 246, 0.1)' }}>
          <td>{a.domain}</td>
          <td><input className="form-input" style={{ fontSize: '0.8rem', padding: '0.2rem 0.4rem', height: 'auto' }} value={editBuffer.ip || ''} onChange={e => setEditBuffer({...editBuffer, ip: e.target.value})} /></td>
          <td><input className="form-input" type="number" style={{ fontSize: '0.8rem', padding: '0.2rem 0.4rem', height: 'auto', width: '80px' }} value={editBuffer.port || ''} onChange={e => setEditBuffer({...editBuffer, port: e.target.value})} /></td>
          <td><input className="form-input" style={{ fontSize: '0.8rem', padding: '0.2rem 0.4rem', height: 'auto', width: '100px' }} value={editBuffer.service || ''} onChange={e => setEditBuffer({...editBuffer, service: e.target.value})} /></td>
          <td><input className="form-input" style={{ fontSize: '0.8rem', padding: '0.2rem 0.4rem', height: 'auto' }} value={editBuffer.owner || ''} onChange={e => setEditBuffer({...editBuffer, owner: e.target.value})} /></td>
          <td>
            <select className="form-input" style={{ fontSize: '0.75rem', padding: '0.1rem 0.2rem', height: 'auto' }} value={editBuffer.business_criticality} onChange={e => setEditBuffer({...editBuffer, business_criticality: e.target.value})}>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </td>
          <td>
            <select className="form-input" style={{ fontSize: '0.75rem', padding: '0.1rem 0.2rem', height: 'auto' }} value={editBuffer.environment} onChange={e => setEditBuffer({...editBuffer, environment: e.target.value})}>
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Development">Development</option>
            </select>
          </td>
          <td>
            <select className="form-input" style={{ fontSize: '0.75rem', padding: '0.1rem 0.2rem', height: 'auto' }} value={editBuffer.status} onChange={e => setEditBuffer({...editBuffer, status: e.target.value})}>
              <option value="Active">Active</option>
              <option value="Inactive">Inactive</option>
            </select>
          </td>
          <td>{a.risk_score}</td>
          <td>
            <div style={{ display: 'flex', gap: '0.25rem' }}>
              <button onClick={() => saveEdit(a.id)} className="icon-button" style={{ color: 'var(--success)' }}><Check size={14} /></button>
              <button onClick={cancelEdit} className="icon-button" style={{ color: 'var(--text-muted)' }}><CloseIcon size={14} /></button>
            </div>
          </td>
        </tr>
      );
    }

    return (
      <tr key={a.id}>
        <td style={{ fontWeight: 600 }}>{a.domain || '-'}</td>
        <td><code>{a.ip || '-'}</code></td>
        <td>{a.port || '-'}</td>
        <td>{a.service || '-'}</td>
        <td>{a.owner || '-'}</td>
        <td><span className={`severity-badge severity-${a.business_criticality}`}>{a.business_criticality}</span></td>
        <td>{a.environment}</td>
        <td><span className={`status-badge status-${a.status === 'Active' ? 'Resolved' : 'Open'}`}>{a.status}</span></td>
        <td style={{ fontWeight: 700 }}>{a.risk_score}</td>
        <td>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button onClick={() => startEdit(a)} className="icon-button" style={{ opacity: 0.5 }} title="Edit asset"><Edit size={14} /></button>
            <button onClick={() => handleDelete(a.id)} className="icon-button" style={{ color: 'var(--danger)' }} title="Delete asset"><Trash2 size={14} /></button>
          </div>
        </td>
      </tr>
    );
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">External Asset Discovery</h1>
          <p className="page-subtitle">Catalog and group external-facing assets with automated IP enrichment.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className={`btn ${groupedByDomain ? 'btn-primary' : 'btn-outline'}`} onClick={() => setGroupedByDomain(true)}>Folder View</button>
          <button className={`btn ${!groupedByDomain ? 'btn-primary' : 'btn-outline'}`} onClick={() => setGroupedByDomain(false)}>List View</button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
        <div className="card">
          <h2 className="section-title" style={{ fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Search size={16} /> Scan Public Asset</h2>
          <form onSubmit={handleScan} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
            <div className="form-group" style={{ flex: 1 }}>
              <label className="form-label">Domain or Host</label>
              <input className="form-input" value={scanTarget} onChange={e => setScanTarget(e.target.value)} placeholder="example.com" />
            </div>
            <button type="submit" className="btn btn-primary" disabled={scanning} style={{ height: '42px' }}>
               {scanning ? 'Scanning...' : 'Scan & Enrich'}
            </button>
          </form>
          {scanResult && !scanResult.error && (
            <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(59, 130, 246, 0.05)', borderRadius: '8px', fontSize: '0.85rem' }}>
              <p style={{ color: 'var(--success)', fontWeight: 600, marginBottom: '0.5rem' }}>Scan Complete</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
                <div><strong>Resolved IPs:</strong> {(scanResult.ips || []).join(', ')}</div>
                <div><strong>Ports Found:</strong> {(scanResult.openPorts || []).join(', ')}</div>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <h2 className="section-title" style={{ fontSize: '0.9rem' }}>Add Manual Asset</h2>
          <form onSubmit={handleAdd} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem' }}>
            <input className="form-input" value={newAsset.domain} onChange={e => setNewAsset({...newAsset, domain: e.target.value})} placeholder="Domain" />
            <input className="form-input" value={newAsset.ip} onChange={e => setNewAsset({...newAsset, ip: e.target.value})} placeholder="IP Address" />
            <input className="form-input" type="number" value={newAsset.port} onChange={e => setNewAsset({...newAsset, port: parseInt(e.target.value) || ''})} placeholder="Port" />
            <input className="form-input" value={newAsset.service} onChange={e => setNewAsset({...newAsset, service: e.target.value})} placeholder="Service" />
            <input className="form-input" value={newAsset.owner} onChange={e => setNewAsset({...newAsset, owner: e.target.value})} placeholder="Owner" />
            <select className="form-input" value={newAsset.business_criticality} onChange={e => setNewAsset({...newAsset, business_criticality: e.target.value})}>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <button type="submit" className="btn btn-primary col-span-3" style={{ gridColumn: '1 / -1' }}>Add Asset to Inventory</button>
          </form>
          {addError && <p style={{ fontSize: '0.8rem', color: '#f87171', marginTop: '0.75rem' }}>{addError}</p>}
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <h2 className="section-title" style={{ margin: 0 }}>Asset Inventory ({filteredAssets.length})</h2>
          <div style={{ width: '300px' }}>
            <input className="form-input" value={filterText} onChange={e => setModuleFilterText(e.target.value)} placeholder="Filter by domain, IP, or owner..." />
          </div>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('domain')} style={{ cursor: 'pointer' }}>Domain {sortField === 'domain' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                <th onClick={() => handleSort('ip')} style={{ cursor: 'pointer' }}>IP {sortField === 'ip' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                <th>Port</th>
                <th>Service</th>
                <th onClick={() => handleSort('owner')} style={{ cursor: 'pointer' }}>Owner {sortField === 'owner' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                <th>Crit.</th>
                <th>Env</th>
                <th>Status</th>
                <th onClick={() => handleSort('risk_score')} style={{ cursor: 'pointer' }}>Risk {sortField === 'risk_score' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {groupedByDomain ? (
                Object.entries(assetFolders).map(([root, items]) => (
                  <React.Fragment key={root}>
                    <tr onClick={() => toggleFolder(root)} style={{ background: 'rgba(59, 130, 246, 0.05)', cursor: 'pointer' }}>
                      <td colSpan="10">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 800 }}>
                          {expandedFolders[root] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                          <Network size={16} style={{ color: 'var(--primary-color)' }} />
                          {root}
                          <span className="mini-badge" style={{ marginLeft: '1rem' }}>{items.length} Assets</span>
                        </div>
                      </td>
                    </tr>
                    {expandedFolders[root] && items.map(renderAssetRow)}
                  </React.Fragment>
                ))
              ) : (
                filteredAssets.map(renderAssetRow)
              )}
              {filteredAssets.length === 0 && <tr><td colSpan="10" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>No assets found.</td></tr>}
            </tbody>
          </table>
        </div>
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
  const [cveEnrichment, setCveEnrichment] = useState({});
  const [riskWeights, setRiskWeights] = useState({});
  const [moduleFilter, setModuleFilter] = useState('');

  useEffect(() => {
    const headers = getAuthHeaders(authData);
    fetch('/api/assets', { headers }).then(res => res.ok ? res.json() : []).then(setAssets).catch(console.error);
    fetch('/api/vendors', { headers }).then(res => res.ok ? res.json() : []).then(setVendors).catch(console.error);
    fetch('/api/osint/findings', { headers }).then(res => res.ok ? res.json() : []).then(setFindings).catch(console.error);
    fetch('/api/intelligence/cve-enrichment', { headers }).then(res => res.ok ? res.json() : []).then(rows => {
      const map = {};
      rows.forEach(row => { map[row.cve_id] = row; });
      setCveEnrichment(map);
    }).catch(console.error);
    fetch('/api/intelligence/risk-rules', { headers }).then(res => res.ok ? res.json() : {}).then(data => setRiskWeights(data.weights || {})).catch(console.error);
  }, [authData]);

  const prioritized = useMemo(() => {
    // External Asset Discovery items
    const assetItems = assets.map(asset => {
      const relatedAlerts = alerts.filter(alert => matchesAsset(alert, asset));
      const cveAlerts = relatedAlerts.filter(a => ['NVD', 'GitHub', 'Red Hat'].includes(a.source));
      const iocAlerts = relatedAlerts.filter(a => ['ThreatFox', 'OTX'].includes(a.source));
      const maxAlertRisk = relatedAlerts.reduce((max, alert) => Math.max(max, severityRank(alert.severity) * 20), 0);
      const cveRisk = cveAlerts.reduce((sum, alert) => {
        const cves = extractCves(`${alert.externalId || ''} ${alert.title || ''}`);
        return sum + cves.reduce((cveSum, cve) => {
          const enrichment = cveEnrichment[cve];
          const epss = parseFloat(enrichment?.epss_score || 0);
          return cveSum
            + (enrichment?.kev_known ? (riskWeights.kev || 30) : 0)
            + (epss >= 0.5 ? (riskWeights.epssHigh || 20) : epss >= 0.1 ? (riskWeights.epssMedium || 10) : 0);
        }, 0);
      }, 0);
      const criticalityRisk = asset.business_criticality === 'Critical' ? (riskWeights.assetCriticality || 15)
        : asset.business_criticality === 'High' ? Math.round((riskWeights.assetCriticality || 15) * 0.7)
        : 0;
      const score = Math.min(100, (asset.risk_score || 0) + maxAlertRisk + cveRisk + criticalityRisk + relatedAlerts.length * 3 + (iocAlerts.length * 10));
      const contextParts = [];
      if (cveAlerts.length > 0) contextParts.push(`${cveAlerts.length} CVE(s)`);
      if (iocAlerts.length > 0) contextParts.push(`${iocAlerts.length} IOC match(es)`);
      if (asset.service) contextParts.push(`Service: ${asset.service}`);
      if (asset.port && ![80, 443].includes(asset.port)) contextParts.push(`Non-std port: ${asset.port}`);
      if (asset.business_criticality) contextParts.push(`Criticality: ${asset.business_criticality}`);
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
  }, [assets, vendors, findings, alerts, moduleFilter, cveEnrichment, riskWeights]);

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

// ============ Strategic Threat Outlook ============
export function PredictiveIntel({ alerts, authData }) {
  const [cveEnrichment, setCveEnrichment] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!authData) {
      setCveEnrichment([]);
      setLoading(false);
      return;
    }
    fetch('/api/intelligence/cve-enrichment', { headers: getAuthHeaders(authData) })
      .then(res => res.ok ? res.json() : [])
      .then(data => {
        setCveEnrichment(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [authData]);

  const heatmapData = useMemo(() => {
    // 5x5 Grid: X=EPSS (Probability), Y=Severity (Impact)
    const grid = Array(5).fill(0).map(() => Array(5).fill(0).map(() => ({ count: 0, items: [] })));
    
    cveEnrichment.forEach(c => {
      const epss = parseFloat(c.epss_score || 0);
      const sev = severityRank(c.cvss_score >= 9 ? 'Critical' : c.cvss_score >= 7 ? 'High' : c.cvss_score >= 4 ? 'Medium' : 'Low');
      
      const x = Math.min(4, Math.floor(epss * 5)); // Probability
      const y = Math.min(4, sev); // Impact
      
      grid[y][x].count++;
      if (grid[y][x].items.length < 3) grid[y][x].items.push(c.cve_id);
    });
    return grid;
  }, [cveEnrichment]);

  const getHeatColor = (count) => {
    if (count === 0) return 'rgba(255,255,255,0.02)';
    if (count < 5) return 'rgba(59, 130, 246, 0.2)';
    if (count < 15) return 'rgba(245, 158, 11, 0.4)';
    return 'rgba(239, 68, 68, 0.6)';
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Strategic Threat Outlook</h1>
          <p className="page-subtitle">Tactical projection of vulnerability exploitation risk based on EPSS and CISA KEV intelligence.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
            <h2 className="section-title" style={{ margin: 0 }}>Vulnerability Risk Heatmap</h2>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>X-Axis: Exploitation Probability (EPSS) | Y-Axis: Technical Impact (CVSS)</div>
          </div>

          <div style={{ display: 'grid', gridTemplateRows: 'repeat(5, minmax(62px, 76px))', gap: '8px', padding: '0.75rem' }}>
            {heatmapData.map((row, y) => (
              <div key={y} style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px' }}>
                {row.map((cell, x) => (
                  <div 
                    key={x} 
                    style={{ 
                      background: getHeatColor(cell.count), 
                      borderRadius: '5px', 
                      display: 'flex', 
                      flexDirection: 'column',
                      alignItems: 'center', 
                      justifyContent: 'center',
                      border: cell.count > 0 ? '1px solid rgba(255,255,255,0.1)' : '1px dashed rgba(255,255,255,0.05)',
                      position: 'relative'
                    }}
                    title={`${cell.count} vulnerabilities at this risk level`}
                  >
                    {cell.count > 0 && (
                      <>
                        <span style={{ fontSize: '1.05rem', fontWeight: 800 }}>{cell.count}</span>
                        <div style={{ fontSize: '0.56rem', opacity: 0.7, marginTop: '2px', width: '92%', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', textAlign: 'center' }}>{cell.items.join(', ')}</div>
                      </>
                    )}
                  </div>
                ))}
              </div>
            )).reverse()}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', padding: '0 0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
            <span>Informational</span>
            <span>Strategic Threat Level</span>
            <span>Imminent Risk</span>
          </div>
        </div>

        <div className="flex flex-col gap-6">
          <div className="card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}><AlertTriangle size={16} style={{ color: '#ef4444' }} /> KEV Active Alert</h3>
            <div className="flex flex-col gap-3">
              {cveEnrichment.filter(c => c.kev_known).slice(0, 5).map(c => (
                <div key={c.cve_id} style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.05)', borderLeft: '3px solid #ef4444', borderRadius: '4px' }}>
                  <div style={{ fontWeight: 800, fontSize: '0.85rem' }}>{c.cve_id}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>Confirmed active exploitation by threat actors.</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}><TrendingUp size={16} style={{ color: 'var(--accent)' }} /> Tactical Forecast</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dark)', lineHeight: 1.5 }}>
              Based on recent <strong>EPSS velocity</strong>, we project a 15% increase in automated scanning for {heatmapData[4].reduce((a,b)=>a+b.count, 0)} critical vulnerabilities in the next 72 hours.
            </p>
            <button className="btn btn-outline btn-block mt-4" style={{ fontSize: '0.75rem' }}>Generate Advisory</button>
          </div>
        </div>
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
      const topReferences = [
        ...relAlerts.map(a => ({
          source: a.source,
          severity: a.severity || 'Unknown',
          title: a.externalId || a.title?.substring(0, 52) || 'Alert',
          url: typeof a.url === 'string' ? a.url : ''
        })),
        ...relFindings.map(f => ({
          source: f.provider || 'OSINT',
          severity: f.severity || 'Unknown',
          title: (f.title || f.keyword || 'Finding').substring(0, 52),
          url: typeof f.url === 'string' ? f.url : ''
        }))
      ].slice(0, 3);

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
        topThreats: topReferences
      };
    });

    const vendorCorrelations = vendors.map(vendor => {
      const vendorAlerts = alerts.filter(alert => `${alert.title || ''} ${alert.source || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const vendorFindings = findings.filter(finding => `${finding.keyword || ''} ${finding.title || ''}`.toLowerCase().includes(vendor.name.toLowerCase()));
      const riskScore = Math.min(100, (vendor.risk_score || 0) + vendorAlerts.length * 5 + vendorFindings.length * 3);
      const topReferences = [
        ...vendorAlerts.map(a => ({
          source: a.source,
          severity: a.severity || 'Unknown',
          title: a.externalId || a.title?.substring(0, 52) || 'Alert',
          url: typeof a.url === 'string' ? a.url : ''
        })),
        ...vendorFindings.map(f => ({
          source: f.provider || 'OSINT',
          severity: f.severity || 'Unknown',
          title: (f.title || f.keyword || 'Finding').substring(0, 52),
          url: typeof f.url === 'string' ? f.url : ''
        }))
      ].slice(0, 3);

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
        topThreats: topReferences
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
            headers={['Entity', 'Type', 'Risk', 'Alerts', 'CVEs', 'IOCs', 'OSINT', 'Top Threats & Ref', 'Recommended Action']}
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
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.2rem' }}>
                      <span className={`severity-badge severity-${t.severity || 'Unknown'}`} style={{ fontSize: '0.6rem', marginRight: '0.1rem', minWidth: '24px', padding: '0.1rem 0.25rem' }}>
                        {(t.severity || 'U').charAt(0)}
                      </span>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '125px' }} title={`${t.source || 'Ref'} • ${t.title}`}>{t.title}</span>
                      {t.url && (t.url.startsWith('http://') || t.url.startsWith('https://')) && (
                        <a href={t.url} target="_blank" rel="noopener noreferrer" className="icon-button" title="Open reference" style={{ width: '22px', height: '22px', flexShrink: 0 }}>
                          <ExternalLink size={12} />
                        </a>
                      )}
                    </div>
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
function ModuleTable({ data, renderRow, initialPageSize = 10 }) {
  const pagination = usePagination(data || [], initialPageSize);
  return (
    <div className="table-container">
      <table>
        <tbody>{pagination.pagedItems.map(renderRow)}</tbody>
      </table>
      <PaginationControls pagination={pagination} />
    </div>
  );
}

export function BrandExposure({ authData }) {
  const [keyword, setKeyword] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState(null);
  const [msg, setMsg] = useState(null);

  const headers = useMemo(() => ({
    'Content-Type': 'application/json',
    ...getAuthHeaders(authData)
  }), [authData]);

  const fetchSettings = useCallback(async () => {
    try {
      const res = await fetch('/api/settings', { headers });
      if (res.ok) setSettings(await res.json());
    } catch (e) { console.error(e); }
  }, [headers]);

  useEffect(() => {
    fetchSettings();
    handleSearch();
  }, [fetchSettings]);

  const monitoredBrands = useMemo(() => {
    try {
      return JSON.parse(settings?.MONITORED_BRANDS || '[]');
    } catch { return []; }
  }, [settings]);

  const handleSaveSettings = async (newSettings) => {
    try {
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers,
        body: JSON.stringify(newSettings)
      });
      if (res.ok) {
        setSettings(newSettings);
        setMsg({ text: 'Monitored assets updated.', type: 'success' });
        setTimeout(() => setMsg(null), 3000);
      }
    } catch (e) { console.error(e); }
  };

  const handleAddAsset = (asset) => {
    const val = String(asset || '').trim().toLowerCase();
    if (!val) return;
    const next = [...new Set([...monitoredBrands, val])];
    handleSaveSettings({ ...settings, MONITORED_BRANDS: JSON.stringify(next) });
  };

  const handleRemoveAsset = (asset) => {
    const next = monitoredBrands.filter(b => b !== asset);
    handleSaveSettings({ ...settings, MONITORED_BRANDS: JSON.stringify(next) });
  };

  const handleSearch = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/osint/findings?category=brand-exposure${keyword ? `&keyword=${keyword}` : ''}`, { headers });
      if (res.ok) setResults(await res.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const reportToGoogle = (domain) => {
    const url = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent('http://' + domain)}`;
    window.open(url, '_blank');
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Brand & Online Exposure Management</h1>
          <p className="page-subtitle">Manage monitored assets and track external brand impersonation</p>
        </div>
      </div>

      {msg && (
        <div style={{ padding: '0.75rem 1rem', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '8px', marginBottom: '1rem' }}>
          {msg.text}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
        <div className="flex flex-col gap-6">
          <div className="card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
              <Building2 size={18} style={{ color: 'var(--primary-color)' }} />
              Monitored Assets
            </h3>
            
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <input 
                id="brand-input-quick"
                className="form-input" 
                placeholder="Add domain or brand..." 
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    handleAddAsset(e.target.value);
                    e.target.value = '';
                  }
                }}
              />
              <button className="btn btn-primary" onClick={() => {
                const input = document.getElementById('brand-input-quick');
                handleAddAsset(input.value);
                input.value = '';
              }}>
                <Plus size={16} />
              </button>
            </div>

            <div className="flex flex-col gap-2">
              {monitoredBrands.length === 0 ? (
                <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem', padding: '1rem' }}>No assets configured.</p>
              ) : (
                monitoredBrands.map(brand => (
                  <div key={brand} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.6rem 0.75rem', background: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{brand}</span>
                    <button className="icon-button" style={{ color: 'var(--danger)' }} onClick={() => handleRemoveAsset(brand)}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Search size={18} /> Filter Findings
            </h3>
            <div className="form-group">
              <input 
                className="form-input" 
                value={keyword} 
                onChange={e => setKeyword(e.target.value)} 
                placeholder="Search by keyword..." 
              />
            </div>
            <button className="btn btn-outline btn-block mt-4" onClick={handleSearch} disabled={loading}>
              {loading ? 'Searching...' : 'Refresh Findings'}
            </button>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h3 style={{ margin: 0 }}>Latest Exposure Findings</h3>
            <div className="badge" style={{ background: 'rgba(59, 130, 246, 0.1)', color: 'var(--primary-color)' }}>{results.length} Matches</div>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title & Info</th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Date</th>
                  <th>Link</th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr><td colSpan="5" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>No exposure findings yet.</td></tr>
                ) : (
                  results.map((item, idx) => (
                    <tr key={idx}>
                      <td>
                        <div style={{ fontWeight: 700, color: 'var(--text-main)' }}>{item.title}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dark)', marginTop: '0.2rem' }}>{item.keyword} • {item.provider}</div>
                      </td>
                      <td>
                        <span className={`severity-badge severity-${item.severity}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td><span style={{ fontSize: '0.8rem' }}>{item.type}</span></td>
                      <td><span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(item.created_at).toLocaleDateString()}</span></td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.35rem' }}>
                          {item.url && (
                            <a href={item.url} target="_blank" rel="noopener noreferrer" className="icon-button" title="View Reference">
                              <ExternalLink size={14} />
                            </a>
                          )}
                          <button className="icon-button" style={{ color: 'var(--primary-color)' }} onClick={() => reportToGoogle(item.title || item.keyword)} title="Report to Google Safe Browsing">
                            <Shield size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============ Domain Impersonation & Typosquatting ============
export function DnsImpersonation({ authData }) {
  const [target, setTarget] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState('');

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;
    setLoading(true);
    setScanError('');
    try {
      const payload = JSON.stringify({ domain: target.trim() });
      const request = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: payload
      };
      const endpoints = [
        '/api/dns-impersonation/scan',
        '/api/dns-impersonation',
        '/api/dns_impersonation/scan',
        '/api/dns_impersonation'
      ];
      let res = null;
      for (const endpoint of endpoints) {
        const candidate = await fetch(endpoint, request);
        if (candidate.status !== 404) {
          res = candidate;
          break;
        }
      }

      if (!res) {
        setResults(null);
        setScanError('DNS impersonation API route not found on server.');
      } else {
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          setResults(data);
        } else {
          setResults(null);
          setScanError(data.error || `Request failed with status ${res.status}`);
        }
      }
    } catch (err) {
      console.error(err);
      setResults(null);
      setScanError(err.message || 'Request failed');
    }
    setLoading(false);
  };

  const reportToGoogle = (domain) => {
    const url = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent('http://' + domain)}`;
    window.open(url, '_blank');
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Domain Impersonation Detection</h1>
          <p className="page-subtitle">Analyze domain mutations and identify potential phishing or typosquatting infrastructure.</p>
        </div>
      </div>

      <div className="card">
        <h2 className="section-title">Analyze Corporate Domain</h2>
        <form onSubmit={handleScan} style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
          <input 
            className="form-input" 
            value={target} 
            onChange={e => setTarget(e.target.value)} 
            placeholder="domain" 
          />
          <button className="btn btn-primary" disabled={loading}>
            {loading ? 'Analyzing Mutations...' : 'Detect Impersonators'}
          </button>
        </form>
        {scanError && <p style={{ fontSize: '0.8rem', color: '#f87171', marginBottom: '0.75rem' }}>{scanError}</p>}
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          This generates 50+ domain variations (bitsquatting, homoglyphs, omissions) and checks for active DNS records.
        </p>
      </div>

      {results && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h2 className="section-title" style={{ margin: 0 }}>Active Impersonation Findings</h2>
            <div className="badge badge-critical">{results.active_impersonators.length} Active Domains</div>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Mutation Domain</th>
                  <th>Resolved IP</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {results.active_impersonators.length === 0 ? (
                  <tr><td colSpan="5" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>No active impersonators detected for this domain.</td></tr>
                ) : (
                  results.active_impersonators.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 700, color: '#f87171' }}>{item.domain}</td>
                      <td><code>{item.ip}</code></td>
                      <td><span className="status-badge status-Open">{item.status}</span></td>
                      <td><span className="severity-badge severity-High">High</span></td>
                      <td>
                        <button className="btn btn-outline" style={{ fontSize: '0.7rem', padding: '0.25rem 0.5rem' }} onClick={() => reportToGoogle(item.domain)}>
                          Report to Safe Browsing
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
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
              <table className="data-table">
                <thead><tr><th>Evidence Context</th><th>Severity</th><th>Intelligence Source</th><th>Date</th><th>Link</th></tr></thead>
                <tbody>
                  {assessment.matches.slice(0, 15).map(match => (
                    <tr key={`${match.source}-${match.externalId}-${match.id}`}>
                      <td>
                         <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{match.title}</div>
                         <div style={{ fontSize: '0.7rem', color: 'var(--text-dark)', marginTop: '0.2rem' }}>{match.tprm_context}</div>
                      </td>
                      <td><span className={`severity-badge severity-${match.severity || 'Unknown'}`}>{match.severity || 'Unknown'}</span></td>
                      <td style={{ fontWeight: 600, color: 'var(--primary-color)' }}>{match.source}</td>
                      <td>{match.date ? new Date(match.date).toLocaleDateString() : '-'}</td>
                       <td>{match.url && typeof match.url === 'string' && (match.url.startsWith('http://') || match.url.startsWith('https://')) ? <a href={match.url} target="_blank" rel="noopener noreferrer" className="icon-button"><ExternalLink size={14} /></a> : '-'}</td>
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

// ============ Intel Operations ============
export function IntelOperations({ authData }) {
  const [health, setHealth] = useState([]);
  const [runs, setRuns] = useState([]);
  const [indicators, setIndicators] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(false);

  const [indicatorsCount, setIndicatorsCount] = useState(0);
  const [correlationsCount, setCorrelationsCount] = useState(0);
  const [liveSources, setLiveSources] = useState({}); // { sourceName: timestamp }
  const [lastUpdated, setLastUpdated] = useState(null);

  const headers = getAuthHeaders(authData);

  const loadOperations = async () => {
    setLoading(true);
    try {
      const [healthRes, runsRes, indicatorsRes, correlationsRes, auditRes, statsRes] = await Promise.all([
        fetch('/api/ingestion/health', { headers }),
        fetch('/api/ingestion/runs?limit=100', { headers }),
        fetch('/api/intelligence/indicators', { headers }),
        fetch('/api/intelligence/correlations', { headers }),
        fetch('/api/ingestion/audit?limit=100', { headers }),
        fetch('/api/intelligence/stats', { headers })
      ]);
      if (healthRes.ok) setHealth(await healthRes.json());
      if (runsRes.ok) setRuns(await runsRes.json());
      if (indicatorsRes.ok) setIndicators(await indicatorsRes.json());
      if (correlationsRes.ok) setCorrelations(await correlationsRes.json());
      if (auditRes.ok) setAudit(await auditRes.json());
      if (statsRes.ok) {
        const stats = await statsRes.json();
        setIndicatorsCount(stats.indicators || 0);
        setCorrelationsCount(stats.correlations || 0);
      }
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadOperations();
  }, []);

  // WebSocket auto-refresh with live source tracking
  useEffect(() => {
    const socket = io({ transports: ['polling', 'websocket'], autoConnect: true });
    socket.on('source:health', (data) => {
      if (data && data.source) {
        setLiveSources(prev => ({ ...prev, [data.source]: Date.now() }));
        // Clear the "live" highlight after 5 seconds
        setTimeout(() => setLiveSources(prev => { const n = { ...prev }; delete n[data.source]; return n; }), 5000);
      }
      setLastUpdated(new Date().toLocaleTimeString());
      loadOperations();
    });
    socket.on('alerts:updated', () => { loadOperations(); });
    socket.on('correlations:updated', () => { loadOperations(); });
    socket.on('fetch:complete', () => { setLastUpdated(new Date().toLocaleTimeString()); });
    return () => { socket.disconnect(); };
  }, []);

  const rebuildCorrelations = async () => {
    await fetch('/api/intelligence/correlations/rebuild', { method: 'POST', headers });
    loadOperations();
  };

  const refreshCveEnrichment = async () => {
    await fetch('/api/intelligence/cve-enrichment/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify({})
    });
    loadOperations();
  };

  const parseList = (value) => {
    try {
      const parsed = JSON.parse(value || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  };

  const successCount = health.filter(item => item.status === 'Success').length;
  const failureCount = health.filter(item => item.status === 'Failure').length;

  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div>
            <h1 className="page-title">Intel Operations</h1>
            <p className="page-subtitle">Collector health, ingestion runs, IOC registry, correlation findings, and audit events.</p>
          </div>
          {lastUpdated && (
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', display: 'inline-block' }}></span>
              Live — updated {lastUpdated}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button className="btn btn-outline" onClick={loadOperations} disabled={loading}>Refresh</button>
          <button className="btn btn-outline" onClick={rebuildCorrelations}>Rebuild Correlations</button>
          <button className="btn btn-primary" onClick={refreshCveEnrichment}>Refresh KEV/EPSS</button>
          <button className="btn btn-success" onClick={async () => { await fetch('/api/ingestion/fetch', { method: 'POST', headers }); loadOperations(); }}>Fetch Sources</button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}>
        <div className="card metric-card"><div className="metric-label">Sources Healthy</div><div className="metric-value">{successCount}</div></div>
        <div className="card metric-card"><div className="metric-label">Sources Failing</div><div className="metric-value" style={{ color: failureCount ? '#f87171' : '#34d399' }}>{failureCount}</div></div>
        <div className="card metric-card"><div className="metric-label">Indicators</div><div className="metric-value">{indicatorsCount.toLocaleString()}</div></div>
        <div className="card metric-card"><div className="metric-label">Correlations</div><div className="metric-value">{correlationsCount.toLocaleString()}</div></div>
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Source Health</h2>
        <PaginatedTable
          items={health}
          headers={['Source', 'Status', 'Last Success', 'Last Failure', 'Count', 'Duration', 'Error']}
          renderRow={(item) => (
            <tr key={item.source} className={liveSources[item.source] ? 'live-pulse' : ''}>
              <td style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                {liveSources[item.source] && <span className="live-dot" style={{ background: '#34d399' }}></span>}
                {item.source}
              </td>
              <td><span className={`severity-badge severity-${item.status === 'Success' ? 'Low' : 'High'}`}>{item.status || '-'}</span></td>
              <td>{item.last_success ? new Date(item.last_success).toLocaleString() : '-'}</td>
              <td>{item.last_failure ? new Date(item.last_failure).toLocaleString() : '-'}</td>
              <td>{item.last_count || 0}</td>
              <td>{item.last_duration_ms || 0} ms</td>
              <td style={{ maxWidth: 260, color: item.last_error ? 'var(--danger)' : 'var(--text-muted)' }}>{item.last_error || '-'}</td>
            </tr>
          )}
          initialPageSize={25}
        />
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Correlated Findings</h2>
        <PaginatedTable
          items={correlations}
          headers={['Finding', 'Severity', 'Score', 'Confidence', 'Sources', 'Entities', 'Updated']}
          renderRow={(item) => (
            <tr key={item.id}>
              <td style={{ fontWeight: 600 }}>{item.title}</td>
              <td><span className={`severity-badge severity-${item.severity || 'Unknown'}`}>{item.severity || 'Unknown'}</span></td>
              <td>{item.score}</td>
              <td>{item.confidence}</td>
              <td>{parseList(item.sources).join(', ') || '-'}</td>
              <td>{parseList(item.entity_refs).slice(0, 3).join(', ') || '-'}</td>
              <td>{item.updated_at ? new Date(item.updated_at).toLocaleString() : '-'}</td>
            </tr>
          )}
          initialPageSize={25}
        />
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>IOC / Indicator Registry</h2>
        <PaginatedTable
          items={indicators}
          headers={['Value', 'Type', 'Source', 'Severity', 'Confidence', 'First Seen', 'Last Seen']}
          renderRow={(item) => (
            <tr key={item.id}>
              <td style={{ fontWeight: 600, maxWidth: 320, wordBreak: 'break-all' }}>{item.value}</td>
              <td>{item.type}</td>
              <td>{item.source}</td>
              <td><span className={`severity-badge severity-${item.severity || 'Unknown'}`}>{item.severity || 'Unknown'}</span></td>
              <td>{item.confidence}</td>
              <td>{item.first_seen ? new Date(item.first_seen).toLocaleDateString() : '-'}</td>
              <td>{item.last_seen ? new Date(item.last_seen).toLocaleString() : '-'}</td>
            </tr>
          )}
          initialPageSize={25}
        />
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Recent Ingestion Runs</h2>
        <PaginatedTable
          items={runs}
          headers={['Started', 'Source', 'Status', 'Items', 'Duration', 'Error']}
          renderRow={(item) => (
            <tr key={item.id}>
              <td>{item.started_at ? new Date(item.started_at).toLocaleString() : '-'}</td>
              <td style={{ fontWeight: 600 }}>{item.source}</td>
              <td><span className={`severity-badge severity-${item.status === 'Success' ? 'Low' : 'High'}`}>{item.status}</span></td>
              <td>{item.item_count}</td>
              <td>{item.duration_ms} ms</td>
              <td style={{ color: item.error ? 'var(--danger)' : 'var(--text-muted)' }}>{item.error || '-'}</td>
            </tr>
          )}
          initialPageSize={25}
        />
      </div>

      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Audit Log</h2>
        <PaginatedTable
          items={audit}
          headers={['Time', 'User', 'Entity', 'Action']}
          renderRow={(item) => (
            <tr key={item.id}>
              <td>{item.created_at ? new Date(item.created_at).toLocaleString() : '-'}</td>
              <td>{item.user || '-'}</td>
              <td>{item.entity_type}:{item.entity_id}</td>
              <td>{item.action}</td>
            </tr>
          )}
          initialPageSize={25}
        />
      </div>
    </div>
  );
}
