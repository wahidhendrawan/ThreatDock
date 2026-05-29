import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  PieChart,
  Pie
} from 'recharts';
import { 
  ShieldCheck, Activity, Zap, Target, 
  ExternalLink, CheckCircle2, XCircle, 
  AlertTriangle, Globe, Eye, MoreVertical, 
  X, Plus, Maximize2, Minimize2, Layout,
  Briefcase, CheckCircle, Clock, ArrowLeft, ArrowRight
} from 'lucide-react';

function getAuthHeaders(authData) {
  if (authData?.token) return { Authorization: `Bearer ${authData.token}` };
  return {};
}

// Custom Tooltip for Source Composition to fix missing values
function SourceTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    return (
      <div style={{
        backgroundColor: '#0f172a',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '8px',
        padding: '0.5rem 0.75rem',
        fontSize: '11px',
        color: '#f8fafc'
      }}>
        <div style={{ fontWeight: 600, marginBottom: '2px' }}>{payload[0].name}</div>
        <div style={{ color: 'var(--primary-color)' }}>Alerts: <span style={{ fontWeight: 700 }}>{payload[0].value}</span></div>
      </div>
    );
  }
  return null;
}

function SeverityTooltip({ active, payload, label }) {
  if (!active || !payload || payload.length === 0) return null;
  const value = payload[0]?.value ?? 0;
  return (
    <div style={{
      backgroundColor: '#0f172a',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      borderRadius: '8px',
      color: '#f8fafc',
      fontSize: '12px',
      padding: '0.625rem 0.75rem'
    }}>
      <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>Severity: {label}</div>
      <div style={{ fontWeight: 700 }}>Total Alerts: {value}</div>
    </div>
  );
}

const DEFAULT_LAYOUT = [
  { id: 'kpis', type: 'KPI_BAR', size: 'full' },
  { id: 'velocity', type: 'THREAT_VELOCITY', size: 'large' },
  { id: 'sources', type: 'SOURCE_DIST', size: 'small' },
  { id: 'status', type: 'CASE_STATUS', size: 'small' },
  { id: 'health', type: 'COLLECTOR_HEALTH', size: 'small' },
  { id: 'brand', type: 'BRAND_EXPOSURE', size: 'small' },
  { id: 'intel', type: 'CORRELATIONS', size: 'small' },
];

function Stats({ alerts, authData }) {
  const [health, setHealth] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [brandFindings, setBrandFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [layout, setLayout] = useState(() => {
    const saved = localStorage.getItem('threatdock_dashboard_layout');
    return saved ? JSON.parse(saved) : DEFAULT_LAYOUT;
  });
  const [showWidgetGallery, setShowShowWidgetGallery] = useState(false);

  const fetchData = useCallback(async () => {
    const headers = getAuthHeaders(authData);
    try {
      const [hRes, cRes, bRes] = await Promise.all([
        fetch('/api/ingestion/health', { headers }),
        fetch('/api/intelligence/correlations', { headers }),
        fetch('/api/osint/findings?category=brand-exposure', { headers })
      ]);
      if (hRes.ok) setHealth(await hRes.json());
      if (cRes.ok) setCorrelations(await cRes.json());
      if (bRes.ok) setBrandFindings(await bRes.json());
    } catch (err) {
      console.error('Dashboard fetch failed:', err);
    } finally {
      setLoading(false);
    }
  }, [authData]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 600000); // 10 minutes
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    localStorage.setItem('threatdock_dashboard_layout', JSON.stringify(layout));
  }, [layout]);

  const removeWidget = (id) => setLayout(layout.filter(w => w.id !== id));
  
  const moveWidget = (id, direction) => {
    const index = layout.findIndex(w => w.id === id);
    if (index === -1) return;
    const nextIndex = direction === 'left' ? index - 1 : index + 1;
    if (nextIndex < 0 || nextIndex >= layout.length) return;
    
    const newLayout = [...layout];
    [newLayout[index], newLayout[nextIndex]] = [newLayout[nextIndex], newLayout[index]];
    setLayout(newLayout);
  };

  const toggleWidgetSize = (id) => {
    setLayout(layout.map(w => {
      if (w.id !== id) return w;
      // Cycle: small (1/3) -> medium (2/3) -> large (3/3)
      const nextSize = w.size === 'small' ? 'medium' : w.size === 'medium' ? 'large' : 'small';
      return { ...w, size: nextSize };
    }));
  };

  const addWidget = (type) => {
    const id = `${type.toLowerCase()}_${Date.now()}`;
    setLayout([...layout, { id, type, size: 'small' }]);
    setShowShowWidgetGallery(false);
  };

  const normalizeSeverity = (value) => {
    const v = String(value || '').toLowerCase();
    if (v === 'critical') return 'Critical';
    if (v === 'high') return 'High';
    if (v === 'medium') return 'Medium';
    if (v === 'low') return 'Low';
    return 'Unknown';
  };

  const severityCounts = alerts.reduce((acc, alert) => {
    const sev = normalizeSeverity(alert.severity);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  
  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
  const severityData = severityOrder
    .map(key => ({
      severity: key,
      count: severityCounts[key] || 0
    }))
    .filter(item => item.count > 0 || severityCounts[item.severity] !== undefined);

  const sourceData = useMemo(() => {
    const counts = alerts.reduce((acc, a) => {
      acc[a.source] = (acc[a.source] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [alerts]);

  const dateCounts = alerts.reduce((acc, alert) => {
    if (!alert.date) return acc;
    const d = new Date(alert.date);
    if (isNaN(d)) return acc;
    const dateKey = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    acc[dateKey] = (acc[dateKey] || 0) + 1;
    return acc;
  }, {});

  const timelineData = Object.keys(dateCounts)
    .map(key => ({ date: key, count: dateCounts[key] }));

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'Critical': return '#ef4444';
      case 'High': return '#f97316';
      case 'Medium': return '#f59e0b';
      case 'Low': return '#3b82f6';
      default: return '#64748b';
    }
  };

  if (loading && alerts.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '400px', color: 'var(--text-muted)' }}>
        <Activity className="animate-spin" size={32} />
        <span style={{ marginLeft: '1rem' }}>Initializating security intelligence...</span>
      </div>
    );
  }

  const statusCounts = alerts.reduce((acc, alert) => {
    const stat = alert.status || 'Open';
    acc[stat] = (acc[stat] || 0) + 1;
    return acc;
  }, { 'Open': 0, 'In Progress': 0, 'Resolved': 0, 'False Positive': 0, 'Accepted Risk': 0 });

  const renderWidget = (w) => {
    const getWidgetStyle = (size) => {
      switch (size) {
        case 'large': return { gridColumn: 'span 3' };
        case 'medium': return { gridColumn: 'span 2' };
        case 'full': return { gridColumn: 'span 3' };
        default: return { gridColumn: 'span 1' };
      }
    };
    
    const widgetStyle = getWidgetStyle(w.size);
    
    const WidgetHeader = ({ title, icon: Icon }) => (
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {Icon && <Icon size={18} style={{ color: 'var(--primary-color)' }} />}
          <h2 className="section-title" style={{ margin: 0, fontSize: '0.9rem' }}>{title}</h2>
        </div>
        <div className="widget-controls" style={{ display: 'flex', gap: '0.35rem' }}>
          <button onClick={() => moveWidget(w.id, 'left')} className="icon-button" style={{ opacity: 0.3 }} title="Move Left">
            <ArrowLeft size={12} />
          </button>
          <button onClick={() => moveWidget(w.id, 'right')} className="icon-button" style={{ opacity: 0.3 }} title="Move Right">
            <ArrowRight size={12} />
          </button>
          <button onClick={() => toggleWidgetSize(w.id)} className="icon-button" style={{ opacity: 0.3 }} title="Resize Widget">
            <Maximize2 size={12} />
          </button>
          <button onClick={() => removeWidget(w.id)} className="icon-button" style={{ opacity: 0.3 }} title="Remove Widget">
            <X size={12} />
          </button>
        </div>
      </div>
    );

    switch (w.type) {
      case 'KPI_BAR':
        return (
          <div key={w.id} style={widgetStyle}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
              <div className="card" style={{ padding: '1.25rem', position: 'relative', overflow: 'hidden' }}>
                <div style={{ position: 'absolute', right: '-10px', top: '-10px', opacity: 0.05 }}><ShieldCheck size={100} /></div>
                <div style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Ingested Alerts</div>
                <div style={{ fontSize: '2.25rem', fontWeight: '900', marginTop: '0.5rem', color: 'var(--primary-color)' }}>{alerts.length.toLocaleString()}</div>
              </div>
              <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #ef4444' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Threats</div>
                <div style={{ fontSize: '2.25rem', fontWeight: '900', marginTop: '0.5rem', color: '#f87171' }}>
                  {statusCounts['Open'] + statusCounts['In Progress']}
                </div>
              </div>
              <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #8b5cf6' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Intelligence Signals</div>
                <div style={{ fontSize: '2.25rem', fontWeight: '900', marginTop: '0.5rem', color: '#a78bfa' }}>{correlations.length}</div>
              </div>
              <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #10b981' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resolution Rate</div>
                <div style={{ fontSize: '2.25rem', fontWeight: '900', marginTop: '0.5rem', color: '#34d399' }}>
                  {alerts.length > 0 ? Math.round((statusCounts['Resolved'] / alerts.length) * 100) : 0}%
                </div>
              </div>
            </div>
          </div>
        );

      case 'CASE_STATUS':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Case Management Summary" icon={Briefcase} />
            <div className="flex flex-col gap-4">
              {[
                { label: 'Open / Triage', value: statusCounts['Open'], color: '#f87171', icon: Clock },
                { label: 'In Progress', value: statusCounts['In Progress'], color: '#fbbf24', icon: Activity },
                { label: 'Resolved / Patched', value: statusCounts['Resolved'], color: '#34d399', icon: CheckCircle },
                { label: 'Accepted Risk', value: statusCounts['Accepted Risk'], color: '#60a5fa', icon: ShieldCheck },
                { label: 'False Positive', value: statusCounts['False Positive'], color: '#94a3b8', icon: XCircle }
              ].map(item => (
                <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.75rem', background: 'rgba(0,0,0,0.1)', borderRadius: '8px' }}>
                  <div style={{ padding: '0.5rem', background: `${item.color}15`, borderRadius: '6px', color: item.color }}>
                    <item.icon size={16} />
                  </div>
                  <div style={{ flex: 1, fontSize: '0.85rem', fontWeight: 600 }}>{item.label}</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: item.color }}>{item.value}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'THREAT_VELOCITY':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Threat Velocity & Ingestion" icon={Activity} />
            <div style={{ height: '280px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timelineData.slice(-14)} margin={{ top: 0, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 10}} />
                  <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 10}} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', fontSize: '11px' }}
                  />
                  <Line type="monotone" dataKey="count" stroke="var(--primary)" strokeWidth={3} dot={{r: 3, fill: 'var(--primary)', strokeWidth: 0}} activeDot={{r: 5, strokeWidth: 0}} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        );

      case 'SOURCE_DIST':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Source Composition" icon={Layout} />
            <div style={{ height: '200px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={sourceData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {sourceData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={[`#3b82f6`, `#8b5cf6`, `#10b981`, `#f59e0b`, `#ef4444`, `#6366f1`, `#ec4899`, `#14b8a6`][index % 8]} />
                    ))}
                  </Pie>
                  <Tooltip content={<SourceTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col gap-2 mt-4">
              {sourceData.slice(0, 4).map((s, i) => (
                <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.65rem' }}>
                  <div style={{ width: '6px', height: '6px', borderRadius: '1px', background: [`#3b82f6`, `#8b5cf6`, `#10b981`, `#f59e0b`][i % 4] }}></div>
                  <span style={{ color: 'var(--text-muted)', flex: 1 }}>{s.name}</span>
                  <span style={{ fontWeight: 700 }}>{s.value}</span>
                </div>
              ))}
            </div>
          </div>
        );

      case 'COLLECTOR_HEALTH':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Collector Health" icon={Zap} />
            <div className="flex flex-col gap-2">
              {health.slice(0, 6).map(item => (
                <div key={item.source} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.6rem', background: 'rgba(0,0,0,0.1)', borderRadius: '6px' }}>
                  {item.status === 'Success' ? <CheckCircle2 size={14} style={{ color: '#10b981' }} /> : <XCircle size={14} style={{ color: '#ef4444' }} />}
                  <div style={{ flex: 1, fontSize: '0.75rem', fontWeight: 600 }}>{item.source}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{item.last_count || 0}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'BRAND_EXPOSURE':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Asset & Brand Exposure" icon={Globe} />
            <div className="flex flex-col gap-2">
              {brandFindings.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <ShieldCheck size={24} style={{ opacity: 0.1, marginBottom: '0.5rem' }} />
                  <p style={{ fontSize: '0.7rem' }}>No active asset findings.</p>
                </div>
              ) : (
                brandFindings.slice(0, 5).map((f, i) => (
                  <div key={i} style={{ padding: '0.65rem', background: 'rgba(0,0,0,0.1)', borderRadius: '6px', borderLeft: `2px solid ${getSeverityColor(f.severity)}` }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.title}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                       <span style={{ fontSize: '0.6rem', color: 'var(--primary-color)' }}>{f.keyword} • {f.provider}</span>
                       <span style={{ fontSize: '0.6rem', color: 'var(--text-dark)' }}>{f.type}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        );

      case 'CORRELATIONS':
        return (
          <div key={w.id} className="card" style={widgetStyle}>
            <WidgetHeader title="Correlated Intelligence" icon={Target} />
            <div className="flex flex-col gap-2">
              {correlations.slice(0, 4).map(c => (
                <div key={c.id} style={{ padding: '0.65rem', background: 'rgba(0,0,0,0.1)', borderRadius: '6px', borderLeft: `2px solid ${getSeverityColor(c.severity)}` }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{c.title}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.2rem' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--accent)' }}>Score: {c.score}</span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-dark)' }}>{c.confidence}% conf</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
        <button 
          onClick={() => setShowShowWidgetGallery(!showWidgetGallery)} 
          className="btn btn-outline" 
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}
        >
          <Plus size={16} /> Add Widget
        </button>
        <button 
          onClick={() => setLayout(DEFAULT_LAYOUT)} 
          className="btn btn-outline" 
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}
        >
          <Layout size={16} /> Reset Layout
        </button>
      </div>

      {showWidgetGallery && (
        <div className="card" style={{ background: 'rgba(59, 130, 246, 0.05)', border: '1px dashed var(--primary-color)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>Widget Gallery</h3>
            <X size={16} onClick={() => setShowShowWidgetGallery(false)} style={{ cursor: 'pointer' }} />
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            {[
              { type: 'KPI_BAR', label: 'Summary KPIs', icon: ShieldCheck },
              { type: 'CASE_STATUS', label: 'Case Status', icon: Briefcase },
              { type: 'THREAT_VELOCITY', label: 'Threat Velocity', icon: Activity },
              { type: 'SOURCE_DIST', label: 'Source Composition', icon: Layout },
              { type: 'COLLECTOR_HEALTH', label: 'Collector Health', icon: Zap },
              { type: 'BRAND_EXPOSURE', label: 'Brand Monitoring', icon: Globe },
              { type: 'CORRELATIONS', label: 'Intel Correlations', icon: Target }
            ].map(w => (
              <button key={w.type} onClick={() => addWidget(w.type)} className="btn btn-outline" style={{ display: 'flex', flexDirection: 'column', padding: '1rem', width: '120px', gap: '0.5rem' }}>
                <w.icon size={20} />
                <span style={{ fontSize: '0.7rem' }}>{w.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>
        {layout.map(renderWidget)}
      </div>
    </div>
  );
}

export default Stats;


