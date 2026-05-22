import React from 'react';
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
  Cell
} from 'recharts';

function Stats({ alerts }) {
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
  
  // Enforce ordering: Critical, High, Medium, Low, Unknown
  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
  const severityData = severityOrder
    .map(key => ({
      severity: key,
      count: severityCounts[key] || 0
    }))
    .filter(item => item.count > 0 || severityCounts[item.severity] !== undefined);

  const dateCounts = alerts.reduce((acc, alert) => {
    if (!alert.date) return acc;
    const d = new Date(alert.date);
    if (isNaN(d)) return acc;
    const dateKey = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    acc[dateKey] = (acc[dateKey] || 0) + 1;
    return acc;
  }, {});

  const timeData = Object.keys(dateCounts)
    .map(key => ({ date: key, count: dateCounts[key] }));

  const timelineData = timeData.length > 0 ? timeData : [{ date: 'No Date', count: alerts.length }];

  // Helper to get color depending on severity
  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'Critical': return '#ef4444';
      case 'High': return '#f97316';
      case 'Medium': return '#f59e0b';
      case 'Low': return '#3b82f6';
      default: return '#64748b';
    }
  };

  if (alerts.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
        <h3>No statistics available</h3>
        <p style={{ fontSize: '0.875rem' }}>Awaiting ingestion of alerts to populate graphs.</p>
      </div>
    );
  }

  // Get total count of each status
  const statusCounts = alerts.reduce((acc, alert) => {
    const stat = alert.status || 'Open';
    acc[stat] = (acc[stat] || 0) + 1;
    return acc;
  }, { 'Open': 0, 'In Progress': 0, 'Resolved': 0 });

  return (
    <div className="grid-main" style={{ gap: '1.5rem' }}>
      {/* Key Metrics row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid var(--primary-color)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Alerts</div>
          <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem' }}>{alerts.length}</div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical/High Alerts</div>
          <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#f87171' }}>
            {alerts.filter(a => ['Critical', 'High'].includes(normalizeSeverity(a.severity))).length}
          </div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Cases</div>
          <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#fbbf24' }}>
            {statusCounts['Open'] + statusCounts['In Progress']}
          </div>
        </div>
        <div className="card" style={{ padding: '1.25rem', borderLeft: '4px solid #10b981' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resolved Cases</div>
          <div style={{ fontSize: '2rem', fontWeight: '800', marginTop: '0.25rem', color: '#34d399' }}>
            {statusCounts['Resolved']}
          </div>
        </div>
      </div>

      {/* Charts Card */}
      <div className="card">
        <h2 className="section-title">Alert Statistics</h2>
        <div className="stats-grid">
          <div>
            <h3 style={{ fontSize: '0.875rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '1rem' }}>Severity Distribution</h3>
            <div className="chart-wrapper">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="severity" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 11, fontWeight: 500}} />
                  <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 11}} />
                  <Tooltip 
                    formatter={(value) => [value, 'Total Alerts']}
                    labelFormatter={(label) => `Severity: ${label}`}
                    cursor={{fill: 'rgba(255, 255, 255, 0.02)'}} 
                    contentStyle={{
                      backgroundColor: '#0f172a', 
                      borderColor: 'rgba(255, 255, 255, 0.08)',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px'
                    }} 
                  />
                  <Bar 
                    dataKey="count" 
                    name="Alerts" 
                    radius={[4, 4, 0, 0]}
                  >
                    {
                      severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={getSeverityColor(entry.severity)} />
                      ))
                    }
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div>
            <h3 style={{ fontSize: '0.875rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '1rem' }}>Alerts Timeline</h3>
            <div className="chart-wrapper">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 11, fontWeight: 500}} />
                  <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 11}} />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: '#0f172a', 
                      borderColor: 'rgba(255, 255, 255, 0.08)',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px'
                    }} 
                  />
                  <Line type="monotone" dataKey="count" name="Alerts" stroke="#6366f1" strokeWidth={3} dot={{r: 4, strokeWidth: 2, fill: '#0a0d16'}} activeDot={{r: 6}} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Stats;
