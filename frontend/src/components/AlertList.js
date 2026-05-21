import React from 'react';

function AlertList({ alerts, onStatusChange }) {
  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? dateStr : d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  if (!alerts || alerts.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
        <p>No alerts found matching your criteria.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Severity</th>
            <th>Date</th>
            <th>Attack Phase</th>
            <th>Status</th>
            <th>Alert Details</th>
          </tr>
        </thead>
        <tbody>
          {alerts.slice(0, 50).map(alert => (
            <tr key={alert.id || `${alert.source}-${alert.externalId}`}>
              <td style={{ fontWeight: '600', color: 'var(--primary-color)' }}>{alert.source}</td>
              <td>
                <span className={`severity-badge severity-${alert.severity || 'Unknown'}`}>
                  {alert.severity || 'Unknown'}
                </span>
              </td>
              <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                {formatDate(alert.date)}
              </td>
              <td>
                <span style={{ 
                  background: 'rgba(255,255,255,0.03)', 
                  padding: '0.25rem 0.5rem', 
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8rem',
                  border: '1px solid var(--border-color)' 
                }}>
                  {alert.attack_phase || 'Unknown'}
                </span>
              </td>
              <td>
                <select
                  className="status-select"
                  value={alert.status || 'Open'}
                  onChange={e => {
                    const newStatus = e.target.value;
                    if (onStatusChange) onStatusChange(alert.id, newStatus);
                  }}
                >
                  <option value="Open">Open</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </td>
              <td>
                {alert.url ? (
                  <a className="alert-link" href={alert.url} target="_blank" rel="noopener noreferrer">
                    {alert.title}
                  </a>
                ) : (
                  alert.title
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AlertList;
