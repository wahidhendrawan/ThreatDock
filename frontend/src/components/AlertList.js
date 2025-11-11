import React from 'react';

/**
 * Component that renders a table of alerts.
 *
 * Props:
 *  - alerts: array of alert objects to display
 */
function AlertList({ alerts, onStatusChange }) {
  return (
    <div className="alert-list" style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Source</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Severity</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Date</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Attack Phase</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Status</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Alert</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map(alert => (
            <tr key={alert.id || `${alert.source}-${alert.externalId}`}
                style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '0.5rem' }}>{alert.source}</td>
              <td style={{ padding: '0.5rem' }}>{alert.severity}</td>
              <td style={{ padding: '0.5rem' }}>{alert.date ? new Date(alert.date).toLocaleString() : ''}</td>
              <td style={{ padding: '0.5rem' }}>{alert.attack_phase || 'Unknown'}</td>
              <td style={{ padding: '0.5rem' }}>
                <select
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
              <td style={{ padding: '0.5rem' }}>
                {alert.url ? (
                  <a href={alert.url} target="_blank" rel="noopener noreferrer">
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