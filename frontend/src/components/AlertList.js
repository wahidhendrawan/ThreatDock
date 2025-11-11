import React from 'react';

/**
 * Component that renders a table of alerts.
 *
 * Props:
 *  - alerts: array of alert objects to display
 */
function AlertList({ alerts }) {
  return (
    <div className="alert-list" style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Source</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Severity</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Date</th>
            <th style={{ borderBottom: '1px solid #ccc', textAlign: 'left', padding: '0.5rem' }}>Alert</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, idx) => (
            <tr key={idx} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '0.5rem' }}>{alert.source}</td>
              <td style={{ padding: '0.5rem' }}>{alert.severity}</td>
              <td style={{ padding: '0.5rem' }}>{alert.date ? new Date(alert.date).toLocaleString() : ''}</td>
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