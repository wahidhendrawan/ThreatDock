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
  Legend
} from 'recharts';

/**
 * Statistics component
 *
 * Renders simple visualisations using Recharts to show the distribution of
 * alerts by severity and the number of alerts over time.  The data is
 * derived from the list of alert objects passed as props.  If no alerts
 * are available, the charts render nothing.
 *
 * Props:
 *  - alerts: array of alert objects
 */
function Stats({ alerts }) {
  // Build a severity distribution map
  const severityCounts = alerts.reduce((acc, alert) => {
    const sev = alert.severity || 'Unknown';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const severityData = Object.keys(severityCounts).map(key => ({
    severity: key,
    count: severityCounts[key]
  }));

  // Group alerts by date (YYYY-MM-DD)
  const dateCounts = alerts.reduce((acc, alert) => {
    if (!alert.date) return acc;
    const d = new Date(alert.date);
    if (isNaN(d)) return acc;
    const dateKey = d.toISOString().split('T')[0];
    acc[dateKey] = (acc[dateKey] || 0) + 1;
    return acc;
  }, {});
  // Convert to array sorted by date ascending
  const timeData = Object.keys(dateCounts)
    .sort()
    .map(key => ({ date: key, count: dateCounts[key] }));

  if (alerts.length === 0) {
    return null;
  }

  return (
    <div className="statistics" style={{ marginTop: '2rem' }}>
      <h2>Alert Statistics</h2>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem' }}>
        <div style={{ flex: '1 1 300px', minWidth: '300px', height: '300px' }}>
          <h3>Severity Distribution</h3>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={severityData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="severity" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" name="Count" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div style={{ flex: '1 1 300px', minWidth: '300px', height: '300px' }}>
          <h3>Alerts Over Time</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={timeData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="count" name="Count" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default Stats;