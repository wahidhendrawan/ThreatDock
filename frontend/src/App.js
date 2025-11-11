import React, { useState, useEffect } from 'react';
import Filters from './components/Filters';
import AlertList from './components/AlertList';

/**
 * Main application component for ThreatDock frontend.
 * Handles state for filters and alerts, and fetches data from the backend API.
 */
function App() {
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  useEffect(() => {
    // Construct query string based on active filters
    const params = [];
    if (severityFilter) params.push(`severity=${encodeURIComponent(severityFilter)}`);
    if (sourceFilter) params.push(`source=${encodeURIComponent(sourceFilter)}`);
    if (startDate) params.push(`start=${startDate}`);
    if (endDate) params.push(`end=${endDate}`);
    const queryString = params.length ? `?${params.join('&')}` : '';
    // Fetch alerts from backend
    fetch(`http://localhost:5000/alerts${queryString}`)
      .then(res => res.json())
      .then(data => setAlerts(data))
      .catch(err => console.error('Error fetching alerts:', err));
  }, [severityFilter, sourceFilter, startDate, endDate]);

  return (
    <div className="App" style={{ padding: '1rem', fontFamily: 'Arial, sans-serif' }}>
      <h1>ThreatDock Security Dashboard</h1>
      <Filters
        severity={severityFilter}
        setSeverity={setSeverityFilter}
        source={sourceFilter}
        setSource={setSourceFilter}
        startDate={startDate}
        setStartDate={setStartDate}
        endDate={endDate}
        setEndDate={setEndDate}
      />
      <AlertList alerts={alerts} />
    </div>
  );
}

export default App;