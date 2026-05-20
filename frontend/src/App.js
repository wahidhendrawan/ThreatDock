import React, { useState, useEffect } from 'react';
import Filters from './components/Filters';
import AlertList from './components/AlertList';
import Stats from './components/Stats';

/**
 * Main application component for ThreatDock frontend.
 * Handles state for filters and alerts, and fetches data from the backend API.
 */

function App() {
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [attackPhaseFilter, setAttackPhaseFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  useEffect(() => {
    // Construct query string based on active filters
    const params = [];
    if (severityFilter) params.push(`severity=${encodeURIComponent(severityFilter)}`);
    if (sourceFilter) params.push(`source=${encodeURIComponent(sourceFilter)}`);
    if (statusFilter) params.push(`status=${encodeURIComponent(statusFilter)}`);
    if (startDate) params.push(`start=${startDate}`);
    if (endDate) params.push(`end=${endDate}`);
    const queryString = params.length ? `?${params.join('&')}` : '';
    // Fetch alerts from backend
    fetch(`http://localhost:5002/alerts${queryString}`)
      .then(res => res.json())
      .then(data => setAlerts(data))
      .catch(err => console.error('Error fetching alerts:', err));
  }, [severityFilter, sourceFilter, statusFilter, startDate, endDate]);

  /**
   * Update the status of a given alert.  Sends a PATCH request to the backend
   * and updates the local list of alerts on success.
   *
   * @param {number} id - The alert ID
   * @param {string} newStatus - The new status value
   */
  const handleStatusChange = (id, newStatus) => {
    fetch(`http://localhost:5002/alerts/${id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: newStatus })
    })
      .then(res => {
        if (!res.ok) {
          throw new Error('Failed to update status');
        }
        return res.json();
      })
      .then(data => {
        // Update local state
        setAlerts(prev => prev.map(a => (a.id === id ? { ...a, status: newStatus } : a)));
      })
      .catch(err => console.error(err.message));
  };

  // Apply client-side filtering for attack phase if selected
  const filteredAlerts = alerts.filter(a => {
    if (attackPhaseFilter && a.attack_phase !== attackPhaseFilter) return false;
    return true;
  });

  return (
    <div className="App">
      <div className="dashboard-header">
        <h1>ThreatDock Security Dashboard</h1>
        <p style={{ color: 'var(--text-muted)' }}>Monitor and analyze security alerts across your environment.</p>
      </div>

      <div className="card">
        <Filters
          severity={severityFilter}
          setSeverity={setSeverityFilter}
          source={sourceFilter}
          setSource={setSourceFilter}
          status={statusFilter}
          setStatus={setStatusFilter}
          attackPhase={attackPhaseFilter}
          setAttackPhase={setAttackPhaseFilter}
          startDate={startDate}
          setStartDate={setStartDate}
          endDate={endDate}
          setEndDate={setEndDate}
        />
      </div>

      <Stats alerts={filteredAlerts} />

      <AlertList alerts={filteredAlerts} onStatusChange={handleStatusChange} />
    </div>
  );
}

export default App;
