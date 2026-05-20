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

  // Authentication State
  const [needsAuth, setNeedsAuth] = useState(false);
  const [credentials, setCredentials] = useState(null); // { user, pass }
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState('');

  useEffect(() => {
    // Construct query string based on active filters
    const params = [];
    if (severityFilter) params.push(`severity=${encodeURIComponent(severityFilter)}`);
    if (sourceFilter) params.push(`source=${encodeURIComponent(sourceFilter)}`);
    if (statusFilter) params.push(`status=${encodeURIComponent(statusFilter)}`);
    if (startDate) params.push(`start=${startDate}`);
    if (endDate) params.push(`end=${endDate}`);
    const queryString = params.length ? `?${params.join('&')}` : '';

    // Prepare headers
    const headers = {};
    if (credentials) {
      const basicAuth = btoa(`${credentials.user}:${credentials.pass}`);
      headers['Authorization'] = `Basic ${basicAuth}`;
    }

    // Fetch alerts from backend
    fetch(`http://localhost:5002/alerts${queryString}`, { headers })
      .then(res => {
        if (res.status === 401) {
          setNeedsAuth(true);
          setCredentials(null);
          if (credentials) setLoginError('Invalid credentials');
          throw new Error('Authentication required');
        }
        setNeedsAuth(false);
        setLoginError('');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        return res.json();
      })
      .then(data => setAlerts(data))
      .catch(err => {
        if (err.message !== 'Authentication required') {
          console.error('Error fetching alerts:', err);
        }
      });
  }, [severityFilter, sourceFilter, statusFilter, startDate, endDate, credentials]);

  const handleStatusChange = (id, newStatus) => {
    const headers = { 'Content-Type': 'application/json' };
    if (credentials) {
      headers['Authorization'] = `Basic ${btoa(`${credentials.user}:${credentials.pass}`)}`;
    }

    fetch(`http://localhost:5002/alerts/${id}`, {
      method: 'PATCH',
      headers: headers,
      body: JSON.stringify({ status: newStatus })
    })
      .then(res => {
        if (res.status === 401) {
          setNeedsAuth(true);
          setCredentials(null);
          throw new Error('Authentication required');
        }
        if (!res.ok) throw new Error('Failed to update status');
        return res.json();
      })
      .then(data => {
        setAlerts(prev => prev.map(a => (a.id === id ? { ...a, status: newStatus } : a)));
      })
      .catch(err => console.error(err.message));
  };

  const handleLogin = (e) => {
    e.preventDefault();
    setCredentials({ user: loginUser, pass: loginPass });
  };

  const handleLogout = () => {
    setCredentials(null);
    setNeedsAuth(true);
  };

  if (needsAuth && !credentials) {
    return (
      <div className="App" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', backgroundColor: 'var(--bg-color)' }}>
        <div className="card" style={{ maxWidth: '400px', width: '100%', padding: '2rem' }}>
          <h2 style={{ textAlign: 'center', marginBottom: '1.5rem', color: 'var(--text-main)' }}>Sign In to ThreatDock</h2>
          {loginError && <div style={{ color: 'var(--severity-critical)', marginBottom: '1rem', textAlign: 'center', fontSize: '0.875rem' }}>{loginError}</div>}
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="filter-group">
              <label>Username</label>
              <input type="text" value={loginUser} onChange={e => setLoginUser(e.target.value)} required />
            </div>
            <div className="filter-group">
              <label>Password</label>
              <input type="password" value={loginPass} onChange={e => setLoginPass(e.target.value)} required />
            </div>
            <button type="submit" style={{ padding: '0.75rem', backgroundColor: 'var(--primary-color)', color: 'white', border: 'none', borderRadius: 'var(--radius-md)', cursor: 'pointer', fontWeight: '600', marginTop: '0.5rem' }}>Sign In</button>
          </form>
        </div>
      </div>
    );
  }

  // Apply client-side filtering for attack phase if selected
  const filteredAlerts = alerts.filter(a => {
    if (attackPhaseFilter && a.attack_phase !== attackPhaseFilter) return false;
    return true;
  });

  return (
    <div className="App">
      <div className="dashboard-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>ThreatDock Security Dashboard</h1>
          <p style={{ color: 'var(--text-muted)' }}>Monitor and analyze security alerts across your environment.</p>
        </div>
        {credentials && (
          <button onClick={handleLogout} style={{ padding: '0.5rem 1rem', backgroundColor: 'transparent', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', cursor: 'pointer', color: 'var(--text-main)' }}>
            Sign Out
          </button>
        )}
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