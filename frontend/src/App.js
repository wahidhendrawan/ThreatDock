import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Filters from './components/Filters';
import AlertList from './components/AlertList';
import Stats from './components/Stats';
import { 
  ThreatHunting, AssetDiscovery, ExposureMonitoring, AssetIntelligence, 
  VulnPrioritization, PredictiveIntel, ThreatAnalysis, DigitalRisk, 
  BrandExposure, ThirdPartyRisk 
} from './pages/Modules';
import Settings from './pages/Settings';

const API_BASE = '';

// Helper to build auth headers from authData
function getAuthHeaders(authData) {
  const headers = {};
  if (authData?.token) {
    headers['Authorization'] = `Bearer ${authData.token}`;
  } else if (authData?.basic) {
    const basicAuth = btoa(`${authData.basic.user}:${authData.basic.pass}`);
    headers['Authorization'] = `Basic ${basicAuth}`;
  }
  return headers;
}

// Dashboard component
function Dashboard({ alerts }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Overview Dashboard</h1>
          <p className="page-subtitle">Security Operations & Threat Intel Metrics</p>
        </div>
      </div>
      <Stats alerts={alerts} />
    </div>
  );
}

function AlertsPage({ alerts, filters, handlers }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Alerts</h1>
          <p className="page-subtitle">Manage and triage active threat intelligence alerts</p>
        </div>
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Query Filters</h2>
        <Filters {...filters} />
      </div>
      <div className="card">
        <h2 className="section-title" style={{ fontSize: '1rem', marginBottom: '1rem' }}>Results ({alerts.length})</h2>
        <AlertList alerts={alerts} onStatusChange={handlers.handleStatusChange} />
      </div>
    </div>
  );
}

function AppContent() {
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [attackPhaseFilter, setAttackPhaseFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [loading, setLoading] = useState(true);

  // Authentication State — start with checking localStorage
  const [authData, setAuthData] = useState(() => {
    try {
      const token = localStorage.getItem('threatdock_token');
      const userStr = localStorage.getItem('threatdock_user');
      if (token && userStr) {
        return { token, user: JSON.parse(userStr) };
      }
      const savedBasic = localStorage.getItem('threatdock_credentials');
      if (savedBasic) {
        const basic = JSON.parse(savedBasic);
        return { basic, user: { name: basic.user } };
      }
      return null;
    } catch {
      return null;
    }
  });

  // needsAuth defaults to true if no saved credentials
  const [needsAuth, setNeedsAuth] = useState(!localStorage.getItem('threatdock_credentials') && !localStorage.getItem('threatdock_token'));

  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState('');

  // Fetch alerts
  const fetchAlerts = useCallback(() => {
    const params = [];
    if (severityFilter) params.push(`severity=${encodeURIComponent(severityFilter)}`);
    if (sourceFilter) params.push(`source=${encodeURIComponent(sourceFilter)}`);
    if (statusFilter) params.push(`status=${encodeURIComponent(statusFilter)}`);
    if (startDate) params.push(`start=${startDate}`);
    if (endDate) params.push(`end=${endDate}`);
    const queryString = params.length ? `?${params.join('&')}` : '';

    const headers = getAuthHeaders(authData);

    setLoading(true);
    fetch(`${API_BASE}/api/alerts${queryString}`, { headers })
      .then(res => {
        if (res.status === 401) {
          setNeedsAuth(true);
          setAuthData(null);
          localStorage.removeItem('threatdock_token');
          localStorage.removeItem('threatdock_user');
          localStorage.removeItem('threatdock_credentials');
          setLoginError('Session expired or invalid credentials.');
          throw new Error('Authentication required');
        }
        setNeedsAuth(false);
        setLoginError('');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        return res.json();
      })
      .then(data => {
        setAlerts(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(err => {
        setLoading(false);
        if (err.message !== 'Authentication required') {
          console.error('Error fetching alerts:', err);
        }
      });
  }, [severityFilter, sourceFilter, statusFilter, startDate, endDate, authData]);

  useEffect(() => {
    if (authData) {
      fetchAlerts();
    }
  }, [fetchAlerts, authData]);

  const handleStatusChange = (id, newStatus) => {
    const headers = { 'Content-Type': 'application/json', ...getAuthHeaders(authData) };

    fetch(`${API_BASE}/api/alerts/${id}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: newStatus })
    })
      .then(res => res.json())
      .then(() => {
        setAlerts(prev => prev.map(a => (a.id === id ? { ...a, status: newStatus } : a)));
      })
      .catch(console.error);
  };

  const handleLogin = (e) => {
    e.preventDefault();
    setLoginError('');

    // Validate credentials against the backend before saving
    const basicAuth = btoa(`${loginUser}:${loginPass}`);
    fetch(`${API_BASE}/api/alerts?limit=1`, {
      headers: { 'Authorization': `Basic ${basicAuth}` }
    })
      .then(res => {
        if (res.status === 401) {
          setLoginError('Invalid username or password.');
          throw new Error('Invalid credentials');
        }
        return res.json();
      })
      .then(() => {
        const basic = { user: loginUser, pass: loginPass };
        localStorage.setItem('threatdock_credentials', JSON.stringify(basic));
        setAuthData({ basic, user: { name: loginUser } });
        setNeedsAuth(false);
        setLoginError('');
      })
      .catch(err => {
        if (err.message !== 'Invalid credentials') {
          setLoginError('Network error. Please try again.');
        }
      });
  };

  const handleLogout = () => {
    localStorage.removeItem('threatdock_token');
    localStorage.removeItem('threatdock_user');
    localStorage.removeItem('threatdock_credentials');
    setAuthData(null);
    setAlerts([]);
    setNeedsAuth(true);
  };

  // Show login screen
  if (needsAuth || !authData) {
    return (
      <div className="login-page">
        <div className="login-card card">
          <div className="login-brand">
            <div className="login-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: '48px', height: '48px', color: 'var(--primary-color)' }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <h1 className="brand-title" style={{ fontSize: '2rem', marginTop: '1rem' }}>ThreatDock</h1>
            <p className="page-subtitle" style={{ marginTop: '0.5rem' }}>Enterprise Threat Intelligence Platform</p>
          </div>
          
          {loginError && (
            <div style={{ 
              padding: '0.75rem 1rem', 
              marginBottom: '1.5rem', 
              background: 'rgba(239,68,68,0.15)', 
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: '8px',
              color: '#f87171',
              fontSize: '0.875rem'
            }}>
              {loginError}
            </div>
          )}

          <form onSubmit={handleLogin} className="flex flex-col gap-4 text-left">
            <div className="form-group">
              <label className="form-label">Username</label>
              <input 
                className="form-input" 
                type="text" 
                value={loginUser} 
                onChange={e => setLoginUser(e.target.value)} 
                placeholder="Enter your username"
                autoFocus
                required 
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input 
                className="form-input" 
                type="password" 
                value={loginPass} 
                onChange={e => setLoginPass(e.target.value)} 
                placeholder="Enter your password"
                required 
              />
            </div>
            <button type="submit" className="btn btn-primary btn-block" style={{ padding: '0.875rem', fontSize: '1rem', marginTop: '0.5rem' }}>
              Sign In
            </button>
          </form>
          
          <p style={{ marginTop: '1.5rem', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
            Protected by ThreatDock Security
          </p>
        </div>
      </div>
    );
  }

  const filteredAlerts = alerts.filter(a => {
    if (attackPhaseFilter && a.attack_phase !== attackPhaseFilter) return false;
    return true;
  });

  const filtersProps = {
    severity: severityFilter, setSeverity: setSeverityFilter,
    source: sourceFilter, setSource: setSourceFilter,
    status: statusFilter, setStatus: setStatusFilter,
    attackPhase: attackPhaseFilter, setAttackPhase: setAttackPhaseFilter,
    startDate, setStartDate, endDate, setEndDate
  };

  return (
    <Layout user={authData?.user} onLogout={handleLogout}>
      <Routes>
        <Route path="/" element={<Dashboard alerts={filteredAlerts} />} />
        <Route path="/alerts" element={<AlertsPage alerts={filteredAlerts} filters={filtersProps} handlers={{ handleStatusChange }} />} />
        <Route path="/hunting" element={<ThreatHunting authData={authData} />} />
        <Route path="/assets" element={<AssetDiscovery authData={authData} />} />
        <Route path="/exposure" element={<ExposureMonitoring alerts={filteredAlerts} />} />
        <Route path="/intel" element={<AssetIntelligence alerts={filteredAlerts} />} />
        <Route path="/prioritization" element={<VulnPrioritization alerts={filteredAlerts} />} />
        <Route path="/predictive" element={<PredictiveIntel alerts={filteredAlerts} />} />
        <Route path="/analysis" element={<ThreatAnalysis alerts={filteredAlerts} />} />
        <Route path="/digital-risk" element={<DigitalRisk alerts={filteredAlerts} />} />
        <Route path="/brand" element={<BrandExposure alerts={filteredAlerts} />} />
        <Route path="/third-party" element={<ThirdPartyRisk authData={authData} />} />
        <Route path="/settings" element={<Settings authData={authData} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;