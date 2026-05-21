import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
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

// Legacy Dashboard component using existing functionality
function Dashboard({ alerts, filters, handlers }) {
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

// OAuth Callback Handler Component
function OAuthCallback({ setAuthData }) {
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    if (code) {
      fetch(`${API_BASE}/auth/callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })
      .then(res => {
        if (!res.ok) throw new Error('Callback exchange failed');
        return res.json();
      })
      .then(data => {
        localStorage.setItem('threatdock_token', data.access_token);
        localStorage.setItem('threatdock_user', JSON.stringify(data.user));
        setAuthData({ token: data.access_token, user: data.user });
        navigate('/');
      })
      .catch(err => {
        setError('Authentication failed: ' + err.message);
      });
    } else {
      setError('No authorization code found in URL');
    }
  }, [navigate, setAuthData]);

  if (error) {
    return <div className="login-page"><div className="card text-red">{error} <a href="/">Return Home</a></div></div>;
  }
  return <div className="login-page"><div className="card">Authenticating with SSO...</div></div>;
}

function AppContent() {
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [attackPhaseFilter, setAttackPhaseFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // Authentication State
  const [ssoConfig, setSsoConfig] = useState(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [authData, setAuthData] = useState(() => {
    try {
      const token = localStorage.getItem('threatdock_token');
      const userStr = localStorage.getItem('threatdock_user');
      if (token && userStr) {
        return { token, user: JSON.parse(userStr) };
      }
      // Legacy basic auth check
      const savedBasic = localStorage.getItem('threatdock_credentials');
      if (savedBasic) return { basic: JSON.parse(savedBasic), user: null };
      return null;
    } catch {
      return null;
    }
  });

  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState('');

  // Fetch SSO Config
  useEffect(() => {
    fetch(`${API_BASE}/auth/config`)
      .then(res => res.json())
      .then(data => setSsoConfig(data))
      .catch(console.error);
  }, []);

  useEffect(() => {
    const params = [];
    if (severityFilter) params.push(`severity=${encodeURIComponent(severityFilter)}`);
    if (sourceFilter) params.push(`source=${encodeURIComponent(sourceFilter)}`);
    if (statusFilter) params.push(`status=${encodeURIComponent(statusFilter)}`);
    if (startDate) params.push(`start=${startDate}`);
    if (endDate) params.push(`end=${endDate}`);
    const queryString = params.length ? `?${params.join('&')}` : '';

    const headers = {};
    if (authData?.token) {
      headers['Authorization'] = `Bearer ${authData.token}`;
    } else if (authData?.basic) {
      const basicAuth = btoa(`${authData.basic.user}:${authData.basic.pass}`);
      headers['Authorization'] = `Basic ${basicAuth}`;
    }

    fetch(`${API_BASE}/api/alerts${queryString}`, { headers })
      .then(res => {
        if (res.status === 401) {
          setNeedsAuth(true);
          if (authData) {
            setLoginError('Session expired or invalid credentials.');
            setAuthData(null);
            localStorage.removeItem('threatdock_token');
            localStorage.removeItem('threatdock_user');
            localStorage.removeItem('threatdock_credentials');
          }
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
  }, [severityFilter, sourceFilter, statusFilter, startDate, endDate, authData]);

  const handleStatusChange = (id, newStatus) => {
    const headers = { 'Content-Type': 'application/json' };
    if (authData?.token) {
      headers['Authorization'] = `Bearer ${authData.token}`;
    } else if (authData?.basic) {
      headers['Authorization'] = `Basic ${btoa(`${authData.basic.user}:${authData.basic.pass}`)}`;
    }

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

  const handleLegacyLogin = (e) => {
    e.preventDefault();
    const basic = { user: loginUser, pass: loginPass };
    localStorage.setItem('threatdock_credentials', JSON.stringify(basic));
    setAuthData({ basic, user: { name: loginUser } });
  };

  const handleSSOLogin = () => {
    window.location.href = `${API_BASE}/auth/login`;
  };

  const handleLogout = () => {
    localStorage.clear();
    setAuthData(null);
    setNeedsAuth(true);
  };

  // Auth Routing Bypass for callback
  if (window.location.pathname === '/callback') {
    return <OAuthCallback setAuthData={setAuthData} />;
  }

  if (needsAuth && !authData) {
    return (
      <div className="login-page">
        <div className="login-card card">
          <div className="login-brand">
            <h1 className="brand-title" style={{ fontSize: '2.5rem' }}>ThreatDock</h1>
            <p className="page-subtitle">Enterprise Threat Intelligence</p>
          </div>
          
          {loginError && <div className="card text-red" style={{ padding: '0.75rem', marginBottom: '1.5rem', background: 'rgba(239,68,68,0.1)' }}>{loginError}</div>}
          
          {/* SSO button hidden per user request
          {ssoConfig?.ssoEnabled ? (
            <div className="flex flex-col gap-4">
              <button onClick={handleSSOLogin} className="btn btn-primary btn-block" style={{ padding: '0.875rem', fontSize: '1rem' }}>
                Sign In with SSO (Authentik)
              </button>
              <div style={{ margin: '1rem 0', color: 'var(--text-muted)' }}>— OR —</div>
            </div>
          ) : null}
          */}

          <form onSubmit={handleLegacyLogin} className="flex flex-col gap-4 text-left">
            <div className="form-group">
              <label className="form-label">Username</label>
              <input className="form-input" type="text" value={loginUser} onChange={e => setLoginUser(e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" value={loginPass} onChange={e => setLoginPass(e.target.value)} required />
            </div>
            <button type="submit" className="btn btn-outline btn-block">Sign In with Local Account</button>
          </form>
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
        <Route path="/hunting" element={<ThreatHunting />} />
        <Route path="/assets" element={<AssetDiscovery />} />
        <Route path="/exposure" element={<ExposureMonitoring />} />
        <Route path="/intel" element={<AssetIntelligence />} />
        <Route path="/prioritization" element={<VulnPrioritization />} />
        <Route path="/predictive" element={<PredictiveIntel />} />
        <Route path="/analysis" element={<ThreatAnalysis />} />
        <Route path="/digital-risk" element={<DigitalRisk />} />
        <Route path="/brand" element={<BrandExposure />} />
        <Route path="/third-party" element={<ThirdPartyRisk />} />
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