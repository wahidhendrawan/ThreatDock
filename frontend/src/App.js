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

  // Authentication State
  const [authData, setAuthData] = useState(() => {
    try {
      const token = localStorage.getItem('threatdock_token');
      const userStr = localStorage.getItem('threatdock_user');
      if (token && userStr) {
        return { token, user: JSON.parse(userStr) };
      }
      return null;
    } catch {
      return null;
    }
  });

  const [needsAuth, setNeedsAuth] = useState(!localStorage.getItem('threatdock_token'));
  
  // Login State
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState('');
  
  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [tempToken, setTempToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaSetupRequired, setMfaSetupRequired] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState(null);

  // SSO State
  const [ssoConfig, setSsoConfig] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/auth/config`)
      .then(res => res.json())
      .then(data => setSsoConfig(data))
      .catch(console.error);
  }, []);

  // Handle SSO Callback
  useEffect(() => {
    if (window.location.pathname === '/callback') {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      if (code) {
        fetch(`${API_BASE}/auth/callback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        })
        .then(res => res.json())
        .then(data => {
          if (data.error) {
            setLoginError(data.error);
          } else if (data.requiresMfa) {
            setMfaRequired(true);
            setTempToken(data.tempToken);
            setMfaSetupRequired(data.setupRequired);
            setMfaSetupData(null);
            setMfaCode('');
            setNeedsAuth(true);
            window.history.replaceState({}, document.title, "/");
          } else if (data.access_token) {
            localStorage.setItem('threatdock_token', data.access_token);
            localStorage.setItem('threatdock_user', JSON.stringify(data.user));
            setAuthData({ token: data.access_token, user: data.user });
            setNeedsAuth(false);
            window.history.replaceState({}, document.title, "/");
          }
        })
        .catch(err => {
          setLoginError('Failed to process SSO callback');
          console.error(err);
        });
      }
    }
  }, []);

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

    fetch(`${API_BASE}/auth/local-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: loginUser, password: loginPass })
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(({ status, data }) => {
        if (status === 401) {
          setLoginError('Invalid username or password.');
          return;
        }
        if (status !== 200) {
          setLoginError(data.error || 'Login failed.');
          return;
        }

        if (data.requiresMfa) {
          setMfaRequired(true);
          setTempToken(data.tempToken);
          setMfaSetupRequired(data.setupRequired);
          setMfaSetupData(null);
          setMfaCode('');
        } else {
          localStorage.setItem('threatdock_token', data.access_token);
          localStorage.setItem('threatdock_user', JSON.stringify(data.user));
          setAuthData({ token: data.access_token, user: data.user });
          setNeedsAuth(false);
        }
      })
      .catch(() => setLoginError('Network error. Please try again.'));
  };

  const handleStartMfaSetup = () => {
    setLoginError('');

    fetch(`${API_BASE}/auth/setup-mfa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken })
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(({ status, data }) => {
        if (status !== 200) {
          setLoginError(data.error || 'Failed to start MFA setup.');
          return;
        }
        setMfaSetupData(data);
      })
      .catch(() => setLoginError('Network error. Please try again.'));
  };

  const handleVerifyMfa = (e) => {
    e.preventDefault();
    setLoginError('');

    fetch(`${API_BASE}/auth/verify-mfa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken, code: mfaCode })
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(({ status, data }) => {
        if (status !== 200) {
          setLoginError(data.error || 'Invalid MFA code.');
          return;
        }
        localStorage.setItem('threatdock_token', data.access_token);
        localStorage.setItem('threatdock_user', JSON.stringify(data.user));
        setAuthData({ token: data.access_token, user: data.user });
        setNeedsAuth(false);
        setMfaRequired(false);
        setTempToken('');
        setMfaSetupRequired(false);
        setMfaSetupData(null);
        setMfaCode('');
      })
      .catch(() => setLoginError('Network error. Please try again.'));
  };

  const handleLogout = () => {
    localStorage.removeItem('threatdock_token');
    localStorage.removeItem('threatdock_user');
    setAuthData(null);
    setAlerts([]);
    setNeedsAuth(true);
    setMfaRequired(false);
    setMfaSetupRequired(false);
    setMfaSetupData(null);
    setLoginUser('');
    setLoginPass('');
    setMfaCode('');
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
            <h1 className="brand-title" style={{ fontSize: '2rem', marginTop: '1rem', color: 'var(--text-main)' }}>ThreatDock</h1>
            <p className="page-subtitle" style={{ marginTop: '0.5rem' }}>Centralized Threat Intelligence Platform</p>
          </div>
          
          {loginError && (
            <div style={{ 
              padding: '0.75rem 1rem', 
              marginBottom: '1.5rem', 
              background: 'rgba(239,68,68,0.15)', 
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: '8px',
              color: '#ef4444',
              fontSize: '0.875rem'
            }}>
              {loginError}
            </div>
          )}

          {!mfaRequired ? (
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
              
              {ssoConfig?.ssoEnabled && (
                <div style={{ marginTop: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', margin: '1rem 0' }}>
                    <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }}></div>
                    <span style={{ padding: '0 1rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>OR</span>
                    <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }}></div>
                  </div>
                  <a href={`${API_BASE}/auth/login`} className="btn btn-outline btn-block" style={{ textDecoration: 'none', padding: '0.875rem', fontSize: '1rem', display: 'flex', justifyContent: 'center' }}>
                    Login with Corporate SSO
                  </a>
                </div>
              )}
            </form>
          ) : (
            <form onSubmit={handleVerifyMfa} className="flex flex-col gap-4 text-left">
              <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                <h3 style={{ color: 'var(--text-main)', marginBottom: '0.5rem' }}>Two-Factor Authentication</h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                  {mfaSetupRequired ? 'MFA is required. Register an authenticator app before continuing.' : 'Enter the 6-digit code from your authenticator app.'}
                </p>
              </div>
              
              {mfaSetupRequired && !mfaSetupData && (
                <button type="button" onClick={handleStartMfaSetup} className="btn btn-primary btn-block" style={{ padding: '0.875rem', fontSize: '1rem' }}>
                  Set Up 2FA
                </button>
              )}

              {mfaSetupData && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', display: 'inline-block', marginBottom: '1rem' }}>
                    <img src={mfaSetupData.qrCodeUrl} alt="MFA QR Code" style={{ width: '180px', height: '180px' }} />
                  </div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                    Secret: {mfaSetupData.secret}
                  </p>
                </div>
              )}

              {(!mfaSetupRequired || mfaSetupData) && (
                <>
                  <div className="form-group">
                    <input 
                      className="form-input" 
                      type="text" 
                      value={mfaCode} 
                      onChange={e => setMfaCode(e.target.value)} 
                      placeholder="000000"
                      maxLength={6}
                      style={{ textAlign: 'center', fontSize: '1.5rem', letterSpacing: '0.5rem' }}
                      autoFocus
                      required 
                    />
                  </div>
                  <button type="submit" className="btn btn-primary btn-block" style={{ padding: '0.875rem', fontSize: '1rem', marginTop: '0.5rem' }}>
                    Verify & Sign In
                  </button>
                </>
              )}
              
              <button type="button" onClick={() => { setMfaRequired(false); setMfaSetupRequired(false); setMfaSetupData(null); setMfaCode(''); }} className="btn btn-outline btn-block" style={{ padding: '0.875rem', fontSize: '1rem', marginTop: '0.5rem' }}>
                Back to Login
              </button>
            </form>
          )}
          
          <p style={{ marginTop: '1.5rem', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
            <a href="https://www.linkedin.com/in/wahid-hendrawan-398385176" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>by Wahid Hendrawan</a>
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
        <Route path="/digital-risk" element={<DigitalRisk alerts={filteredAlerts} authData={authData} />} />
        <Route path="/brand" element={<BrandExposure alerts={filteredAlerts} authData={authData} />} />
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
