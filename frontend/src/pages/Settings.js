import React, { useState, useEffect } from 'react';
import { Save, Plus, Trash2, Edit } from 'lucide-react';

export default function Settings({ authData }) {
  const [activeTab, setActiveTab] = useState('sso');
  const [settings, setSettings] = useState(null);
  const [users, setUsers] = useState([]);
  const [userEdits, setUserEdits] = useState({});
  
  // New User Form
  const [newUser, setNewUser] = useState({ username: '', password: '', email: '', role: 'Analyst' });

  // Notifications
  const [msg, setMsg] = useState({ text: '', type: '' });
  
  // MFA Setup
  const [mfaSetupData, setMfaSetupData] = useState(null);
  const [mfaCode, setMfaCode] = useState('');

  const headers = { 
    'Content-Type': 'application/json',
    ...(authData?.token ? { 'Authorization': `Bearer ${authData.token}` } : 
        authData?.basic ? { 'Authorization': `Basic ${btoa(authData.basic.user + ':' + authData.basic.pass)}` } : {})
  };

  const API_BASE = '/api';

  useEffect(() => {
    fetchSettings();
    fetchUsers();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await fetch(`${API_BASE}/settings`, { headers });
      if (res.ok) {
        setSettings(await res.json());
      } else if (res.status === 403) {
        setMsg({ text: 'You do not have permission to view settings.', type: 'error' });
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API_BASE}/users`, { headers });
      if (res.ok) {
        const rows = await res.json();
        setUsers(rows);
        const edits = {};
        rows.forEach((u) => { edits[u.id] = { username: u.username || '', email: u.email || '', role: u.role || 'Analyst' }; });
        setUserEdits(edits);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/settings`, {
        method: 'PUT',
        headers,
        body: JSON.stringify(settings)
      });
      if (res.ok) {
        setMsg({ text: 'Settings saved successfully. Changes take effect immediately.', type: 'success' });
      } else {
        setMsg({ text: 'Failed to save settings. Check permissions.', type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error saving settings.', type: 'error' });
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers,
        body: JSON.stringify(newUser)
      });
      if (res.ok) {
        setMsg({ text: 'User added successfully', type: 'success' });
        setNewUser({ username: '', password: '', email: '', role: 'Analyst' });
        fetchUsers();
      } else {
        const err = await res.json();
        setMsg({ text: `Error: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error adding user.', type: 'error' });
    }
  };


  const handleSaveUser = async (id) => {
    try {
      const edited = userEdits[id];
      if (!edited) return;

      const res = await fetch(`${API_BASE}/users/${id}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify(edited)
      });

      if (res.ok) {
        setMsg({ text: 'User updated', type: 'success' });
        fetchUsers();
      } else {
        const err = await res.json();
        setMsg({ text: `Error: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error updating user.', type: 'error' });
    }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      const res = await fetch(`${API_BASE}/users/${id}`, {
        method: 'DELETE',
        headers
      });
      if (res.ok) {
        setMsg({ text: 'User deleted', type: 'success' });
        fetchUsers();
      }
    } catch (e) {
      setMsg({ text: 'Network error deleting user.', type: 'error' });
    }
  };

  const handleSetupMfa = async (userId) => {
    try {
      const res = await fetch(`${API_BASE}/users/${userId}/mfa/setup`, {
        method: 'POST',
        headers
      });
      if (res.ok) {
        const data = await res.json();
        setMfaSetupData({ ...data, userId });
      } else {
        const err = await res.json();
        setMsg({ text: `Failed to start MFA setup: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error.', type: 'error' });
    }
  };

  const handleVerifyMfaSetup = async () => {
    try {
      const res = await fetch(`${API_BASE}/users/${mfaSetupData.userId}/mfa/enable`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ code: mfaCode })
      });
      if (res.ok) {
        setMsg({ text: 'MFA Enabled Successfully', type: 'success' });
        setMfaSetupData(null);
        setMfaCode('');
      } else {
        const err = await res.json();
        setMsg({ text: `Verification failed: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error.', type: 'error' });
    }
  };

  if (!settings && !msg.text) return <div className="card">Loading settings...</div>;

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '2rem' }}>
        <div>
          <h1 className="page-title">Settings & Management</h1>
          <div className="page-subtitle">Configure OAuth integration and manage local users</div>
        </div>
      </div>

      {msg.text && (
        <div style={{ padding: '1rem', marginBottom: '1.5rem', borderRadius: '8px', 
             backgroundColor: msg.type === 'error' ? 'var(--danger)' : 'var(--success)', 
             color: '#fff', opacity: 0.9 }}>
          {msg.text}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
        <button 
          className={`btn ${activeTab === 'sso' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setActiveTab('sso')}
          style={{ border: 'none', background: activeTab === 'sso' ? 'var(--primary)' : 'transparent' }}
        >
          Security & SSO
        </button>
        <button 
          className={`btn ${activeTab === 'users' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setActiveTab('users')}
          style={{ border: 'none', background: activeTab === 'users' ? 'var(--primary)' : 'transparent' }}
        >
          User Management
        </button>
      </div>

      {activeTab === 'sso' && settings && (
        <div className="card">
          <h2 style={{ marginBottom: '1.5rem' }}>Global Security Configuration</h2>
          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            
            <div className="form-group">
              <label className="form-label">Require 2FA (MFA) Globally for Local Users</label>
              <select 
                className="form-select"
                value={settings.MFA_REQUIRED || 'true'} 
                onChange={(e) => setSettings({...settings, MFA_REQUIRED: e.target.value})}
              >
                <option value="true">Enabled (Mandatory)</option>
                <option value="false">Disabled (Optional)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Force MFA for Analyst Role</label>
              <select
                className="form-select"
                value={settings.ANALYST_MFA_REQUIRED || 'false'}
                onChange={(e) => setSettings({...settings, ANALYST_MFA_REQUIRED: e.target.value})}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Enable Corporate SSO (OIDC)</label>
              <select 
                className="form-select"
                value={settings.SSO_ENABLED} 
                onChange={(e) => setSettings({...settings, SSO_ENABLED: e.target.value})}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Issuer URL</label>
              <input 
                type="url" className="form-input" 
                value={settings.OIDC_ISSUER_URL || ''}
                onChange={(e) => setSettings({...settings, OIDC_ISSUER_URL: e.target.value})}
                placeholder="https://sso.yourdomain.com/application/o/app-name/"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Client ID</label>
              <input 
                type="text" className="form-input" 
                value={settings.OIDC_CLIENT_ID || ''}
                onChange={(e) => setSettings({...settings, OIDC_CLIENT_ID: e.target.value})}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Client Secret (Optional if Public Client)</label>
              <input 
                type="password" className="form-input" 
                value={settings.OIDC_CLIENT_SECRET || ''}
                onChange={(e) => setSettings({...settings, OIDC_CLIENT_SECRET: e.target.value})}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Frontend Callback URL (Informational)</label>
              <input 
                type="text" className="form-input" 
                value={`${settings.FRONTEND_URL || ''}/callback`}
                disabled
              />
            </div>

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="grid grid-cols-1 gap-4" style={{ gridTemplateColumns: '1fr 2fr' }}>
          {/* Add User Form */}
          <div className="card">
            <h3 style={{ marginBottom: '1.5rem' }}>Add Local User</h3>
            <form onSubmit={handleAddUser} className="form-group">
              <div className="form-group">
                <label className="form-label">Username</label>
                <input required type="text" className="form-input" value={newUser.username} onChange={e => setNewUser({...newUser, username: e.target.value})} />
              </div>
              <div className="form-group">
                <label className="form-label">Password</label>
                <input required type="password" className="form-input" value={newUser.password} onChange={e => setNewUser({...newUser, password: e.target.value})} />
              </div>
              <div className="form-group">
                <label className="form-label">Email</label>
                <input type="email" className="form-input" value={newUser.email} onChange={e => setNewUser({...newUser, email: e.target.value})} />
              </div>
              <div className="form-group">
                <label className="form-label">Role</label>
                <select className="form-select" value={newUser.role} onChange={e => setNewUser({...newUser, role: e.target.value})}>
                  <option value="Admin">Admin</option>
                  <option value="Analyst">Analyst</option>
                </select>
              </div>
              <button type="submit" className="btn btn-primary mt-4"><Plus size={16}/> Create User</button>
            </form>
          </div>

          {/* User List */}
          <div className="card table-responsive">
            <h3 style={{ marginBottom: '1.5rem' }}>User List</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td>{u.id}</td>
                    <td><input className="form-input" value={(userEdits[u.id] && userEdits[u.id].username) || ''} onChange={(e)=>setUserEdits({ ...userEdits, [u.id]: { ...(userEdits[u.id] || {}), username: e.target.value } })} /></td>
                    <td><input className="form-input" value={(userEdits[u.id] && userEdits[u.id].email) || ''} onChange={(e)=>setUserEdits({ ...userEdits, [u.id]: { ...(userEdits[u.id] || {}), email: e.target.value } })} placeholder="email@example.com" /></td>
                    <td>
                      <select
                        className="form-select"
                        value={(userEdits[u.id] && userEdits[u.id].role) || u.role}
                        onChange={(e) => setUserEdits({ ...userEdits, [u.id]: { ...(userEdits[u.id] || {}), role: e.target.value } })}
                      >
                        <option value="Admin">Admin</option>
                        <option value="Analyst">Analyst</option>
                      </select>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button onClick={() => handleSetupMfa(u.id)} className="btn btn-outline" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} title="Setup MFA">
                          Setup 2FA
                        </button>
                        <button onClick={() => handleSaveUser(u.id)} className="btn btn-outline" style={{ padding: '0.25rem 0.5rem' }} title="Save User">
                          <Edit size={14} />
                        </button>
                        <button onClick={() => handleDeleteUser(u.id)} className="btn btn-danger" style={{ padding: '0.25rem 0.5rem' }}>
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MFA Setup Modal Overlay */}
      {mfaSetupData && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ maxWidth: '400px', width: '100%', textAlign: 'center' }}>
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-main)' }}>Set Up Authenticator App</h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
              Scan the QR code below using Google Authenticator, Microsoft Authenticator, or Authy.
            </p>
            <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', display: 'inline-block', marginBottom: '1.5rem' }}>
              <img src={mfaSetupData.qrCodeUrl} alt="MFA QR Code" style={{ width: '200px', height: '200px' }} />
            </div>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label" style={{ textAlign: 'left' }}>Enter Verification Code</label>
              <input 
                className="form-input" 
                type="text" 
                placeholder="000000" 
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                maxLength={6}
                style={{ textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.5rem' }}
              />
            </div>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <button onClick={() => setMfaSetupData(null)} className="btn btn-outline btn-block">Cancel</button>
              <button onClick={handleVerifyMfaSetup} className="btn btn-primary btn-block">Verify & Enable</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
