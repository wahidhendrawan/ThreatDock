import React, { useState, useEffect } from 'react';
import { Lock, Shield, Globe, Eye, Bell, Wifi, Users, Save, Plus, Trash2, Edit, Key, CheckCircle, AlertCircle } from 'lucide-react';

export default function Settings({ authData }) {
  const [activeTab, setActiveTab] = useState('auth');
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
  const [safeQrUrl, setSafeQrUrl] = useState('');

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
        setMsg({ text: 'User updated successfully', type: 'success' });
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
        if (typeof data.qrCodeUrl === 'string' && data.qrCodeUrl.startsWith('data:image/png;base64,')) {
          setSafeQrUrl(data.qrCodeUrl);
        } else {
          setSafeQrUrl('');
        }
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
        setSafeQrUrl('');
        setMfaCode('');
        fetchUsers();
      } else {
        const err = await res.json();
        setMsg({ text: `Verification failed: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error.', type: 'error' });
    }
  };

  const handleDeleteMfa = async (userId) => {
    if (!window.confirm('Delete MFA setup for this user? They will need to enroll again if MFA is required.')) return;
    try {
      const res = await fetch(`${API_BASE}/users/${userId}/mfa`, {
        method: 'DELETE',
        headers
      });
      if (res.ok) {
        setMsg({ text: 'MFA setup deleted', type: 'success' });
        fetchUsers();
      } else {
        const err = await res.json();
        setMsg({ text: `Failed to delete MFA: ${err.error}`, type: 'error' });
      }
    } catch (e) {
      setMsg({ text: 'Network error deleting MFA.', type: 'error' });
    }
  };

  /* ── Helper: status dot for API key fields ── */
  const StatusDot = ({ value }) => (
    <span style={{
      display: 'inline-block',
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      backgroundColor: value ? '#22c55e' : '#f59e0b',
      marginRight: '8px',
      flexShrink: 0
    }}
    title={value ? 'Configured' : 'Not configured'}
    />
  );

  /* ── Helper: single API-key / secret field ── */
  const ApiKeyField = ({ label, description, settingKey, placeholder }) => (
    <div className="form-group" style={{ marginBottom: '1.25rem' }}>
      <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
        <StatusDot value={settings[settingKey]} />
        {label}
      </label>
      <input
        type="password"
        className="form-input"
        value={settings[settingKey] || ''}
        onChange={(e) => setSettings({ ...settings, [settingKey]: e.target.value })}
        placeholder={placeholder || 'Optional'}
      />
      {description && (
        <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
          {description}
        </span>
      )}
    </div>
  );

  /* ── Tab definitions ── */
  const tabs = [
    { id: 'auth',    label: 'Authentication & SSO',    icon: Lock },
    { id: 'threat',  label: 'Threat Intelligence APIs', icon: Shield },
    { id: 'asset',   label: 'Asset & Exposure APIs',    icon: Globe },
    { id: 'risk',    label: 'Digital Risk APIs',         icon: Eye },
    { id: 'notify',  label: 'Notifications',             icon: Bell },
    { id: 'network', label: 'Network',                   icon: Wifi },
    { id: 'users',   label: 'User Management',           icon: Users },
  ];

  if (!settings && !msg.text) return <div className="card">Loading settings...</div>;

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '2rem' }}>
        <div>
          <h1 className="page-title">Settings & Management</h1>
          <div className="page-subtitle">Configure integrations, API keys, notifications and manage users</div>
        </div>
      </div>

      {msg.text && (
        <div style={{ padding: '1rem', marginBottom: '1.5rem', borderRadius: '8px',
                     backgroundColor: msg.type === 'error' ? 'var(--danger)' : 'var(--success)',
                     color: '#fff', opacity: 0.9, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {msg.type === 'error' ? <AlertCircle size={18} /> : <CheckCircle size={18} />}
          {msg.text}
        </div>
      )}

      {/* ───────── Tabs ───────── */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem', flexWrap: 'wrap' }}>
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              className={`btn ${activeTab === t.id ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActiveTab(t.id)}
              style={{
                border: 'none',
                background: activeTab === t.id ? 'var(--primary)' : 'transparent',
                display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem'
              }}
            >
              <Icon size={15} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* ═══════════════════════════════════════════════════════════════
           TAB 1 — Authentication & SSO
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'auth' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Lock size={20} /> Authentication & SSO
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              Multi-factor authentication requirements and corporate SSO / OIDC configuration.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            {/* MFA Required */}
            <div className="form-group">
              <label className="form-label">Require 2FA (MFA) Globally for Local Users</label>
              <select
                className="form-select"
                value={settings.MFA_REQUIRED || 'true'}
                onChange={(e) => setSettings({ ...settings, MFA_REQUIRED: e.target.value })}
              >
                <option value="true">Enabled (Mandatory)</option>
                <option value="false">Disabled (Optional)</option>
              </select>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                When enabled, all local users must configure an authenticator app before accessing the platform.
              </span>
            </div>

            {/* Analyst MFA */}
            <div className="form-group">
              <label className="form-label">Force MFA for Analyst Role</label>
              <select
                className="form-select"
                value={settings.ANALYST_MFA_REQUIRED || 'false'}
                onChange={(e) => setSettings({ ...settings, ANALYST_MFA_REQUIRED: e.target.value })}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Enforce MFA specifically for users with the Analyst role, even if global MFA is disabled.
              </span>
            </div>

            {/* SSO Enabled */}
            <div className="form-group">
              <label className="form-label">Enable Corporate SSO (OIDC)</label>
              <select
                className="form-select"
                value={settings.SSO_ENABLED}
                onChange={(e) => setSettings({ ...settings, SSO_ENABLED: e.target.value })}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Allow users to log in via your corporate identity provider using OpenID Connect.
              </span>
            </div>

            {/* OIDC Issuer URL */}
            <div className="form-group">
              <label className="form-label">OIDC Issuer URL</label>
              <input
                type="url" className="form-input"
                value={settings.OIDC_ISSUER_URL || ''}
                onChange={(e) => setSettings({ ...settings, OIDC_ISSUER_URL: e.target.value })}
                placeholder="https://sso.yourdomain.com/application/o/app-name/"
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                The OpenID Connect discovery endpoint of your identity provider.
              </span>
            </div>

            {/* OIDC Client ID */}
            <div className="form-group">
              <label className="form-label">OIDC Client ID</label>
              <input
                type="text" className="form-input"
                value={settings.OIDC_CLIENT_ID || ''}
                onChange={(e) => setSettings({ ...settings, OIDC_CLIENT_ID: e.target.value })}
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                The client identifier registered with your identity provider.
              </span>
            </div>

            {/* OIDC Client Secret */}
            <div className="form-group">
              <label className="form-label">OIDC Client Secret</label>
              <input
                type="password" className="form-input"
                value={settings.OIDC_CLIENT_SECRET || ''}
                onChange={(e) => setSettings({ ...settings, OIDC_CLIENT_SECRET: e.target.value })}
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Optional if using a public client. Required for confidential OIDC clients.
              </span>
            </div>

            {/* Frontend Callback URL */}
            <div className="form-group">
              <label className="form-label">Frontend Callback URL (Informational)</label>
              <input
                type="text" className="form-input"
                value={`${settings.FRONTEND_URL || ''}/callback`}
                disabled
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Use this as the redirect URI when configuring your identity provider.
              </span>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 2 — Threat Intelligence APIs
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'threat' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Shield size={20} /> Threat Intelligence APIs
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              API keys for vulnerability databases, threat feeds, and IOC sources.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            <ApiKeyField
              label="GitHub Token"
              description="Used to query the GitHub Advisory Database for known vulnerabilities in open-source packages."
              settingKey="GITHUB_TOKEN"
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            />
            <ApiKeyField
              label="NVD API Key"
              description="Access the NIST National Vulnerability Database for CVE enrichment and lookups."
              settingKey="NVD_API_KEY"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            />
            <ApiKeyField
              label="AlienVault OTX API Key"
              description="Open Threat Exchange — community-driven threat intelligence with IOC and pulse data."
              settingKey="OTX_API_KEY"
            />
            <ApiKeyField
              label="ThreatFox Auth Key"
              description="ThreatFox by abuse.ch — indicators of compromise (IOCs) including malware, C2 servers."
              settingKey="THREATFOX_AUTH_KEY"
            />

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.MISP_URL} />
                MISP Instance URL
              </label>
              <input
                type="url"
                className="form-input"
                value={settings.MISP_URL || ''}
                onChange={(e) => setSettings({ ...settings, MISP_URL: e.target.value })}
                placeholder="https://misp.yourdomain.com"
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Base URL of your MISP (Malware Information Sharing Platform) instance.
              </span>
            </div>

            <ApiKeyField
              label="MISP API Key"
              description="Authentication key for your MISP instance to pull and push threat intelligence events."
              settingKey="MISP_API_KEY"
            />
            <ApiKeyField
              label="IntelOwl API Key"
              description="IntelOwl — aggregated threat intelligence analysis for observables (IPs, domains, hashes)."
              settingKey="INTELO_OWL_API_KEY"
            />

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 3 — Asset & Exposure APIs
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'asset' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Globe size={20} /> Asset & Exposure APIs
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              Services for asset discovery, domain intelligence, and external exposure scanning.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            <ApiKeyField
              label="SecurityTrails API Key"
              description="Discover subdomains, DNS records, and historical WHOIS data for your assets."
              settingKey="SECURITYTRAILS_API_KEY"
            />
            <ApiKeyField
              label="VirusTotal API Key"
              description="Community API for domain reputation, file analysis, and URL scanning intelligence."
              settingKey="VIRUSTOTAL_API_KEY"
            />
            <ApiKeyField
              label="URLScan.io API Key"
              description="Automated website scanning — detect phishing, brand impersonation, and exposure."
              settingKey="URLSCAN_API_KEY"
            />

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 4 — Digital Risk APIs
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'risk' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Eye size={20} /> Digital Risk APIs
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              Credential leak monitoring, dark web exposure, and identity breach detection.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            <ApiKeyField
              label="Have I Been Pwned API Key"
              description="Check if employee or corporate email addresses appear in known data breaches."
              settingKey="HIBP_API_KEY"
            />
            <ApiKeyField
              label="Intelligence X API Key"
              description="Search leaked databases, dark web pastes, and historical data for identity exposure."
              settingKey="INTELX_API_KEY"
            />

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 5 — Notifications
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'notify' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Bell size={20} /> Notifications
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              Webhook URLs for alerting and the minimum severity threshold for outgoing notifications.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.SLACK_WEBHOOK_URL} />
                Slack Webhook URL
              </label>
              <input
                type="password"
                className="form-input"
                value={settings.SLACK_WEBHOOK_URL || ''}
                onChange={(e) => setSettings({ ...settings, SLACK_WEBHOOK_URL: e.target.value })}
                placeholder="https://hooks.slack.com/services/..."
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Incoming webhook URL for posting alerts to a Slack channel.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.N8N_WEBHOOK_URL} />
                n8n Webhook URL
              </label>
              <input
                type="password"
                className="form-input"
                value={settings.N8N_WEBHOOK_URL || ''}
                onChange={(e) => setSettings({ ...settings, N8N_WEBHOOK_URL: e.target.value })}
                placeholder="https://n8n.yourdomain.com/webhook/..."
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                n8n automation webhook for custom notification workflows and integrations.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.TELEGRAM_BOT_TOKEN} />
                Telegram Bot Token
              </label>
              <input
                type="password"
                className="form-input"
                value={settings.TELEGRAM_BOT_TOKEN || ''}
                onChange={(e) => setSettings({ ...settings, TELEGRAM_BOT_TOKEN: e.target.value })}
                placeholder="123456789:ABCdefGHIjklMNO..."
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Bot token from BotFather for sending Telegram notifications.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.TELEGRAM_CHAT_ID} />
                Telegram Chat ID
              </label>
              <input
                type="password"
                className="form-input"
                value={settings.TELEGRAM_CHAT_ID || ''}
                onChange={(e) => setSettings({ ...settings, TELEGRAM_CHAT_ID: e.target.value })}
                placeholder="-1001234567890"
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Chat ID or Channel ID where Telegram messages should be sent.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.TEAMS_WEBHOOK_URL} />
                Microsoft Teams Webhook URL
              </label>
              <input
                type="password"
                className="form-input"
                value={settings.TEAMS_WEBHOOK_URL || ''}
                onChange={(e) => setSettings({ ...settings, TEAMS_WEBHOOK_URL: e.target.value })}
                placeholder="https://yourdomain.webhook.office.com/webhookb2/..."
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Incoming webhook URL for a Microsoft Teams channel.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label">Notification Threshold</label>
              <select
                className="form-select"
                value={settings.NOTIFY_THRESHOLD || 'High'}
                onChange={(e) => setSettings({ ...settings, NOTIFY_THRESHOLD: e.target.value })}
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Minimum severity level that triggers a notification. Findings below this threshold are logged but not alerted.
              </span>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 6 — Network
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'network' && settings && (
        <div className="card">
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Wifi size={20} /> Network
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', margin: 0 }}>
              Network-level configuration for DNS resolution and scanning infrastructure.
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="grid grid-cols-1 gap-4">
            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <StatusDot value={settings.PUBLIC_DNS_SERVERS} />
                Public DNS Servers
              </label>
              <input
                type="text"
                className="form-input"
                value={settings.PUBLIC_DNS_SERVERS || ''}
                onChange={(e) => setSettings({ ...settings, PUBLIC_DNS_SERVERS: e.target.value })}
                placeholder="8.8.8.8,1.1.1.1,9.9.9.9"
              />
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Comma-separated list of public DNS servers used for domain resolution during scans (e.g. 8.8.8.8, 1.1.1.1).
              </span>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary"><Save size={16} /> Save Configuration</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════
           TAB 7 — User Management  (kept as-is)
         ═══════════════════════════════════════════════════════════════ */}
      {activeTab === 'users' && (
        <div className="grid grid-cols-1 gap-4" style={{ gridTemplateColumns: '1fr 2fr' }}>
          {/* Add User Form */}
          <div className="card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <Users size={18} /> Add Local User
            </h3>
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
                  <th>MFA</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td>{u.id}</td>
                    <td>
                      <input
                        className="form-input"
                        value={(userEdits[u.id] && userEdits[u.id].username) || ''}
                        onChange={(e)=>setUserEdits({ ...userEdits, [u.id]: { ...(userEdits[u.id] || {}), username: e.target.value } })}
                      />
                    </td>
                    <td>
                      <input
                        className="form-input"
                        value={(userEdits[u.id] && userEdits[u.id].email) || ''}
                        onChange={(e)=>setUserEdits({ ...userEdits, [u.id]: { ...(userEdits[u.id] || {}), email: e.target.value } })}
                        placeholder="email@example.com"
                      />
                    </td>
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
                      <span className={`badge ${u.mfa_enabled ? 'badge-low' : 'badge-critical'}`}>
                        {u.mfa_enabled ? 'Enabled' : 'Not Set'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button onClick={() => handleSetupMfa(u.id)} className="btn btn-outline" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} title="Setup MFA">
                          Setup 2FA
                        </button>
                        <button onClick={() => handleDeleteMfa(u.id)} className="btn btn-outline" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} title="Delete MFA">
                          Delete 2FA
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
                    <td colSpan="6" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ───────── MFA Setup Modal Overlay ───────── */}
      {mfaSetupData && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ maxWidth: '400px', width: '100%', textAlign: 'center' }}>
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-main)' }}>Set Up Authenticator App</h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
              Scan the QR code below using Google Authenticator, Microsoft Authenticator, or Authy.
            </p>
            <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', display: 'inline-block', marginBottom: '1.5rem' }}>
              {safeQrUrl ? <img src={safeQrUrl} alt="MFA QR Code" style={{ width: '200px', height: '200px' }} /> : null}
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
              <button onClick={() => { setMfaSetupData(null); setSafeQrUrl(''); }} className="btn btn-outline btn-block">Cancel</button>
              <button onClick={handleVerifyMfaSetup} className="btn btn-primary btn-block">Verify & Enable</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
