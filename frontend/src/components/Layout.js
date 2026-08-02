import React, { useState, useEffect } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { 
  ShieldAlert, LayoutDashboard, Search, Globe, 
  Activity, Brain, Crosshair, TrendingUp, 
  Network, Lock, Eye, Building2, Settings, LogOut, Sun, Moon, HeartPulse
} from 'lucide-react';

const navItems = [
  { path: '/', label: 'Command Center', icon: <LayoutDashboard size={20} /> },
  { path: '/alerts', label: 'Security Alerts', icon: <ShieldAlert size={20} /> },
  { path: '/hunting', label: 'Threat Hunting', icon: <Search size={20} /> },
  { path: '/operations', label: 'Intel Operations', icon: <Network size={20} /> },
  { path: '/assets', label: 'External Asset Discovery', icon: <Globe size={20} /> },
  { path: '/exposure', label: 'Exposure Monitoring', icon: <Activity size={20} /> },
  { path: '/intel', label: 'Contextual Asset Intel', icon: <Brain size={20} /> },
  { path: '/prioritization', label: 'Vuln Prioritization', icon: <Crosshair size={20} /> },
  { path: '/predictive', label: 'Threat Outlook', icon: <TrendingUp size={20} /> },
  { path: '/analysis', label: 'Threat Analysis', icon: <Network size={20} /> },
  { path: '/digital-risk', label: 'Digital Risk Protection', icon: <Lock size={20} /> },
  { path: '/brand', label: 'Brand & Online Exposure', icon: <Eye size={20} /> },
  { path: '/dns-impersonation', label: 'Domain Impersonation', icon: <Globe size={20} /> },
  { path: '/third-party', label: 'Third-Party Risk', icon: <Building2 size={20} /> },
  { path: '/status', label: 'System Status', icon: <HeartPulse size={20} /> },
  { path: '/settings', label: 'Settings', icon: <Settings size={20} /> },
];

function Layout({ user, onLogout, children }) {
  const [theme, setTheme] = useState(localStorage.getItem('threatdock_theme') || 'midnight');

  useEffect(() => {
    if (theme === 'days') {
      document.body.classList.add('theme-days');
    } else {
      document.body.classList.remove('theme-days');
    }
    localStorage.setItem('threatdock_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'midnight' ? 'days' : 'midnight');
  };

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="sidebar-header">
          <ShieldAlert className="brand-icon" size={28} strokeWidth={2.5} />
          <span className="brand-title">ThreatDock</span>
        </div>
        
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink 
              key={item.path} 
              to={item.path} 
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-profile">
            <div className="avatar">
              {user ? user.name.charAt(0).toUpperCase() : '?'}
            </div>
            <div className="user-info">
              <div className="user-name">{user ? user.name : 'Anonymous'}</div>
              <div className="user-role">{user ? `${user.role || 'Analyst'}${user.email ? ` • ${user.email}` : ''}` : 'Analyst'}</div>
            </div>
            <button onClick={toggleTheme} style={{background:'transparent', border:'none', color:'var(--text-muted)', cursor:'pointer', padding:'4px', marginRight:'4px'}} title={`Switch to ${theme === 'midnight' ? 'Days' : 'Midnight'} Mode`}>
              {theme === 'midnight' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button onClick={onLogout} style={{background:'transparent', border:'none', color:'var(--text-muted)', cursor:'pointer', padding:'4px'}} title="Logout">
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        {children}
      </main>
    </div>
  );
}

export default Layout;
