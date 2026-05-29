import React, { useState, useEffect, useCallback } from 'react';
import { 
  ChevronDown, ChevronUp, MessageSquare, Save, 
  ExternalLink, Clock, User, ShieldAlert, 
  Tag, Info, AlertCircle, Bookmark, Trash2
} from 'lucide-react';
import PaginationControls, { usePagination } from './PaginationControls';

function getAuthHeaders(authData) {
  if (authData?.token) return { Authorization: `Bearer ${authData.token}` };
  if (authData?.basic) return { Authorization: `Basic ${btoa(`${authData.basic.user}:${authData.basic.pass}`)}` };
  return {};
}

function parseTags(tags) {
  if (Array.isArray(tags)) return tags;
  try {
    const parsed = JSON.parse(tags || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return String(tags || '').split(',').map(tag => tag.trim()).filter(Boolean);
  }
}

function AlertList({ alerts, authData, onStatusChange, onAlertUpdate }) {
  const pagination = usePagination(alerts || [], 100);
  const [expandedId, setExpandedId] = useState(null);
  const [commentsByAlert, setCommentsByAlert] = useState({});
  const [commentDrafts, setCommentDrafts] = useState({});
  const [localEdits, setLocalEdits] = useState({});
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const res = await fetch('/api/users/list/simple', { headers: getAuthHeaders(authData) });
        if (res.ok) setUsers(await res.json());
      } catch (e) { console.error(e); }
    };
    fetchUsers();
  }, [authData]);

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? dateStr : d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const formatDateTime = (dateStr) => {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? dateStr : d.toLocaleString();
  };

  const loadComments = async (alertId) => {
    if (commentsByAlert[alertId]) return;
    try {
      const res = await fetch(`/api/alerts/${alertId}/comments`, { headers: getAuthHeaders(authData) });
      if (res.ok) {
        const rows = await res.json();
        setCommentsByAlert(prev => ({ ...prev, [alertId]: rows }));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const toggleExpanded = (alertId) => {
    const nextId = expandedId === alertId ? null : alertId;
    setExpandedId(nextId);
    if (nextId) loadComments(nextId);
  };

  const updateAlert = (alert, patch) => {
    if (onAlertUpdate) onAlertUpdate(alert.id, patch);
  };

  const handleStatus = (alert, status) => {
    if (onStatusChange) onStatusChange(alert.id, status);
  };

  const saveLocalEdit = (alert, field) => {
    const value = localEdits[`${alert.id}:${field}`];
    if (value === undefined) return;
    if (field === 'tags') {
      updateAlert(alert, { tags: value.split(',').map(tag => tag.trim()).filter(Boolean) });
    } else {
      updateAlert(alert, { [field]: value });
    }
  };

  const postComment = async (alert) => {
    const body = String(commentDrafts[alert.id] || '').trim();
    if (!body) return;
    try {
      const res = await fetch(`/api/alerts/${alert.id}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(authData) },
        body: JSON.stringify({ body })
      });
      if (res.ok) {
        const saved = await res.json();
        setCommentsByAlert(prev => ({ ...prev, [alert.id]: [...(prev[alert.id] || []), saved] }));
        setCommentDrafts(prev => ({ ...prev, [alert.id]: '' }));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const deleteComment = async (alertId, commentId) => {
    if (!window.confirm('Delete this case update?')) return;
    try {
      const res = await fetch(`/api/alerts/${alertId}/comments/${commentId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(authData)
      });
      if (res.ok) {
        setCommentsByAlert(prev => ({
          ...prev,
          [alertId]: prev[alertId].filter(c => c.id !== commentId)
        }));
      }
    } catch (err) {
      console.error(err);
    }
  };

  if (!alerts || alerts.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
        <ShieldAlert size={48} style={{ opacity: 0.2, marginBottom: '1rem' }} />
        <p style={{ fontSize: '1rem', fontWeight: 500 }}>No alerts found matching your criteria.</p>
        <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>Adjust your filters or wait for the next intelligence ingestion cycle.</p>
      </div>
    );
  }

  return (
    <div className="table-container" style={{ border: 'none', background: 'transparent' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: '40px' }}></th>
            <th style={{ width: '120px' }}>Source</th>
            <th style={{ width: '100px' }}>Severity</th>
            <th style={{ width: '80px' }}>Priority</th>
            <th style={{ width: '140px' }}>Status</th>
            <th style={{ width: '150px' }}>Assignee</th>
            <th>Alert Intelligence</th>
            <th style={{ width: '100px' }}>Date</th>
          </tr>
        </thead>
        <tbody>
          {pagination.pagedItems.map(alert => {
            const tags = parseTags(alert.tags);
            const isExpanded = expandedId === alert.id;
            const priorityClass = `priority-${alert.priority || 'P3'}`;
            const statusClass = `status-${(alert.status || 'Open').replace(' ', '-')}`;

            return (
              <React.Fragment key={alert.id || `${alert.source}-${alert.externalId}`}>
                <tr 
                  className={isExpanded ? 'active-row' : ''} 
                  style={{ 
                    cursor: 'pointer',
                    background: isExpanded ? 'rgba(59, 130, 246, 0.04)' : 'var(--bg-card)'
                  }}
                  onClick={() => toggleExpanded(alert.id)}
                >
                  <td>
                    <button className="icon-button" type="button" style={{ border: 'none' }}>
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 700, color: 'var(--primary-color)', fontSize: '0.8rem' }}>{alert.source}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`severity-badge severity-${alert.severity || 'Unknown'}`}>
                      {alert.severity || 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`priority-badge ${priorityClass}`}>{alert.priority || 'P3'}</span>
                  </td>
                  <td>
                    <span className={`status-badge ${statusClass}`}>
                      {alert.status || 'Open'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: alert.assignee ? 'var(--text-main)' : 'var(--text-muted)' }}>
                      <User size={12} />
                      <span style={{ fontSize: '0.8rem' }}>{alert.assignee || 'Unassigned'}</span>
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-main)' }}>{alert.title}</span>
                        {alert.url && (
                          <a 
                            href={alert.url} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            onClick={e => e.stopPropagation()}
                            style={{ color: 'var(--text-muted)' }}
                          >
                            <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                      <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dark)' }}>{alert.externalId || 'No Reference ID'}</span>
                        <div style={{ height: '10px', width: '1px', background: 'var(--border-color)' }}></div>
                        <span style={{ fontSize: '0.7rem', color: 'var(--accent)', fontWeight: 600 }}>{alert.attack_phase || 'Initial Analysis'}</span>
                        {tags.map(tag => <span key={tag} className="mini-badge" style={{ fontSize: '0.65rem' }}>{tag}</span>)}
                      </div>
                    </div>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      <Clock size={12} />
                      {formatDate(alert.date)}
                    </div>
                  </td>
                </tr>
                {isExpanded && (
                  <tr onClick={e => e.stopPropagation()}>
                    <td colSpan="8" style={{ background: 'rgba(59, 130, 246, 0.02)', padding: '0' }}>
                      <div className="case-panel" style={{ padding: '1.5rem 2rem', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)' }}>
                        <div className="card" style={{ gridColumn: 'span 1', background: 'rgba(0,0,0,0.1)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: 'var(--primary-color)' }}>
                            <Bookmark size={16} />
                            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase' }}>Case Management</h3>
                          </div>
                          
                          <div className="flex flex-col gap-4">
                            <div className="form-group">
                              <label className="form-label">Priority Level</label>
                              <select
                                className="form-select"
                                value={alert.priority || 'P3'}
                                onChange={e => updateAlert(alert, { priority: e.target.value })}
                              >
                                <option value="P1">P1 - Critical (Immediate Action)</option>
                                <option value="P2">P2 - High (Action Required)</option>
                                <option value="P3">P3 - Medium (Monitor)</option>
                                <option value="P4">P4 - Low (Informational)</option>
                              </select>
                            </div>

                            <div className="form-group">
                              <label className="form-label">Current Status</label>
                              <select
                                className="form-select"
                                value={alert.status || 'Open'}
                                onChange={e => handleStatus(alert, e.target.value)}
                              >
                                <option value="Open">Open</option>
                                <option value="In Progress">In Progress</option>
                                <option value="Resolved">Resolved / Patched</option>
                                <option value="False Positive">False Positive</option>
                                <option value="Accepted Risk">Accepted Risk</option>
                              </select>
                            </div>

                            <div className="form-group">
                              <label className="form-label">Assignee</label>
                              <select
                                className="form-select"
                                value={alert.assignee || ''}
                                onChange={e => updateAlert(alert, { assignee: e.target.value })}
                              >
                                <option value="">Unassigned</option>
                                {users.map(u => (
                                  <option key={u} value={u}>{u}</option>
                                ))}
                              </select>
                            </div>

                            <div className="form-group">
                              <label className="form-label">SLA / Due Date</label>
                              <input
                                className="form-input"
                                type="date"
                                defaultValue={alert.sla_due ? String(alert.sla_due).slice(0, 10) : ''}
                                onChange={e => updateAlert(alert, { sla_due: e.target.value })}
                              />
                            </div>
                          </div>
                        </div>

                        <div className="card" style={{ gridColumn: 'span 2', background: 'rgba(0,0,0,0.1)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: 'var(--primary-color)' }}>
                            <Info size={16} />
                            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase' }}>Investigation Details</h3>
                          </div>

                          <div className="flex flex-col gap-4">
                            <div className="form-group">
                              <label className="form-label">Case Summary & Notes</label>
                              <textarea
                                className="form-input"
                                rows="4"
                                style={{ resize: 'vertical' }}
                                defaultValue={alert.case_summary || ''}
                                onChange={e => setLocalEdits(prev => ({ ...prev, [`${alert.id}:case_summary`]: e.target.value }))}
                                onBlur={() => saveLocalEdit(alert, 'case_summary')}
                                placeholder="Describe findings, impact assessment, and remediation steps taken..."
                              />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                              <div className="form-group">
                                <label className="form-label"><Tag size={12} style={{ marginRight: '0.25rem' }} /> Tags</label>
                                <input
                                  className="form-input"
                                  defaultValue={tags.join(', ')}
                                  onChange={e => setLocalEdits(prev => ({ ...prev, [`${alert.id}:tags`]: e.target.value }))}
                                  onBlur={() => saveLocalEdit(alert, 'tags')}
                                  placeholder="cve-match, production, priority-patch"
                                />
                              </div>
                              <div className="form-group">
                                <label className="form-label"><AlertCircle size={12} style={{ marginRight: '0.25rem' }} /> Attack Phase</label>
                                <select
                                  className="form-select"
                                  value={alert.attack_phase || 'Unknown'}
                                  onChange={e => updateAlert(alert, { attack_phase: e.target.value })}
                                >
                                  <option value="Unknown">Unknown Phase</option>
                                  <option value="Reconnaissance">Reconnaissance</option>
                                  <option value="Initial Access">Initial Access</option>
                                  <option value="Execution">Execution</option>
                                  <option value="Persistence">Persistence</option>
                                  <option value="Privilege Escalation">Privilege Escalation</option>
                                  <option value="Defense Evasion">Defense Evasion</option>
                                  <option value="Credential Access">Credential Access</option>
                                  <option value="Discovery">Discovery</option>
                                  <option value="Lateral Movement">Lateral Movement</option>
                                  <option value="Command and Control">C2</option>
                                  <option value="Exfiltration">Exfiltration</option>
                                  <option value="Impact">Impact</option>
                                </select>
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="card" style={{ gridColumn: '1 / -1', background: 'rgba(0,0,0,0.1)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: 'var(--primary-color)' }}>
                            <MessageSquare size={16} />
                            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase' }}>Activity & Comments</h3>
                          </div>
                          
                          <div className="comment-list" style={{ maxHeight: '250px', background: 'transparent', border: 'none', padding: 0 }}>
                            {(commentsByAlert[alert.id] || []).length === 0 ? (
                              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }}>
                                <MessageSquare size={24} style={{ opacity: 0.1, marginBottom: '0.5rem' }} />
                                <p style={{ fontSize: '0.8rem' }}>No case activity recorded yet.</p>
                              </div>
                            ) : (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                                {(commentsByAlert[alert.id] || []).map(comment => (
                                  <div key={comment.id} className="comment-item" style={{ border: '1px solid var(--border-color)', position: 'relative' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                                      <span style={{ fontWeight: 700, fontSize: '0.75rem', color: 'var(--primary-color)' }}>{comment.user || 'Analyst'}</span>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ color: 'var(--text-dark)', fontSize: '0.7rem' }}>{formatDateTime(comment.created_at)}</span>
                                        <button 
                                          className="icon-button" 
                                          style={{ padding: '0.1rem', color: 'var(--danger)', opacity: 0.4 }}
                                          onClick={() => deleteComment(alert.id, comment.id)}
                                          title="Delete update"
                                        >
                                          <Trash2 size={12} />
                                        </button>
                                      </div>
                                    </div>
                                    <div style={{ fontSize: '0.85rem', lineHeight: 1.4 }}>{comment.body}</div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          
                          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem' }}>
                            <input
                              className="form-input"
                              style={{ flex: 1 }}
                              value={commentDrafts[alert.id] || ''}
                              onChange={e => setCommentDrafts(prev => ({ ...prev, [alert.id]: e.target.value }))}
                              placeholder="Type investigation note or activity update..."
                              onKeyDown={e => e.key === 'Enter' && postComment(alert)}
                            />
                            <button type="button" className="btn btn-primary" onClick={() => postComment(alert)}>
                              Add Update
                            </button>
                          </div>
                        </div>

                        <div style={{ gridColumn: '1 / -1', marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ color: 'var(--text-dark)', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <Clock size={12} />
                            Last system update: {formatDateTime(alert.updated_at)}
                          </div>
                          <div style={{ color: 'var(--success)', fontSize: '0.75rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <Save size={14} /> Auto-saving active
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
      <PaginationControls pagination={pagination} />
    </div>
  );
}

export default AlertList;

