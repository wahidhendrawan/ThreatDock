import React from 'react';

function Filters({
  severity,
  setSeverity,
  source,
  setSource,
  status,
  setStatus,
  attackPhase,
  setAttackPhase,
  startDate,
  setStartDate,
  endDate,
  setEndDate
}) {
  return (
    <div className="filters-container">
      <div className="filter-group">
        <label htmlFor="filter-severity">Severity</label>
        <select id="filter-severity" value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Unknown">Unknown</option>
        </select>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-source">Source</label>
        <select id="filter-source" value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All</option>
          <option value="GitHub">GitHub</option>
          <option value="NVD">NVD</option>
          <option value="Red Hat">Red Hat</option>
          <option value="OTX">OTX</option>
          <option value="ThreatFox">ThreatFox</option>
          <option value="SANS Internet Storm Center">SANS Internet Storm Center</option>
          <option value="US‑CERT Alerts">US‑CERT Alerts</option>
          <option value="BleepingComputer">BleepingComputer</option>
          <option value="Krebs on Security">Krebs on Security</option>
          <option value="MISP">MISP</option>
          <option value="IntelOwl">IntelOwl</option>
          <option value="YARA/Sigma">YARA/Sigma</option>
        </select>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-status">Status</label>
        <select id="filter-status" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All</option>
          <option value="Open">Open</option>
          <option value="In Progress">In Progress</option>
          <option value="Resolved">Resolved</option>
        </select>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-attack-phase">Attack Phase</label>
        <select id="filter-attack-phase" value={attackPhase} onChange={e => setAttackPhase(e.target.value)}>
          <option value="">All</option>
          <option value="Unknown">Unknown</option>
          <option value="Initial Access">Initial Access</option>
          <option value="Execution">Execution</option>
          <option value="Persistence">Persistence</option>
          <option value="Privilege Escalation">Privilege Escalation</option>
          <option value="Defense Evasion">Defense Evasion</option>
          <option value="Credential Access">Credential Access</option>
          <option value="Discovery">Discovery</option>
          <option value="Lateral Movement">Lateral Movement</option>
          <option value="Collection">Collection</option>
          <option value="Command and Control">Command and Control</option>
          <option value="Exfiltration">Exfiltration</option>
          <option value="Impact">Impact</option>
        </select>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-start-date">Start Date</label>
        <input id="filter-start-date" type="date" value={startDate} onChange={e => setStartDate(e.target.value)} />
      </div>

      <div className="filter-group">
        <label htmlFor="filter-end-date">End Date</label>
        <input id="filter-end-date" type="date" value={endDate} onChange={e => setEndDate(e.target.value)} />
      </div>
    </div>
  );
}

export default Filters;
