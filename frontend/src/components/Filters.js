import React from 'react';

/**
 * Filter component that allows users to narrow down alerts by severity,
 * source and date range.
 *
 * Props:
 *  - severity: current severity filter
 *  - setSeverity: function to update severity
 *  - source: current source filter
 *  - setSource: function to update source
 *  - startDate: current start date
 *  - setStartDate: function to update start date
 *  - endDate: current end date
 *  - setEndDate: function to update end date
 */
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
    <div className="filters" style={{ marginBottom: '1rem', display: 'flex', flexWrap: 'wrap', gap: '1rem' }}>
      <label>
        Severity:
        <select value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Unknown">Unknown</option>
        </select>
      </label>
      <label>
        Source:
        <select value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All</option>
          <option value="GitHub">GitHub</option>
          <option value="NVD">NVD</option>
          <option value="Red Hat">Red Hat</option>
          <option value="OTX">OTX</option>
          <option value="ThreatFox">ThreatFox</option>
          {/* RSS-based sources */}
          <option value="SANS Internet Storm Center">SANS Internet Storm Center</option>
          <option value="US‑CERT Alerts">US‑CERT Alerts</option>
          <option value="BleepingComputer">BleepingComputer</option>
          <option value="Dark Reading">Dark Reading</option>
          <option value="Krebs on Security">Krebs on Security</option>
          {/* Additional sources */}
          <option value="MISP">MISP</option>
          <option value="IntelOwl">IntelOwl</option>
          <option value="YARA/Sigma">YARA/Sigma</option>
        </select>
      </label>
      <label>
        Status:
        <select value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All</option>
          <option value="Open">Open</option>
          <option value="In Progress">In Progress</option>
          <option value="Resolved">Resolved</option>
        </select>
      </label>
      <label>
        Attack Phase:
        <select value={attackPhase} onChange={e => setAttackPhase(e.target.value)}>
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
      </label>
      <label>
        Start Date:
        <input type="date" value={startDate} onChange={e => setStartDate(e.target.value)} />
      </label>
      <label>
        End Date:
        <input type="date" value={endDate} onChange={e => setEndDate(e.target.value)} />
      </label>
    </div>
  );
}

export default Filters;