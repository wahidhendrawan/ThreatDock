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