import React from 'react';
import { 
  Search, Globe, Activity, Brain, Crosshair, 
  TrendingUp, Network, Lock, Eye, Building2 
} from 'lucide-react';

const Placeholder = ({ title, icon: Icon, description }) => (
  <div className="flex flex-col gap-4">
    <div className="page-header">
      <div>
        <h1 className="page-title">{title}</h1>
        <p className="page-subtitle">{description}</p>
      </div>
    </div>
    <div className="card module-placeholder">
      <Icon size={64} />
      <h2>Module Initialization</h2>
      <p style={{ marginTop: '0.5rem', maxWidth: '400px' }}>
        The {title} module is currently syncing with external intelligence feeds. 
        Data will populate here once initial discovery is complete.
      </p>
    </div>
  </div>
);

export const ThreatHunting = () => <Placeholder title="Threat Hunting" icon={Search} description="Proactively search across multiple intelligence sources for specific IOCs." />;
export const AssetDiscovery = () => <Placeholder title="External Asset Discovery" icon={Globe} description="Discover and catalog external-facing assets (domains, IPs, services)." />;
export const ExposureMonitoring = () => <Placeholder title="Exposure Monitoring" icon={Activity} description="Continuous monitoring of exposed ports, SSL certificates, and misconfigurations." />;
export const AssetIntelligence = () => <Placeholder title="Contextual Asset Intelligence" icon={Brain} description="Enriched context for assets including WHOIS, DNS, and historical data." />;
export const VulnPrioritization = () => <Placeholder title="Threat-Based Vulnerability Prioritization" icon={Crosshair} description="Prioritize remediation based on CVSS, EPSS, and active exploitation intel." />;
export const PredictiveIntel = () => <Placeholder title="Predictive Threat Intelligence" icon={TrendingUp} description="Forecast emerging threats and attack vectors based on historical trends." />;
export const ThreatAnalysis = () => <Placeholder title="Context-Rich Threat Analysis" icon={Network} description="Deep dive into alerts with MITRE ATT&CK mapping and IOC correlation." />;
export const DigitalRisk = () => <Placeholder title="Digital Risk & Identity Protection" icon={Lock} description="Monitor credential leaks, dark web mentions, and identity exposures." />;
export const BrandExposure = () => <Placeholder title="Brand & Online Exposure Management" icon={Eye} description="Track brand mentions, phishing domains, and typosquatting." />;
export const ThirdPartyRisk = () => <Placeholder title="Third-Party Risk Management" icon={Building2} description="Assess and monitor the security posture of vendors and partners." />;
