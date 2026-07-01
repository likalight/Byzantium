import { useEffect, useState } from 'react';
import { TopBar } from '../components/TopBar';
import { StatusDot } from '../components/StatusDot';
import { getHealth } from '../api';

type ServiceStatus = 'ok' | 'warn' | 'error' | 'unknown';

interface ServiceCard {
  name: string;
  status: ServiceStatus;
  statusText: string;
  metric: string;
  icon: string;
}

const mockServices: ServiceCard[] = [
  { name: 'Gateway API',     status: 'ok',   statusText: 'Operational',            metric: '99.98% uptime',              icon: '◈' },
  { name: 'PostgreSQL',      status: 'ok',   statusText: 'Connected',               metric: 'Response: 4ms',              icon: '◉' },
  { name: 'Redis Cache',     status: 'ok',   statusText: 'Healthy',                 metric: 'Hit rate: 94%',              icon: '⚡' },
  { name: 'Bitcoin Anchor',  status: 'ok',   statusText: 'Synchronized',            metric: 'Last anchor: 23min ago',     icon: '₿' },
  { name: 'immuDB',          status: 'ok',   statusText: 'Operational',             metric: '12,847 entries',             icon: '≡' },
  { name: 'Neo4j Graph',     status: 'ok',   statusText: 'Online',                  metric: '28 agents indexed',          icon: '◎' },
  { name: 'TEE Enclave',     status: 'warn', statusText: 'Attestation pending',     metric: 'Refresh in 2h',             icon: '⚿' },
];

const statusLabel: Record<ServiceStatus, string> = {
  ok:      'Operational',
  warn:    'Degraded',
  error:   'Down',
  unknown: 'Unknown',
};

const statusBg: Record<ServiceStatus, string> = {
  ok:      'bg-green/5 border-green/15',
  warn:    'bg-gold/5 border-gold/15',
  error:   'bg-red/5 border-red/15',
  unknown: 'bg-dim/5 border-dim/15',
};

export function Health() {
  const [services, setServices] = useState<ServiceCard[]>(mockServices);
  const [lastChecked, setLastChecked] = useState(new Date());
  const [apiStatus, setApiStatus] = useState<'ok' | 'error' | 'loading'>('loading');

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await getHealth();
        if (data && data.status) {
          // Merge real API health data into first card
          setServices(prev => prev.map((s, i) =>
            i === 0
              ? { ...s, status: data.status === 'ok' ? 'ok' : 'error', statusText: data.status === 'ok' ? 'Operational' : 'Error' }
              : s
          ));
          setApiStatus('ok');
        }
      } catch {
        setApiStatus('error');
      }
      setLastChecked(new Date());
    };
    checkHealth();
    const id = setInterval(checkHealth, 30000);
    return () => clearInterval(id);
  }, []);

  const okCount   = services.filter(s => s.status === 'ok').length;
  const warnCount = services.filter(s => s.status === 'warn').length;
  const errCount  = services.filter(s => s.status === 'error').length;
  const overallStatus: ServiceStatus = errCount > 0 ? 'error' : warnCount > 0 ? 'warn' : 'ok';

  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="System Health" sub="Real-time service status and monitoring" />
      <div className="p-8">

        {/* Overall status banner */}
        <div className={`border rounded-xl p-5 mb-6 ${statusBg[overallStatus]}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <StatusDot status={overallStatus} />
              <div>
                <div className="text-white font-semibold">
                  {overallStatus === 'ok' ? 'All Systems Operational' :
                   overallStatus === 'warn' ? 'Minor Issues Detected' :
                   'Service Disruption'}
                </div>
                <div className="text-dim text-xs mt-0.5">
                  {okCount} healthy · {warnCount} degraded · {errCount} down
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-dim text-xs">Last checked</div>
              <div className="text-mid text-xs font-medium">{lastChecked.toLocaleTimeString()}</div>
              <div className="text-xs mt-1">
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                  apiStatus === 'ok'      ? 'bg-green/10 text-green border border-green/20' :
                  apiStatus === 'error'   ? 'bg-red/10 text-red border border-red/20' :
                                            'bg-dim/10 text-dim border border-dim/20'
                }`}>
                  API {apiStatus === 'loading' ? 'checking...' : apiStatus === 'ok' ? 'reachable' : 'unreachable (demo mode)'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Service cards grid */}
        <div className="grid grid-cols-3 gap-4">
          {services.map(svc => (
            <div
              key={svc.name}
              className={`bg-card border rounded-xl p-5 transition-colors ${statusBg[svc.status]}`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-lg bg-border flex items-center justify-center text-mid text-lg">
                    {svc.icon}
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">{svc.name}</div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <StatusDot status={svc.status} />
                      <span className="text-xs" style={{
                        color: svc.status === 'ok' ? '#2ecc80' : svc.status === 'warn' ? '#f5c842' : '#f05050'
                      }}>
                        {statusLabel[svc.status]}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="border-t border-border pt-3">
                <div className="text-dim text-xs">{svc.statusText}</div>
                <div className="text-mid text-sm font-medium mt-0.5">{svc.metric}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Uptime table */}
        <div className="mt-6 bg-card border border-border rounded-xl">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-white font-medium text-sm">30-Day Uptime</div>
          </div>
          <div className="divide-y divide-border">
            {services.map(svc => (
              <div key={svc.name} className="px-5 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm text-mid">
                  <StatusDot status={svc.status} />
                  {svc.name}
                </div>
                <div className="flex items-center gap-6">
                  {/* Mini uptime bar */}
                  <div className="flex gap-0.5">
                    {Array.from({ length: 30 }, (_, i) => {
                      const isToday = i === 29;
                      const hasIssue = isToday && svc.status === 'warn';
                      return (
                        <div
                          key={i}
                          className="w-1.5 h-4 rounded-sm"
                          style={{
                            background: hasIssue ? '#f5c842' : '#2ecc80',
                            opacity: i < 27 ? 0.7 : 1,
                          }}
                        />
                      );
                    })}
                  </div>
                  <span className="text-xs font-medium text-green w-16 text-right">
                    {svc.status === 'ok' ? '100.00%' : svc.status === 'warn' ? '99.72%' : '98.14%'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
