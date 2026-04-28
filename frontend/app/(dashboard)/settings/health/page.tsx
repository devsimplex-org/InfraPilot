"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Database,
  Server,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  Lock,
  Cpu,
  MemoryStick,
  HardDrive,
  Circle,
} from "lucide-react";
import { api, Agent, TLSHealthResult } from "@/lib/api";
import { MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { Button } from "@/components/ui/page-layout";

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatMB(mb: number): string {
  if (mb >= 1024 * 1024) return `${(mb / (1024 * 1024)).toFixed(1)} TB`;
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${mb} MB`;
}

function formatUptime(seconds: number): string {
  if (seconds <= 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function ScoreRing({ score, size = 100 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? "#4ade80" : score >= 50 ? "#fbbf24" : "#f87171";
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="currentColor" strokeWidth="8" fill="none" className="text-gray-200 dark:text-gray-700" />
        <circle cx={size / 2} cy={size / 2} r={radius} stroke={color} strokeWidth="8" fill="none" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} className="transition-all duration-500" />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xl font-bold text-gray-900 dark:text-white">{score}</span>
      </div>
    </div>
  );
}

function MiniBar({ pct, colorClass }: { pct: number; colorClass: string }) {
  const bar = pct > 85 ? "bg-red-500" : pct > 65 ? "bg-amber-500" : colorClass;
  return (
    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
      <div className={`${bar} h-1.5 rounded-full transition-all duration-500`} style={{ width: `${Math.min(100, pct)}%` }} />
    </div>
  );
}

function AgentResourceCard({ agent }: { agent: Agent }) {
  const cpuPct = agent.cpu_percent ?? 0;
  const ramPct = agent.memory_total_mb > 0 ? (agent.memory_used_mb / agent.memory_total_mb) * 100 : 0;
  const diskPct = agent.disk_total_mb > 0 ? (agent.disk_used_mb / agent.disk_total_mb) * 100 : 0;
  const hasMetrics = agent.memory_total_mb > 0;

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 min-w-0">
          <Server className="h-4 w-4 text-gray-400 shrink-0" />
          <div className="min-w-0">
            <p className="font-medium text-gray-900 dark:text-white text-sm truncate">{agent.name}</p>
            <p className="text-xs text-gray-400 truncate">{agent.hostname || "unknown"}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {agent.uptime_seconds > 0 && (
            <span className="text-xs text-gray-400 tabular-nums">up {formatUptime(agent.uptime_seconds)}</span>
          )}
          <span className={`inline-flex items-center gap-1 text-xs font-medium ${
            agent.status === "active" ? "text-green-600 dark:text-green-400" :
            agent.status === "pending" ? "text-yellow-600 dark:text-yellow-400" :
            "text-gray-500 dark:text-gray-400"
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${
              agent.status === "active" ? "bg-green-500" :
              agent.status === "pending" ? "bg-yellow-500" : "bg-gray-400"
            }`} />
            {agent.status.charAt(0).toUpperCase() + agent.status.slice(1)}
          </span>
        </div>
      </div>

      {/* Metrics */}
      {hasMetrics ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Cpu className="h-3 w-3 text-blue-500 shrink-0" />
            <span className="text-[11px] text-gray-400 w-8 shrink-0">CPU</span>
            <MiniBar pct={cpuPct} colorClass="bg-blue-500" />
            <span className="text-[11px] text-gray-500 dark:text-gray-400 w-10 text-right tabular-nums shrink-0">{cpuPct.toFixed(1)}%</span>
          </div>
          <div className="flex items-center gap-2">
            <MemoryStick className="h-3 w-3 text-violet-500 shrink-0" />
            <span className="text-[11px] text-gray-400 w-8 shrink-0">RAM</span>
            <MiniBar pct={ramPct} colorClass="bg-violet-500" />
            <span className="text-[11px] text-gray-500 dark:text-gray-400 w-24 text-right tabular-nums shrink-0">{formatMB(agent.memory_used_mb)} / {formatMB(agent.memory_total_mb)}</span>
          </div>
          <div className="flex items-center gap-2">
            <HardDrive className="h-3 w-3 text-emerald-500 shrink-0" />
            <span className="text-[11px] text-gray-400 w-8 shrink-0">Disk</span>
            <MiniBar pct={diskPct} colorClass="bg-emerald-500" />
            <span className="text-[11px] text-gray-500 dark:text-gray-400 w-24 text-right tabular-nums shrink-0">{formatMB(agent.disk_used_mb)} / {formatMB(agent.disk_total_mb)}</span>
          </div>
        </div>
      ) : (
        <p className="text-xs text-gray-400 italic">
          {agent.status === "active" ? "Waiting for first heartbeat…" : "No metrics available"}
        </p>
      )}
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

type HealthStatus = "healthy" | "warning" | "critical" | "degraded";

export default function SettingsHealthPage() {
  const queryClient = useQueryClient();

  const { data: tlsHealth, isLoading: tlsLoading, refetch: refetchTLS } = useQuery({
    queryKey: ["tls-health"],
    queryFn: api.getTLSHealth,
    refetchInterval: 60000,
  });

  const { data: dbHealth, isLoading: dbLoading, refetch: refetchDB } = useQuery({
    queryKey: ["db-health"],
    queryFn: api.getDBHealth,
    refetchInterval: 30000,
  });

  const { data: sysHealth, isLoading: sysLoading, refetch: refetchSys } = useQuery({
    queryKey: ["sys-health"],
    queryFn: api.getSystemHealth,
    refetchInterval: 30000,
  });

  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
    refetchInterval: 15000,
  });

  const refetchAll = () => {
    refetchTLS();
    refetchDB();
    refetchSys();
    queryClient.invalidateQueries({ queryKey: ["agents"] });
  };

  const scoreStatus = (score: number): HealthStatus =>
    score >= 80 ? "healthy" : score >= 50 ? "warning" : "critical";

  const strStatus = (s: string): HealthStatus =>
    s === "healthy" ? "healthy" : s === "degraded" ? "degraded" : s === "warning" ? "warning" : "critical";

  const tlsStatusOf = (s: string): HealthStatus => {
    if (s === "healthy") return "healthy";
    if (s === "warning") return "warning";
    if (s === "critical" || s === "expired") return "critical";
    return "degraded";
  };

  const certificateColumns = [
    {
      key: "domain",
      header: "Domain",
      sortable: true,
      render: (value: string) => <span className="font-medium text-gray-900 dark:text-white">{value}</span>,
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (value: string) => <StatusIndicator status={tlsStatusOf(value)} />,
    },
    {
      key: "issuer",
      header: "Issuer",
      render: (value: string) => <span className="text-sm text-gray-600 dark:text-gray-400">{value || "—"}</span>,
    },
    {
      key: "expires_at",
      header: "Expires",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {value ? new Date(value).toLocaleDateString() : "—"}
        </span>
      ),
    },
    {
      key: "days_left",
      header: "Days Left",
      sortable: true,
      render: (value: number) => value === undefined ? <span>—</span> : (
        <span className={value <= 14 ? "text-red-500" : value <= 30 ? "text-amber-500" : "text-gray-900 dark:text-white"}>
          {value}d
        </span>
      ),
    },
    {
      key: "score",
      header: "Score",
      sortable: true,
      render: (value: number) => (
        <div className="flex items-center gap-2">
          <div className="w-16 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${value >= 80 ? "bg-green-400" : value >= 50 ? "bg-amber-400" : "bg-red-400"}`} style={{ width: `${value}%` }} />
          </div>
          <span className="text-sm tabular-nums">{value}</span>
        </div>
      ),
    },
  ];

  const activeAgents = agents?.filter(a => a.status === "active") ?? [];
  const offlineAgents = agents?.filter(a => a.status === "offline") ?? [];
  const agentsWithHighCPU = activeAgents.filter(a => a.cpu_percent > 80);
  const agentsWithHighRAM = activeAgents.filter(a => a.memory_total_mb > 0 && (a.memory_used_mb / a.memory_total_mb) > 0.85);
  const agentsWithHighDisk = activeAgents.filter(a => a.disk_total_mb > 0 && (a.disk_used_mb / a.disk_total_mb) > 0.85);

  return (
    <div className="space-y-8">
      {/* Section header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">System Health</h2>
          <p className="text-sm text-gray-500">Infrastructure status across agents, TLS, and platform services</p>
        </div>
        <Button variant="secondary" icon={RefreshCw} onClick={refetchAll}>Refresh</Button>
      </div>

      {/* ── Alerts ─────────────────────────────────────────────────────── */}
      {(agentsWithHighCPU.length > 0 || agentsWithHighRAM.length > 0 || agentsWithHighDisk.length > 0 || offlineAgents.length > 0) && (
        <div className="space-y-2">
          {offlineAgents.map(a => (
            <div key={a.id} className="flex items-center gap-3 px-4 py-2.5 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              <XCircle className="h-4 w-4 shrink-0" />
              Agent <strong>{a.name}</strong> ({a.hostname || "unknown"}) is offline
            </div>
          ))}
          {agentsWithHighCPU.map(a => (
            <div key={a.id} className="flex items-center gap-3 px-4 py-2.5 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg text-sm text-amber-700 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              High CPU on <strong>{a.name}</strong>: {a.cpu_percent.toFixed(1)}%
            </div>
          ))}
          {agentsWithHighRAM.map(a => (
            <div key={a.id} className="flex items-center gap-3 px-4 py-2.5 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg text-sm text-amber-700 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              High memory on <strong>{a.name}</strong>: {formatMB(a.memory_used_mb)} / {formatMB(a.memory_total_mb)}
            </div>
          ))}
          {agentsWithHighDisk.map(a => (
            <div key={a.id} className="flex items-center gap-3 px-4 py-2.5 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg text-sm text-amber-700 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              High disk on <strong>{a.name}</strong>: {formatMB(a.disk_used_mb)} / {formatMB(a.disk_total_mb)}
            </div>
          ))}
        </div>
      )}

      {/* ── Agent Resources ─────────────────────────────────────────────── */}
      {agents && agents.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide">
            Agent Resources
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map(agent => (
              <AgentResourceCard key={agent.id} agent={agent} />
            ))}
          </div>
        </div>
      )}

      {/* ── Platform Health ──────────────────────────────────────────────── */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide">
          Platform
        </h3>
        <MetricsGrid columns={3}>
          {/* TLS */}
          <Card>
            <Card.Header>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Shield className="h-5 w-5 text-blue-400" />
                  <h2 className="text-base font-semibold text-gray-900 dark:text-white">TLS Certificates</h2>
                </div>
                {tlsHealth && <StatusIndicator status={scoreStatus(tlsHealth.overall_score)} size="sm" />}
              </div>
            </Card.Header>
            <Card.Body>
              {tlsLoading ? (
                <div className="flex items-center justify-center h-28"><Spinner /></div>
              ) : tlsHealth ? (
                <div className="flex items-center gap-5">
                  <ScoreRing score={tlsHealth.overall_score} />
                  <div className="space-y-1.5 text-sm flex-1">
                    {[
                      { label: "Total Proxies", value: tlsHealth.total_proxies, color: "" },
                      { label: "SSL Enabled", value: tlsHealth.ssl_enabled, color: "" },
                      { label: "Healthy", value: tlsHealth.healthy, color: "text-green-500" },
                      { label: "Warning", value: tlsHealth.warning, color: "text-amber-500" },
                      { label: "Critical", value: tlsHealth.critical + tlsHealth.expired, color: "text-red-500" },
                    ].map(row => (
                      <div key={row.label} className="flex justify-between gap-4">
                        <span className={`${row.color || "text-gray-500 dark:text-gray-400"}`}>{row.label}</span>
                        <span className="font-medium text-gray-900 dark:text-white tabular-nums">{row.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : <EmptyState title="No data" size="sm" />}
            </Card.Body>
          </Card>

          {/* Database */}
          <Card>
            <Card.Header>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Database className="h-5 w-5 text-purple-400" />
                  <h2 className="text-base font-semibold text-gray-900 dark:text-white">Database</h2>
                </div>
                {dbHealth && <StatusIndicator status={strStatus(dbHealth.status)} size="sm" />}
              </div>
            </Card.Header>
            <Card.Body>
              {dbLoading ? (
                <div className="flex items-center justify-center h-28"><Spinner /></div>
              ) : dbHealth ? (
                <div className="flex items-center gap-5">
                  <ScoreRing score={dbHealth.score} />
                  <div className="space-y-1.5 text-sm flex-1">
                    {[
                      { label: "Latency", value: `${dbHealth.latency_ms.toFixed(1)}ms` },
                      { label: "Connections", value: `${dbHealth.active_connections}/${dbHealth.max_connections}` },
                      { label: "Size", value: dbHealth.database_size || "N/A" },
                      { label: "Tables", value: String(dbHealth.table_count) },
                    ].map(row => (
                      <div key={row.label} className="flex justify-between gap-4">
                        <span className="text-gray-500 dark:text-gray-400">{row.label}</span>
                        <span className="font-medium text-gray-900 dark:text-white tabular-nums">{row.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : <EmptyState title="No data" size="sm" />}
            </Card.Body>
          </Card>

          {/* Backend Process */}
          <Card>
            <Card.Header>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Server className="h-5 w-5 text-cyan-400" />
                  <h2 className="text-base font-semibold text-gray-900 dark:text-white">Backend Process</h2>
                </div>
                {sysHealth && <StatusIndicator status={strStatus(sysHealth.status as string)} size="sm" />}
              </div>
            </Card.Header>
            <Card.Body>
              {sysLoading ? (
                <div className="flex items-center justify-center h-28"><Spinner /></div>
              ) : sysHealth ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-3 pb-1">
                    <Clock className="h-4 w-4 text-gray-400" />
                    <div>
                      <p className="text-xs text-gray-400">Uptime</p>
                      <p className="text-sm font-semibold text-gray-900 dark:text-white">{sysHealth.uptime}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    {[
                      { label: "Goroutines", value: sysHealth.goroutines },
                      { label: "Heap", value: `${sysHealth.memory_mb.toFixed(1)} MB` },
                      { label: "CPU Cores", value: sysHealth.cpu_cores },
                    ].map(row => (
                      <div key={row.label}>
                        <p className="text-xs text-gray-400">{row.label}</p>
                        <p className="font-medium text-gray-900 dark:text-white tabular-nums">{row.value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : <EmptyState title="No data" size="sm" />}
            </Card.Body>
          </Card>
        </MetricsGrid>
      </div>

      {/* ── TLS Certificate Details ──────────────────────────────────────── */}
      {tlsHealth?.certificates && tlsHealth.certificates.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide">
            TLS Certificate Details
          </h3>
          <Card>
            <Card.Body className="p-0">
              <Table
                columns={certificateColumns}
                data={tlsHealth.certificates}
                keyExtractor={(row: TLSHealthResult) => row.proxy_id}
                hoverable
              />
            </Card.Body>
          </Card>
        </div>
      )}
    </div>
  );
}
