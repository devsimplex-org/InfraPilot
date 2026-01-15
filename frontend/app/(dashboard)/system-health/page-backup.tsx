"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Shield,
  Database,
  Server,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  Lock,
} from "lucide-react";
import { api, TLSHealthResult } from "@/lib/api";

const statusColors = {
  healthy: "text-green-400 bg-green-500/10",
  warning: "text-yellow-400 bg-yellow-500/10",
  critical: "text-red-400 bg-red-500/10",
  expired: "text-red-400 bg-red-500/10",
  degraded: "text-yellow-400 bg-yellow-500/10",
  unhealthy: "text-red-400 bg-red-500/10",
  none: "text-gray-500 bg-gray-500/10",
};

const statusIcons = {
  healthy: <CheckCircle className="h-5 w-5 text-green-400" />,
  warning: <AlertTriangle className="h-5 w-5 text-yellow-400" />,
  critical: <XCircle className="h-5 w-5 text-red-400" />,
  expired: <XCircle className="h-5 w-5 text-red-400" />,
  degraded: <AlertTriangle className="h-5 w-5 text-yellow-400" />,
  unhealthy: <XCircle className="h-5 w-5 text-red-400" />,
  none: <Lock className="h-5 w-5 text-gray-500" />,
};

function ScoreRing({ score, size = 120 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color =
    score >= 80 ? "#4ade80" : score >= 50 ? "#fbbf24" : "#f87171";

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth="8"
          fill="none"
          className="text-gray-300 dark:text-gray-700"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth="8"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-500"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-2xl font-bold text-gray-900 dark:text-white">{score}</span>
      </div>
    </div>
  );
}

export default function HealthPage() {
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

  const refetchAll = () => {
    refetchTLS();
    refetchDB();
    refetchSys();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Activity className="h-7 w-7 text-green-400" />
            System Health
          </h1>
          <p className="text-gray-600 dark:text-gray-400">Monitor TLS certificates, database, and system status</p>
        </div>
        <button
          onClick={refetchAll}
          className="flex items-center gap-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Health Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* TLS Health Card */}
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6 text-blue-400" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">TLS Certificates</h2>
            </div>
            {tlsHealth && (
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                tlsHealth.overall_score >= 80 ? statusColors.healthy :
                tlsHealth.overall_score >= 50 ? statusColors.warning : statusColors.critical
              }`}>
                {tlsHealth.overall_score >= 80 ? "Healthy" :
                 tlsHealth.overall_score >= 50 ? "Warning" : "Critical"}
              </span>
            )}
          </div>
          {tlsLoading ? (
            <div className="h-32 flex items-center justify-center text-gray-500">Loading...</div>
          ) : tlsHealth ? (
            <div className="flex items-center gap-6">
              <ScoreRing score={tlsHealth.overall_score} />
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">Total Proxies</span>
                  <span className="text-gray-900 dark:text-white font-medium">{tlsHealth.total_proxies}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">SSL Enabled</span>
                  <span className="text-gray-900 dark:text-white font-medium">{tlsHealth.ssl_enabled}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-green-400">Healthy</span>
                  <span className="text-gray-900 dark:text-white font-medium">{tlsHealth.healthy}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-yellow-400">Warning</span>
                  <span className="text-gray-900 dark:text-white font-medium">{tlsHealth.warning}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-red-400">Critical/Expired</span>
                  <span className="text-gray-900 dark:text-white font-medium">{tlsHealth.critical + tlsHealth.expired}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-32 flex items-center justify-center text-gray-500">No data</div>
          )}
        </div>

        {/* Database Health Card */}
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Database className="h-6 w-6 text-purple-400" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Database</h2>
            </div>
            {dbHealth && (
              <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[dbHealth.status]}`}>
                {dbHealth.status.charAt(0).toUpperCase() + dbHealth.status.slice(1)}
              </span>
            )}
          </div>
          {dbLoading ? (
            <div className="h-32 flex items-center justify-center text-gray-500">Loading...</div>
          ) : dbHealth ? (
            <div className="flex items-center gap-6">
              <ScoreRing score={dbHealth.score} />
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">Latency</span>
                  <span className="text-gray-900 dark:text-white font-medium">{dbHealth.latency_ms.toFixed(2)}ms</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">Connections</span>
                  <span className="text-gray-900 dark:text-white font-medium">{dbHealth.active_connections}/{dbHealth.max_connections}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">Database Size</span>
                  <span className="text-gray-900 dark:text-white font-medium">{dbHealth.database_size || "N/A"}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-gray-500 dark:text-gray-400">Tables</span>
                  <span className="text-gray-900 dark:text-white font-medium">{dbHealth.table_count}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-32 flex items-center justify-center text-gray-500">No data</div>
          )}
        </div>

        {/* System Health Card */}
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Server className="h-6 w-6 text-cyan-400" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">System</h2>
            </div>
            {sysHealth && (
              <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[sysHealth.status as keyof typeof statusColors] || statusColors.healthy}`}>
                {sysHealth.status.charAt(0).toUpperCase() + sysHealth.status.slice(1)}
              </span>
            )}
          </div>
          {sysLoading ? (
            <div className="h-32 flex items-center justify-center text-gray-500">Loading...</div>
          ) : sysHealth ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <Clock className="h-5 w-5 text-gray-500 dark:text-gray-400" />
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Uptime</p>
                  <p className="text-lg font-semibold text-gray-900 dark:text-white">{sysHealth.uptime}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-500 dark:text-gray-400">Goroutines</p>
                  <p className="text-gray-900 dark:text-white font-medium">{sysHealth.goroutines}</p>
                </div>
                <div>
                  <p className="text-gray-500 dark:text-gray-400">Memory</p>
                  <p className="text-gray-900 dark:text-white font-medium">{sysHealth.memory_mb.toFixed(1)} MB</p>
                </div>
                <div>
                  <p className="text-gray-500 dark:text-gray-400">CPU Cores</p>
                  <p className="text-gray-900 dark:text-white font-medium">{sysHealth.cpu_cores}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-32 flex items-center justify-center text-gray-500">No data</div>
          )}
        </div>
      </div>

      {/* TLS Certificates Table */}
      {tlsHealth && tlsHealth.certificates && tlsHealth.certificates.length > 0 && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Certificate Details</h2>
          </div>
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-800/50">
              <tr className="text-left text-xs text-gray-500 dark:text-gray-400 uppercase">
                <th className="px-6 py-3">Domain</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Issuer</th>
                <th className="px-6 py-3">Expires</th>
                <th className="px-6 py-3">Days Left</th>
                <th className="px-6 py-3">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {tlsHealth.certificates.map((cert: TLSHealthResult) => (
                <tr key={cert.proxy_id} className="hover:bg-gray-50 dark:hover:bg-gray-800/30">
                  <td className="px-6 py-4 text-sm text-gray-900 dark:text-white font-medium">
                    {cert.domain}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${statusColors[cert.status]}`}>
                      {statusIcons[cert.status]}
                      {cert.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {cert.issuer || "-"}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {cert.expires_at ? new Date(cert.expires_at).toLocaleDateString() : "-"}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    {cert.days_left !== undefined ? (
                      <span className={cert.days_left <= 14 ? "text-red-400" : cert.days_left <= 30 ? "text-yellow-400" : "text-gray-900 dark:text-white"}>
                        {cert.days_left} days
                      </span>
                    ) : "-"}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            cert.score >= 80 ? "bg-green-400" :
                            cert.score >= 50 ? "bg-yellow-400" : "bg-red-400"
                          }`}
                          style={{ width: `${cert.score}%` }}
                        />
                      </div>
                      <span className="text-sm text-gray-900 dark:text-white">{cert.score}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
