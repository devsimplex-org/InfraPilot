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
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { Button } from "@/components/ui/page-layout";

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

  const getHealthStatus = (score: number): "healthy" | "warning" | "critical" | "degraded" => {
    if (score >= 80) return "healthy";
    if (score >= 50) return "warning";
    return "critical";
  };

  const getDBStatus = (status: string): "healthy" | "warning" | "critical" | "degraded" => {
    if (status === "healthy") return "healthy";
    if (status === "degraded") return "degraded";
    if (status === "warning") return "warning";
    return "critical";
  };

  const getSysStatus = (status: string): "healthy" | "warning" | "critical" | "degraded" => {
    if (status === "healthy") return "healthy";
    if (status === "degraded") return "degraded";
    if (status === "warning") return "warning";
    return "critical";
  };

  const getTLSStatusIndicator = (status: string): "healthy" | "warning" | "critical" | "degraded" => {
    switch (status) {
      case "healthy":
        return "healthy";
      case "warning":
        return "warning";
      case "critical":
      case "expired":
        return "critical";
      default:
        return "degraded";
    }
  };

  // Define table columns for certificates
  const certificateColumns = [
    {
      key: "domain",
      header: "Domain",
      sortable: true,
      render: (value: string) => (
        <span className="font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (value: string) => (
        <StatusIndicator status={getTLSStatusIndicator(value)} />
      ),
    },
    {
      key: "issuer",
      header: "Issuer",
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{value || "-"}</span>
      ),
    },
    {
      key: "expires_at",
      header: "Expires",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {value ? new Date(value).toLocaleDateString() : "-"}
        </span>
      ),
    },
    {
      key: "days_left",
      header: "Days Left",
      sortable: true,
      render: (value: number) => {
        if (value === undefined) return <span>-</span>;
        return (
          <span className={value <= 14 ? "text-red-400" : value <= 30 ? "text-yellow-400" : "text-gray-900 dark:text-white"}>
            {value} days
          </span>
        );
      },
    },
    {
      key: "score",
      header: "Score",
      sortable: true,
      render: (value: number) => (
        <div className="flex items-center gap-2">
          <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                value >= 80 ? "bg-green-400" :
                value >= 50 ? "bg-yellow-400" : "bg-red-400"
              }`}
              style={{ width: `${value}%` }}
            />
          </div>
          <span className="text-sm text-gray-900 dark:text-white">{value}</span>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Health"
        description="Monitor TLS certificates, database, and system status"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform", href: "/" },
              { label: "Health", current: true },
            ]}
          />
        }
        action={
          <Button
            variant="secondary"
            icon={RefreshCw}
            onClick={refetchAll}
          >
            Refresh
          </Button>
        }
      />

      {/* Health Summary Metrics */}
      <MetricsGrid columns={3}>
        {/* TLS Health Card */}
        <Card>
          <Card.Header>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className="h-6 w-6 text-blue-400" />
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">TLS Certificates</h2>
              </div>
              {tlsHealth && (
                <StatusIndicator status={getHealthStatus(tlsHealth.overall_score)} size="sm" />
              )}
            </div>
          </Card.Header>
          <Card.Body>
            {tlsLoading ? (
              <div className="flex items-center justify-center h-32">
                <Spinner />
              </div>
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
              <EmptyState title="No data" size="sm" />
            )}
          </Card.Body>
        </Card>

        {/* Database Health Card */}
        <Card>
          <Card.Header>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Database className="h-6 w-6 text-purple-400" />
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Database</h2>
              </div>
              {dbHealth && (
                <StatusIndicator status={getDBStatus(dbHealth.status)} size="sm" />
              )}
            </div>
          </Card.Header>
          <Card.Body>
            {dbLoading ? (
              <div className="flex items-center justify-center h-32">
                <Spinner />
              </div>
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
              <EmptyState title="No data" size="sm" />
            )}
          </Card.Body>
        </Card>

        {/* System Health Card */}
        <Card>
          <Card.Header>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Server className="h-6 w-6 text-cyan-400" />
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">System</h2>
              </div>
              {sysHealth && (
                <StatusIndicator status={getSysStatus(sysHealth.status as string)} size="sm" />
              )}
            </div>
          </Card.Header>
          <Card.Body>
            {sysLoading ? (
              <div className="flex items-center justify-center h-32">
                <Spinner />
              </div>
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
              <EmptyState title="No data" size="sm" />
            )}
          </Card.Body>
        </Card>
      </MetricsGrid>

      {/* TLS Certificates Table */}
      {tlsHealth && tlsHealth.certificates && tlsHealth.certificates.length > 0 && (
        <Card>
          <Card.Header>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Certificate Details</h2>
          </Card.Header>
          <Card.Body className="p-0">
            <Table
              columns={certificateColumns}
              data={tlsHealth.certificates}
              keyExtractor={(row: TLSHealthResult) => row.proxy_id}
              hoverable
            />
          </Card.Body>
        </Card>
      )}
    </div>
  );
}
