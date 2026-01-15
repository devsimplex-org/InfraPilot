"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Package,
  ShieldCheck,
  Clock,
  GitBranch,
} from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { SeverityBadge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface SecurityPosture {
  overall_score: number;
  risk_level: string;
  deployment_stats: DeploymentStats;
  vulnerability_stats: VulnerabilityStats;
  policy_stats: PolicyComplianceStats;
  sbom_stats: SBOMStatistics;
  recent_events: SecurityEvent[];
  trends: SecurityTrends;
}

interface DeploymentStats {
  total: number;
  successful: number;
  failed: number;
  blocked: number;
  success_rate: number;
  last_24h: number;
  avg_deploy_time: string;
}

interface VulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixable: number;
  fixable_percent: number;
  affected_images: number;
}

interface PolicyComplianceStats {
  total_evaluations: number;
  allowed: number;
  warned: number;
  denied: number;
  compliance_rate: number;
}

interface SBOMStatistics {
  total_sboms: number;
  total_packages: number;
  unique_packages: number;
  avg_per_image: number;
  os_packages: number;
  library_packages: number;
}

interface SecurityEvent {
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  timestamp: string;
  source: string;
}

interface SecurityTrends {
  deployments: TrendDataPoint[];
  vulnerabilities: TrendDataPoint[];
  policy_denials: TrendDataPoint[];
}

interface TrendDataPoint {
  date: string;
  value: number;
}

export default function SecurityDashboard() {
  const { data: posture, isLoading } = useQuery({
    queryKey: ["security-posture"],
    queryFn: () => api.fetchAPI<SecurityPosture>("/security/posture"),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Map risk level to status level for StatusIndicator
  const getRiskStatus = (riskLevel: string) => {
    switch (riskLevel) {
      case "low":
        return "healthy";
      case "medium":
        return "warning";
      case "high":
        return "degraded";
      case "critical":
        return "critical";
      default:
        return "warning";
    }
  };

  // Get score color
  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Security Posture"
          description="Real-time DevSecOps metrics and security insights"
          breadcrumbs={
            <Breadcrumb
              items={[
                { label: "Overview", href: "/" },
                { label: "Security Posture", current: true },
              ]}
            />
          }
        />
        <Spinner.Page label="Loading security posture..." />
      </div>
    );
  }

  if (!posture) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Security Posture"
          description="Real-time DevSecOps metrics and security insights"
          breadcrumbs={
            <Breadcrumb
              items={[
                { label: "Overview", href: "/" },
                { label: "Security Posture", current: true },
              ]}
            />
          }
        />
        <EmptyState
          icon={Shield}
          title="No security data available"
          description="Unable to load security posture data"
        />
      </div>
    );
  }

  // Define table columns for recent security events
  const eventColumns = [
    {
      key: "severity",
      header: "Severity",
      width: "120px",
      render: (value: string) => (
        <SeverityBadge severity={value as any} size="sm" />
      ),
    },
    {
      key: "title",
      header: "Event",
      render: (value: string, row: SecurityEvent) => (
        <div>
          <div className="text-sm font-medium text-gray-900 dark:text-white">
            {value}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {row.description}
          </div>
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      width: "150px",
      render: (value: string) => (
        <div className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400">
          <GitBranch className="w-3 h-3" />
          {value}
        </div>
      ),
    },
    {
      key: "timestamp",
      header: "Time",
      width: "180px",
      align: "right" as const,
      render: (value: string) => (
        <div className="flex items-center justify-end gap-1 text-xs text-gray-500 dark:text-gray-400">
          <Clock className="w-3 h-3" />
          {new Date(value).toLocaleString()}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Section 1: Page Header with Breadcrumbs */}
      <PageHeader
        title="Security Posture"
        description="Real-time DevSecOps metrics and security insights"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Overview", href: "/" },
              { label: "Security Posture", current: true },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-3">
            <StatusIndicator
              status={getRiskStatus(posture.risk_level)}
              label={`${posture.risk_level} Risk`}
              pulse
              size="sm"
            />
            <span className="text-xs text-gray-500 dark:text-gray-400">
              Last updated: {new Date().toLocaleTimeString()}
            </span>
          </div>
        }
      />

      {/* Section 2: Overall Security Score Card */}
      <Card variant="default">
        <Card.Body>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                Overall Security Score
              </h2>
              <div className="flex items-baseline gap-4">
                <span className={`text-6xl font-bold ${getScoreColor(posture.overall_score)}`}>
                  {posture.overall_score}
                </span>
                <span className="text-2xl text-gray-400">/100</span>
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              <Shield className="w-12 h-12 text-primary-600 dark:text-primary-400" />
            </div>
          </div>

          {/* Score breakdown metrics */}
          <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">Success Rate</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {posture.deployment_stats.success_rate.toFixed(1)}%
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">Compliance</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {posture.policy_stats.compliance_rate.toFixed(1)}%
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">Critical Vulns</p>
              <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                {posture.vulnerability_stats.critical}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">Fixable</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                {posture.vulnerability_stats.fixable_percent.toFixed(0)}%
              </p>
            </div>
          </div>
        </Card.Body>
      </Card>

      {/* Section 3: Key Metrics Grid */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Deployments"
          value={posture.deployment_stats.total}
          description={`${posture.deployment_stats.successful} successful`}
          icon={Activity}
          iconColor="text-blue-600 dark:text-blue-400"
        />

        <StatCard
          label="Vulnerabilities"
          value={posture.vulnerability_stats.total}
          description={`${posture.vulnerability_stats.critical} critical, ${posture.vulnerability_stats.high} high`}
          icon={AlertTriangle}
          iconColor="text-red-600 dark:text-red-400"
          valueColor={
            posture.vulnerability_stats.critical > 0
              ? "text-red-600 dark:text-red-400"
              : "text-gray-900 dark:text-white"
          }
        />

        <StatCard
          label="Policy Compliance"
          value={`${posture.policy_stats.compliance_rate.toFixed(0)}%`}
          description={`${posture.policy_stats.denied} denied, ${posture.policy_stats.warned} warned`}
          icon={ShieldCheck}
          iconColor="text-purple-600 dark:text-purple-400"
          valueColor={
            posture.policy_stats.compliance_rate >= 80
              ? "text-green-600 dark:text-green-400"
              : "text-yellow-600 dark:text-yellow-400"
          }
        />

        <StatCard
          label="SBOM Coverage"
          value={posture.sbom_stats.total_sboms}
          description={`${posture.sbom_stats.total_packages.toLocaleString()} packages tracked`}
          icon={Package}
          iconColor="text-indigo-600 dark:text-indigo-400"
        />
      </MetricsGrid>

      {/* Section 4: Two Column Layout - Vulnerability Breakdown & Deployment Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Breakdown */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Vulnerability Breakdown
            </h3>
          </Card.Header>
          <Card.Body>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-red-600 rounded-full"></div>
                  <span className="text-sm text-gray-700 dark:text-gray-300">Critical</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.vulnerability_stats.critical}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-orange-600 rounded-full"></div>
                  <span className="text-sm text-gray-700 dark:text-gray-300">High</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.vulnerability_stats.high}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-yellow-600 rounded-full"></div>
                  <span className="text-sm text-gray-700 dark:text-gray-300">Medium</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.vulnerability_stats.medium}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-blue-600 rounded-full"></div>
                  <span className="text-sm text-gray-700 dark:text-gray-300">Low</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.vulnerability_stats.low}
                </span>
              </div>
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Fixable</span>
                  <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                    {posture.vulnerability_stats.fixable} ({posture.vulnerability_stats.fixable_percent.toFixed(0)}%)
                  </span>
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Affected Images</span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {posture.vulnerability_stats.affected_images}
                  </span>
                </div>
              </div>
            </div>
          </Card.Body>
        </Card>

        {/* Deployment Statistics */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Deployment Statistics
            </h3>
          </Card.Header>
          <Card.Body>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Successful</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.deployment_stats.successful}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-600" />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Failed</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.deployment_stats.failed}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-orange-600" />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Blocked</span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {posture.deployment_stats.blocked}
                </span>
              </div>
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Success Rate</span>
                  <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                    {posture.deployment_stats.success_rate.toFixed(1)}%
                  </span>
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Last 24h</span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {posture.deployment_stats.last_24h}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Avg Deploy Time</span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {posture.deployment_stats.avg_deploy_time}
                  </span>
                </div>
              </div>
            </div>
          </Card.Body>
        </Card>
      </div>

      {/* Section 5: Trend Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Deployment Trends */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Deployment Trends (7 days)
            </h3>
          </Card.Header>
          <Card.Body>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={posture.trends.deployments}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" stroke="#9CA3AF" fontSize={12} />
                <YAxis stroke="#9CA3AF" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1F2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#3B82F6"
                  fill="#3B82F6"
                  fillOpacity={0.3}
                />
              </AreaChart>
            </ResponsiveContainer>
          </Card.Body>
        </Card>

        {/* Vulnerability Trends */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Critical + High Vulnerabilities (7 days)
            </h3>
          </Card.Header>
          <Card.Body>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={posture.trends.vulnerabilities}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" stroke="#9CA3AF" fontSize={12} />
                <YAxis stroke="#9CA3AF" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1F2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#EF4444"
                  strokeWidth={2}
                  dot={{ fill: "#EF4444" }}
                />
              </LineChart>
            </ResponsiveContainer>
          </Card.Body>
        </Card>
      </div>

      {/* Section 6: Recent Security Events Table */}
      <Card>
        <Card.Header>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Security Events
          </h3>
        </Card.Header>
        <Card.Body className="p-0">
          <Table
            columns={eventColumns}
            data={posture.recent_events}
            keyExtractor={(row) => row.id}
            hoverable
            emptyState={
              <EmptyState
                icon={CheckCircle}
                title="No recent security events"
                description="Your infrastructure security is looking good"
                size="sm"
              />
            }
          />
        </Card.Body>
      </Card>
    </div>
  );
}
