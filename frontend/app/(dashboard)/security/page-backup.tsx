"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Package,
  ShieldCheck,
  GitBranch,
  Clock,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
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

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!posture) {
    return null;
  }

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case "low":
        return "text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/20";
      case "medium":
        return "text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20";
      case "high":
        return "text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-900/20";
      case "critical":
        return "text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/20";
      default:
        return "text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400";
      case "high":
        return "bg-orange-100 dark:bg-orange-900/20 text-orange-700 dark:text-orange-400";
      case "medium":
        return "bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400";
      case "low":
        return "bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400";
      default:
        return "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400";
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-4 lg:p-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Shield className="w-8 h-8 text-primary-600" />
          Security Posture Dashboard
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Real-time DevSecOps metrics and security insights
        </p>
      </div>

      {/* Security Score Card */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Overall Security Score
            </h2>
            <div className="flex items-baseline gap-4">
              <span className={cn("text-6xl font-bold", getScoreColor(posture.overall_score))}>
                {posture.overall_score}
              </span>
              <span className="text-2xl text-gray-400">/100</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <span
              className={cn(
                "px-4 py-2 rounded-full text-sm font-semibold uppercase",
                getRiskLevelColor(posture.risk_level)
              )}
            >
              {posture.risk_level} Risk
            </span>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Last updated: {new Date().toLocaleTimeString()}
            </p>
          </div>
        </div>

        {/* Score breakdown */}
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
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {/* Deployments Card */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Deployments</h3>
            <Activity className="w-5 h-5 text-blue-500" />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900 dark:text-white">
                {posture.deployment_stats.total}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">total</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle className="w-4 h-4 text-green-600" />
              <span className="text-gray-600 dark:text-gray-400">
                {posture.deployment_stats.successful} successful
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <XCircle className="w-4 h-4 text-red-600" />
              <span className="text-gray-600 dark:text-gray-400">
                {posture.deployment_stats.failed} failed
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Shield className="w-4 h-4 text-orange-600" />
              <span className="text-gray-600 dark:text-gray-400">
                {posture.deployment_stats.blocked} blocked
              </span>
            </div>
          </div>
        </div>

        {/* Vulnerabilities Card */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
              Vulnerabilities
            </h3>
            <AlertTriangle className="w-5 h-5 text-red-500" />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900 dark:text-white">
                {posture.vulnerability_stats.total}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">total</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-red-600 rounded-full"></div>
                <span className="text-gray-600 dark:text-gray-400">
                  {posture.vulnerability_stats.critical} critical
                </span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-orange-600 rounded-full"></div>
                <span className="text-gray-600 dark:text-gray-400">
                  {posture.vulnerability_stats.high} high
                </span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-yellow-600 rounded-full"></div>
                <span className="text-gray-600 dark:text-gray-400">
                  {posture.vulnerability_stats.medium} medium
                </span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-blue-600 rounded-full"></div>
                <span className="text-gray-600 dark:text-gray-400">
                  {posture.vulnerability_stats.low} low
                </span>
              </div>
            </div>
            <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
              <span className="text-xs text-green-600 dark:text-green-400">
                {posture.vulnerability_stats.fixable} fixable (
                {posture.vulnerability_stats.fixable_percent.toFixed(0)}%)
              </span>
            </div>
          </div>
        </div>

        {/* Policy Compliance Card */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
              Policy Compliance
            </h3>
            <ShieldCheck className="w-5 h-5 text-purple-500" />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900 dark:text-white">
                {posture.policy_stats.compliance_rate.toFixed(0)}%
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">compliant</span>
            </div>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Allowed</span>
                <span className="text-green-600 dark:text-green-400">
                  {posture.policy_stats.allowed}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Warned</span>
                <span className="text-yellow-600 dark:text-yellow-400">
                  {posture.policy_stats.warned}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Denied</span>
                <span className="text-red-600 dark:text-red-400">
                  {posture.policy_stats.denied}
                </span>
              </div>
            </div>
            <div className="pt-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-500 dark:text-gray-400">
              {posture.policy_stats.total_evaluations} evaluations (30d)
            </div>
          </div>
        </div>

        {/* SBOM Statistics Card */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
              SBOM Coverage
            </h3>
            <Package className="w-5 h-5 text-indigo-500" />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900 dark:text-white">
                {posture.sbom_stats.total_sboms}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">SBOMs</span>
            </div>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Total packages</span>
                <span className="text-gray-900 dark:text-white">
                  {posture.sbom_stats.total_packages.toLocaleString()}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Avg per image</span>
                <span className="text-gray-900 dark:text-white">
                  {Math.round(posture.sbom_stats.avg_per_image)}
                </span>
              </div>
            </div>
            <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center gap-2 text-xs">
                <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{
                      width: `${
                        (posture.sbom_stats.os_packages / posture.sbom_stats.total_packages) * 100
                      }%`,
                    }}
                  />
                </div>
                <span className="text-gray-500 dark:text-gray-400">OS packages</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Trend Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Deployment Trends */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Deployment Trends (7 days)
          </h3>
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
        </div>

        {/* Vulnerability Trends */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Critical + High Vulnerabilities (7 days)
          </h3>
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
        </div>
      </div>

      {/* Recent Security Events */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Recent Security Events
        </h3>
        <div className="space-y-3">
          {posture.recent_events.length === 0 ? (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">
              No recent security events
            </p>
          ) : (
            posture.recent_events.map((event) => (
              <div
                key={event.id}
                className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <div className="flex-shrink-0 mt-0.5">
                  {event.severity === "critical" || event.severity === "high" ? (
                    <AlertTriangle className="w-5 h-5 text-red-600" />
                  ) : event.severity === "medium" ? (
                    <AlertTriangle className="w-5 h-5 text-yellow-600" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-600" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                      {event.title}
                    </h4>
                    <span
                      className={cn(
                        "px-2 py-0.5 text-xs font-medium rounded-full",
                        getSeverityColor(event.severity)
                      )}
                    >
                      {event.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
                    {event.description}
                  </p>
                  <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <GitBranch className="w-3 h-3" />
                      {event.source}
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
