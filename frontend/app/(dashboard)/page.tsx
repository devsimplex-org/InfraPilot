"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Package,
  AlertTriangle,
  Shield,
  CheckCircle2,
  XCircle,
  Activity,
  TrendingUp,
  Clock,
  Users,
  FileText,
  Rocket,
} from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Timeline } from "@/components/ui/Timeline";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function DashboardPage() {
  const router = useRouter();
  // Fetch agents
  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgent = agents?.find((a) => a.status === "active");
  const activeAgents = agents?.filter((a) => a.status === "active").length || 0;
  const totalAgents = agents?.length || 0;

  // Fetch containers for active agent
  const { data: containers } = useQuery({
    queryKey: ["containers", activeAgent?.id],
    queryFn: () => activeAgent ? api.getContainers(activeAgent.id) : Promise.resolve([]),
    enabled: !!activeAgent,
    refetchInterval: 10000,
  });

  // Fetch proxies for active agent
  const { data: proxies } = useQuery({
    queryKey: ["proxies", activeAgent?.id],
    queryFn: () => activeAgent ? api.getProxyHosts(activeAgent.id) : Promise.resolve([]),
    enabled: !!activeAgent,
  });

  // Fetch deployments for active agent
  const { data: deployments } = useQuery({
    queryKey: ["deployments", activeAgent?.id],
    queryFn: () => activeAgent ? api.getDeployments(activeAgent.id) : Promise.resolve([]),
    enabled: !!activeAgent,
  });

  // Fetch alert history
  const { data: alertHistory } = useQuery({
    queryKey: ["alertHistory"],
    queryFn: () => api.getAlertHistory(10),
  });

  // Calculate metrics
  const runningContainers = containers?.filter((c) => c.status === "running").length || 0;
  const totalContainers = containers?.length || 0;
  const activeProxies = proxies?.filter((p: { status: string }) => p.status === "active").length || 0;
  const totalProxies = proxies?.length || 0;
  const activeAlerts = alertHistory?.filter((a) => !a.resolved_at).length || 0;
  const criticalAlerts = alertHistory?.filter((a) => !a.resolved_at && a.severity === "critical").length || 0;
  const totalDeployments = deployments?.length || 0;
  const runningDeployments = deployments?.filter((d: { status: string }) => d.status === "running").length || 0;

  // Calculate security posture (simple heuristic)
  const getOverallStatus = () => {
    if (criticalAlerts > 0) return 'critical';
    if (activeAlerts > 3) return 'warning';
    if (activeAlerts > 0) return 'degraded';
    return 'healthy';
  };

  const overallStatus = getOverallStatus();

  // Loading state
  if (agentsLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Dashboard"
          description="Overview of your infrastructure security and operations"
        />
        <Spinner.Page label="Loading dashboard..." />
      </div>
    );
  }

  // No agents state
  if (!activeAgent) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Dashboard"
          description="Overview of your infrastructure security and operations"
        />
        <EmptyState
          icon={Activity}
          title="No active agents"
          description="Connect your first agent to start monitoring your infrastructure"
          action={
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              Connect Agent
            </button>
          }
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Dashboard"
        description="Are we safe? Overview of your infrastructure security and operations"
        action={
          <div className="flex items-center gap-3">
            <StatusIndicator status={overallStatus} pulse size="sm" />
            <span className="text-xs text-gray-500 dark:text-gray-400">
              Auto-refresh • 10s
            </span>
          </div>
        }
      />

      {/* Key Metrics Grid */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Containers"
          value={totalContainers}
          description={runningContainers === totalContainers ? "All running" : `${runningContainers} running`}
          icon={Package}
          iconColor="text-blue-600 dark:text-blue-400"
          trend={runningContainers === totalContainers ? "up" : undefined}
          trendValue={runningContainers === totalContainers ? "All healthy" : undefined}
          onClick={() => router.push("/docker#containers")}
        />

        <StatCard
          label="Deployments"
          value={totalDeployments}
          description={runningDeployments === totalDeployments ? "All running" : `${runningDeployments} running`}
          icon={Rocket}
          iconColor="text-purple-600 dark:text-purple-400"
          trend={runningDeployments === totalDeployments && totalDeployments > 0 ? "up" : undefined}
          trendValue={runningDeployments === totalDeployments && totalDeployments > 0 ? "All healthy" : undefined}
          onClick={() => router.push("/deployments")}
        />

        <StatCard
          label="Critical Alerts"
          value={criticalAlerts}
          description={criticalAlerts === 0 ? "No critical issues" : "Attention needed"}
          icon={AlertTriangle}
          iconColor={criticalAlerts > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
          valueColor={criticalAlerts > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
          onClick={() => router.push("/alerts")}
        />

        <StatCard
          label="Security Posture"
          value={activeAlerts === 0 ? "Excellent" : activeAlerts < 3 ? "Good" : "Fair"}
          description={`${activeAlerts} active issue${activeAlerts !== 1 ? 's' : ''}`}
          icon={Shield}
          iconColor="text-purple-600 dark:text-purple-400"
          trend={activeAlerts === 0 ? "up" : "down"}
          trendValue={activeAlerts === 0 ? "No issues" : `${activeAlerts} to resolve`}
        />
      </MetricsGrid>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Status */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              System Status
            </h3>
          </Card.Header>
          <Card.Body>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700 dark:text-gray-300">Overall Health</span>
                <StatusIndicator status={overallStatus} pulse size="sm" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700 dark:text-gray-300">Containers</span>
                <StatusIndicator
                  status={runningContainers === totalContainers ? "healthy" : "warning"}
                  label={`${runningContainers}/${totalContainers} running`}
                  size="sm"
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700 dark:text-gray-300">Proxy Hosts</span>
                <StatusIndicator
                  status={activeProxies > 0 ? "healthy" : "degraded"}
                  label={`${activeProxies}/${totalProxies} active`}
                  size="sm"
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700 dark:text-gray-300">Agents</span>
                <StatusIndicator
                  status={activeAgents === totalAgents ? "healthy" : "critical"}
                  label={`${activeAgents}/${totalAgents} online`}
                  size="sm"
                  pulse={activeAgents < totalAgents}
                />
              </div>
            </div>
          </Card.Body>
        </Card>

        {/* Recent Activity */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Activity
            </h3>
          </Card.Header>
          <Card.Body>
            {alertHistory && alertHistory.length > 0 ? (
              <Timeline>
                {alertHistory.slice(0, 5).map((alert, index) => (
                  <Timeline.Item
                    key={alert.id}
                    icon={alert.resolved_at ? CheckCircle2 : AlertTriangle}
                    iconColor={alert.resolved_at
                      ? "text-green-600 dark:text-green-400"
                      : alert.severity === "critical"
                        ? "text-red-600 dark:text-red-400"
                        : "text-yellow-600 dark:text-yellow-400"
                    }
                    title={alert.message}
                    timestamp={new Date(alert.triggered_at).toLocaleTimeString()}
                    isLast={index === Math.min(alertHistory.length, 5) - 1}
                  />
                ))}
              </Timeline>
            ) : (
              <EmptyState
                icon={CheckCircle2}
                title="No recent alerts"
                description="Your infrastructure is running smoothly"
                size="sm"
                iconClassName="text-green-500 dark:text-green-400"
              />
            )}
          </Card.Body>
        </Card>
      </div>

      {/* Containers & Proxies Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Containers */}
        <Card>
          <Card.Header
            action={
              <Link href="/docker#containers" className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400">
                View all
              </Link>
            }
          >
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Containers
            </h3>
          </Card.Header>
          <Card.Body>
            {containers && containers.length > 0 ? (
              <div className="space-y-3">
                {containers.slice(0, 5).map((container) => (
                  <div
                    key={container.container_id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <StatusIndicator
                        status={container.status === "running" ? "healthy" : "critical"}
                        showLabel={false}
                        pulse={container.status === "running"}
                        size="sm"
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {container.name}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                          {container.image}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400">
                      <span>CPU: {(container.cpu_percent || 0).toFixed(1)}%</span>
                      <span>Mem: {container.memory_mb || 0}MB</span>
                    </div>
                  </div>
                ))}
                {containers.length > 5 && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-3">
                    +{containers.length - 5} more containers
                  </p>
                )}
              </div>
            ) : (
              <EmptyState
                icon={Package}
                title="No containers"
                description="No containers are currently running"
                size="sm"
              />
            )}
          </Card.Body>
        </Card>

        {/* Proxy Hosts */}
        <Card>
          <Card.Header
            action={
              <Link href="/proxies" className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400">
                View all
              </Link>
            }
          >
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Proxy Hosts
            </h3>
          </Card.Header>
          <Card.Body>
            {proxies && proxies.length > 0 ? (
              <div className="space-y-3">
                {proxies.slice(0, 5).map((proxy: any) => (
                  <div
                    key={proxy.id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {proxy.domain}
                        </p>
                        {proxy.ssl_enabled && (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
                        )}
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                        {proxy.upstream_target}
                      </p>
                    </div>
                    <StatusIndicator
                      status={proxy.status === "active" ? "healthy" : "warning"}
                      size="sm"
                    />
                  </div>
                ))}
                {proxies.length > 5 && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-3">
                    +{proxies.length - 5} more proxies
                  </p>
                )}
              </div>
            ) : (
              <EmptyState
                icon={Activity}
                title="No proxy hosts"
                description="No proxy hosts are configured"
                size="sm"
              />
            )}
          </Card.Body>
        </Card>
      </div>
    </div>
  );
}
