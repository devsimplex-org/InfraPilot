"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Server,
  Shield,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Plus,
  ArrowRight,
  Globe,
  Zap,
  Lock,
  RefreshCw,
  Bot,
  MapPin,
  Settings,
} from "lucide-react";
import Link from "next/link";
import { api, TrafficResource, TrafficPolicy } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { SlideOver } from "@/components/ui/SlideOver";
import { Tabs } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";

type TrafficTab = "overview" | "resources" | "policies" | "proxies";

interface ProxyHost {
  id: string;
  agent_id: string;
  domain: string;
  upstream_target: string;
  ssl_enabled: boolean;
  ssl_expires_at: string | null;
  force_ssl: boolean;
  http2_enabled: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

export default function TrafficPage() {
  const [activeTab, setActiveTab] = useState<TrafficTab>("overview");
  const [selectedResource, setSelectedResource] = useState<TrafficResource | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<TrafficPolicy | null>(null);
  const queryClient = useQueryClient();

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.[0]?.id;

  // Query traffic summary
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["traffic-summary"],
    queryFn: () => api.getTrafficSummary(),
  });

  // Query resources
  const { data: resourcesData, isLoading: resourcesLoading } = useQuery({
    queryKey: ["traffic-resources"],
    queryFn: () => api.listTrafficResources({}),
  });

  // Query policies
  const { data: policiesData, isLoading: policiesLoading } = useQuery({
    queryKey: ["traffic-policies"],
    queryFn: () => api.listTrafficPolicies({}),
  });

  // Query proxies
  const { data: proxiesData, isLoading: proxiesLoading } = useQuery({
    queryKey: ["proxies", defaultAgentId],
    queryFn: () => api.getProxyHosts(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  // Delete mutations
  const deleteResourceMutation = useMutation({
    mutationFn: (resourceId: string) => api.deleteTrafficResource(resourceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-resources"] });
      queryClient.invalidateQueries({ queryKey: ["traffic-summary"] });
      setSelectedResource(null);
    },
  });

  const deletePolicyMutation = useMutation({
    mutationFn: (policyId: string) => api.deleteTrafficPolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-policies"] });
      setSelectedPolicy(null);
    },
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return <Badge color="green">Active</Badge>;
      case "draft":
        return <Badge color="gray">Draft</Badge>;
      case "pending":
        return <Badge color="yellow">Pending</Badge>;
      case "disabled":
        return <Badge color="gray">Disabled</Badge>;
      case "error":
        return <Badge color="red">Error</Badge>;
      default:
        return <Badge>{status}</Badge>;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "draft":
        return <Clock className="h-4 w-4 text-gray-400" />;
      case "pending":
        return <RefreshCw className="h-4 w-4 text-yellow-500 animate-spin" />;
      case "disabled":
        return <XCircle className="h-4 w-4 text-gray-400" />;
      case "error":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const getGatewayBadge = (type: string) => {
    return type === "system" ? (
      <Badge color="purple">System</Badge>
    ) : (
      <Badge color="blue">Application</Badge>
    );
  };

  const getPolicyTypeIcon = (type: string) => {
    const icons: Record<string, typeof Shield> = {
      rate_limit: Zap,
      bot_protection: Bot,
      geo_blocking: MapPin,
      captcha: Lock,
      ip_filtering: Shield,
      header_transform: Settings,
      cors: Globe,
      authentication: Lock,
    };
    const Icon = icons[type] || Shield;
    return <Icon className="h-4 w-4" />;
  };

  const getPolicyTypeBadge = (type: string) => {
    const colors: Record<string, "blue" | "green" | "yellow" | "red" | "purple" | "gray"> = {
      rate_limit: "blue",
      bot_protection: "purple",
      geo_blocking: "yellow",
      captcha: "green",
      ip_filtering: "red",
      header_transform: "gray",
      cors: "blue",
      authentication: "green",
    };
    const labels: Record<string, string> = {
      rate_limit: "Rate Limit",
      bot_protection: "Bot Protection",
      geo_blocking: "Geo Blocking",
      captcha: "CAPTCHA",
      ip_filtering: "IP Filtering",
      header_transform: "Header Transform",
      cors: "CORS",
      authentication: "Authentication",
    };
    return <Badge color={colors[type] || "gray"}>{labels[type] || type}</Badge>;
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Tab configuration
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "resources", label: "Resources", count: resourcesData?.resources?.length || 0 },
    { id: "policies", label: "Policies", count: policiesData?.policies?.length || 0 },
    { id: "proxies", label: "Proxies", count: proxiesData?.length || 0 },
  ];

  // Resource columns
  const resourceColumns = [
    {
      key: "name",
      header: "Resource",
      sortable: true,
      render: (value: string, row: TrafficResource) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
            {row.gateway_type === "system" ? (
              <Server className="h-4 w-4 text-purple-600 dark:text-purple-400" />
            ) : (
              <Globe className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            )}
          </div>
          <div>
            <Link
              href={`/traffic/resources/${row.id}`}
              className="font-medium text-gray-900 dark:text-white hover:text-primary-600"
            >
              {value}
            </Link>
            {row.description && (
              <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                {row.description}
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "domains",
      header: "Domains",
      render: (value: string[]) => (
        <div className="space-y-1">
          {value?.slice(0, 2).map((domain, i) => (
            <div key={i} className="text-sm text-gray-700 dark:text-gray-300">
              {domain}
            </div>
          ))}
          {value?.length > 2 && (
            <div className="text-xs text-gray-500">+{value.length - 2} more</div>
          )}
        </div>
      ),
    },
    {
      key: "gateway_type",
      header: "Type",
      render: (value: string) => getGatewayBadge(value),
    },
    {
      key: "status",
      header: "Status",
      render: (value: string) => (
        <div className="flex items-center gap-2">
          {getStatusIcon(value)}
          {getStatusBadge(value)}
        </div>
      ),
    },
  ];

  // Policy columns
  const policyColumns = [
    {
      key: "name",
      header: "Policy",
      sortable: true,
      render: (value: string, row: TrafficPolicy) => (
        <div className="flex items-center gap-3">
          <div className={cn(
            "p-2 rounded-lg",
            row.enabled ? "bg-gray-100 dark:bg-gray-800" : "bg-gray-50 dark:bg-gray-800/50"
          )}>
            {getPolicyTypeIcon(row.policy_type)}
          </div>
          <div>
            <div className={cn(
              "font-medium",
              row.enabled ? "text-gray-900 dark:text-white" : "text-gray-500 dark:text-gray-400"
            )}>
              {value}
            </div>
            {row.description && (
              <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                {row.description}
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "policy_type",
      header: "Type",
      render: (value: string) => getPolicyTypeBadge(value),
    },
    {
      key: "is_global",
      header: "Scope",
      render: (value: boolean) =>
        value ? <Badge color="yellow">Global</Badge> : <Badge color="gray">Assignment</Badge>,
    },
    {
      key: "enabled",
      header: "Status",
      render: (value: boolean) =>
        value ? (
          <div className="flex items-center gap-1">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <Badge color="green">Enabled</Badge>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <XCircle className="h-4 w-4 text-gray-400" />
            <Badge color="gray">Disabled</Badge>
          </div>
        ),
    },
  ];

  // Proxy columns
  const proxyColumns = [
    {
      key: "domain",
      header: "Domain",
      render: (value: string, row: ProxyHost) => (
        <div className="flex items-center gap-3">
          <div className={cn(
            "p-2 rounded-lg",
            row.ssl_enabled ? "bg-green-100 dark:bg-green-900/30" : "bg-gray-100 dark:bg-gray-800"
          )}>
            {row.ssl_enabled ? (
              <Lock className="h-4 w-4 text-green-600 dark:text-green-400" />
            ) : (
              <Globe className="h-4 w-4 text-gray-600 dark:text-gray-400" />
            )}
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white">{value}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">→ {row.upstream_target}</div>
          </div>
        </div>
      ),
    },
    {
      key: "ssl_enabled",
      header: "SSL",
      render: (value: boolean) =>
        value ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>,
    },
    {
      key: "status",
      header: "Status",
      render: (value: string) => {
        switch (value) {
          case "active":
            return <Badge color="green">Active</Badge>;
          case "pending":
            return <Badge color="yellow">Pending</Badge>;
          case "error":
            return <Badge color="red">Error</Badge>;
          default:
            return <Badge>{value}</Badge>;
        }
      },
    },
    {
      key: "created_at",
      header: "Created",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
      ),
    },
  ];

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb items={[{ label: "Traffic", current: true }]} />
  );

  const isLoading =
    (activeTab === "overview" && (summaryLoading || resourcesLoading || policiesLoading)) ||
    (activeTab === "resources" && resourcesLoading) ||
    (activeTab === "policies" && policiesLoading) ||
    (activeTab === "proxies" && proxiesLoading);

  const renderOverview = () => (
    <>
      {/* Summary Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Total Resources"
          value={summary?.total_resources || 0}
          icon={Network}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Active Resources"
          value={summary?.active_resources || 0}
          icon={CheckCircle2}
          iconColor="text-green-600"
          valueColor="text-green-600 dark:text-green-400"
        />
        <StatCard
          label="Policies"
          value={policiesData?.policies?.length || 0}
          icon={Shield}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Proxies"
          value={proxiesData?.length || 0}
          icon={Globe}
          iconColor="text-orange-600"
        />
      </MetricsGrid>

      {/* Gateway Types */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <Server className="h-5 w-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">System Gateways</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Infrastructure-level traffic</p>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white">
            {summary?.system_gateways || 0}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
              <Globe className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">Application Gateways</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Application-level routing</p>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white">
            {summary?.application_gateways || 0}
          </div>
        </div>
      </div>

      {/* Recent Resources & Policies */}
      <div className="grid grid-cols-2 gap-6">
        {/* Recent Resources */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h3 className="font-semibold text-gray-900 dark:text-white">Recent Resources</h3>
            <button
              onClick={() => setActiveTab("resources")}
              className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
            >
              View all
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {resourcesData?.resources && resourcesData.resources.length > 0 ? (
              resourcesData.resources.slice(0, 5).map((resource) => (
                <Link
                  key={resource.id}
                  href={`/traffic/resources/${resource.id}`}
                  className="flex items-center justify-between px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                      <Network className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">{resource.name}</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {resource.domains?.slice(0, 2).join(", ")}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getGatewayBadge(resource.gateway_type)}
                    {getStatusBadge(resource.status)}
                  </div>
                </Link>
              ))
            ) : (
              <div className="px-6 py-8 text-center">
                <Network className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No traffic resources yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Recent Proxies */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h3 className="font-semibold text-gray-900 dark:text-white">Active Proxies</h3>
            <button
              onClick={() => setActiveTab("proxies")}
              className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
            >
              View all
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {proxiesData && proxiesData.length > 0 ? (
              proxiesData.slice(0, 5).map((proxy: ProxyHost) => (
                <div
                  key={proxy.id}
                  className="flex items-center justify-between px-6 py-4"
                >
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      "p-2 rounded-lg",
                      proxy.ssl_enabled ? "bg-green-100 dark:bg-green-900/30" : "bg-gray-100 dark:bg-gray-800"
                    )}>
                      {proxy.ssl_enabled ? (
                        <Lock className="h-4 w-4 text-green-600 dark:text-green-400" />
                      ) : (
                        <Globe className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                      )}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">{proxy.domain}</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">→ {proxy.upstream_target}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {proxy.ssl_enabled && <Badge color="green">SSL</Badge>}
                    {getStatusBadge(proxy.status)}
                  </div>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center">
                <Globe className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No proxies configured yet</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );

  const renderContent = () => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" label={`Loading ${activeTab}...`} />
        </div>
      );
    }

    switch (activeTab) {
      case "overview":
        return renderOverview();

      case "resources":
        const resources = resourcesData?.resources || [];
        return resources.length > 0 ? (
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              columns={resourceColumns}
              data={resources}
              keyExtractor={(row) => row.id}
              onRowClick={(row) => setSelectedResource(row)}
              hoverable
            />
          </div>
        ) : (
          <EmptyState
            icon={Network}
            title="No traffic resources"
            description="Create your first traffic resource to manage routing and load balancing"
            action={
              <Link
                href="/traffic/resources"
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
              >
                Create Resource
              </Link>
            }
          />
        );

      case "policies":
        const policies = policiesData?.policies || [];
        return policies.length > 0 ? (
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              columns={policyColumns}
              data={policies}
              keyExtractor={(row) => row.id}
              onRowClick={(row) => setSelectedPolicy(row)}
              hoverable
            />
          </div>
        ) : (
          <EmptyState
            icon={Shield}
            title="No traffic policies"
            description="Create policies to control traffic flow, rate limiting, and security"
            action={
              <Link
                href="/traffic/policies"
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
              >
                Create Policy
              </Link>
            }
          />
        );

      case "proxies":
        const proxies = proxiesData || [];
        return proxies.length > 0 ? (
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              columns={proxyColumns}
              data={proxies}
              keyExtractor={(row) => row.id}
              hoverable
            />
          </div>
        ) : (
          <EmptyState
            icon={Globe}
            title="No proxies configured"
            description="Set up reverse proxies to expose your services with SSL and routing"
            action={
              <Link
                href="/proxies"
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
              >
                Add Proxy
              </Link>
            }
          />
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Traffic Management"
        description="Manage traffic routing, load balancing, proxies, and security policies"
        breadcrumbs={breadcrumbs}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                queryClient.invalidateQueries({ queryKey: ["traffic-summary"] });
                queryClient.invalidateQueries({ queryKey: ["traffic-resources"] });
                queryClient.invalidateQueries({ queryKey: ["traffic-policies"] });
                queryClient.invalidateQueries({ queryKey: ["proxies"] });
              }}
              className="flex items-center gap-2 px-3 py-2 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
            <Link
              href="/proxies"
              className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              <Plus className="h-4 w-4" />
              Add Proxy
            </Link>
          </div>
        }
      />

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
        <Tabs
          tabs={tabs}
          activeTab={activeTab}
          onChange={(id) => setActiveTab(id as TrafficTab)}
        />
      </div>

      {/* Content */}
      <div className="space-y-6">{renderContent()}</div>

      {/* Resource Detail SlideOver */}
      <SlideOver isOpen={!!selectedResource} onClose={() => setSelectedResource(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedResource(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Resource Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedResource?.name}</p>
          </div>
        </SlideOver.Header>
        <SlideOver.Body>
          {selectedResource && (
            <div className="space-y-6">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Status</h4>
                <div className="flex items-center gap-2">
                  {getStatusIcon(selectedResource.status)}
                  {getStatusBadge(selectedResource.status)}
                  {getGatewayBadge(selectedResource.gateway_type)}
                </div>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Domains</h4>
                <div className="space-y-1">
                  {selectedResource.domains?.map((domain, i) => (
                    <div key={i} className="flex items-center gap-2 px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                      <Globe className="h-4 w-4 text-gray-400" />
                      <span className="text-sm text-gray-700 dark:text-gray-300">{domain}</span>
                    </div>
                  ))}
                </div>
              </div>
              {selectedResource.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                  <p className="text-sm text-gray-700 dark:text-gray-300">{selectedResource.description}</p>
                </div>
              )}
            </div>
          )}
        </SlideOver.Body>
        <SlideOver.Footer>
          <button
            onClick={() => setSelectedResource(null)}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Close
          </button>
          <Link
            href={`/traffic/resources/${selectedResource?.id}`}
            className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
          >
            View Full Details
          </Link>
        </SlideOver.Footer>
      </SlideOver>

      {/* Policy Detail SlideOver */}
      <SlideOver isOpen={!!selectedPolicy} onClose={() => setSelectedPolicy(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedPolicy(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Policy Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedPolicy?.name}</p>
          </div>
        </SlideOver.Header>
        <SlideOver.Body>
          {selectedPolicy && (
            <div className="space-y-6">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Type & Status</h4>
                <div className="flex items-center gap-2">
                  {getPolicyTypeBadge(selectedPolicy.policy_type)}
                  {selectedPolicy.is_global && <Badge color="yellow">Global</Badge>}
                  {selectedPolicy.enabled ? (
                    <Badge color="green">Enabled</Badge>
                  ) : (
                    <Badge color="gray">Disabled</Badge>
                  )}
                </div>
              </div>
              {selectedPolicy.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                  <p className="text-sm text-gray-700 dark:text-gray-300">{selectedPolicy.description}</p>
                </div>
              )}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Configuration</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded-lg overflow-x-auto">
                  {JSON.stringify(selectedPolicy.config, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </SlideOver.Body>
        <SlideOver.Footer>
          <button
            onClick={() => setSelectedPolicy(null)}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Close
          </button>
          <button className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700">
            Edit Policy
          </button>
        </SlideOver.Footer>
      </SlideOver>
    </div>
  );
}
