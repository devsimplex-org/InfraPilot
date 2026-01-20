"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import {
  Network,
  Server,
  Globe,
  Shield,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Plus,
  Trash2,
  RefreshCw,
  ArrowLeft,
  Settings,
  History,
  Zap,
  Heart,
} from "lucide-react";
import Link from "next/link";
import { api, TrafficResource, TrafficUpstream, TrafficApplyHistory } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { cn } from "@/lib/utils";

type TabType = "overview" | "upstreams" | "policies" | "history";

export default function TrafficResourceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const resourceId = params.id as string;
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const queryClient = useQueryClient();

  // Query resource
  const { data: resource, isLoading: resourceLoading } = useQuery({
    queryKey: ["traffic-resource", resourceId],
    queryFn: () => api.getTrafficResource(resourceId),
    enabled: !!resourceId,
  });

  // Query upstreams
  const { data: upstreamsData, isLoading: upstreamsLoading } = useQuery({
    queryKey: ["traffic-upstreams", resourceId],
    queryFn: () => api.listTrafficUpstreams(resourceId),
    enabled: !!resourceId,
  });

  // Query history
  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ["traffic-history", resourceId],
    queryFn: () => api.getTrafficApplyHistory(resourceId),
    enabled: !!resourceId,
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteTrafficResource(resourceId),
    onSuccess: () => {
      router.push("/traffic/resources");
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
        return <CheckCircle2 className="h-5 w-5 text-green-500" />;
      case "draft":
        return <Clock className="h-5 w-5 text-gray-400" />;
      case "pending":
        return <RefreshCw className="h-5 w-5 text-yellow-500 animate-spin" />;
      case "disabled":
        return <XCircle className="h-5 w-5 text-gray-400" />;
      case "error":
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      default:
        return null;
    }
  };

  const getGatewayBadge = (type: string) => {
    return type === "system" ? (
      <Badge color="purple">System Gateway</Badge>
    ) : (
      <Badge color="blue">Application Gateway</Badge>
    );
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

  const getLbMethodLabel = (method: string) => {
    const labels: Record<string, string> = {
      round_robin: "Round Robin",
      least_conn: "Least Connections",
      ip_hash: "IP Hash",
      random: "Random",
    };
    return labels[method] || method;
  };

  // Upstream table columns
  const upstreamColumns = [
    {
      key: "name",
      header: "Upstream",
      render: (value: string, row: TrafficUpstream) => (
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-gray-400" />
          <span className="font-medium text-gray-900 dark:text-white">{value}</span>
        </div>
      ),
    },
    {
      key: "lb_method",
      header: "Load Balancing",
      render: (value: string) => (
        <Badge color="gray">{getLbMethodLabel(value)}</Badge>
      ),
    },
    {
      key: "total_targets",
      header: "Targets",
      render: (value: number, row: TrafficUpstream) => (
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-700 dark:text-gray-300">{value}</span>
          {row.health_check_enabled && (
            <div className="flex items-center gap-1">
              <span className="text-green-600">{row.healthy_targets}</span>
              <span className="text-gray-400">/</span>
              <span className="text-gray-600">{value}</span>
              <Heart className="h-3 w-3 text-green-500" />
            </div>
          )}
        </div>
      ),
    },
    {
      key: "health_check_enabled",
      header: "Health Check",
      render: (value: boolean, row: TrafficUpstream) =>
        value ? (
          <div className="flex items-center gap-1">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <span className="text-sm text-gray-600 dark:text-gray-400">{row.health_check_path}</span>
          </div>
        ) : (
          <Badge color="gray">Disabled</Badge>
        ),
    },
  ];

  // History table columns
  const historyColumns = [
    {
      key: "action",
      header: "Action",
      render: (value: string) => {
        const colors: Record<string, "blue" | "green" | "yellow" | "red" | "gray"> = {
          create: "green",
          update: "blue",
          delete: "red",
          apply: "green",
          validate: "yellow",
          rollback: "yellow",
        };
        return <Badge color={colors[value] || "gray"}>{value}</Badge>;
      },
    },
    {
      key: "validation_passed",
      header: "Validation",
      render: (value: boolean | undefined) =>
        value === undefined ? (
          <span className="text-gray-400">-</span>
        ) : value ? (
          <CheckCircle2 className="h-4 w-4 text-green-500" />
        ) : (
          <XCircle className="h-4 w-4 text-red-500" />
        ),
    },
    {
      key: "success",
      header: "Result",
      render: (value: boolean | undefined) =>
        value === undefined ? (
          <span className="text-gray-400">-</span>
        ) : value ? (
          <Badge color="green">Success</Badge>
        ) : (
          <Badge color="red">Failed</Badge>
        ),
    },
    {
      key: "apply_duration_ms",
      header: "Duration",
      render: (value: number | undefined) =>
        value ? (
          <span className="text-sm text-gray-600 dark:text-gray-400">{value}ms</span>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "applied_at",
      header: "Time",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {formatTimestamp(value)}
        </span>
      ),
    },
  ];

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Traffic", href: "/traffic" },
        { label: "Resources", href: "/traffic/resources" },
        { label: resource?.name || "Loading...", current: true },
      ]}
    />
  );

  // Page Header Action
  const headerAction = (
    <div className="flex items-center gap-2">
      <button
        onClick={() => queryClient.invalidateQueries({ queryKey: ["traffic-resource", resourceId] })}
        className="flex items-center gap-2 px-3 py-2 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
      >
        <RefreshCw className="h-4 w-4" />
        Refresh
      </button>
      <button
        onClick={() => {
          if (confirm("Are you sure you want to delete this resource?")) {
            deleteMutation.mutate();
          }
        }}
        className="flex items-center gap-2 px-3 py-2 text-red-600 bg-white dark:bg-gray-800 border border-red-300 dark:border-red-600 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20"
      >
        <Trash2 className="h-4 w-4" />
        Delete
      </button>
    </div>
  );

  if (resourceLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading resource..." />
      </div>
    );
  }

  if (!resource) {
    return (
      <EmptyState
        icon={Network}
        title="Resource not found"
        description="The traffic resource you're looking for doesn't exist"
        action={
          <Link
            href="/traffic/resources"
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
          >
            Back to Resources
          </Link>
        }
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title={resource.name}
        description={resource.description || "Traffic resource configuration"}
        breadcrumbs={breadcrumbs}
        action={headerAction}
      />

      {/* Status Banner */}
      <div className="flex items-center gap-4 p-4 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
        <div className="flex items-center gap-3">
          {getStatusIcon(resource.status)}
          {getStatusBadge(resource.status)}
          {getGatewayBadge(resource.gateway_type)}
        </div>
        {resource.last_error && (
          <div className="flex-1 px-4 py-2 bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 text-sm text-red-700 dark:text-red-300">
            {resource.last_error}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-800">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: "overview", label: "Overview", icon: Network },
            { id: "upstreams", label: "Upstreams", icon: Server },
            { id: "policies", label: "Policies", icon: Shield },
            { id: "history", label: "History", icon: History },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as TabType)}
              className={cn(
                "py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2",
                activeTab === tab.id
                  ? "border-primary-600 text-primary-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Metrics */}
          <MetricsGrid columns={4}>
            <StatCard
              label="Domains"
              value={resource.domains.length}
              icon={Globe}
              iconColor="text-blue-600"
            />
            <StatCard
              label="Paths"
              value={resource.paths.length}
              icon={Network}
              iconColor="text-green-600"
            />
            <StatCard
              label="Upstreams"
              value={upstreamsData?.upstreams?.length || 0}
              icon={Server}
              iconColor="text-purple-600"
            />
            <StatCard
              label="History Events"
              value={historyData?.history?.length || 0}
              icon={History}
              iconColor="text-gray-600"
            />
          </MetricsGrid>

          <div className="grid grid-cols-2 gap-6">
            {/* Domains */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Domains</h3>
              <div className="space-y-2">
                {resource.domains.map((domain, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <Globe className="h-4 w-4 text-gray-400" />
                    <span className="text-sm text-gray-700 dark:text-gray-300">{domain}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Paths */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Path Configuration</h3>
              <div className="space-y-2">
                {resource.paths.map((pathConfig, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <span className="text-sm text-gray-700 dark:text-gray-300 font-mono">
                      {pathConfig.path}
                    </span>
                    <Badge color="gray">{pathConfig.match}</Badge>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Labels & Annotations */}
          {(Object.keys(resource.labels || {}).length > 0 ||
            Object.keys(resource.annotations || {}).length > 0) && (
            <div className="grid grid-cols-2 gap-6">
              {Object.keys(resource.labels || {}).length > 0 && (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Labels</h3>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(resource.labels).map(([key, value]) => (
                      <Badge key={key} color="gray">
                        {key}: {value}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {Object.keys(resource.annotations || {}).length > 0 && (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Annotations</h3>
                  <div className="space-y-2">
                    {Object.entries(resource.annotations).map(([key, value]) => (
                      <div key={key} className="text-sm">
                        <span className="text-gray-500 dark:text-gray-400">{key}:</span>{" "}
                        <span className="text-gray-700 dark:text-gray-300">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Timestamps */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Timestamps</h3>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-sm text-gray-500 dark:text-gray-400">Created</div>
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {formatTimestamp(resource.created_at)}
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-500 dark:text-gray-400">Updated</div>
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {formatTimestamp(resource.updated_at)}
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-500 dark:text-gray-400">Last Applied</div>
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {resource.last_applied_at ? formatTimestamp(resource.last_applied_at) : "Never"}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "upstreams" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          {upstreamsLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading upstreams..." />
            </div>
          ) : upstreamsData?.upstreams && upstreamsData.upstreams.length > 0 ? (
            <Table
              columns={upstreamColumns}
              data={upstreamsData.upstreams}
              keyExtractor={(row) => row.id}
              hoverable
            />
          ) : (
            <EmptyState
              icon={Server}
              title="No upstreams configured"
              description="Add upstream servers for load balancing"
              action={
                <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium">
                  Add Upstream
                </button>
              }
              size="sm"
            />
          )}
        </div>
      )}

      {activeTab === "policies" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <EmptyState
            icon={Shield}
            title="No policies assigned"
            description="Assign traffic policies like rate limiting, bot protection, or geo-blocking"
            action={
              <Link
                href="/traffic/policies"
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
              >
                Browse Policies
              </Link>
            }
            size="sm"
          />
        </div>
      )}

      {activeTab === "history" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          {historyLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading history..." />
            </div>
          ) : historyData?.history && historyData.history.length > 0 ? (
            <Table
              columns={historyColumns}
              data={historyData.history}
              keyExtractor={(row) => row.id}
              hoverable
            />
          ) : (
            <EmptyState
              icon={History}
              title="No history yet"
              description="Apply changes to see the history of this resource"
              size="sm"
            />
          )}
        </div>
      )}
    </div>
  );
}
