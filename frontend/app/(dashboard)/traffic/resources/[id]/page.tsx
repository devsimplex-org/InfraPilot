"use client";

import { useState, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import { Dialog, Transition } from "@headlessui/react";
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
  Play,
  RotateCcw,
  Eye,
  Code,
  X,
  Edit2,
  Save,
  Loader2,
} from "lucide-react";
import Link from "next/link";
import {
  api,
  TrafficResource,
  TrafficUpstream,
  TrafficApplyHistory,
  TrafficPolicy,
  TrafficPolicyAssignment,
  ApplyTrafficResponse,
  CreateTrafficUpstreamRequest,
  UpstreamTarget,
  TrafficConfigPreview,
} from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/utils";

type TabType = "overview" | "upstreams" | "policies" | "history" | "config";

export default function TrafficResourceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const resourceId = params.id as string;
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const queryClient = useQueryClient();

  // Modal states
  const [showApplyModal, setShowApplyModal] = useState(false);
  const [showUpstreamModal, setShowUpstreamModal] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [editingUpstream, setEditingUpstream] = useState<TrafficUpstream | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyTrafficResponse | null>(null);

  // Confirm dialog states
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showRollbackConfirm, setShowRollbackConfirm] = useState(false);
  const [upstreamToDelete, setUpstreamToDelete] = useState<string | null>(null);
  const [assignmentToDelete, setAssignmentToDelete] = useState<string | null>(null);

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

  // Query config preview
  const { data: configPreview, isLoading: configLoading } = useQuery({
    queryKey: ["traffic-config-preview", resourceId],
    queryFn: () => api.getTrafficResourceConfigPreview(resourceId),
    enabled: !!resourceId && activeTab === "config",
  });

  // Query policies for assignment modal
  const { data: policiesData } = useQuery({
    queryKey: ["traffic-policies"],
    queryFn: () => api.listTrafficPolicies({}),
    enabled: showPolicyModal,
  });

  // Query policy assignments for this resource
  const { data: assignmentsData } = useQuery({
    queryKey: ["traffic-resource-assignments", resourceId],
    queryFn: () => api.listTrafficResourcePolicyAssignments(resourceId),
    enabled: !!resourceId,
  });

  // Delete resource mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteTrafficResource(resourceId),
    onSuccess: () => {
      router.push("/traffic/resources");
    },
  });

  // Apply mutation
  const applyMutation = useMutation({
    mutationFn: (force: boolean) => api.applyTrafficResource(resourceId, force),
    onSuccess: (result) => {
      setApplyResult(result);
      queryClient.invalidateQueries({ queryKey: ["traffic-resource", resourceId] });
      queryClient.invalidateQueries({ queryKey: ["traffic-history", resourceId] });
    },
    onError: (error: Error) => {
      setApplyResult({
        success: false,
        resource_id: resourceId,
        action: "apply",
        validation_passed: false,
        errors: [error.message],
        duration_ms: 0,
      });
    },
  });

  // Dry-run mutation
  const dryRunMutation = useMutation({
    mutationFn: () => api.dryRunTrafficResource(resourceId),
    onSuccess: (result) => {
      setApplyResult(result);
      setShowApplyModal(true);
    },
    onError: (error: Error) => {
      setApplyResult({
        success: false,
        resource_id: resourceId,
        action: "dry_run",
        validation_passed: false,
        errors: [error.message],
        duration_ms: 0,
      });
      setShowApplyModal(true);
    },
  });

  // Rollback mutation
  const rollbackMutation = useMutation({
    mutationFn: () => api.rollbackTrafficResource(resourceId),
    onSuccess: (result) => {
      setApplyResult(result);
      setShowApplyModal(true);
      queryClient.invalidateQueries({ queryKey: ["traffic-resource", resourceId] });
      queryClient.invalidateQueries({ queryKey: ["traffic-history", resourceId] });
    },
    onError: (error: Error) => {
      setApplyResult({
        success: false,
        resource_id: resourceId,
        action: "rollback",
        validation_passed: false,
        errors: [error.message],
        duration_ms: 0,
      });
      setShowApplyModal(true);
    },
  });

  // Create/Update upstream mutation
  const createUpstreamMutation = useMutation({
    mutationFn: (data: CreateTrafficUpstreamRequest) => api.createTrafficUpstream(resourceId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-upstreams", resourceId] });
      setShowUpstreamModal(false);
      setEditingUpstream(null);
    },
  });

  const updateUpstreamMutation = useMutation({
    mutationFn: ({ upstreamId, data }: { upstreamId: string; data: Partial<CreateTrafficUpstreamRequest> }) =>
      api.updateTrafficUpstream(resourceId, upstreamId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-upstreams", resourceId] });
      setShowUpstreamModal(false);
      setEditingUpstream(null);
    },
  });

  // Delete upstream mutation
  const deleteUpstreamMutation = useMutation({
    mutationFn: (upstreamId: string) => api.deleteTrafficUpstream(resourceId, upstreamId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-upstreams", resourceId] });
    },
  });

  // Assign policy mutation
  const assignPolicyMutation = useMutation({
    mutationFn: ({ policyId, data }: { policyId: string; data: { traffic_resource_id: string; priority?: number } }) =>
      api.assignTrafficPolicy(policyId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-resource-assignments", resourceId] });
      setShowPolicyModal(false);
    },
  });

  // Unassign policy mutation
  const unassignPolicyMutation = useMutation({
    mutationFn: (assignmentId: string) => api.unassignTrafficPolicy(assignmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-resource-assignments", resourceId] });
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
    {
      key: "id",
      header: "Actions",
      render: (value: string, row: TrafficUpstream) => (
        <div className="flex items-center gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              setEditingUpstream(row);
              setShowUpstreamModal(true);
            }}
            className="p-1 text-gray-500 hover:text-primary-600 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
          >
            <Edit2 className="h-4 w-4" />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              setUpstreamToDelete(value);
            }}
            className="p-1 text-gray-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
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

  // Page Header Actions
  const headerAction = (
    <div className="flex items-center gap-2">
      <button
        onClick={() => dryRunMutation.mutate()}
        disabled={dryRunMutation.isPending}
        className="flex items-center gap-2 px-3 py-2 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
      >
        {dryRunMutation.isPending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Eye className="h-4 w-4" />
        )}
        Dry Run
      </button>
      <button
        onClick={() => {
          setApplyResult(null);
          applyMutation.mutate(false);
          setShowApplyModal(true);
        }}
        disabled={applyMutation.isPending}
        className="flex items-center gap-2 px-3 py-2 text-white bg-green-600 rounded-lg hover:bg-green-700 disabled:opacity-50"
      >
        {applyMutation.isPending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        Apply
      </button>
      {historyData?.history && historyData.history.length > 0 && (
        <button
          onClick={() => setShowRollbackConfirm(true)}
          disabled={rollbackMutation.isPending}
          className="flex items-center gap-2 px-3 py-2 text-yellow-700 dark:text-yellow-300 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded-lg hover:bg-yellow-100 dark:hover:bg-yellow-900/30 disabled:opacity-50"
        >
          {rollbackMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RotateCcw className="h-4 w-4" />
          )}
          Rollback
        </button>
      )}
      <button
        onClick={() => queryClient.invalidateQueries({ queryKey: ["traffic-resource", resourceId] })}
        className="flex items-center gap-2 px-3 py-2 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
      >
        <RefreshCw className="h-4 w-4" />
        Refresh
      </button>
      <button
        onClick={() => setShowDeleteConfirm(true)}
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
            { id: "config", label: "Config Preview", icon: Code },
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
            <Card>
              <CardBody>
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
              </CardBody>
            </Card>

            {/* Paths */}
            <Card>
              <CardBody>
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
              </CardBody>
            </Card>
          </div>

          {/* Labels & Annotations */}
          {(Object.keys(resource.labels || {}).length > 0 ||
            Object.keys(resource.annotations || {}).length > 0) && (
            <div className="grid grid-cols-2 gap-6">
              {Object.keys(resource.labels || {}).length > 0 && (
                <Card>
                  <CardBody>
                    <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Labels</h3>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(resource.labels).map(([key, value]) => (
                        <Badge key={key} color="gray">
                          {key}: {value}
                        </Badge>
                      ))}
                    </div>
                  </CardBody>
                </Card>
              )}

              {Object.keys(resource.annotations || {}).length > 0 && (
                <Card>
                  <CardBody>
                    <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Annotations</h3>
                    <div className="space-y-2">
                      {Object.entries(resource.annotations).map(([key, value]) => (
                        <div key={key} className="text-sm">
                          <span className="text-gray-500 dark:text-gray-400">{key}:</span>{" "}
                          <span className="text-gray-700 dark:text-gray-300">{value}</span>
                        </div>
                      ))}
                    </div>
                  </CardBody>
                </Card>
              )}
            </div>
          )}

          {/* Timestamps */}
          <Card>
            <CardBody>
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
            </CardBody>
          </Card>
        </div>
      )}

      {activeTab === "upstreams" && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => {
                setEditingUpstream(null);
                setShowUpstreamModal(true);
              }}
              className="flex items-center gap-2 px-4 py-2 text-white bg-primary-600 rounded-lg hover:bg-primary-700 text-sm font-medium"
            >
              <Plus className="h-4 w-4" />
              Add Upstream
            </button>
          </div>

          <Card>
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
                  <button
                    onClick={() => {
                      setEditingUpstream(null);
                      setShowUpstreamModal(true);
                    }}
                    className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
                  >
                    Add Upstream
                  </button>
                }
                size="sm"
              />
            )}
          </Card>
        </div>
      )}

      {activeTab === "policies" && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => setShowPolicyModal(true)}
              className="flex items-center gap-2 px-4 py-2 text-white bg-primary-600 rounded-lg hover:bg-primary-700 text-sm font-medium"
            >
              <Plus className="h-4 w-4" />
              Assign Policy
            </button>
          </div>

          <Card>
            {assignmentsData?.assignments && assignmentsData.assignments.length > 0 ? (
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {assignmentsData.assignments.map((assignment) => (
                  <div key={assignment.id} className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <Shield className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          Policy ID: {assignment.policy_id}
                        </div>
                        {assignment.path_pattern && (
                          <div className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                            Path: {assignment.path_pattern}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge color="gray">Priority: {assignment.priority}</Badge>
                      {assignment.enabled ? (
                        <Badge color="green">Enabled</Badge>
                      ) : (
                        <Badge color="gray">Disabled</Badge>
                      )}
                      <button
                        onClick={() => setAssignmentToDelete(assignment.id)}
                        className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Shield}
                title="No policies assigned"
                description="Assign traffic policies like rate limiting, bot protection, or geo-blocking"
                action={
                  <button
                    onClick={() => setShowPolicyModal(true)}
                    className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
                  >
                    Assign Policy
                  </button>
                }
                size="sm"
              />
            )}
          </Card>
        </div>
      )}

      {activeTab === "history" && (
        <Card>
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
        </Card>
      )}

      {activeTab === "config" && (
        <Card>
          {configLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading config preview..." />
            </div>
          ) : configPreview?.nginx_config ? (
            <CardBody>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-gray-900 dark:text-white">Generated Nginx Configuration</h3>
                <div className="flex items-center gap-2 text-sm text-gray-500">
                  <span>Hash: {configPreview.config_hash?.substring(0, 8)}...</span>
                </div>
              </div>
              <pre className="text-xs bg-gray-900 text-green-400 p-4 rounded-lg overflow-auto max-h-[600px] font-mono">
                {configPreview.nginx_config}
              </pre>
            </CardBody>
          ) : (
            <EmptyState
              icon={Code}
              title="No config preview available"
              description="Configure upstreams and apply to generate the nginx config"
              size="sm"
            />
          )}
        </Card>
      )}

      {/* Apply Result Modal */}
      <Transition.Root show={showApplyModal} as={Fragment}>
        <Dialog as="div" className="relative z-50" onClose={setShowApplyModal}>
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-gray-900/50 backdrop-blur-sm" />
          </Transition.Child>

          <div className="fixed inset-0 z-10 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center p-4">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-300"
                enterFrom="opacity-0 scale-95"
                enterTo="opacity-100 scale-100"
                leave="ease-in duration-200"
                leaveFrom="opacity-100 scale-100"
                leaveTo="opacity-0 scale-95"
              >
                <Dialog.Panel className="relative transform overflow-hidden rounded-xl bg-white dark:bg-gray-900 shadow-xl transition-all w-full max-w-lg">
                  <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                      <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                        {applyResult?.action === "dry_run" ? "Dry Run Result" : applyResult?.action === "rollback" ? "Rollback Result" : "Apply Result"}
                      </Dialog.Title>
                      <button
                        onClick={() => setShowApplyModal(false)}
                        className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                      >
                        <X className="h-5 w-5" />
                      </button>
                    </div>
                  </div>

                  <div className="px-6 py-4">
                    {applyMutation.isPending || dryRunMutation.isPending || rollbackMutation.isPending ? (
                      <div className="flex flex-col items-center py-8">
                        <Loader2 className="h-8 w-8 text-primary-600 animate-spin mb-4" />
                        <p className="text-gray-600 dark:text-gray-400">Processing...</p>
                      </div>
                    ) : applyResult ? (
                      <div className="space-y-4">
                        <div className={cn(
                          "p-4 rounded-lg",
                          applyResult.success || applyResult.validation_passed
                            ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
                            : "bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800"
                        )}>
                          <div className="flex items-center gap-2">
                            {applyResult.success || applyResult.validation_passed ? (
                              <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
                            )}
                            <span className={cn(
                              "font-medium",
                              applyResult.success || applyResult.validation_passed
                                ? "text-green-700 dark:text-green-300"
                                : "text-red-700 dark:text-red-300"
                            )}>
                              {applyResult.success || applyResult.validation_passed ? "Success" : "Failed"}
                            </span>
                          </div>
                        </div>

                        {applyResult.duration_ms > 0 && (
                          <div className="text-sm text-gray-600 dark:text-gray-400">
                            Duration: {applyResult.duration_ms}ms
                          </div>
                        )}

                        {applyResult.errors && applyResult.errors.length > 0 && (
                          <div>
                            <h4 className="text-sm font-medium text-red-700 dark:text-red-300 mb-2">Errors:</h4>
                            <ul className="text-sm text-red-600 dark:text-red-400 space-y-1">
                              {applyResult.errors.map((error, idx) => (
                                <li key={idx}>{error}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {applyResult.warnings && applyResult.warnings.length > 0 && (
                          <div>
                            <h4 className="text-sm font-medium text-yellow-700 dark:text-yellow-300 mb-2">Warnings:</h4>
                            <ul className="text-sm text-yellow-600 dark:text-yellow-400 space-y-1">
                              {applyResult.warnings.map((warning, idx) => (
                                <li key={idx}>{warning}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {applyResult.validation_output && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Validation Output:</h4>
                            <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded-lg overflow-x-auto">
                              {applyResult.validation_output}
                            </pre>
                          </div>
                        )}
                      </div>
                    ) : null}
                  </div>

                  <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 flex justify-end">
                    <button
                      onClick={() => setShowApplyModal(false)}
                      className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                      Close
                    </button>
                  </div>
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition.Root>

      {/* Upstream Modal */}
      <UpstreamModal
        isOpen={showUpstreamModal}
        onClose={() => {
          setShowUpstreamModal(false);
          setEditingUpstream(null);
        }}
        upstream={editingUpstream}
        onSave={(data) => {
          if (editingUpstream) {
            updateUpstreamMutation.mutate({ upstreamId: editingUpstream.id, data });
          } else {
            createUpstreamMutation.mutate(data);
          }
        }}
        isLoading={createUpstreamMutation.isPending || updateUpstreamMutation.isPending}
      />

      {/* Policy Assignment Modal */}
      <PolicyAssignmentModal
        isOpen={showPolicyModal}
        onClose={() => setShowPolicyModal(false)}
        policies={policiesData?.policies || []}
        resourceId={resourceId}
        onAssign={(policyId, priority) => {
          assignPolicyMutation.mutate({
            policyId,
            data: { traffic_resource_id: resourceId, priority },
          });
        }}
        isLoading={assignPolicyMutation.isPending}
      />

      {/* Confirm Dialogs */}
      <ConfirmDialog
        isOpen={showDeleteConfirm}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={() => {
          deleteMutation.mutate();
          setShowDeleteConfirm(false);
        }}
        title="Delete Traffic Resource"
        message={`Are you sure you want to delete "${resource?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
      />

      <ConfirmDialog
        isOpen={showRollbackConfirm}
        onClose={() => setShowRollbackConfirm(false)}
        onConfirm={() => {
          rollbackMutation.mutate();
          setShowRollbackConfirm(false);
        }}
        title="Rollback Configuration"
        message="This will revert to the previous configuration. Are you sure you want to rollback?"
        confirmText="Rollback"
        variant="warning"
        icon="redeploy"
        isLoading={rollbackMutation.isPending}
      />

      <ConfirmDialog
        isOpen={!!upstreamToDelete}
        onClose={() => setUpstreamToDelete(null)}
        onConfirm={() => {
          if (upstreamToDelete) {
            deleteUpstreamMutation.mutate(upstreamToDelete);
            setUpstreamToDelete(null);
          }
        }}
        title="Delete Upstream"
        message="Are you sure you want to delete this upstream? This will affect traffic routing."
        confirmText="Delete"
        variant="danger"
        icon="delete"
        isLoading={deleteUpstreamMutation.isPending}
      />

      <ConfirmDialog
        isOpen={!!assignmentToDelete}
        onClose={() => setAssignmentToDelete(null)}
        onConfirm={() => {
          if (assignmentToDelete) {
            unassignPolicyMutation.mutate(assignmentToDelete);
            setAssignmentToDelete(null);
          }
        }}
        title="Remove Policy Assignment"
        message="Are you sure you want to remove this policy from the resource?"
        confirmText="Remove"
        variant="danger"
        icon="delete"
        isLoading={unassignPolicyMutation.isPending}
      />
    </div>
  );
}

// Upstream Modal Component
interface UpstreamModalProps {
  isOpen: boolean;
  onClose: () => void;
  upstream: TrafficUpstream | null;
  onSave: (data: CreateTrafficUpstreamRequest) => void;
  isLoading: boolean;
}

function UpstreamModal({ isOpen, onClose, upstream, onSave, isLoading }: UpstreamModalProps) {
  const [name, setName] = useState("");
  const [lbMethod, setLbMethod] = useState<"round_robin" | "least_conn" | "ip_hash" | "random">("round_robin");
  const [targets, setTargets] = useState<{ address: string; port: number; weight: number }[]>([
    { address: "", port: 80, weight: 1 },
  ]);
  const [healthCheckEnabled, setHealthCheckEnabled] = useState(false);
  const [healthCheckPath, setHealthCheckPath] = useState("/health");
  const [healthCheckInterval, setHealthCheckInterval] = useState(10);

  // Reset form when modal opens
  useState(() => {
    if (isOpen) {
      if (upstream) {
        setName(upstream.name);
        setLbMethod(upstream.lb_method);
        setTargets(
          upstream.targets.map((t) => ({ address: t.address, port: t.port, weight: t.weight }))
        );
        setHealthCheckEnabled(upstream.health_check_enabled);
        setHealthCheckPath(upstream.health_check_path);
        setHealthCheckInterval(upstream.health_check_interval_sec);
      } else {
        setName("");
        setLbMethod("round_robin");
        setTargets([{ address: "", port: 80, weight: 1 }]);
        setHealthCheckEnabled(false);
        setHealthCheckPath("/health");
        setHealthCheckInterval(10);
      }
    }
  });

  const handleSave = () => {
    onSave({
      name,
      lb_method: lbMethod,
      targets: targets.filter((t) => t.address.trim() !== "").map((t) => ({
        address: t.address,
        port: t.port,
        weight: t.weight,
        max_fails: 3,
        fail_timeout_sec: 10,
        is_healthy: true,
        consecutive_failures: 0,
        enabled: true,
      })),
      health_check_enabled: healthCheckEnabled,
      health_check_path: healthCheckPath,
      health_check_interval_sec: healthCheckInterval,
    });
  };

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-900/50 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-xl bg-white dark:bg-gray-900 shadow-xl transition-all w-full max-w-lg">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between">
                    <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                      {upstream ? "Edit Upstream" : "Add Upstream"}
                    </Dialog.Title>
                    <button
                      onClick={onClose}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                </div>

                <div className="px-6 py-4 space-y-4 max-h-[60vh] overflow-y-auto">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Upstream Name
                    </label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g., backend-api"
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Load Balancing Method
                    </label>
                    <select
                      value={lbMethod}
                      onChange={(e) => setLbMethod(e.target.value as typeof lbMethod)}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="round_robin">Round Robin</option>
                      <option value="least_conn">Least Connections</option>
                      <option value="ip_hash">IP Hash</option>
                      <option value="random">Random</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Targets
                    </label>
                    <div className="space-y-2">
                      {targets.map((target, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={target.address}
                            onChange={(e) => {
                              const updated = [...targets];
                              updated[idx] = { ...updated[idx], address: e.target.value };
                              setTargets(updated);
                            }}
                            placeholder="192.168.1.10 or container_name"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          <input
                            type="number"
                            value={target.port}
                            onChange={(e) => {
                              const updated = [...targets];
                              updated[idx] = { ...updated[idx], port: parseInt(e.target.value) || 80 };
                              setTargets(updated);
                            }}
                            className="w-20 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          <input
                            type="number"
                            value={target.weight}
                            onChange={(e) => {
                              const updated = [...targets];
                              updated[idx] = { ...updated[idx], weight: parseInt(e.target.value) || 1 };
                              setTargets(updated);
                            }}
                            className="w-16 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                            min="1"
                          />
                          {targets.length > 1 && (
                            <button
                              onClick={() => setTargets(targets.filter((_, i) => i !== idx))}
                              className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => setTargets([...targets, { address: "", port: 80, weight: 1 }])}
                      className="mt-2 flex items-center gap-2 text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700"
                    >
                      <Plus className="h-4 w-4" />
                      Add Target
                    </button>
                  </div>

                  <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={healthCheckEnabled}
                        onChange={(e) => setHealthCheckEnabled(e.target.checked)}
                        className="text-primary-600 rounded"
                      />
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Enable Health Checks
                      </span>
                    </label>

                    {healthCheckEnabled && (
                      <div className="mt-3 space-y-3 pl-6">
                        <div>
                          <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                            Health Check Path
                          </label>
                          <input
                            type="text"
                            value={healthCheckPath}
                            onChange={(e) => setHealthCheckPath(e.target.value)}
                            placeholder="/health"
                            className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                        </div>
                        <div>
                          <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                            Check Interval (seconds)
                          </label>
                          <input
                            type="number"
                            value={healthCheckInterval}
                            onChange={(e) => setHealthCheckInterval(parseInt(e.target.value) || 10)}
                            min="1"
                            className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 flex justify-end gap-3">
                  <button
                    onClick={onClose}
                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={!name.trim() || targets.every((t) => !t.address.trim()) || isLoading}
                    className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:opacity-50 flex items-center gap-2"
                  >
                    {isLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Save className="h-4 w-4" />
                    )}
                    {upstream ? "Update" : "Create"}
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}

// Policy Assignment Modal Component
interface PolicyAssignmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  policies: TrafficPolicy[];
  resourceId: string;
  onAssign: (policyId: string, priority: number) => void;
  isLoading: boolean;
}

function PolicyAssignmentModal({
  isOpen,
  onClose,
  policies,
  resourceId,
  onAssign,
  isLoading,
}: PolicyAssignmentModalProps) {
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>("");
  const [priority, setPriority] = useState(100);

  const getPolicyTypeLabel = (type: string) => {
    const labels: Record<string, string> = {
      rate_limit: "Rate Limit",
      bot_protection: "Bot Protection",
      geo_blocking: "Geo Blocking",
      ip_filtering: "IP Filtering",
      cors: "CORS",
      authentication: "Authentication",
      header_transform: "Header Transform",
    };
    return labels[type] || type;
  };

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-900/50 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-xl bg-white dark:bg-gray-900 shadow-xl transition-all w-full max-w-lg">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between">
                    <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                      Assign Policy
                    </Dialog.Title>
                    <button
                      onClick={onClose}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                </div>

                <div className="px-6 py-4 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Select Policy
                    </label>
                    {policies.length > 0 ? (
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {policies.map((policy) => (
                          <label
                            key={policy.id}
                            className={cn(
                              "flex items-center justify-between p-3 rounded-lg border cursor-pointer",
                              selectedPolicyId === policy.id
                                ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                                : "border-gray-200 dark:border-gray-700 hover:border-gray-300"
                            )}
                          >
                            <div className="flex items-center gap-3">
                              <input
                                type="radio"
                                name="policy"
                                value={policy.id}
                                checked={selectedPolicyId === policy.id}
                                onChange={() => setSelectedPolicyId(policy.id)}
                                className="text-primary-600"
                              />
                              <div>
                                <div className="font-medium text-gray-900 dark:text-white">
                                  {policy.name}
                                </div>
                                <div className="text-xs text-gray-500 dark:text-gray-400">
                                  {getPolicyTypeLabel(policy.policy_type)}
                                </div>
                              </div>
                            </div>
                            {policy.enabled ? (
                              <Badge color="green">Enabled</Badge>
                            ) : (
                              <Badge color="gray">Disabled</Badge>
                            )}
                          </label>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        No policies available.{" "}
                        <Link href="/traffic/policies/create" className="text-primary-600 hover:underline">
                          Create one
                        </Link>
                      </p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Priority
                    </label>
                    <input
                      type="number"
                      value={priority}
                      onChange={(e) => setPriority(parseInt(e.target.value) || 100)}
                      min="1"
                      max="1000"
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    />
                    <p className="mt-1 text-xs text-gray-500">Higher values take precedence</p>
                  </div>
                </div>

                <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 flex justify-end gap-3">
                  <button
                    onClick={onClose}
                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => onAssign(selectedPolicyId, priority)}
                    disabled={!selectedPolicyId || isLoading}
                    className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:opacity-50 flex items-center gap-2"
                  >
                    {isLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Plus className="h-4 w-4" />
                    )}
                    Assign
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
