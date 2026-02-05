"use client";

import { useState, useEffect, useMemo } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  Package,
  Shield,
  AlertTriangle,
  CheckCircle,
  GitBranch,
  FileCode,
  ExternalLink,
  RefreshCw,
  RotateCcw,
  Trash2,
  Download,
  Container,
  Clock,
  Activity,
  ChevronDown,
  ChevronRight,
  Layers,
} from "lucide-react";
import { api, Deployment, ScanResult, Vulnerability, SBOM } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Table, type Column } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { Card } from "@/components/ui/Card";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { FilterPanel, type FilterGroup } from "@/components/ui/FilterPanel";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { RedeployWizard } from "@/components/RedeployWizard";
import { cn } from "@/lib/utils";

type PanelTab = "overview" | "scan" | "vulnerabilities" | "sbom";
type ConfirmAction = { type: "redeploy" | "delete"; deployment: Deployment } | null;

export default function DeploymentsPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("overview");
  const [vulnerabilitySeverityFilter, setVulnerabilitySeverityFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [environmentFilter, setEnvironmentFilter] = useState<string>("all");
  const [searchFilter, setSearchFilter] = useState("");
  const [redeployingId, setRedeployingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction>(null);
  const [redeployWizardOpen, setRedeployWizardOpen] = useState(false);
  const [redeployTarget, setRedeployTarget] = useState<Deployment | null>(null);

  // Multi-select state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkDeleteProgress, setBulkDeleteProgress] = useState<{
    total: number;
    completed: number;
    failed: string[];
  } | null>(null);
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);

  // Stack grouping state
  const [viewMode, setViewMode] = useState<"flat" | "grouped">("flat");
  const [expandedStacks, setExpandedStacks] = useState<Set<string>>(new Set());

  // Redeploy mutation
  const redeployMutation = useMutation({
    mutationFn: ({ deploymentId, pullLatest, skipScanning }: { deploymentId: string; pullLatest: boolean; skipScanning: boolean }) => {
      if (!selectedAgent) throw new Error("No agent selected");
      return api.redeployDeployment(selectedAgent, deploymentId, pullLatest, skipScanning);
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
      setRedeployingId(null);
      setRedeployWizardOpen(false);
      setRedeployTarget(null);
      // Optionally select the new deployment
      if (data.id) {
        // The new deployment will appear in the list after refetch
      }
    },
    onError: () => {
      setRedeployingId(null);
      setRedeployWizardOpen(false);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (deploymentId: string) => {
      if (!selectedAgent) throw new Error("No agent selected");
      return api.deleteDeployment(selectedAgent, deploymentId);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
      setDeletingId(null);
      // Close the slide-over if the deleted deployment was selected
      if (selectedDeployment?.id === deletingId) {
        setSelectedDeployment(null);
      }
    },
    onError: () => {
      setDeletingId(null);
    },
  });

  // Bulk delete mutation
  const bulkDeleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = { completed: 0, failed: [] as string[] };
      for (const id of ids) {
        try {
          await api.deleteDeployment(selectedAgent!, id);
          results.completed++;
          setBulkDeleteProgress(prev => prev ? { ...prev, completed: prev.completed + 1 } : null);
        } catch {
          results.failed.push(id);
          setBulkDeleteProgress(prev => prev ? { ...prev, failed: [...prev.failed, id] } : null);
        }
      }
      return results;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
      setSelectedIds(new Set());
      setBulkDeleteProgress(null);
      setShowBulkDeleteModal(false);
    },
  });

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch deployments for selected agent
  const { data: deployments, isLoading } = useQuery({
    queryKey: ["deployments", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getDeployments(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 10000,
  });

  // Fetch scan results for selected deployment
  const { data: scanResult } = useQuery({
    queryKey: ["scanResult", selectedDeployment?.scan_result_id],
    queryFn: () =>
      selectedDeployment?.scan_result_id
        ? api.getScanDetails(selectedDeployment.scan_result_id)
        : Promise.resolve(null),
    enabled: !!selectedDeployment?.scan_result_id && (panelTab === "scan" || panelTab === "vulnerabilities"),
  });

  // Fetch vulnerabilities for scan
  const { data: vulnerabilities } = useQuery({
    queryKey: ["vulnerabilities", selectedDeployment?.scan_result_id, vulnerabilitySeverityFilter],
    queryFn: () =>
      selectedDeployment?.scan_result_id
        ? api.getScanVulnerabilities(selectedDeployment.scan_result_id, {
            severity: vulnerabilitySeverityFilter[0],
          })
        : Promise.resolve([]),
    enabled: !!selectedDeployment?.scan_result_id && panelTab === "vulnerabilities",
  });

  // Fetch SBOM for selected deployment
  const { data: sboms } = useQuery({
    queryKey: ["sboms", selectedDeployment?.sbom_id],
    queryFn: () => (selectedDeployment?.sbom_id ? api.listSBOMs() : Promise.resolve([])),
    enabled: !!selectedDeployment?.sbom_id && panelTab === "sbom",
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  // Sync deployment status with actual container state when agent changes
  useEffect(() => {
    if (selectedAgent) {
      api.syncDeploymentStatus(selectedAgent).then((result) => {
        if (result.synced > 0) {
          // Refresh deployments list if any were synced
          queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
        }
      }).catch(() => {
        // Silently ignore sync errors - not critical
      });
    }
  }, [selectedAgent, queryClient]);

  // Calculate metrics
  const metrics = useMemo(() => {
    if (!deployments) return null;

    const total = deployments.length;
    const running = deployments.filter((d) => d.status === "running").length;
    const failed = deployments.filter((d) => d.status === "failed").length;
    const scanning = deployments.filter((d) =>
      d.status === "scanning" || d.status === "policy_check" || d.status === "deploying"
    ).length;

    // Count deployments with critical vulnerabilities
    const withScans = deployments.filter((d) => d.scan_result_id).length;

    // Policy decisions
    const blocked = deployments.filter((d) => d.policy_decision === "deny").length;
    const warned = deployments.filter((d) => d.policy_decision === "warn").length;

    // Unique environments
    const environments = new Set(deployments.map((d) => d.environment)).size;

    return {
      total,
      running,
      failed,
      scanning,
      withScans,
      blocked,
      warned,
      environments,
    };
  }, [deployments]);

  // Filter deployments
  const filteredDeployments = useMemo(() => {
    if (!deployments) return [];

    return deployments
      .filter((deployment): deployment is Deployment => !!deployment) // Remove null/undefined
      .filter((deployment) => {
        // Status filter
        const matchesStatus = statusFilter === "all" || deployment.status === statusFilter;

        // Environment filter
        const matchesEnv = environmentFilter === "all" || deployment.environment === environmentFilter;

        // Search filter
        const matchesSearch = !searchFilter ||
          deployment.service_name?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          deployment.image_repository?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          deployment.container_name?.toLowerCase().includes(searchFilter.toLowerCase());

        return matchesStatus && matchesEnv && matchesSearch;
      });
  }, [deployments, statusFilter, environmentFilter, searchFilter]);

  // Get unique environments for filters
  const uniqueEnvironments = useMemo(() => {
    if (!deployments) return [];
    return Array.from(new Set(deployments.map((d) => d.environment)));
  }, [deployments]);

  // Group deployments by stack_id
  const groupedDeployments = useMemo(() => {
    if (!filteredDeployments) return new Map<string, { stackId: string | null; deployments: Deployment[] }>();

    const groups = new Map<string, { stackId: string | null; deployments: Deployment[] }>();

    for (const d of filteredDeployments) {
      const key = d.stack_id || "standalone";
      if (!groups.has(key)) {
        groups.set(key, { stackId: d.stack_id || null, deployments: [] });
      }
      groups.get(key)!.deployments.push(d);
    }

    return groups;
  }, [filteredDeployments]);

  // Toggle stack expansion
  const toggleStackExpanded = (key: string) => {
    setExpandedStacks(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  // Handle row selection with type conversion
  const handleRowSelect = (keys: Set<string | number>) => {
    const stringKeys = new Set<string>();
    keys.forEach(key => stringKeys.add(String(key)));
    setSelectedIds(stringKeys);
  };

  const getDeploymentStatus = (status: Deployment["status"]): "healthy" | "warning" | "degraded" | "critical" => {
    switch (status) {
      case "running":
        return "healthy";
      case "failed":
        return "critical";
      case "scanning":
      case "policy_check":
      case "deploying":
        return "warning";
      case "rolled_back":
        return "degraded";
      default:
        return "degraded";
    }
  };

  const getPolicyDecisionStatus = (decision?: "allow" | "warn" | "deny"): "healthy" | "warning" | "critical" | undefined => {
    if (!decision) return undefined;
    switch (decision) {
      case "allow":
        return "healthy";
      case "warn":
        return "warning";
      case "deny":
        return "critical";
    }
  };

  // Table columns - render receives (cellValue, fullRow)
  const columns: Column<Deployment>[] = [
    {
      key: "service_name",
      header: "Service",
      sortable: true,
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        return (
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
              <Package className="w-4 h-4 text-primary-600 dark:text-primary-400" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                {row.service_name || "Unnamed Service"}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                ID: {row.id?.substring(0, 8) || "—"}...
              </p>
            </div>
          </div>
        );
      },
    },
    {
      key: "environment",
      header: "Environment",
      sortable: true,
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        const envColors: Record<string, string> = {
          prod: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
          production: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
          staging: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
          dev: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
          development: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
        };
        return (
          <span className={cn(
            "px-2 py-1 text-xs font-medium rounded-full",
            envColors[row.environment?.toLowerCase()] || "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300"
          )}>
            {row.environment || "—"}
          </span>
        );
      },
    },
    {
      key: "image_repository",
      header: "Image",
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        const fullImage = (row.image_repository || "") + (row.image_tag ? `:${row.image_tag}` : "");
        return (
          <div className="min-w-0">
            <p className="text-sm font-mono text-gray-900 dark:text-white truncate max-w-[200px]" title={fullImage}>
              {row.image_repository || "—"}
            </p>
            {row.image_tag && (
              <p className="text-xs text-primary-600 dark:text-primary-400 font-mono">
                :{row.image_tag}
              </p>
            )}
          </div>
        );
      },
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        return (
          <div className="space-y-1">
            <StatusIndicator
              status={getDeploymentStatus(row.status)}
              label={row.status?.replace(/_/g, " ") || "unknown"}
              size="sm"
              pulse={row.status === "running"}
            />
            {row.status_message && (
              <p className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-[150px]" title={row.status_message}>
                {row.status_message}
              </p>
            )}
          </div>
        );
      },
    },
    {
      key: "container_name",
      header: "Container",
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        if (row.container_name || row.container_id) {
          return (
            <div className="flex items-center gap-2">
              <Container className="w-4 h-4 text-green-500" />
              <span className="text-xs font-mono text-gray-900 dark:text-white">
                {row.container_name || row.container_id?.substring(0, 12)}
              </span>
            </div>
          );
        }
        return <span className="text-xs text-gray-400">—</span>;
      },
    },
    {
      key: "policy_decision",
      header: "Policy",
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        if (!row.policy_decision) {
          return <span className="text-xs text-gray-400">Pending</span>;
        }
        return (
          <StatusIndicator
            status={getPolicyDecisionStatus(row.policy_decision)!}
            label={row.policy_decision === "allow" ? "Allowed" : row.policy_decision === "warn" ? "Warning" : "Blocked"}
            size="sm"
          />
        );
      },
    },
    {
      key: "scan_result_id",
      header: "Scan",
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        if (row.scan_result_id) {
          return (
            <div className="flex items-center gap-1">
              <Shield className="w-4 h-4 text-green-500" />
              <span className="text-xs text-green-600 dark:text-green-400">Scanned</span>
            </div>
          );
        }
        if (row.status === "scanning") {
          return (
            <div className="flex items-center gap-1">
              <RefreshCw className="w-4 h-4 text-yellow-500 animate-spin" />
              <span className="text-xs text-yellow-600 dark:text-yellow-400">Scanning...</span>
            </div>
          );
        }
        return <span className="text-xs text-gray-400">—</span>;
      },
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      render: (_value: string, row: Deployment) => {
        if (!row?.id) return null;
        if (!row.created_at) {
          return <span className="text-xs text-gray-400">—</span>;
        }
        return (
          <div className="text-xs text-gray-600 dark:text-gray-400">
            <p>{new Date(row.created_at).toLocaleDateString()}</p>
            <p>{new Date(row.created_at).toLocaleTimeString()}</p>
          </div>
        );
      },
    },
    {
      key: "actions",
      header: "Actions",
      render: (_value: unknown, row: Deployment) => {
        if (!row?.id) return null;
        const isRedeploying = redeployingId === row.id;
        const isDeleting = deletingId === row.id;
        return (
          <div className="flex items-center gap-1">
            <button
              onClick={(e) => {
                e.stopPropagation();
                setRedeployTarget(row);
                setRedeployWizardOpen(true);
              }}
              disabled={isRedeploying}
              className="p-1.5 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 rounded disabled:opacity-50"
              title="Redeploy"
            >
              <RotateCcw className={cn("h-4 w-4", isRedeploying && "animate-spin")} />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setConfirmAction({ type: "delete", deployment: row });
              }}
              disabled={isDeleting || row.status === "running"}
              className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded disabled:opacity-50"
              title={row.status === "running" ? "Stop container first" : "Delete deployment"}
            >
              <Trash2 className={cn("h-4 w-4", isDeleting && "animate-pulse")} />
            </button>
          </div>
        );
      },
    },
  ];

  // Vulnerability filters
  const vulnerabilityFilters: FilterGroup[] = [
    {
      id: "severity",
      label: "Severity",
      type: "checkbox",
      options: [
        { label: "Critical", value: "CRITICAL" },
        { label: "High", value: "HIGH" },
        { label: "Medium", value: "MEDIUM" },
        { label: "Low", value: "LOW" },
      ],
      value: vulnerabilitySeverityFilter,
      onChange: (value) => setVulnerabilitySeverityFilter(value as string[]),
    },
  ];

  // Loading state
  if (!selectedAgent && activeAgents.length === 0 && !isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Deployments"
          description="Manage and monitor deployments with security scanning"
          breadcrumbs={<Breadcrumb items={[{ label: "Deploy", href: "/deploy" }, { label: "Deployments" }]} />}
        />
        <EmptyState
          icon={Package}
          title="No active agents"
          description="Connect your first agent to start monitoring deployments"
          action={
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
              Connect Agent
            </button>
          }
        />
      </div>
    );
  }

  return (
    <>
      <div className="space-y-6">
        {/* Page Header */}
        <PageHeader
          title="Deployments"
          description="Manage and monitor deployments with security scanning across all environments"
          breadcrumbs={<Breadcrumb items={[{ label: "Deploy", href: "/deploy" }, { label: "Deployments" }]} />}
          action={
            <div className="flex items-center gap-3">
              {/* View Mode Toggle */}
              <div className="flex items-center gap-1 border border-gray-300 dark:border-gray-600 rounded-lg p-1 bg-white dark:bg-gray-800">
                <button
                  onClick={() => setViewMode("flat")}
                  className={cn(
                    "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                    viewMode === "flat"
                      ? "bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white"
                      : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                  )}
                >
                  List
                </button>
                <button
                  onClick={() => setViewMode("grouped")}
                  className={cn(
                    "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                    viewMode === "grouped"
                      ? "bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white"
                      : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                  )}
                >
                  Stacks
                </button>
              </div>

              {activeAgents.length > 1 && (
                <select
                  value={selectedAgent || ""}
                  onChange={(e) => {
                    setSelectedAgent(e.target.value);
                    setSelectedDeployment(null);
                  }}
                  className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-4 py-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  {activeAgents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name}
                    </option>
                  ))}
                </select>
              )}
              <button
                onClick={() =>
                  queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] })
                }
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Refresh
              </button>
            </div>
          }
        />

        {/* Metrics Section */}
        {metrics && (
          <MetricsGrid columns={4}>
            <StatCard
              label="Total Deployments"
              value={metrics.total}
              description={`${metrics.running} running`}
              icon={Package}
              iconColor="text-blue-600 dark:text-blue-400"
              trend={metrics.running === metrics.total ? "up" : undefined}
              trendValue={metrics.running === metrics.total ? "All running" : undefined}
            />

            <StatCard
              label="Failed Deployments"
              value={metrics.failed}
              description={metrics.failed === 0 ? "No failures" : "Needs attention"}
              icon={AlertTriangle}
              iconColor={metrics.failed > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
              valueColor={metrics.failed > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
            />

            <StatCard
              label="In Progress"
              value={metrics.scanning}
              description={metrics.scanning > 0 ? "Active deployments" : "No active deployments"}
              icon={Activity}
              iconColor="text-yellow-600 dark:text-yellow-400"
            />

            <StatCard
              label="Policy Blocked"
              value={metrics.blocked}
              description={metrics.warned > 0 ? `${metrics.warned} warnings` : metrics.blocked === 0 ? "No blocks" : "Review policies"}
              icon={Shield}
              iconColor={metrics.blocked > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
              valueColor={metrics.blocked > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
            />
          </MetricsGrid>
        )}

        {/* Filters and Table */}
        <div className="flex gap-6">
          {/* Filters Sidebar */}
          <div className="w-64 flex-shrink-0">
            <FilterPanel
              filters={[
                {
                  id: "status",
                  label: "Status",
                  type: "radio",
                  options: [
                    { label: "All", value: "all", count: metrics?.total || 0 },
                    { label: "Running", value: "running", count: metrics?.running || 0 },
                    { label: "Failed", value: "failed", count: metrics?.failed || 0 },
                    { label: "Scanning", value: "scanning", count: deployments?.filter(d => d.status === "scanning").length || 0 },
                    { label: "Pending", value: "pending", count: deployments?.filter(d => d.status === "pending").length || 0 },
                  ],
                  value: statusFilter,
                  onChange: (value) => setStatusFilter(value as string),
                },
                {
                  id: "environment",
                  label: "Environment",
                  type: "radio",
                  options: [
                    { label: "All", value: "all", count: metrics?.total || 0 },
                    ...uniqueEnvironments.map((env) => ({
                      label: env.charAt(0).toUpperCase() + env.slice(1),
                      value: env,
                      count: deployments?.filter(d => d.environment === env).length || 0,
                    })),
                  ],
                  value: environmentFilter,
                  onChange: (value) => setEnvironmentFilter(value as string),
                },
                {
                  id: "search",
                  label: "Search",
                  type: "search",
                  value: searchFilter,
                  onChange: (value) => setSearchFilter(value as string),
                },
              ]}
              onReset={() => {
                setStatusFilter("all");
                setEnvironmentFilter("all");
                setSearchFilter("");
              }}
            />
          </div>

          {/* Main Content */}
          <div className="flex-1 min-w-0">
            {/* Bulk Actions Toolbar */}
            {selectedIds.size > 0 && (
              <div className="flex items-center justify-between p-3 bg-primary-50 dark:bg-primary-900/20 rounded-lg mb-4 border border-primary-200 dark:border-primary-800">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {selectedIds.size} deployment{selectedIds.size > 1 ? "s" : ""} selected
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedIds(new Set())}
                    className="px-3 py-1.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                  >
                    Clear
                  </button>
                  <button
                    onClick={() => setShowBulkDeleteModal(true)}
                    disabled={[...selectedIds].some(id =>
                      filteredDeployments?.find(d => d.id === id)?.status === "running"
                    )}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    title={[...selectedIds].some(id => filteredDeployments?.find(d => d.id === id)?.status === "running") ? "Cannot delete running deployments" : "Delete selected deployments"}
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete Selected
                  </button>
                </div>
              </div>
            )}

            <Card>
              <Card.Body className="p-0">
                {isLoading ? (
                  <div className="p-12">
                    <Spinner.Page label="Loading deployments..." />
                  </div>
                ) : filteredDeployments.length > 0 ? (
                  viewMode === "flat" ? (
                    <Table
                      columns={columns}
                      data={filteredDeployments}
                      keyExtractor={(deployment) => deployment.id}
                      onRowClick={(deployment) => setSelectedDeployment(deployment)}
                      loading={isLoading}
                      hoverable
                      selectedRows={selectedIds}
                      onRowSelect={handleRowSelect}
                    />
                  ) : (
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                      {[...groupedDeployments.entries()].map(([key, group]) => (
                        <div key={key}>
                          {/* Stack header - expandable */}
                          <button
                            onClick={() => toggleStackExpanded(key)}
                            className="w-full flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              {expandedStacks.has(key) ? (
                                <ChevronDown className="w-4 h-4 text-gray-500" />
                              ) : (
                                <ChevronRight className="w-4 h-4 text-gray-500" />
                              )}
                              <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                                <Layers className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                              </div>
                              <span className="font-medium text-gray-900 dark:text-white">
                                {group.stackId ? `Stack ${group.stackId.substring(0, 8)}...` : "Standalone Deployments"}
                              </span>
                              <Badge variant="default" size="sm">
                                {group.deployments.length}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              {/* Stack-level stats */}
                              <span className="text-xs text-gray-500 dark:text-gray-400">
                                {group.deployments.filter(d => d.status === "running").length} running
                              </span>
                            </div>
                          </button>

                          {/* Deployments table - collapsed by default */}
                          {expandedStacks.has(key) && (
                            <div className="border-t border-gray-100 dark:border-gray-800">
                              <Table
                                columns={columns}
                                data={group.deployments}
                                keyExtractor={(deployment) => deployment.id}
                                onRowClick={(deployment) => setSelectedDeployment(deployment)}
                                hoverable
                                selectedRows={selectedIds}
                                onRowSelect={handleRowSelect}
                              />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )
                ) : (
                  <EmptyState
                    icon={Package}
                    title="No deployments found"
                    description={
                      statusFilter !== "all" || environmentFilter !== "all" || searchFilter
                        ? "No deployments match the current filters"
                        : "No deployments found for this agent"
                    }
                  />
                )}
              </Card.Body>
            </Card>
          </div>
        </div>
      </div>

      {/* Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedDeployment}
        onClose={() => setSelectedDeployment(null)}
        size="lg"
      >
        {selectedDeployment && (
          <>
            <SlideOver.Header onClose={() => setSelectedDeployment(null)} showCloseButton>
              <div className="flex items-center justify-between w-full pr-8">
                <div>
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedDeployment.service_name}</h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{selectedDeployment.environment}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setRedeployTarget(selectedDeployment);
                      setRedeployWizardOpen(true);
                    }}
                    disabled={redeployingId === selectedDeployment.id}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
                  >
                    <RotateCcw className={cn("h-4 w-4", redeployingId === selectedDeployment.id && "animate-spin")} />
                    Redeploy
                  </button>
                  <button
                    onClick={() => setConfirmAction({ type: "delete", deployment: selectedDeployment })}
                    disabled={deletingId === selectedDeployment.id || selectedDeployment.status === "running"}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-lg transition-colors disabled:opacity-50"
                    title={selectedDeployment.status === "running" ? "Stop container first" : "Delete deployment"}
                  >
                    <Trash2 className={cn("h-4 w-4", deletingId === selectedDeployment.id && "animate-pulse")} />
                    Delete
                  </button>
                </div>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex items-center gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg mb-6">
                {[
                  { id: "overview", label: "Overview" },
                  { id: "scan", label: "Scan Results", count: scanResult?.total },
                  { id: "vulnerabilities", label: "Vulnerabilities", count: vulnerabilities?.length },
                  { id: "sbom", label: "SBOM" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setPanelTab(tab.id as PanelTab)}
                    className={cn(
                      "flex-1 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                      panelTab === tab.id
                        ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                        : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                    )}
                  >
                    {tab.label}
                    {tab.count !== undefined && (
                      <span
                        className={cn(
                          "ml-2 px-1.5 py-0.5 text-xs rounded-full",
                          panelTab === tab.id
                            ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                            : "bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400"
                        )}
                      >
                        {tab.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div className="space-y-6">
                {/* Overview Tab */}
                {panelTab === "overview" && (
                  <>
                    {/* Quick Actions */}
                    {selectedDeployment.sbom_id && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Quick Actions</h3>
                        </Card.Header>
                        <Card.Body className="space-y-2">
                          <button
                            onClick={() => api.downloadSBOM(selectedDeployment.sbom_id!)}
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
                          >
                            <Download className="w-4 h-4" />
                            Download SBOM
                          </button>
                          {selectedDeployment.scan_result_id && (
                            <button
                              onClick={() => setPanelTab("scan")}
                              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
                            >
                              <Shield className="w-4 h-4" />
                              View Scan Results
                            </button>
                          )}
                        </Card.Body>
                      </Card>
                    )}

                    {/* Deployment Info */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Deployment Info</h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Service</p>
                            <p className="font-medium text-gray-900 dark:text-white">{selectedDeployment.service_name}</p>
                          </div>
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Environment</p>
                            <Badge variant="default">{selectedDeployment.environment}</Badge>
                          </div>
                        </div>
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Status</p>
                          <StatusIndicator
                            status={getDeploymentStatus(selectedDeployment.status)}
                            label={selectedDeployment.status}
                            pulse={selectedDeployment.status === "running"}
                          />
                        </div>
                        {selectedDeployment.status_message && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Message</p>
                            <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.status_message}</p>
                          </div>
                        )}
                        {selectedDeployment.policy_decision && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Policy</p>
                            <StatusIndicator
                              status={getPolicyDecisionStatus(selectedDeployment.policy_decision)!}
                              label={selectedDeployment.policy_decision === "allow" ? "Allowed" : selectedDeployment.policy_decision === "warn" ? "Warning" : "Blocked"}
                            />
                          </div>
                        )}
                        {selectedDeployment.policy_reason && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Policy Reason</p>
                            <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.policy_reason}</p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    {/* Image Info */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                          <Container className="w-4 h-4" />
                          Image
                        </h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Repository</p>
                          <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                            {selectedDeployment.image_repository}
                          </p>
                        </div>
                        {selectedDeployment.image_tag && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Tag</p>
                            <p className="text-sm font-mono text-gray-900 dark:text-white">{selectedDeployment.image_tag}</p>
                          </div>
                        )}
                        {selectedDeployment.image_digest && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Digest</p>
                            <p className="text-xs font-mono text-gray-900 dark:text-white break-all">
                              {selectedDeployment.image_digest.substring(0, 20)}...
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    {/* Git Info */}
                    {(selectedDeployment.git_repo || selectedDeployment.git_commit) && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                            <GitBranch className="w-4 h-4" />
                            Git Info
                          </h3>
                        </Card.Header>
                        <Card.Body className="space-y-3">
                          {selectedDeployment.git_repo && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Repository</p>
                              <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                                {selectedDeployment.git_repo}
                              </p>
                            </div>
                          )}
                          <div className="grid grid-cols-2 gap-4">
                            {selectedDeployment.git_branch && (
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Branch</p>
                                <p className="text-sm font-mono text-gray-900 dark:text-white">
                                  {selectedDeployment.git_branch}
                                </p>
                              </div>
                            )}
                            {selectedDeployment.git_commit && (
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Commit</p>
                                <p className="text-sm font-mono text-gray-900 dark:text-white">
                                  {selectedDeployment.git_commit.substring(0, 8)}
                                </p>
                              </div>
                            )}
                          </div>
                        </Card.Body>
                      </Card>
                    )}

                    {/* CI/CD Info */}
                    {(selectedDeployment.ci_provider || selectedDeployment.ci_pipeline_id) && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">CI/CD</h3>
                        </Card.Header>
                        <Card.Body className="space-y-3">
                          {selectedDeployment.ci_provider && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Provider</p>
                              <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.ci_provider}</p>
                            </div>
                          )}
                          {selectedDeployment.ci_pipeline_id && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Pipeline ID</p>
                              <p className="text-sm font-mono text-gray-900 dark:text-white">
                                {selectedDeployment.ci_pipeline_id}
                              </p>
                            </div>
                          )}
                          {selectedDeployment.ci_build_url && (
                            <a
                              href={selectedDeployment.ci_build_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
                            >
                              View Build
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </Card.Body>
                      </Card>
                    )}

                    {/* Metadata */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                          <Clock className="w-4 h-4" />
                          Metadata
                        </h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Created</p>
                          <p className="text-sm text-gray-900 dark:text-white">
                            {new Date(selectedDeployment.created_at).toLocaleString()}
                          </p>
                        </div>
                        {selectedDeployment.deployed_at && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Deployed</p>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {new Date(selectedDeployment.deployed_at).toLocaleString()}
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>
                  </>
                )}

                {/* Scan Tab */}
                {panelTab === "scan" && scanResult && (
                  <>
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Scan Summary</h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Scanner</p>
                            <p className="text-gray-900 dark:text-white">{scanResult.scanner_name}</p>
                          </div>
                          {scanResult.scanner_version && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 mb-1">Version</p>
                              <p className="text-gray-900 dark:text-white">{scanResult.scanner_version}</p>
                            </div>
                          )}
                        </div>
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Scanned</p>
                          <p className="text-sm text-gray-900 dark:text-white">
                            {new Date(scanResult.scanned_at).toLocaleString()}
                          </p>
                        </div>
                        {scanResult.scan_duration_ms && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Duration</p>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {(scanResult.scan_duration_ms / 1000).toFixed(2)}s
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Vulnerability Distribution</h3>
                      </Card.Header>
                      <Card.Body className="space-y-4">
                        {/* Severity Bars */}
                        <div className="space-y-3">
                          {scanResult.critical > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Critical</span>
                                <span className="text-sm font-semibold text-red-600 dark:text-red-400">
                                  {scanResult.critical}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-red-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.critical / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.high > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">High</span>
                                <span className="text-sm font-semibold text-orange-600 dark:text-orange-400">
                                  {scanResult.high}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-orange-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.high / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.medium > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Medium</span>
                                <span className="text-sm font-semibold text-yellow-600 dark:text-yellow-400">
                                  {scanResult.medium}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-yellow-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.medium / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.low > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Low</span>
                                <span className="text-sm font-semibold text-blue-600 dark:text-blue-400">
                                  {scanResult.low}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-blue-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.low / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Summary Stats */}
                        <div className="grid grid-cols-2 gap-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Total</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-white">
                              {scanResult.total}
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Fixable</p>
                            <p className="text-lg font-semibold text-green-600 dark:text-green-400">
                              {scanResult.fixable}
                            </p>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>

                    {scanResult.total === 0 && (
                      <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                        <div className="flex items-center gap-3">
                          <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0" />
                          <div>
                            <p className="text-sm font-medium text-green-900 dark:text-green-100">
                              No Vulnerabilities Found
                            </p>
                            <p className="text-xs text-green-700 dark:text-green-300 mt-0.5">
                              This image has passed security scanning with zero vulnerabilities.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}

                {panelTab === "scan" && !scanResult && (
                  <EmptyState
                    icon={Shield}
                    title="No Scan Results"
                    description="This deployment hasn't been scanned yet."
                    size="sm"
                  />
                )}

                {/* Vulnerabilities Tab */}
                {panelTab === "vulnerabilities" && (
                  <>
                    <FilterPanel
                      filters={vulnerabilityFilters}
                      onReset={() => setVulnerabilitySeverityFilter([])}
                    />

                    {vulnerabilities && vulnerabilities.length > 0 ? (
                      <div className="space-y-3">
                        {vulnerabilities.map((vuln) => (
                          <Card key={vuln.id}>
                            <Card.Body>
                              <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                                    {vuln.cve_id}
                                  </span>
                                  <SeverityBadge
                                    severity={vuln.severity.toLowerCase() as "critical" | "high" | "medium" | "low"}
                                    size="sm"
                                  />
                                  {vuln.cvss_score && (
                                    <span className="text-xs text-gray-600 dark:text-gray-400">
                                      CVSS: {vuln.cvss_score.toFixed(1)}
                                    </span>
                                  )}
                                </div>
                                {vuln.fix_available && (
                                  <Badge variant="status" status="healthy" size="sm">
                                    Fix Available
                                  </Badge>
                                )}
                              </div>

                              {vuln.title && (
                                <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                                  {vuln.title}
                                </p>
                              )}

                              <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                                <span className="font-semibold">{vuln.package_name}</span>
                                {vuln.package_version && <span> @ {vuln.package_version}</span>}
                                {vuln.fixed_version && (
                                  <span className="text-green-600 dark:text-green-400">
                                    {" "}→ {vuln.fixed_version}
                                  </span>
                                )}
                              </div>

                              {vuln.description && (
                                <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
                                  {vuln.description}
                                </p>
                              )}
                            </Card.Body>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <EmptyState
                        icon={CheckCircle}
                        title="No Vulnerabilities"
                        description={
                          vulnerabilitySeverityFilter.length > 0
                            ? "No vulnerabilities found for this filter."
                            : "No vulnerabilities found in this deployment."
                        }
                        size="sm"
                      />
                    )}
                  </>
                )}

                {/* SBOM Tab */}
                {panelTab === "sbom" && selectedDeployment.sbom_id && sboms && sboms.length > 0 && (
                  <>
                    {sboms
                      .filter((s) => s.id === selectedDeployment.sbom_id)
                      .map((sbom) => (
                        <div key={sbom.id} className="space-y-4">
                          <Card>
                            <Card.Header>
                              <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                <FileCode className="w-4 h-4" />
                                SBOM Info
                              </h3>
                            </Card.Header>
                            <Card.Body className="space-y-3">
                              <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                  <p className="text-gray-500 dark:text-gray-400 mb-1">Format</p>
                                  <p className="text-gray-900 dark:text-white">{sbom.format.toUpperCase()}</p>
                                </div>
                                <div>
                                  <p className="text-gray-500 dark:text-gray-400 mb-1">Spec Version</p>
                                  <p className="text-gray-900 dark:text-white">{sbom.spec_version}</p>
                                </div>
                              </div>
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Generator</p>
                                <p className="text-sm text-gray-900 dark:text-white">
                                  {sbom.generator_name}
                                  {sbom.generator_version && ` ${sbom.generator_version}`}
                                </p>
                              </div>
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Generated</p>
                                <p className="text-sm text-gray-900 dark:text-white">
                                  {new Date(sbom.created_at).toLocaleString()}
                                </p>
                              </div>
                            </Card.Body>
                          </Card>

                          <Card>
                            <Card.Header>
                              <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                <Package className="w-4 h-4" />
                                Package Summary
                              </h3>
                            </Card.Header>
                            <Card.Body className="space-y-3">
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">Total Packages</span>
                                <span className="text-lg font-semibold text-gray-900 dark:text-white">
                                  {sbom.total_packages}
                                </span>
                              </div>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">OS Packages</span>
                                <span className="text-sm text-gray-900 dark:text-white">{sbom.os_packages}</span>
                              </div>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">Library Packages</span>
                                <span className="text-sm text-gray-900 dark:text-white">
                                  {sbom.library_packages}
                                </span>
                              </div>
                            </Card.Body>
                          </Card>

                          <button
                            onClick={() => api.downloadSBOM(sbom.id)}
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
                          >
                            <Download className="w-4 h-4" />
                            Download SBOM
                          </button>
                        </div>
                      ))}
                  </>
                )}

                {panelTab === "sbom" && !selectedDeployment.sbom_id && (
                  <EmptyState
                    icon={FileCode}
                    title="No SBOM"
                    description="No SBOM has been generated for this deployment."
                    size="sm"
                  />
                )}
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Redeploy Wizard */}
      <RedeployWizard
        isOpen={redeployWizardOpen}
        deployment={redeployTarget}
        onClose={() => {
          setRedeployWizardOpen(false);
          setRedeployTarget(null);
        }}
        onConfirm={(pullLatest, skipScanning) => {
          if (!redeployTarget) return;
          setRedeployingId(redeployTarget.id);
          redeployMutation.mutate({ deploymentId: redeployTarget.id, pullLatest, skipScanning });
        }}
        isLoading={redeployMutation.isPending}
      />

      {/* Confirmation Dialog (Delete only) */}
      <ConfirmDialog
        isOpen={!!confirmAction && confirmAction.type === "delete"}
        onClose={() => setConfirmAction(null)}
        onConfirm={() => {
          if (!confirmAction || confirmAction.type !== "delete") return;
          setDeletingId(confirmAction.deployment.id);
          deleteMutation.mutate(confirmAction.deployment.id);
          setConfirmAction(null);
        }}
        title={confirmAction?.type === "delete" ? `Delete ${confirmAction?.deployment.service_name}?` : ""}
        message="This will permanently remove the deployment record. The container will not be affected."
        confirmText="Delete"
        variant="danger"
        icon="delete"
      />

      {/* Bulk Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showBulkDeleteModal}
        onClose={() => {
          if (!bulkDeleteMutation.isPending) {
            setShowBulkDeleteModal(false);
            setBulkDeleteProgress(null);
          }
        }}
        onConfirm={() => {
          const deletableIds = [...selectedIds].filter(id => {
            const d = filteredDeployments?.find(dep => dep.id === id);
            return d && d.status !== "running";
          });
          setBulkDeleteProgress({ total: deletableIds.length, completed: 0, failed: [] });
          bulkDeleteMutation.mutate(deletableIds);
        }}
        title={`Delete ${selectedIds.size} deployment${selectedIds.size > 1 ? "s" : ""}?`}
        message={
          bulkDeleteProgress
            ? `Deleting... ${bulkDeleteProgress.completed}/${bulkDeleteProgress.total} completed${bulkDeleteProgress.failed.length > 0 ? ` (${bulkDeleteProgress.failed.length} failed)` : ""}`
            : "This will permanently remove the selected deployment records. Running containers will not be affected."
        }
        confirmText={bulkDeleteProgress ? "Deleting..." : "Delete All"}
        variant="danger"
        icon="delete"
        isLoading={bulkDeleteMutation.isPending}
      />
    </>
  );
}
