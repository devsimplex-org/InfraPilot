"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Rocket, Trash2, RefreshCw, Box, Layers, CheckCircle, XCircle, Clock,
  Search, MoreHorizontal, Tag, GitBranch, AlertTriangle, ChevronDown,
  ChevronRight, Eye, Shield, FileCode, StopCircle, User,
} from "lucide-react";
import { api, ServiceConfig, ManagedStack, Stack, Container } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/page-layout";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/utils";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function relativeTime(ts?: string | null): string {
  if (!ts) return "—";
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function svcStatusBadge(status?: string) {
  const colorMap: Record<string, string> = {
    running:   "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    failed:    "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    deploying: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    pending:   "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    stopped:   "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  };
  const cls = colorMap[status ?? ""] ?? "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400";
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{status ?? "unknown"}</span>;
}

function envBadge(env: string) {
  const cls =
    env === "prod"    ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" :
    env === "staging" ? "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" :
                        "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{env}</span>;
}

// ─── Unified stack type (discovered + managed) ────────────────────────────────

interface UnifiedStack {
  name: string;
  container_count: number;
  running_count: number;
  status: "running" | "partial" | "stopped";
  containers: Container[];
  isManaged: boolean;
  managedData?: ManagedStack;
}

const stackStatusConfig = {
  running: { color: "green" as const, icon: CheckCircle, label: "Running" },
  partial: { color: "yellow" as const, icon: AlertTriangle, label: "Partial" },
  stopped: { color: "gray" as const, icon: StopCircle, label: "Stopped" },
};

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AppsPage() {
  const queryClient = useQueryClient();
  const { selectedAgent, openContainerPanel } = useDocker();

  // Filters
  const [search, setSearch] = useState("");
  const [stackStatusFilter, setStackStatusFilter] = useState<"all" | "running" | "partial" | "stopped">("all");

  // Services state
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [redeployTarget, setRedeployTarget] = useState<ServiceConfig | null>(null);
  const [redeployTag, setRedeployTag] = useState("");
  const [deleteSvcTarget, setDeleteSvcTarget] = useState<ServiceConfig | null>(null);

  // Stacks state
  const [expandedStacks, setExpandedStacks] = useState<Set<string>>(new Set());
  const [deleteStackTarget, setDeleteStackTarget] = useState<UnifiedStack | null>(null);

  // ─── Queries ───────────────────────────────────────────────────────────────

  const { data: services, isLoading: loadingServices } = useQuery({
    queryKey: ["services"],
    queryFn: () => api.listServices(),
    refetchInterval: 15000,
  });

  const { data: discoveredStacks, isLoading: loadingDiscovered } = useQuery({
    queryKey: ["stacks", selectedAgent],
    queryFn: () => selectedAgent ? api.getStacks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 5000,
  });

  const { data: managedStacks, isLoading: loadingManaged } = useQuery({
    queryKey: ["managed-stacks", selectedAgent],
    queryFn: () => selectedAgent ? api.listManagedStacks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 5000,
  });

  // ─── Mutations ─────────────────────────────────────────────────────────────

  const redeployMutation = useMutation({
    mutationFn: (svc: ServiceConfig) =>
      api.deployService(svc.service_name, svc.environment, redeployTag ? { image_tag: redeployTag } : {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["deployments"] });
      setRedeployTarget(null);
      setRedeployTag("");
    },
  });

  const deleteServiceMutation = useMutation({
    mutationFn: (svc: ServiceConfig) => api.deleteService(svc.service_name, svc.environment),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      setDeleteSvcTarget(null);
    },
  });

  const deleteStackMutation = useMutation({
    mutationFn: (stackId: string) => api.deleteStack(selectedAgent!, stackId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["managed-stacks", selectedAgent] });
      queryClient.invalidateQueries({ queryKey: ["stacks", selectedAgent] });
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setDeleteStackTarget(null);
    },
  });

  // ─── Unified stacks ────────────────────────────────────────────────────────

  const unifiedStacks = useMemo((): UnifiedStack[] => {
    if (!discoveredStacks) return [];
    const managedMap = new Map<string, ManagedStack>();
    managedStacks?.forEach((ms) => managedMap.set(ms.name, ms));
    return discoveredStacks.map((ds): UnifiedStack => {
      const managed = managedMap.get(ds.name);
      return {
        name: ds.name,
        container_count: ds.container_count,
        running_count: ds.running_count,
        status: ds.status,
        containers: ds.containers,
        isManaged: !!managed,
        managedData: managed,
      };
    });
  }, [discoveredStacks, managedStacks]);

  // ─── Filtered data ─────────────────────────────────────────────────────────

  const filteredServices = useMemo(() => {
    if (!services) return [];
    return services.filter((s) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return s.service_name.toLowerCase().includes(q) || s.image_repository.toLowerCase().includes(q);
    });
  }, [services, search]);

  const filteredStacks = useMemo(() => {
    return unifiedStacks.filter((s) => {
      if (stackStatusFilter !== "all" && s.status !== stackStatusFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return s.name.toLowerCase().includes(q) || s.managedData?.environment?.toLowerCase().includes(q);
    });
  }, [unifiedStacks, stackStatusFilter, search]);

  // ─── Metrics ───────────────────────────────────────────────────────────────

  const metrics = useMemo(() => {
    const svcRunning = (services ?? []).filter((s) => s.status === "running").length;
    const stkRunning = unifiedStacks.filter((s) => s.status === "running").length;
    const svcFailed = (services ?? []).filter((s) => s.status === "failed").length;
    const stkPartial = unifiedStacks.filter((s) => s.status === "partial").length;
    return {
      services: services?.length ?? 0,
      stacks: unifiedStacks.length,
      running: svcRunning + stkRunning,
      issues: svcFailed + stkPartial,
    };
  }, [services, unifiedStacks]);

  const toggleExpanded = (name: string) => {
    setExpandedStacks((prev) => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const isLoading = loadingServices || loadingDiscovered || loadingManaged;
  if (isLoading && !services && !discoveredStacks) return <Spinner.LogoPage label="Loading apps..." />;

  return (
    <div className="space-y-6">

      {/* ─── Stats ─────────────────────────────────────────────────────────── */}
      <MetricsGrid>
        <StatCard title="Services" value={metrics.services} icon={Box} description="single-container" />
        <StatCard title="Stacks" value={metrics.stacks} icon={Layers} description={`${unifiedStacks.filter(s => s.isManaged).length} managed`} />
        <StatCard title="Running" value={metrics.running} icon={CheckCircle} variant="success" />
        <StatCard title="Issues" value={metrics.issues} icon={XCircle} variant="danger" />
      </MetricsGrid>

      {/* ─── Search ────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search apps..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-sm bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
        </div>
        <button
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["services"] });
            queryClient.invalidateQueries({ queryKey: ["stacks", selectedAgent] });
            queryClient.invalidateQueries({ queryKey: ["managed-stacks", selectedAgent] });
          }}
          className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 1 — SERVICES (single-container)
      ══════════════════════════════════════════════════════════════════════ */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Box className="h-4 w-4 text-blue-500" />
          <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
            Services
          </h2>
          <span className="text-xs text-gray-400 dark:text-gray-500 font-medium bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">
            {filteredServices.length}
          </span>
        </div>

        {filteredServices.length === 0 ? (
          <EmptyState
            icon={Box}
            title="No services"
            description='Deploy a service with: infrapilot deploy <name> --image <image>'
          />
        ) : (
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Service</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Env</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Image</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Status</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Deployed</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Container</th>
                  <th className="px-4 py-3 w-10" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                {filteredServices.map((svc) => {
                  const key = `${svc.service_name}:${svc.environment}`;
                  const displayTag = svc.current_tag ?? svc.image_tag;
                  return (
                    <tr key={svc.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-medium text-gray-900 dark:text-white">{svc.service_name}</div>
                        {svc.git_repo && (
                          <div className="flex items-center gap-1 mt-0.5 text-xs text-gray-400">
                            <GitBranch className="h-3 w-3" />{svc.git_repo}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">{envBadge(svc.environment)}</td>
                      <td className="px-4 py-3">
                        <div className="font-mono text-xs text-gray-700 dark:text-gray-300 flex items-center gap-1">
                          <Tag className="h-3 w-3 text-gray-400 shrink-0" />
                          <span className="truncate max-w-[200px]" title={`${svc.image_repository}:${displayTag}`}>
                            {svc.image_repository}:{displayTag}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">{svcStatusBadge(svc.status)}</td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">{relativeTime(svc.deployed_at)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500 dark:text-gray-400">{svc.container_name ?? "—"}</td>
                      <td className="px-4 py-3">
                        <div className="relative">
                          <button
                            onClick={() => setOpenMenu(openMenu === key ? null : key)}
                            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                          >
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                          {openMenu === key && (
                            <>
                              <div className="fixed inset-0 z-10" onClick={() => setOpenMenu(null)} />
                              <div className="absolute right-0 top-full mt-1 w-40 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 shadow-lg z-20 py-1">
                                <button
                                  onClick={() => { setRedeployTarget(svc); setRedeployTag(svc.current_tag ?? svc.image_tag ?? ""); setOpenMenu(null); }}
                                  className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                                >
                                  <Rocket className="h-4 w-4 text-primary-500" />Redeploy
                                </button>
                                <button
                                  onClick={() => { setDeleteSvcTarget(svc); setOpenMenu(null); }}
                                  className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
                                >
                                  <Trash2 className="h-4 w-4" />Delete
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 2 — STACKS (compose)
      ══════════════════════════════════════════════════════════════════════ */}
      <div>
        <div className="flex items-center gap-3 mb-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-purple-500" />
            <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
              Stacks
            </h2>
            <span className="text-xs text-gray-400 dark:text-gray-500 font-medium bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">
              {filteredStacks.length}
            </span>
          </div>
          {/* Stack status filter */}
          <div className="flex gap-1 rounded-lg border border-gray-200 dark:border-gray-700 p-0.5 bg-gray-50 dark:bg-gray-800/50 ml-auto">
            {(["all", "running", "partial", "stopped"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStackStatusFilter(s)}
                className={cn(
                  "px-3 py-1 text-xs font-medium rounded-md transition-colors capitalize",
                  stackStatusFilter === s
                    ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                    : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                )}
              >
                {s === "all" ? "All" : s}
              </button>
            ))}
          </div>
        </div>

        {filteredStacks.length === 0 ? (
          <EmptyState
            icon={Layers}
            title="No stacks found"
            description={
              unifiedStacks.length === 0
                ? "Deploy your first stack using the Deploy App button above"
                : "No stacks match your current filters"
            }
          />
        ) : (
          <div className="space-y-3">
            {filteredStacks.map((stack) => (
              <StackCard
                key={stack.name}
                stack={stack}
                isExpanded={expandedStacks.has(stack.name)}
                onToggleExpand={() => toggleExpanded(stack.name)}
                onOpenContainer={openContainerPanel}
                onDelete={() => setDeleteStackTarget(stack)}
              />
            ))}
          </div>
        )}
      </div>

      {/* ─── Redeploy Modal ────────────────────────────────────────────────── */}
      {redeployTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setRedeployTarget(null); setRedeployTag(""); }} />
          <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Rocket className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Redeploy Service</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">{redeployTarget.service_name} · {redeployTarget.environment}</p>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Image Tag</label>
              <input
                type="text"
                value={redeployTag}
                onChange={(e) => setRedeployTag(e.target.value)}
                placeholder={redeployTarget.image_tag || "latest"}
                className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm font-mono text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
              <p className="text-xs text-gray-400 mt-1">Leave blank to use the currently configured tag</p>
            </div>
            {redeployMutation.isError && (
              <div className="flex items-start gap-2 p-3 mt-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <AlertTriangle className="h-4 w-4 text-red-600 shrink-0 mt-0.5" />
                <p className="text-sm text-red-600 dark:text-red-400">{(redeployMutation.error as Error)?.message ?? "Deploy failed"}</p>
              </div>
            )}
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => { setRedeployTarget(null); setRedeployTag(""); redeployMutation.reset(); }} className="px-4 py-2 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium">Cancel</button>
              <button onClick={() => redeployMutation.mutate(redeployTarget)} disabled={redeployMutation.isPending} className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium disabled:opacity-50">
                {redeployMutation.isPending ? <><RefreshCw className="h-4 w-4 animate-spin" />Deploying...</> : <><Rocket className="h-4 w-4" />Deploy</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Delete Service Modal ──────────────────────────────────────────── */}
      <ConfirmDialog
        isOpen={!!deleteSvcTarget}
        onClose={() => setDeleteSvcTarget(null)}
        onConfirm={() => deleteSvcTarget && deleteServiceMutation.mutate(deleteSvcTarget)}
        title={`Delete Service "${deleteSvcTarget?.service_name}"?`}
        message="This removes the service definition. Running containers are not stopped."
        confirmText="Delete"
        variant="danger"
        isLoading={deleteServiceMutation.isPending}
      />

      {/* ─── Delete Stack Confirm ──────────────────────────────────────────── */}
      <ConfirmDialog
        isOpen={!!deleteStackTarget}
        onClose={() => setDeleteStackTarget(null)}
        onConfirm={() => {
          if (deleteStackTarget?.managedData) deleteStackMutation.mutate(deleteStackTarget.managedData.id);
          else setDeleteStackTarget(null);
        }}
        title={`Delete Stack "${deleteStackTarget?.name}"?`}
        message={
          deleteStackTarget?.isManaged
            ? `This will stop and remove all containers in this stack. ${deleteStackTarget?.running_count || 0} running container(s) will be stopped.`
            : "This stack is not managed by InfraPilot. Use docker-compose down on the host to remove it."
        }
        confirmText={deleteStackTarget?.isManaged ? "Delete Stack" : "Close"}
        variant="danger"
        isLoading={deleteStackMutation.isPending}
      />
    </div>
  );
}

// ─── Stack Card ───────────────────────────────────────────────────────────────

function StackCard({
  stack,
  isExpanded,
  onToggleExpand,
  onOpenContainer,
  onDelete,
}: {
  stack: UnifiedStack;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onOpenContainer: (id: string) => void;
  onDelete: () => void;
}) {
  const managed = stack.managedData;
  const cfg = stackStatusConfig[stack.status];
  const StatusIcon = cfg.icon;

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
        onClick={onToggleExpand}
      >
        <div className="flex items-center gap-3">
          <span className="text-gray-400">
            {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </span>
          <div className={cn("p-2 rounded-lg", stack.isManaged ? "bg-purple-100 dark:bg-purple-900/30" : "bg-gray-100 dark:bg-gray-800")}>
            <Layers className={cn("h-4 w-4", stack.isManaged ? "text-purple-600 dark:text-purple-400" : "text-gray-500 dark:text-gray-400")} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-gray-900 dark:text-white">{stack.name}</span>
              {managed?.environment && envBadge(managed.environment)}
              <Badge color={cfg.color}>
                <StatusIcon className="h-3 w-3 mr-1" />
                {cfg.label}
              </Badge>
              {stack.isManaged ? (
                <Badge color="purple">
                  <Shield className="h-3 w-3 mr-1" />Managed
                </Badge>
              ) : (
                <Badge color="gray">External</Badge>
              )}
            </div>
            <div className="flex items-center gap-4 mt-1 text-xs text-gray-500 dark:text-gray-400 flex-wrap">
              <span className="flex items-center gap-1">
                <Box className="h-3 w-3" />
                {stack.running_count}/{stack.container_count} containers
              </span>
              {managed?.deployed_at && (
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {relativeTime(managed.deployed_at)}
                </span>
              )}
              {managed?.deployed_by && (
                <span className="flex items-center gap-1">
                  <User className="h-3 w-3" />{managed.deployed_by}
                </span>
              )}
              {managed?.status_message && (
                <span className="text-xs italic">{managed.status_message}</span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          {stack.isManaged && (
            <Button variant="secondary" size="sm" onClick={onDelete}>
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Managed metadata bar */}
      {isExpanded && stack.isManaged && managed && (
        <div className="px-4 py-2.5 bg-purple-50 dark:bg-purple-900/10 border-t border-purple-100 dark:border-purple-900/30 flex items-center gap-6 text-sm flex-wrap">
          <span className="flex items-center gap-1.5 text-purple-700 dark:text-purple-300 font-medium">
            <Shield className="h-3.5 w-3.5" />Managed Stack
          </span>
          {managed.service_count > 0 && (
            <span className="text-gray-600 dark:text-gray-400">
              {managed.running_count}/{managed.service_count} services tracked
            </span>
          )}
          {managed.variables && Object.keys(managed.variables).length > 0 && (
            <span className="text-gray-600 dark:text-gray-400">
              {Object.keys(managed.variables).length} variables
            </span>
          )}
          {managed.compose_yaml && (
            <span className="flex items-center gap-1 text-gray-600 dark:text-gray-400">
              <FileCode className="h-3.5 w-3.5" />Compose YAML stored
            </span>
          )}
        </div>
      )}

      {/* Container table */}
      {isExpanded && stack.containers.length > 0 && (
        <div className="border-t border-gray-200 dark:border-gray-800 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-800/50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Container</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Image</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Networks</th>
                <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {stack.containers.map((container) => (
                <ContainerRow key={container.container_id} container={container} onOpenContainer={onOpenContainer} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Container Row ────────────────────────────────────────────────────────────

function ContainerRow({ container, onOpenContainer }: { container: Container; onOpenContainer: (id: string) => void }) {
  const color = container.status === "running" ? "green" : container.status === "paused" ? "yellow" : "gray";
  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/30">
      <td className="px-4 py-3 font-medium text-gray-900 dark:text-white">{container.name}</td>
      <td className="px-4 py-3 font-mono text-xs text-gray-600 dark:text-gray-400 max-w-xs truncate">{container.image}</td>
      <td className="px-4 py-3">
        <Badge color={color as "green" | "yellow" | "gray"}>{container.status}</Badge>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {container.networks?.slice(0, 2).map((n) => (
            <span key={n} className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 rounded text-gray-600 dark:text-gray-400">{n}</span>
          ))}
          {container.networks && container.networks.length > 2 && (
            <span className="text-xs text-gray-500">+{container.networks.length - 2}</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3 text-right">
        <Button variant="ghost" size="sm" onClick={() => onOpenContainer(container.container_id)}>
          <Eye className="h-4 w-4" />
        </Button>
      </td>
    </tr>
  );
}
