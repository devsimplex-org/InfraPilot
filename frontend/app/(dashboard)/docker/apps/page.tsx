"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Rocket,
  Trash2,
  RefreshCw,
  Box,
  Layers,
  CheckCircle,
  XCircle,
  Clock,
  Search,
  MoreHorizontal,
  Tag,
  GitBranch,
  AlertTriangle,
} from "lucide-react";
import { api, ServiceConfig, ManagedStack } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { cn } from "@/lib/utils";

// ─── Types ───────────────────────────────────────────────────────────────────

type AppKind = "service" | "stack";

interface AppRow {
  id: string;
  kind: AppKind;
  name: string;
  environment: string;
  image?: string;       // services only
  serviceCount?: number; // stacks only
  runningCount?: number; // stacks only
  status: string;
  deployedAt?: string;
  containerName?: string;
  raw: ServiceConfig | ManagedStack;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusBadge(status?: string) {
  const colorMap: Record<string, string> = {
    running:   "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    partial:   "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    failed:    "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    deploying: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    pending:   "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    stopped:   "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  };
  const cls = colorMap[status ?? ""] ?? "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status ?? "unknown"}
    </span>
  );
}

function envBadge(env: string) {
  const cls =
    env === "prod"    ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" :
    env === "staging" ? "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" :
                        "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{env}</span>;
}

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

function toAppRow(item: ServiceConfig | ManagedStack): AppRow {
  if ("service_name" in item) {
    // ServiceConfig
    const svc = item as ServiceConfig;
    const displayTag = svc.current_tag ?? svc.image_tag;
    return {
      id: svc.id,
      kind: "service",
      name: svc.service_name,
      environment: svc.environment,
      image: `${svc.image_repository}:${displayTag}`,
      status: svc.status ?? "unknown",
      deployedAt: svc.deployed_at,
      containerName: svc.container_name,
      raw: svc,
    };
  } else {
    // ManagedStack
    const stk = item as ManagedStack;
    return {
      id: stk.id,
      kind: "stack",
      name: stk.name,
      environment: stk.environment,
      serviceCount: stk.service_count,
      runningCount: stk.running_count,
      status: stk.status,
      deployedAt: stk.deployed_at,
      raw: stk,
    };
  }
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AppsPage() {
  const queryClient = useQueryClient();
  const { selectedAgent } = useDocker();

  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState<"all" | "dev" | "staging" | "prod">("all");
  const [kindFilter, setKindFilter] = useState<"all" | "service" | "stack">("all");
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  // Redeploy (services only)
  const [redeployTarget, setRedeployTarget] = useState<AppRow | null>(null);
  const [redeployTag, setRedeployTag] = useState("");

  // Delete confirm
  const [deleteTarget, setDeleteTarget] = useState<AppRow | null>(null);

  // ─── Queries ───────────────────────────────────────────────────────────────

  const { data: services, isLoading: loadingServices } = useQuery({
    queryKey: ["services"],
    queryFn: () => api.listServices(),
    refetchInterval: 15000,
  });

  const { data: managedStacks, isLoading: loadingStacks } = useQuery({
    queryKey: ["managed-stacks", selectedAgent],
    queryFn: () => selectedAgent ? api.listManagedStacks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 15000,
  });

  // ─── Mutations ────────────────────────────────────────────────────────────

  const redeployMutation = useMutation({
    mutationFn: (row: AppRow) => {
      const svc = row.raw as ServiceConfig;
      return api.deployService(svc.service_name, svc.environment, redeployTag ? { image_tag: redeployTag } : {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["deployments"] });
      setRedeployTarget(null);
      setRedeployTag("");
    },
  });

  const deleteServiceMutation = useMutation({
    mutationFn: (row: AppRow) => {
      const svc = row.raw as ServiceConfig;
      return api.deleteService(svc.service_name, svc.environment);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      setDeleteTarget(null);
    },
  });

  const deleteStackMutation = useMutation({
    mutationFn: (row: AppRow) => {
      if (!selectedAgent) throw new Error("No agent selected");
      return api.deleteStack(selectedAgent, row.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["managed-stacks"] });
      setDeleteTarget(null);
    },
  });

  // ─── Derived data ─────────────────────────────────────────────────────────

  const rows: AppRow[] = useMemo(() => {
    const svcRows = (services ?? []).map(toAppRow);
    const stkRows = (managedStacks ?? []).map(toAppRow);
    // Deduplicate stacks by name+env (keep latest)
    const stackSeen = new Set<string>();
    const dedupedStacks = stkRows.filter((r) => {
      const k = `${r.name}:${r.environment}`;
      if (stackSeen.has(k)) return false;
      stackSeen.add(k);
      return true;
    });
    return [...svcRows, ...dedupedStacks];
  }, [services, managedStacks]);

  const filtered = useMemo(() => {
    return rows.filter((r) => {
      if (kindFilter !== "all" && r.kind !== kindFilter) return false;
      if (envFilter !== "all" && r.environment !== envFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!r.name.toLowerCase().includes(q) && !(r.image ?? "").toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [rows, kindFilter, envFilter, search]);

  const metrics = useMemo(() => ({
    total: rows.length,
    running: rows.filter((r) => r.status === "running").length,
    failed: rows.filter((r) => r.status === "failed").length,
    deploying: rows.filter((r) => r.status === "deploying" || r.status === "pending").length,
  }), [rows]);

  // ─── Render ───────────────────────────────────────────────────────────────

  if (loadingServices && loadingStacks) return <Spinner.LogoPage label="Loading apps..." />;

  return (
    <div className="space-y-6">
      {/* Stats */}
      <MetricsGrid>
        <StatCard title="Total Apps" value={metrics.total} icon={Box} />
        <StatCard title="Running" value={metrics.running} icon={CheckCircle} variant="success" />
        <StatCard title="Failed" value={metrics.failed} icon={XCircle} variant="danger" />
        <StatCard title="Deploying" value={metrics.deploying} icon={Clock} variant="warning" />
      </MetricsGrid>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search apps..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-sm bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
        </div>

        {/* Kind filter */}
        <div className="flex gap-1 rounded-lg border border-gray-200 dark:border-gray-700 p-0.5 bg-gray-50 dark:bg-gray-800/50">
          {(["all", "service", "stack"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setKindFilter(k)}
              className={cn(
                "px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize",
                kindFilter === k
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                  : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              )}
            >
              {k === "all" ? "All" : k === "service" ? "Services" : "Stacks"}
            </button>
          ))}
        </div>

        {/* Env filter */}
        <div className="flex gap-1 rounded-lg border border-gray-200 dark:border-gray-700 p-0.5 bg-gray-50 dark:bg-gray-800/50">
          {(["all", "dev", "staging", "prod"] as const).map((env) => (
            <button
              key={env}
              onClick={() => setEnvFilter(env)}
              className={cn(
                "px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                envFilter === env
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                  : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              )}
            >
              {env === "all" ? "All Envs" : env}
            </button>
          ))}
        </div>

        <button
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["services"] });
            queryClient.invalidateQueries({ queryKey: ["managed-stacks"] });
          }}
          className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={Box}
          title="No apps found"
          description='Deploy your first app using the "Deploy App" button above, or via the CLI: infrapilot deploy <name>'
        />
      ) : (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">App</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Type</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Env</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Image / Services</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 uppercase text-xs tracking-wider">Deployed</th>
                <th className="px-4 py-3 w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {filtered.map((row) => {
                const menuKey = row.id;
                return (
                  <tr key={row.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                    {/* Name */}
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-900 dark:text-white">{row.name}</div>
                      {row.kind === "service" && (row.raw as ServiceConfig).git_repo && (
                        <div className="flex items-center gap-1 mt-0.5 text-xs text-gray-400">
                          <GitBranch className="h-3 w-3" />
                          {(row.raw as ServiceConfig).git_repo}
                        </div>
                      )}
                    </td>

                    {/* Kind badge */}
                    <td className="px-4 py-3">
                      {row.kind === "service" ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                          <Box className="h-3 w-3" />
                          Service
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
                          <Layers className="h-3 w-3" />
                          Stack
                        </span>
                      )}
                    </td>

                    {/* Env */}
                    <td className="px-4 py-3">{envBadge(row.environment)}</td>

                    {/* Image / service count */}
                    <td className="px-4 py-3">
                      {row.kind === "service" ? (
                        <div className="font-mono text-xs text-gray-700 dark:text-gray-300 flex items-center gap-1">
                          <Tag className="h-3 w-3 text-gray-400 shrink-0" />
                          <span className="truncate max-w-[220px]" title={row.image}>{row.image}</span>
                        </div>
                      ) : (
                        <div className="text-xs text-gray-600 dark:text-gray-400 flex items-center gap-1">
                          <Layers className="h-3 w-3 text-gray-400 shrink-0" />
                          {row.runningCount}/{row.serviceCount} services running
                        </div>
                      )}
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">{statusBadge(row.status)}</td>

                    {/* Deployed at */}
                    <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">
                      {relativeTime(row.deployedAt)}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="relative">
                        <button
                          onClick={() => setOpenMenu(openMenu === menuKey ? null : menuKey)}
                          className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </button>
                        {openMenu === menuKey && (
                          <>
                            <div className="fixed inset-0 z-10" onClick={() => setOpenMenu(null)} />
                            <div className="absolute right-0 top-full mt-1 w-40 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 shadow-lg z-20 py-1">
                              {row.kind === "service" && (
                                <button
                                  onClick={() => {
                                    const svc = row.raw as ServiceConfig;
                                    setRedeployTarget(row);
                                    setRedeployTag(svc.current_tag ?? svc.image_tag ?? "");
                                    setOpenMenu(null);
                                  }}
                                  className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                                >
                                  <Rocket className="h-4 w-4 text-primary-500" />
                                  Redeploy
                                </button>
                              )}
                              <button
                                onClick={() => { setDeleteTarget(row); setOpenMenu(null); }}
                                className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                              >
                                <Trash2 className="h-4 w-4" />
                                Delete
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

      {/* ─── Redeploy Modal ─────────────────────────────────────────────────── */}
      {redeployTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => { setRedeployTarget(null); setRedeployTag(""); }}
          />
          <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Rocket className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Redeploy Service</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {redeployTarget.name} · {redeployTarget.environment}
                </p>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Image Tag
                </label>
                <input
                  type="text"
                  value={redeployTag}
                  onChange={(e) => setRedeployTag(e.target.value)}
                  placeholder={(redeployTarget.raw as ServiceConfig).image_tag || "latest"}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm font-mono text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                <p className="text-xs text-gray-400 mt-1">Leave blank to use the currently configured tag</p>
              </div>
              {redeployMutation.isError && (
                <div className="flex items-start gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <AlertTriangle className="h-4 w-4 text-red-600 shrink-0 mt-0.5" />
                  <p className="text-sm text-red-600 dark:text-red-400">
                    {(redeployMutation.error as Error)?.message ?? "Deploy failed"}
                  </p>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => { setRedeployTarget(null); setRedeployTag(""); redeployMutation.reset(); }}
                className="px-4 py-2 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium"
              >
                Cancel
              </button>
              <button
                onClick={() => redeployMutation.mutate(redeployTarget)}
                disabled={redeployMutation.isPending}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium disabled:opacity-50"
              >
                {redeployMutation.isPending ? (
                  <><RefreshCw className="h-4 w-4 animate-spin" />Deploying...</>
                ) : (
                  <><Rocket className="h-4 w-4" />Deploy</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Delete Confirm Modal ───────────────────────────────────────────── */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setDeleteTarget(null)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-sm mx-4 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
                <Trash2 className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Delete {deleteTarget.kind === "stack" ? "Stack" : "Service"}
              </h3>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
              Remove{" "}
              <strong className="text-gray-900 dark:text-white">{deleteTarget.name}</strong>{" "}
              ({deleteTarget.environment})?
            </p>
            <p className="text-xs text-gray-400 mb-5">
              {deleteTarget.kind === "service"
                ? "This removes the service definition. Running containers are not stopped."
                : "This removes the stack record. Running containers may remain."}
            </p>
            {(deleteServiceMutation.isError || deleteStackMutation.isError) && (
              <p className="text-sm text-red-600 dark:text-red-400 mb-3">
                {((deleteServiceMutation.error ?? deleteStackMutation.error) as Error)?.message ?? "Delete failed"}
              </p>
            )}
            <div className="flex justify-end gap-3">
              <button
                onClick={() => { setDeleteTarget(null); deleteServiceMutation.reset(); deleteStackMutation.reset(); }}
                className="px-4 py-2 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (deleteTarget.kind === "service") deleteServiceMutation.mutate(deleteTarget);
                  else deleteStackMutation.mutate(deleteTarget);
                }}
                disabled={deleteServiceMutation.isPending || deleteStackMutation.isPending}
                className="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium disabled:opacity-50"
              >
                {(deleteServiceMutation.isPending || deleteStackMutation.isPending) ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
