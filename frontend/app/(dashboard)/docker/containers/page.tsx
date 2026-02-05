"use client";

import { useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  CheckSquare,
  MinusSquare,
  Square,
  Lock,
  Trash2,
  Play,
  RotateCcw,
  Cpu,
  MemoryStick,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Terminal as TerminalIcon,
} from "lucide-react";
import { api, Container } from "@/lib/api";
import { useDocker, getStatusLevel } from "@/lib/docker-context";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Terminal } from "@/components/containers/Terminal";
import { cn } from "@/lib/utils";

type StatusFilter = "all" | "running" | "exited";

export default function DockerContainersPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { selectedAgent, forceDelete, setForceDelete } = useDocker();

  // Local state
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedContainerIds, setSelectedContainerIds] = useState<Set<string>>(new Set());
  const [showBulkModal, setShowBulkModal] = useState<"stop" | "delete" | null>(null);
  const [bulkProgress, setBulkProgress] = useState<{ total: number; completed: number; failed: string[] } | null>(null);

  // SlideOver state
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [containerPanelTab, setContainerPanelTab] = useState<"details" | "logs" | "terminal">("details");
  const [logsTail, setLogsTail] = useState(100);
  const [copied, setCopied] = useState<string | null>(null);
  const [showStopModal, setShowStopModal] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [showDeleteContainerModal, setShowDeleteContainerModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Fetch containers
  const { data: containers, isLoading } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () => selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 10000,
  });

  // Fetch container logs
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["containerLogs", selectedAgent, selectedContainer?.container_id, logsTail],
    queryFn: () =>
      selectedAgent && selectedContainer
        ? api.getContainerLogs(selectedAgent, selectedContainer.container_id, logsTail)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!selectedContainer && containerPanelTab === "logs",
  });

  // Single container mutations
  const startMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.startContainer(selectedAgent!, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    },
  });

  const stopMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.stopContainer(selectedAgent!, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowStopModal(false);
    },
  });

  const restartMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.restartContainer(selectedAgent!, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowRestartModal(false);
    },
  });

  const deleteContainerMutation = useMutation({
    mutationFn: () =>
      api.deleteContainer(selectedAgent!, selectedContainer!.container_id, selectedContainer!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowDeleteContainerModal(false);
      setSelectedContainer(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Filtered containers
  const filteredContainers = useMemo(() => {
    if (!containers) return [];
    return containers.filter((c) => {
      const matchesStatus = statusFilter === "all" || c.status === statusFilter;
      const matchesSearch = !searchFilter ||
        c.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
        c.image.toLowerCase().includes(searchFilter.toLowerCase());
      return matchesStatus && matchesSearch;
    });
  }, [containers, statusFilter, searchFilter]);

  // Management container check
  const isManagementContainer = (container: Container) => {
    const protectedNames = ["infrapilot", "infrapilot-ee", "infrapilot_ee"];
    return protectedNames.includes(container.name) || container.image.includes("infrapilot");
  };

  const selectableContainers = filteredContainers.filter((c) => !isManagementContainer(c));

  // Selection helpers
  const toggleSelection = (id: string) => {
    setSelectedContainerIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) newSet.delete(id);
      else newSet.add(id);
      return newSet;
    });
  };

  const selectAll = () => setSelectedContainerIds(new Set(selectableContainers.map((c) => c.container_id)));
  const selectNone = () => setSelectedContainerIds(new Set());
  const selectRunning = () => setSelectedContainerIds(new Set(selectableContainers.filter((c) => c.status === "running").map((c) => c.container_id)));
  const selectStopped = () => setSelectedContainerIds(new Set(selectableContainers.filter((c) => c.status === "exited").map((c) => c.container_id)));

  const isAllSelected = selectableContainers.length > 0 && selectedContainerIds.size === selectableContainers.length;
  const isSomeSelected = selectedContainerIds.size > 0 && !isAllSelected;
  const selectedData = filteredContainers.filter((c) => selectedContainerIds.has(c.container_id));
  const runningSelectedCount = selectedData.filter((c) => c.status === "running").length;

  // Metrics
  const metrics = {
    total: containers?.length || 0,
    running: containers?.filter((c) => c.status === "running").length || 0,
    stopped: containers?.filter((c) => c.status === "exited").length || 0,
    cpuUsage: containers?.reduce((sum, c) => sum + (c.cpu_percent || 0), 0) || 0,
    memoryUsage: containers?.reduce((sum, c) => sum + (c.memory_mb || 0), 0) || 0,
  };

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Bulk operations
  const handleBulkStop = async () => {
    const toStop = selectedData.filter((c) => c.status === "running");
    if (toStop.length === 0) return;
    setBulkProgress({ total: toStop.length, completed: 0, failed: [] });
    const failed: string[] = [];
    for (let i = 0; i < toStop.length; i++) {
      try {
        await api.stopContainer(selectedAgent!, toStop[i].container_id);
      } catch {
        failed.push(toStop[i].name);
      }
      setBulkProgress({ total: toStop.length, completed: i + 1, failed });
    }
    queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    if (failed.length === 0) {
      setShowBulkModal(null);
      selectNone();
      setBulkProgress(null);
    }
  };

  const handleBulkDelete = async () => {
    setBulkProgress({ total: selectedData.length, completed: 0, failed: [] });
    const failed: string[] = [];
    for (let i = 0; i < selectedData.length; i++) {
      try {
        await api.deleteContainer(selectedAgent!, selectedData[i].container_id, selectedData[i].name, forceDelete);
      } catch {
        failed.push(selectedData[i].name);
      }
      setBulkProgress({ total: selectedData.length, completed: i + 1, failed });
    }
    queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    if (failed.length === 0) {
      setShowBulkModal(null);
      selectNone();
      setBulkProgress(null);
      setForceDelete(false);
    }
  };

  // Table columns
  const columns = [
    {
      key: "checkbox",
      header: (
        <button onClick={(e) => { e.stopPropagation(); isAllSelected ? selectNone() : selectAll(); }} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
          {isAllSelected ? <CheckSquare className="h-4 w-4 text-primary-600" /> : isSomeSelected ? <MinusSquare className="h-4 w-4 text-primary-600" /> : <Square className="h-4 w-4 text-gray-400" />}
        </button>
      ),
      width: "40px",
      render: (_: unknown, row: Container) => (
        <button onClick={(e) => { e.stopPropagation(); if (!isManagementContainer(row)) toggleSelection(row.container_id); }} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" title={isManagementContainer(row) ? "Management container" : undefined}>
          {isManagementContainer(row) ? <Lock className="h-4 w-4 text-gray-400" /> : selectedContainerIds.has(row.container_id) ? <CheckSquare className="h-4 w-4 text-primary-600" /> : <Square className="h-4 w-4 text-gray-400" />}
        </button>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (_: unknown, row: Container) => <StatusIndicator status={getStatusLevel(row.status)} label={row.status} />,
    },
    {
      key: "name",
      header: "Container",
      sortable: true,
      render: (_: unknown, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{row.name}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{row.image}</div>
        </div>
      ),
    },
    {
      key: "stack_name",
      header: "Stack",
      render: (value: string | undefined) => value ? (
        <Badge className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">{value}</Badge>
      ) : <span className="text-gray-400 text-sm">Standalone</span>,
    },
    {
      key: "cpu_percent",
      header: "CPU",
      render: (value: number | undefined) => <span className="text-sm text-gray-900 dark:text-white">{value?.toFixed(1) || 0}%</span>,
    },
    {
      key: "memory_mb",
      header: "Memory",
      render: (value: number | undefined) => <span className="text-sm text-gray-900 dark:text-white">{value?.toFixed(0) || 0} MB</span>,
    },
  ];

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-4">
      {/* Metrics */}
      <MetricsGrid columns={5}>
        <StatCard label="Total" value={metrics.total} icon={ContainerIcon} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="Running" value={metrics.running} icon={Play} iconColor="text-green-600 dark:text-green-400" />
        <StatCard label="Stopped" value={metrics.stopped} icon={Square} iconColor="text-red-600 dark:text-red-400" />
        <StatCard label="CPU Usage" value={`${metrics.cpuUsage.toFixed(1)}%`} icon={Cpu} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="Memory Usage" value={`${metrics.memoryUsage.toFixed(0)} MB`} icon={MemoryStick} iconColor="text-purple-600 dark:text-purple-400" />
      </MetricsGrid>

      {/* Filters */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">Status:</span>
          <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
            {(["all", "running", "exited"] as StatusFilter[]).map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={cn(
                  "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                  statusFilter === status
                    ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                    : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                )}
              >
                {status === "all" ? `All (${metrics.total})` : status === "running" ? `Running (${metrics.running})` : `Stopped (${metrics.stopped})`}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Input placeholder="Search containers..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="w-64" />
          {(statusFilter !== "all" || searchFilter) && (
            <button onClick={() => { setStatusFilter("all"); setSearchFilter(""); }} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">Reset</button>
          )}
        </div>
      </div>

      {/* Selection Bar */}
      {containers && containers.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500 dark:text-gray-400">Quick select:</span>
            <button onClick={selectAll} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg">All ({selectableContainers.length})</button>
            <button onClick={selectRunning} disabled={metrics.running === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50">Running ({metrics.running})</button>
            <button onClick={selectStopped} disabled={metrics.stopped === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50">Stopped ({metrics.stopped})</button>
            {selectedContainerIds.size > 0 && <button onClick={selectNone} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400">Clear</button>}
          </div>
          {selectedContainerIds.size > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-700 dark:text-gray-300"><strong>{selectedContainerIds.size}</strong> selected</span>
              {runningSelectedCount > 0 && (
                <Button variant="secondary" size="sm" onClick={() => setShowBulkModal("stop")}>
                  <RotateCcw className="h-4 w-4 mr-1" />Stop Selected
                </Button>
              )}
              <Button variant="danger" size="sm" onClick={() => setShowBulkModal("delete")}>
                <Trash2 className="h-4 w-4 mr-1" />Delete Selected
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <Spinner.LogoPage label="Loading containers..." />
      ) : filteredContainers.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            data={filteredContainers}
            columns={columns}
            keyExtractor={(row) => row.container_id}
            onRowClick={(row) => { setSelectedContainer(row); setContainerPanelTab("details"); }}
            hoverable
            rowClassName={(row) => cn(selectedContainerIds.has(row.container_id) && "bg-blue-50 dark:bg-blue-900/10")}
          />
        </div>
      ) : (
        <EmptyState
          icon={ContainerIcon}
          title="No containers found"
          description={containers?.length === 0 ? "Deploy a container to get started" : "No containers match the current filters"}
        />
      )}

      {/* Bulk Operation Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => !bulkProgress && setShowBulkModal(null)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-lg w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={cn("p-2 rounded-full", showBulkModal === "stop" ? "bg-yellow-100 dark:bg-yellow-900/30" : "bg-red-100 dark:bg-red-900/30")}>
                {showBulkModal === "stop" ? <RotateCcw className="h-5 w-5 text-yellow-600" /> : <Trash2 className="h-5 w-5 text-red-600" />}
              </div>
              <h3 className="text-lg font-semibold">{showBulkModal === "stop" ? `Stop ${runningSelectedCount} Containers` : `Delete ${selectedContainerIds.size} Containers`}</h3>
            </div>
            {!bulkProgress ? (
              <>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  {showBulkModal === "stop" ? `Stop ${runningSelectedCount} running containers?` : `Delete ${selectedContainerIds.size} containers?`}
                </p>
                {showBulkModal === "delete" && runningSelectedCount > 0 && (
                  <label className="flex items-center gap-2 mb-4">
                    <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300" />
                    <span className="text-sm text-yellow-600">Force delete running containers ({runningSelectedCount})</span>
                  </label>
                )}
                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => { setShowBulkModal(null); setForceDelete(false); }}>Cancel</Button>
                  <Button variant={showBulkModal === "stop" ? "secondary" : "danger"} onClick={showBulkModal === "stop" ? handleBulkStop : handleBulkDelete} disabled={showBulkModal === "delete" && runningSelectedCount > 0 && !forceDelete}>
                    {showBulkModal === "stop" ? "Stop" : "Delete"}
                  </Button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>{showBulkModal === "stop" ? "Stopping..." : "Deleting..."}</span>
                    <span>{bulkProgress.completed} / {bulkProgress.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className={cn("h-2 rounded-full transition-all", showBulkModal === "stop" ? "bg-yellow-500" : "bg-red-600")} style={{ width: `${(bulkProgress.completed / bulkProgress.total) * 100}%` }} />
                  </div>
                </div>
                {bulkProgress.failed.length > 0 && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm font-medium text-red-600 mb-2">Failed: {bulkProgress.failed.length}</p>
                    <ul className="text-xs text-red-600">{bulkProgress.failed.map((n, i) => <li key={i}>• {n}</li>)}</ul>
                  </div>
                )}
                {bulkProgress.completed === bulkProgress.total && (
                  <div className="flex justify-end">
                    <Button variant="secondary" onClick={() => { setShowBulkModal(null); selectNone(); setBulkProgress(null); setForceDelete(false); }}>
                      {bulkProgress.failed.length > 0 ? "Close" : "Done"}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Container SlideOver */}
      <SlideOver isOpen={!!selectedContainer} onClose={() => setSelectedContainer(null)} size="lg">
        {selectedContainer && (
          <>
            <SlideOver.Header onClose={() => setSelectedContainer(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedContainer.image}</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-2 mb-6 border-b border-gray-200 dark:border-gray-700">
                <button onClick={() => setContainerPanelTab("details")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "details" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Details</button>
                <button onClick={() => setContainerPanelTab("logs")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "logs" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Logs</button>
                {selectedContainer.status === "running" && (
                  <button onClick={() => setContainerPanelTab("terminal")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "terminal" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Terminal</button>
                )}
              </div>

              {containerPanelTab === "details" && (
                <div className="space-y-6">
                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedContainer.status === "running" ? (
                        <>
                          <button onClick={() => setShowStopModal(true)} disabled={stopMutation.isPending} className="px-3 py-1.5 text-sm bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 rounded-lg hover:bg-yellow-200 dark:hover:bg-yellow-900/50 disabled:opacity-50">
                            <Square className="h-4 w-4 inline mr-1" />Stop
                          </button>
                          <button onClick={() => setShowRestartModal(true)} disabled={restartMutation.isPending} className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50 disabled:opacity-50">
                            <RotateCcw className="h-4 w-4 inline mr-1" />Restart
                          </button>
                        </>
                      ) : (
                        <button onClick={() => startMutation.mutate({ containerId: selectedContainer.container_id })} disabled={startMutation.isPending} className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50 disabled:opacity-50">
                          <Play className="h-4 w-4 inline mr-1" />Start
                        </button>
                      )}
                      <button onClick={() => router.push(`/docker/containers/${selectedAgent}/${selectedContainer.container_id}`)} className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
                        <ExternalLink className="h-4 w-4 inline mr-1" />Full Details
                      </button>
                      <button onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteContainerModal(true); }} className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50">
                        <Trash2 className="h-4 w-4 inline mr-1" />Delete
                      </button>
                    </div>
                  </div>

                  {/* Container Info */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Container Info</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                        <StatusIndicator status={getStatusLevel(selectedContainer.status)} label={selectedContainer.status} size="sm" />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Container ID</span>
                        <div className="flex items-center gap-1">
                          <code className="text-sm">{selectedContainer.container_id.slice(0, 12)}</code>
                          <button onClick={() => handleCopy(selectedContainer.container_id, "container-id")} className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded">
                            {copied === "container-id" ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400" />}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Stack</span>
                        <span className="text-sm text-gray-900 dark:text-white">{selectedContainer.stack_name || "Standalone"}</span>
                      </div>
                    </div>
                  </div>

                  {/* Resources */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Resources</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <Cpu className="h-3 w-3" />CPU Usage
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.cpu_percent?.toFixed(1) || 0}%</p>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <MemoryStick className="h-3 w-3" />Memory
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.memory_mb || 0} MB</p>
                      </div>
                    </div>
                  </div>

                  {/* Networks */}
                  {selectedContainer.networks && selectedContainer.networks.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Networks</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedContainer.networks.map((network) => (
                          <Badge key={network} size="sm">{network}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {containerPanelTab === "logs" && (
                <div className="flex flex-col -mx-6 h-[calc(100vh-300px)]">
                  <div className="flex items-center justify-between px-6 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
                    <select value={logsTail} onChange={(e) => setLogsTail(Number(e.target.value))} className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs text-gray-200">
                      <option value={50}>50 lines</option>
                      <option value={100}>100 lines</option>
                      <option value={500}>500 lines</option>
                      <option value={1000}>1000 lines</option>
                    </select>
                    <button onClick={() => refetchLogs()} className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                      <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                    </button>
                  </div>
                  <div className="flex-1 bg-gray-900 overflow-y-auto min-h-0 px-6">
                    {logsLoading ? (
                      <div className="flex items-center justify-center h-32"><div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-500" /></div>
                    ) : logsData?.logs ? (
                      <div className="font-mono text-xs py-2">
                        {logsData.logs.split("\n").filter((l: string) => l.trim()).map((line: string, idx: number) => (
                          <div key={idx} className="text-gray-300 hover:bg-gray-800/50 py-0.5 px-3 -mx-3">{line}</div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center text-gray-500 py-8 text-sm">No logs available</div>
                    )}
                  </div>
                </div>
              )}

              {containerPanelTab === "terminal" && (
                selectedContainer.status !== "running" ? (
                  <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                    <TerminalIcon className="h-8 w-8 mb-2 opacity-50" />
                    <p className="text-sm">Container must be running to access terminal</p>
                  </div>
                ) : (
                  <div className="h-[500px] bg-gray-900 rounded-lg overflow-hidden -mx-6">
                    <Terminal containerId={selectedContainer.container_id} agentId={selectedAgent!} onClose={() => setContainerPanelTab("details")} />
                  </div>
                )
              )}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Confirmation Dialogs */}
      <ConfirmDialog isOpen={showStopModal && !!selectedContainer} onClose={() => setShowStopModal(false)} onConfirm={() => stopMutation.mutate({ containerId: selectedContainer!.container_id })} title="Stop Container" message={`Are you sure you want to stop ${selectedContainer?.name}?`} confirmText="Stop Container" variant="warning" icon="stop" isLoading={stopMutation.isPending} />

      <ConfirmDialog isOpen={showRestartModal && !!selectedContainer} onClose={() => setShowRestartModal(false)} onConfirm={() => restartMutation.mutate({ containerId: selectedContainer!.container_id })} title="Restart Container" message={`Are you sure you want to restart ${selectedContainer?.name}?`} confirmText="Restart Container" variant="default" icon="redeploy" isLoading={restartMutation.isPending} />

      <ConfirmDialog
        isOpen={showDeleteContainerModal && !!selectedContainer}
        onClose={() => { setShowDeleteContainerModal(false); setDeleteError(null); setForceDelete(false); }}
        onConfirm={() => deleteContainerMutation.mutate()}
        title="Delete Container"
        message={`Are you sure you want to delete ${selectedContainer?.name}?`}
        confirmText="Delete Container"
        variant="danger"
        icon="delete"
        isLoading={deleteContainerMutation.isPending}
        error={deleteError}
      >
        {selectedContainer?.status === "running" && (
          <label className="flex items-center gap-2 mt-4">
            <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300" />
            <span className="text-sm text-yellow-600">Force delete (container is running)</span>
          </label>
        )}
      </ConfirmDialog>
    </div>
  );
}
