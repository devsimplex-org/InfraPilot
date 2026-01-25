"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  Play,
  Square,
  RotateCcw,
  RefreshCw,
  Clock,
  Layers,
  Copy,
  Terminal as TerminalIcon,
  Cpu,
  MemoryStick,
  Check,
  ExternalLink,
  Trash2,
} from "lucide-react";
import { api, Container } from "@/lib/api";
import { Terminal } from "@/components/containers/Terminal";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";

type PanelTab = "details" | "logs" | "terminal";
type StatusFilter = "all" | "running" | "exited" | "paused";

export default function ContainersPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("details");
  const [logsTail, setLogsTail] = useState(100);
  const [copied, setCopied] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmName, setDeleteConfirmName] = useState("");
  const [forceDelete, setForceDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [showStopModal, setShowStopModal] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [searchFilter, setSearchFilter] = useState("");

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch containers for selected agent
  const { data: containers, isLoading } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Fetch logs for selected container
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["containerLogs", selectedAgent, selectedContainer?.container_id, logsTail],
    queryFn: () =>
      selectedAgent && selectedContainer
        ? api.getContainerLogs(selectedAgent, selectedContainer.container_id, logsTail)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!selectedContainer && panelTab === "logs",
  });

  // Container actions
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
    },
  });

  const restartMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.restartContainer(selectedAgent!, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () =>
      api.deleteContainer(selectedAgent!, selectedContainer!.container_id, deleteConfirmName, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowDeleteModal(false);
      setDeleteConfirmName("");
      setForceDelete(false);
      setDeleteError(null);
      setSelectedContainer(null);
    },
    onError: (error: Error) => {
      setDeleteError(error.message);
    },
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  // Update selected container from fresh data
  useEffect(() => {
    if (selectedContainer && containers) {
      const updated = containers.find(c => c.container_id === selectedContainer.container_id);
      if (updated) {
        setSelectedContainer(updated);
      }
    }
  }, [containers, selectedContainer]);

  // Filter containers
  const filteredContainers = containers?.filter((container) => {
    const matchesStatus = statusFilter === "all" || container.status === statusFilter;
    const matchesSearch = !searchFilter ||
      container.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      container.image.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesStatus && matchesSearch;
  }) || [];

  // Calculate metrics
  const metrics = {
    total: containers?.length || 0,
    running: containers?.filter(c => c.status === "running").length || 0,
    stopped: containers?.filter(c => c.status === "exited").length || 0,
    cpuUsage: containers?.length
      ? (containers.reduce((sum, c) => sum + (c.cpu_percent || 0), 0) / containers.length).toFixed(1)
      : 0,
    memoryUsage: containers?.reduce((sum, c) => sum + (c.memory_mb || 0), 0) || 0,
  };

  const getStatusLevel = (status: string) => {
    if (status === "running") return "healthy";
    if (status === "exited") return "critical";
    if (status === "paused") return "warning";
    return "degraded";
  };

  const handleCopyId = () => {
    if (selectedContainer) {
      navigator.clipboard.writeText(selectedContainer.container_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleContainerAction = (action: "start" | "stop" | "restart", container: Container) => {
    switch (action) {
      case "start":
        startMutation.mutate({ containerId: container.container_id });
        break;
      case "stop":
        stopMutation.mutate({ containerId: container.container_id });
        break;
      case "restart":
        restartMutation.mutate({ containerId: container.container_id });
        break;
    }
  };

  // Parse log line with timestamp and level
  const parseLogLine = (line: string) => {
    const timestampMatch = line.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*/);
    let timestamp = "";
    let message = line;

    if (timestampMatch) {
      timestamp = timestampMatch[1];
      message = line.slice(timestampMatch[0].length);
    }

    const lowerMessage = message.toLowerCase();
    let level: "error" | "warn" | "info" | "debug" = "info";
    if (lowerMessage.includes("error") || lowerMessage.includes("err ") || lowerMessage.includes("fatal") || lowerMessage.includes("panic")) {
      level = "error";
    } else if (lowerMessage.includes("warn") || lowerMessage.includes("warning")) {
      level = "warn";
    } else if (lowerMessage.includes("debug") || lowerMessage.includes("trace")) {
      level = "debug";
    }

    return { timestamp, message, level };
  };

  // Table columns
  const columns = [
    {
      key: "status",
      header: "Status",
      width: "120px",
      render: (value: string) => (
        <StatusIndicator
          status={getStatusLevel(value)}
          label={value}
          size="sm"
        />
      ),
    },
    {
      key: "name",
      header: "Container Name",
      render: (value: string, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
            {row.image}
          </div>
        </div>
      ),
    },
    {
      key: "stack_name",
      header: "Stack",
      render: (value: string) => value ? (
        <Badge size="sm">
          <Layers className="h-3 w-3" />
          {value}
        </Badge>
      ) : (
        <span className="text-gray-400 text-sm">Standalone</span>
      ),
    },
    {
      key: "cpu_percent",
      header: "CPU",
      align: "right" as const,
      render: (value: number) => (
        <div className="flex items-center gap-1 justify-end text-sm">
          <Cpu className="h-3 w-3 text-gray-400" />
          <span>{value?.toFixed(1) || 0}%</span>
        </div>
      ),
    },
    {
      key: "memory_mb",
      header: "Memory",
      align: "right" as const,
      render: (value: number, row: Container) => (
        <div className="flex items-center gap-1 justify-end text-sm">
          <MemoryStick className="h-3 w-3 text-gray-400" />
          <span>
            {value || 0} MB
            {row.memory_limit_mb && row.memory_limit_mb > 0 && (
              <span className="text-gray-400"> / {row.memory_limit_mb} MB</span>
            )}
          </span>
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      width: "100px",
      render: (_: any, row: Container) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/containers/${selectedAgent}/${row.container_id}`);
          }}
          className="flex items-center gap-1 text-xs text-primary-600 dark:text-primary-400 hover:underline"
        >
          <ExternalLink className="h-3 w-3" />
          Details
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Containers"
        description="View and manage Docker containers"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Run", href: "/" },
              { label: "Containers", current: true },
            ]}
          />
        }
      />

      {/* Agent selector */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Select Agent
        </label>
        <select
          value={selectedAgent || ""}
          onChange={(e) => {
            setSelectedAgent(e.target.value || null);
            setSelectedContainer(null);
          }}
          className="w-full max-w-xs px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="">Select an agent...</option>
          {agents?.map((agent) => (
            <option
              key={agent.id}
              value={agent.id}
              disabled={agent.status !== "active"}
            >
              {agent.name} ({agent.status})
            </option>
          ))}
        </select>
      </div>

      {selectedAgent && (
        <>
          {/* Metrics */}
          <MetricsGrid columns={4} className="mb-6">
            <StatCard
              label="Running"
              value={metrics.running}
              icon={ContainerIcon}
              iconColor="text-green-600 dark:text-green-400"
            />
            <StatCard
              label="Stopped"
              value={metrics.stopped}
              icon={Square}
              iconColor="text-red-600 dark:text-red-400"
            />
            <StatCard
              label="CPU Usage"
              value={`${metrics.cpuUsage}%`}
              icon={Cpu}
              iconColor="text-blue-600 dark:text-blue-400"
            />
            <StatCard
              label="Memory Usage"
              value={`${metrics.memoryUsage} MB`}
              icon={MemoryStick}
              iconColor="text-purple-600 dark:text-purple-400"
            />
          </MetricsGrid>

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
                      { label: "All", value: "all", count: metrics.total },
                      { label: "Running", value: "running", count: metrics.running },
                      { label: "Stopped", value: "exited", count: metrics.stopped },
                    ],
                    value: statusFilter,
                    onChange: (value) => setStatusFilter(value as StatusFilter),
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
                  setSearchFilter("");
                }}
              />
            </div>

            {/* Containers Table */}
            <div className="flex-1 min-w-0">
              {isLoading ? (
                <div className="flex items-center justify-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
                </div>
              ) : filteredContainers.length > 0 ? (
                <Table
                  columns={columns}
                  data={filteredContainers}
                  keyExtractor={(row) => row.container_id}
                  onRowClick={(row) => {
                    setSelectedContainer(row);
                    setPanelTab("details");
                  }}
                  selectedRows={selectedContainer ? new Set([selectedContainer.container_id]) : undefined}
                  hoverable
                />
              ) : (
                <EmptyState
                  icon={ContainerIcon}
                  title="No containers found"
                  description={containers?.length === 0
                    ? "Make sure Docker is running and containers are deployed"
                    : "No containers match the current filters"
                  }
                />
              )}
            </div>
          </div>
        </>
      )}

      {/* SlideOver for container details */}
      <SlideOver
        isOpen={!!selectedContainer}
        onClose={() => setSelectedContainer(null)}
        size="lg"
      >
        {selectedContainer && (
          <>
            <SlideOver.Header onClose={() => setSelectedContainer(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedContainer.name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {selectedContainer.image}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-2 mb-6 border-b border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setPanelTab("details")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    panelTab === "details"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Details
                </button>
                <button
                  onClick={() => setPanelTab("logs")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    panelTab === "logs"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Logs
                </button>
                {selectedContainer.status === "running" && (
                  <button
                    onClick={() => setPanelTab("terminal")}
                    className={cn(
                      "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                      panelTab === "terminal"
                        ? "border-primary-600 text-primary-600 dark:text-primary-400"
                        : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                    )}
                  >
                    Terminal
                  </button>
                )}
              </div>

              {/* Tab Content */}
              {panelTab === "details" && (
                <div className="space-y-6">
                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedContainer.status === "running" ? (
                        <>
                          <button
                            onClick={() => setShowStopModal(true)}
                            disabled={stopMutation.isPending}
                            className="px-3 py-1.5 text-sm bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 rounded-lg hover:bg-yellow-200 dark:hover:bg-yellow-900/50 transition-colors disabled:opacity-50"
                          >
                            <Square className="h-4 w-4 inline mr-1" />
                            Stop
                          </button>
                          <button
                            onClick={() => setShowRestartModal(true)}
                            disabled={restartMutation.isPending}
                            className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors disabled:opacity-50"
                          >
                            <RotateCcw className="h-4 w-4 inline mr-1" />
                            Restart
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={() => handleContainerAction("start", selectedContainer)}
                          disabled={startMutation.isPending}
                          className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50 transition-colors disabled:opacity-50"
                        >
                          <Play className="h-4 w-4 inline mr-1" />
                          Start
                        </button>
                      )}
                      <button
                        onClick={() => router.push(`/containers/${selectedAgent}/${selectedContainer.container_id}`)}
                        className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                      >
                        <ExternalLink className="h-4 w-4 inline mr-1" />
                        Full Details
                      </button>
                      <button
                        onClick={() => {
                          setDeleteConfirmName("");
                          setForceDelete(false);
                          setDeleteError(null);
                          setShowDeleteModal(true);
                        }}
                        className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50 transition-colors"
                      >
                        <Trash2 className="h-4 w-4 inline mr-1" />
                        Delete
                      </button>
                    </div>
                  </div>

                  {/* Container Info */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Container Info</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                        <StatusIndicator
                          status={getStatusLevel(selectedContainer.status)}
                          label={selectedContainer.status}
                          size="sm"
                        />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Container ID</span>
                        <div className="flex items-center gap-1">
                          <code className="text-sm">{selectedContainer.container_id.slice(0, 12)}</code>
                          <button
                            onClick={handleCopyId}
                            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                            title="Copy full ID"
                          >
                            {copied ? (
                              <Check className="h-3 w-3 text-green-500" />
                            ) : (
                              <Copy className="h-3 w-3 text-gray-400" />
                            )}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Stack</span>
                        <span className="text-sm text-gray-900 dark:text-white">
                          {selectedContainer.stack_name || "Standalone"}
                        </span>
                      </div>
                      {selectedContainer.created_at && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                          <span className="text-sm text-gray-900 dark:text-white">
                            {new Date(selectedContainer.created_at).toLocaleString()}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Image */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Image</h3>
                    <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                      <code className="text-sm text-gray-900 dark:text-white font-mono break-all">
                        {selectedContainer.image}
                      </code>
                    </div>
                  </div>

                  {/* Resources */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Resources</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <Cpu className="h-3 w-3" />
                          CPU Usage
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">
                          {selectedContainer.cpu_percent?.toFixed(1) || 0}%
                        </p>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <MemoryStick className="h-3 w-3" />
                          Memory
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">
                          {selectedContainer.memory_mb || 0} MB
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Networks */}
                  {selectedContainer.networks && selectedContainer.networks.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Networks</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedContainer.networks.map((network) => (
                          <Badge key={network} size="sm">
                            {network}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {panelTab === "logs" && (
                <div className="flex flex-col -mx-6 h-[calc(100vh-300px)]">
                  <div className="flex items-center justify-between px-6 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
                    <select
                      value={logsTail}
                      onChange={(e) => setLogsTail(Number(e.target.value))}
                      className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs text-gray-200"
                    >
                      <option value={50}>50 lines</option>
                      <option value={100}>100 lines</option>
                      <option value={500}>500 lines</option>
                      <option value={1000}>1000 lines</option>
                    </select>
                    <button
                      onClick={() => refetchLogs()}
                      className="p-1.5 hover:bg-gray-700 rounded transition-colors"
                      title="Refresh logs"
                    >
                      <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                    </button>
                  </div>
                  <div className="flex-1 bg-gray-900 overflow-y-auto min-h-0 px-6">
                    {logsLoading ? (
                      <div className="flex items-center justify-center h-32">
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-500" />
                      </div>
                    ) : logsData?.logs ? (
                      <div className="font-mono text-xs">
                        {logsData.logs.split("\n").filter((l: string) => l.trim()).map((line: string, idx: number) => {
                          const { timestamp, message, level } = parseLogLine(line);
                          const levelColor = level === "error" ? "text-red-400" :
                                           level === "warn" ? "text-yellow-400" :
                                           level === "debug" ? "text-gray-500" : "text-gray-300";
                          const levelBg = level === "error" ? "bg-red-500/10 border-l-2 border-red-500" :
                                        level === "warn" ? "bg-yellow-500/10 border-l-2 border-yellow-500" : "";
                          return (
                            <div key={idx} className={cn("flex gap-2 px-3 py-0.5 hover:bg-gray-800/50", levelBg)}>
                              {timestamp && (
                                <span className="text-gray-600 flex-shrink-0 w-20 truncate" title={timestamp}>
                                  {new Date(timestamp).toLocaleTimeString()}
                                </span>
                              )}
                              <span className={cn("break-all", levelColor)}>{message}</span>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="text-center text-gray-500 py-8 text-sm">
                        No logs available
                      </div>
                    )}
                  </div>
                </div>
              )}

              {panelTab === "terminal" && (
                selectedContainer.status !== "running" ? (
                  <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                    <TerminalIcon className="h-8 w-8 mb-2 opacity-50" />
                    <p className="text-sm">Container must be running to access terminal</p>
                  </div>
                ) : (
                  <div className="h-[500px] bg-gray-900 rounded-lg overflow-hidden -mx-6">
                    <Terminal
                      containerId={selectedContainer.container_id}
                      agentId={selectedAgent!}
                      onClose={() => setPanelTab("details")}
                    />
                  </div>
                )
              )}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Modals */}
      <ConfirmDialog
        isOpen={showStopModal && !!selectedContainer}
        onClose={() => setShowStopModal(false)}
        onConfirm={() => {
          if (selectedContainer) {
            handleContainerAction("stop", selectedContainer);
          }
        }}
        title="Stop Container"
        message={`Are you sure you want to stop this container?\n\nContainer: ${selectedContainer?.name || ''}`}
        confirmText="Stop Container"
        variant="warning"
        icon="stop"
        isLoading={stopMutation.isPending}
      />

      <ConfirmDialog
        isOpen={showRestartModal && !!selectedContainer}
        onClose={() => setShowRestartModal(false)}
        onConfirm={() => {
          if (selectedContainer) {
            handleContainerAction("restart", selectedContainer);
          }
        }}
        title="Restart Container"
        message={`Are you sure you want to restart this container?\n\nContainer: ${selectedContainer?.name || ''}\n\nThis will briefly interrupt any services running in this container.`}
        confirmText="Restart Container"
        variant="default"
        icon="redeploy"
        isLoading={restartMutation.isPending}
      />

      <ConfirmDialog
        isOpen={showDeleteModal && !!selectedContainer}
        onClose={() => {
          setShowDeleteModal(false);
          setDeleteConfirmName("");
          setForceDelete(false);
          setDeleteError(null);
        }}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Container"
        message="This action cannot be undone."
        confirmText="Delete Container"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
        confirmLevel="name"
        confirmValue={selectedContainer?.name}
        error={deleteError}
        onInputChange={setDeleteConfirmName}
      >
        {selectedContainer?.status === "running" && (
          <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <input
              type="checkbox"
              checked={forceDelete}
              onChange={(e) => setForceDelete(e.target.checked)}
              className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500"
            />
            Force delete (stop container first)
          </label>
        )}
      </ConfirmDialog>
    </div>
  );
}
