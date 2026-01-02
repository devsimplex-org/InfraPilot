"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  Play,
  Square,
  RotateCcw,
  Server,
  FileText,
  X,
  RefreshCw,
  Info,
  Clock,
  Layers,
  Globe,
  Copy,
  Terminal as TerminalIcon,
} from "lucide-react";
import { api, Container, Agent } from "@/lib/api";
import { Terminal } from "@/components/containers/Terminal";
import { formatRelativeTime, cn } from "@/lib/utils";

export default function ContainersPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [logsContainer, setLogsContainer] = useState<Container | null>(null);
  const [logsTail, setLogsTail] = useState(100);
  const [viewMode, setViewMode] = useState<"all" | "stacks">("all");
  const [detailContainer, setDetailContainer] = useState<Container | null>(null);
  const [terminalContainer, setTerminalContainer] = useState<Container | null>(null);

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

  // Fetch logs for selected container
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["containerLogs", selectedAgent, logsContainer?.container_id, logsTail],
    queryFn: () =>
      selectedAgent && logsContainer
        ? api.getContainerLogs(selectedAgent, logsContainer.container_id, logsTail)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!logsContainer,
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  if (!selectedAgent && activeAgents.length > 0) {
    setSelectedAgent(activeAgents[0].id);
  }

  // Group containers by stack (docker-compose project)
  const containersByStack = containers?.reduce((acc, container) => {
    const stack = container.stack_name || "Standalone";
    if (!acc[stack]) acc[stack] = [];
    acc[stack].push(container);
    return acc;
  }, {} as Record<string, Container[]>) || {};

  const stackNames = Object.keys(containersByStack).sort((a, b) => {
    if (a === "Standalone") return 1;
    if (b === "Standalone") return -1;
    return a.localeCompare(b);
  });

  const getStatusColor = (status: string) => {
    if (status === "running") return "bg-green-500";
    if (status === "exited") return "bg-red-500";
    if (status === "paused") return "bg-yellow-500";
    return "bg-gray-500";
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "running":
        return "bg-green-500/10 text-green-400 border-green-500/30";
      case "exited":
        return "bg-red-500/10 text-red-400 border-red-500/30";
      case "paused":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      default:
        return "bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/30";
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Containers</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            View and manage Docker containers across your agents
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* View Mode Toggle */}
          <div className="flex bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setViewMode("all")}
              className={cn(
                "px-3 py-1.5 text-sm rounded-md transition-colors",
                viewMode === "all"
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                  : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              )}
            >
              All
            </button>
            <button
              onClick={() => setViewMode("stacks")}
              className={cn(
                "px-3 py-1.5 text-sm rounded-md transition-colors",
                viewMode === "stacks"
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                  : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              )}
            >
              By Stack
            </button>
          </div>
        </div>
      </div>

      {/* Agent selector */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Select Agent
        </label>
        <select
          value={selectedAgent || ""}
          onChange={(e) => setSelectedAgent(e.target.value || null)}
          className="w-full max-w-xs px-4 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
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

      {/* Containers grid */}
      {selectedAgent ? (
        <div className="space-y-4">
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
            </div>
          ) : containers && containers.length > 0 ? (
            viewMode === "all" ? (
              /* All containers view */
              <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                {containers.map((container) => {
                  const isNginx = container.image.includes("nginx") || container.name.toLowerCase().includes("nginx");

                  return (
                    <div
                      key={container.id}
                      className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 hover:border-gray-300 dark:hover:border-gray-700 p-4 transition-colors"
                    >
                      {/* Header */}
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <div className={cn("w-2 h-2 rounded-full", getStatusColor(container.status))} />
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="text-gray-900 dark:text-white font-medium">{container.name}</h3>
                              {isNginx && (
                                <span className="px-1.5 py-0.5 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded">
                                  nginx
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-gray-500 mt-0.5">{container.container_id.slice(0, 12)}</p>
                          </div>
                        </div>
                        <span className={cn("px-2 py-1 text-xs font-medium rounded border", getStatusBadge(container.status))}>
                          {container.status}
                        </span>
                      </div>

                      {/* Image */}
                      <div className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                        <span className="text-gray-500">Image:</span> {container.image}
                      </div>

                      {/* Stack */}
                      {container.stack_name && (
                        <div className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                          <span className="text-gray-500">Stack:</span> {container.stack_name}
                        </div>
                      )}

                      {/* Metrics */}
                      <div className="grid grid-cols-2 gap-2 mb-4 text-sm">
                        <div className="bg-gray-100 dark:bg-gray-800/50 rounded px-2 py-1">
                          <span className="text-gray-500">CPU:</span>{" "}
                          <span className="text-gray-900 dark:text-white">{container.cpu_percent?.toFixed(1) || 0}%</span>
                        </div>
                        <div className="bg-gray-100 dark:bg-gray-800/50 rounded px-2 py-1">
                          <span className="text-gray-500">Memory:</span>{" "}
                          <span className="text-gray-900 dark:text-white">{container.memory_mb || 0} MB</span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-gray-200 dark:border-gray-800">
                        {container.status === "running" ? (
                          <>
                            <button
                              onClick={() => stopMutation.mutate({ containerId: container.container_id })}
                              disabled={stopMutation.isPending}
                              className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                            >
                              <Square className="h-3 w-3" />
                              Stop
                            </button>
                            <button
                              onClick={() => restartMutation.mutate({ containerId: container.container_id })}
                              disabled={restartMutation.isPending}
                              className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                            >
                              <RotateCcw className="h-3 w-3" />
                              Restart
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => startMutation.mutate({ containerId: container.container_id })}
                            disabled={startMutation.isPending}
                            className="flex items-center gap-1 px-3 py-1.5 text-sm bg-green-600 hover:bg-green-700 text-white rounded transition-colors"
                          >
                            <Play className="h-3 w-3" />
                            Start
                          </button>
                        )}

                        <button
                          onClick={() => setLogsContainer(container)}
                          className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                        >
                          <FileText className="h-3 w-3" />
                          Logs
                        </button>

                        {container.status === "running" && (
                          <button
                            onClick={() => setTerminalContainer(container)}
                            className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                          >
                            <TerminalIcon className="h-3 w-3" />
                            Terminal
                          </button>
                        )}

                        <button
                          onClick={() => setDetailContainer(container)}
                          className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                        >
                          <Info className="h-3 w-3" />
                          Details
                        </button>
                      </div>
                    </div>
                  );
              })}
            </div>
            ) : (
              /* Stacks view */
              <div className="space-y-6">
                {stackNames.map((stackName) => {
                  const stackContainers = containersByStack[stackName];
                  const runningCount = stackContainers.filter(c => c.status === "running").length;

                  return (
                    <div key={stackName} className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                      {/* Stack Header */}
                      <div className="px-4 py-3 bg-gray-100 dark:bg-gray-800/50 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="p-1.5 bg-primary-500/10 rounded">
                            <ContainerIcon className="h-4 w-4 text-primary-400" />
                          </div>
                          <div>
                            <h3 className="text-gray-900 dark:text-white font-medium">{stackName}</h3>
                            <p className="text-xs text-gray-500">
                              {runningCount}/{stackContainers.length} running
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={cn(
                            "px-2 py-1 text-xs rounded",
                            runningCount === stackContainers.length
                              ? "bg-green-500/10 text-green-400"
                              : runningCount === 0
                              ? "bg-red-500/10 text-red-400"
                              : "bg-yellow-500/10 text-yellow-400"
                          )}>
                            {runningCount === stackContainers.length ? "All Running" :
                             runningCount === 0 ? "Stopped" : "Partial"}
                          </span>
                        </div>
                      </div>

                      {/* Stack Containers */}
                      <div className="divide-y divide-gray-800">
                        {stackContainers.map((container) => {
                          const isNginx = container.image.includes("nginx") || container.name.toLowerCase().includes("nginx");

                          return (
                            <div key={container.id} className="px-4 py-3 flex items-center justify-between hover:bg-gray-100 dark:bg-gray-800/30">
                              <div className="flex items-center gap-3">
                                <div className={cn("w-2 h-2 rounded-full", getStatusColor(container.status))} />
                                <div>
                                  <div className="flex items-center gap-2">
                                    <span className="text-gray-900 dark:text-white">{container.name}</span>
                                    {isNginx && (
                                      <span className="px-1.5 py-0.5 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded">
                                        nginx
                                      </span>
                                    )}
                                  </div>
                                  <p className="text-xs text-gray-500">{container.image}</p>
                                </div>
                              </div>

                              <div className="flex items-center gap-2">
                                {container.status === "running" ? (
                                  <>
                                    <button
                                      onClick={() => stopMutation.mutate({ containerId: container.container_id })}
                                      className="p-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                                      title="Stop"
                                    >
                                      <Square className="h-3 w-3 text-gray-600 dark:text-gray-400" />
                                    </button>
                                    <button
                                      onClick={() => restartMutation.mutate({ containerId: container.container_id })}
                                      className="p-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                                      title="Restart"
                                    >
                                      <RotateCcw className="h-3 w-3 text-gray-600 dark:text-gray-400" />
                                    </button>
                                  </>
                                ) : (
                                  <button
                                    onClick={() => startMutation.mutate({ containerId: container.container_id })}
                                    className="p-1.5 bg-green-600 hover:bg-green-700 rounded transition-colors"
                                    title="Start"
                                  >
                                    <Play className="h-3 w-3 text-white" />
                                  </button>
                                )}
                                <button
                                  onClick={() => setLogsContainer(container)}
                                  className="p-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                                  title="Logs"
                                >
                                  <FileText className="h-3 w-3 text-gray-600 dark:text-gray-400" />
                                </button>
                                {container.status === "running" && (
                                  <button
                                    onClick={() => setTerminalContainer(container)}
                                    className="p-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                                    title="Terminal"
                                  >
                                    <TerminalIcon className="h-3 w-3 text-gray-600 dark:text-gray-400" />
                                  </button>
                                )}
                                <button
                                  onClick={() => setDetailContainer(container)}
                                  className="p-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                                  title="Details"
                                >
                                  <Info className="h-3 w-3 text-gray-600 dark:text-gray-400" />
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 py-12 text-center text-gray-500">
              <ContainerIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No containers found</p>
              <p className="text-sm mt-1">
                Make sure Docker is running and containers are deployed
              </p>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 py-12 text-center text-gray-500">
          <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Select an agent to view containers</p>
          {activeAgents.length === 0 && (
            <p className="text-sm mt-1">
              No active agents available. Register an agent first.
            </p>
          )}
        </div>
      )}

      {/* Logs Modal */}
      {logsContainer && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-4xl max-h-[80vh] border border-gray-200 dark:border-gray-800 flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-800">
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">Container Logs</h2>
                <p className="text-sm text-gray-600 dark:text-gray-400">{logsContainer.name}</p>
              </div>
              <div className="flex items-center gap-3">
                <select
                  value={logsTail}
                  onChange={(e) => setLogsTail(Number(e.target.value))}
                  className="px-3 py-1.5 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white"
                >
                  <option value={50}>Last 50 lines</option>
                  <option value={100}>Last 100 lines</option>
                  <option value={500}>Last 500 lines</option>
                  <option value={1000}>Last 1000 lines</option>
                </select>
                <button
                  onClick={() => refetchLogs()}
                  className="p-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                  title="Refresh logs"
                >
                  <RefreshCw className={cn("h-4 w-4 text-gray-600 dark:text-gray-400", logsLoading && "animate-spin")} />
                </button>
                <button
                  onClick={() => setLogsContainer(null)}
                  className="p-2 hover:bg-gray-100 dark:bg-gray-800 rounded transition-colors"
                >
                  <X className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                </button>
              </div>
            </div>

            {/* Logs content */}
            <div className="flex-1 overflow-auto p-4">
              {logsLoading ? (
                <div className="flex items-center justify-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
                </div>
              ) : logsData?.logs ? (
                <pre className="text-sm text-gray-700 dark:text-gray-300 font-mono whitespace-pre-wrap break-all">
                  {logsData.logs}
                </pre>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  No logs available
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Container Detail Modal */}
      {detailContainer && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-2xl max-h-[80vh] border border-gray-200 dark:border-gray-800 flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-800">
              <div className="flex items-center gap-3">
                <div className={cn("w-3 h-3 rounded-full", getStatusColor(detailContainer.status))} />
                <div>
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">{detailContainer.name}</h2>
                  <p className="text-sm text-gray-600 dark:text-gray-400">{detailContainer.image}</p>
                </div>
              </div>
              <button
                onClick={() => setDetailContainer(null)}
                className="p-2 hover:bg-gray-100 dark:bg-gray-800 rounded transition-colors"
              >
                <X className="h-5 w-5 text-gray-600 dark:text-gray-400" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-4 space-y-4">
              {/* Status & Actions */}
              <div className="flex items-center justify-between">
                <span className={cn("px-3 py-1.5 text-sm font-medium rounded border", getStatusBadge(detailContainer.status))}>
                  {detailContainer.status}
                </span>
                <div className="flex items-center gap-2">
                  {detailContainer.status === "running" ? (
                    <>
                      <button
                        onClick={() => {
                          stopMutation.mutate({ containerId: detailContainer.container_id });
                          setDetailContainer(null);
                        }}
                        className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                      >
                        <Square className="h-3 w-3" />
                        Stop
                      </button>
                      <button
                        onClick={() => {
                          restartMutation.mutate({ containerId: detailContainer.container_id });
                          setDetailContainer(null);
                        }}
                        className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded transition-colors"
                      >
                        <RotateCcw className="h-3 w-3" />
                        Restart
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => {
                        startMutation.mutate({ containerId: detailContainer.container_id });
                        setDetailContainer(null);
                      }}
                      className="flex items-center gap-1 px-3 py-1.5 text-sm bg-green-600 hover:bg-green-700 text-white rounded transition-colors"
                    >
                      <Play className="h-3 w-3" />
                      Start
                    </button>
                  )}
                  <button
                    onClick={() => {
                      setLogsContainer(detailContainer);
                      setDetailContainer(null);
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 text-sm bg-primary-600 hover:bg-primary-700 text-white rounded transition-colors"
                  >
                    <FileText className="h-3 w-3" />
                    View Logs
                  </button>
                  {detailContainer.status === "running" && (
                    <button
                      onClick={() => {
                        setTerminalContainer(detailContainer);
                        setDetailContainer(null);
                      }}
                      className="flex items-center gap-1 px-3 py-1.5 text-sm bg-gray-600 hover:bg-gray-500 text-white rounded transition-colors"
                    >
                      <TerminalIcon className="h-3 w-3" />
                      Terminal
                    </button>
                  )}
                </div>
              </div>

              {/* Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Container ID */}
                <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-1">
                    <ContainerIcon className="h-3 w-3" />
                    Container ID
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-gray-900 dark:text-white text-sm font-mono">
                      {detailContainer.container_id.slice(0, 12)}
                    </code>
                    <button
                      onClick={() => navigator.clipboard.writeText(detailContainer.container_id)}
                      className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                      title="Copy full ID"
                    >
                      <Copy className="h-3 w-3 text-gray-500" />
                    </button>
                  </div>
                </div>

                {/* Stack */}
                <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-1">
                    <Layers className="h-3 w-3" />
                    Stack
                  </div>
                  <p className="text-gray-900 dark:text-white text-sm">
                    {detailContainer.stack_name || "Standalone"}
                  </p>
                </div>

                {/* Created */}
                {detailContainer.created_at && (
                  <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                    <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-1">
                      <Clock className="h-3 w-3" />
                      Created
                    </div>
                    <p className="text-gray-900 dark:text-white text-sm">
                      {new Date(detailContainer.created_at).toLocaleString()}
                    </p>
                  </div>
                )}

                {/* Metrics */}
                <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-1">
                    <Server className="h-3 w-3" />
                    Resources
                  </div>
                  <p className="text-gray-900 dark:text-white text-sm">
                    CPU: {detailContainer.cpu_percent?.toFixed(1) || 0}% · RAM: {detailContainer.memory_mb || 0} MB
                  </p>
                </div>
              </div>

              {/* Networks */}
              {detailContainer.networks && detailContainer.networks.length > 0 && (
                <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-2">
                    <Globe className="h-3 w-3" />
                    Networks
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {detailContainer.networks.map((network) => (
                      <span
                        key={network}
                        className="px-2 py-1 text-xs bg-gray-700 text-gray-700 dark:text-gray-300 rounded"
                      >
                        {network}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Image */}
              <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-xs mb-1">
                  <Layers className="h-3 w-3" />
                  Image
                </div>
                <code className="text-gray-900 dark:text-white text-sm font-mono break-all">
                  {detailContainer.image}
                </code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Terminal Modal */}
      {terminalContainer && selectedAgent && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-4xl h-[600px] border border-gray-300 dark:border-gray-700 overflow-hidden flex flex-col">
            <Terminal
              containerId={terminalContainer.container_id}
              agentId={selectedAgent}
              onClose={() => setTerminalContainer(null)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
