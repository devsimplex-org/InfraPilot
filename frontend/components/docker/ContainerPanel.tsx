"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Square,
  Play,
  RotateCcw,
  Cpu,
  MemoryStick,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Trash2,
  Terminal as TerminalIcon,
  Pause,
  Zap,
  Edit3,
  Settings,
  Code,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  HardDrive,
} from "lucide-react";
import { api, Container } from "@/lib/api";
import { useDocker, getStatusLevel, formatSize } from "@/lib/docker-context";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Terminal } from "@/components/containers/Terminal";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

export function ContainerPanel() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { selectedAgent, containerPanelId, closeContainerPanel, forceDelete, setForceDelete } = useDocker();

  // Local state
  const [tab, setTab] = useState<"details" | "logs" | "terminal" | "config">("details");
  const [logsTail, setLogsTail] = useState(100);
  const [copied, setCopied] = useState<string | null>(null);
  const [showStopModal, setShowStopModal] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showKillModal, setShowKillModal] = useState(false);
  const [showRenameModal, setShowRenameModal] = useState(false);
  const [showRestartPolicyModal, setShowRestartPolicyModal] = useState(false);
  const [showResourcesModal, setShowResourcesModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [selectedSignal, setSelectedSignal] = useState("SIGTERM");
  const [newName, setNewName] = useState("");
  const [restartPolicy, setRestartPolicy] = useState("no");
  const [maxRetries, setMaxRetries] = useState(0);
  const [memoryLimit, setMemoryLimit] = useState("");
  const [cpuShares, setCpuShares] = useState("");
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["env"]));

  // Reset tab when panel opens
  useEffect(() => {
    if (containerPanelId) {
      setTab("details");
    }
  }, [containerPanelId]);

  // Fetch container details - supports lookup by ID, ID prefix, or container name
  const { data: container, isLoading: containerLoading } = useQuery({
    queryKey: ["container-detail", selectedAgent, containerPanelId],
    queryFn: async () => {
      if (!selectedAgent || !containerPanelId) return null;
      const containers = await api.getContainers(selectedAgent);
      return containers.find((c) =>
        c.container_id === containerPanelId ||
        c.container_id.startsWith(containerPanelId) ||
        c.name === containerPanelId
      ) || null;
    },
    enabled: !!selectedAgent && !!containerPanelId,
  });

  // Fetch detailed container info (with config, resources, etc.)
  const { data: containerDetail } = useQuery({
    queryKey: ["container-inspect", selectedAgent, container?.container_id],
    queryFn: () =>
      selectedAgent && container
        ? api.getContainerDetail(selectedAgent, container.container_id)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!container && (tab === "config" || tab === "details"),
  });

  // Fetch logs
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["containerLogs", selectedAgent, containerPanelId, logsTail],
    queryFn: () =>
      selectedAgent && containerPanelId
        ? api.getContainerLogs(selectedAgent, containerPanelId, logsTail)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!containerPanelId && tab === "logs",
  });

  // Mutations
  const invalidateContainers = () => {
    queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    queryClient.invalidateQueries({ queryKey: ["container-detail", selectedAgent, containerPanelId] });
    queryClient.invalidateQueries({ queryKey: ["container-inspect", selectedAgent] });
  };

  const startMutation = useMutation({
    mutationFn: () => api.startContainer(selectedAgent!, container!.container_id),
    onSuccess: invalidateContainers,
  });

  const stopMutation = useMutation({
    mutationFn: () => api.stopContainer(selectedAgent!, container!.container_id),
    onSuccess: () => {
      invalidateContainers();
      setShowStopModal(false);
    },
  });

  const restartMutation = useMutation({
    mutationFn: () => api.restartContainer(selectedAgent!, container!.container_id),
    onSuccess: () => {
      invalidateContainers();
      setShowRestartModal(false);
    },
  });

  const pauseMutation = useMutation({
    mutationFn: () => api.pauseContainer(selectedAgent!, container!.container_id),
    onSuccess: invalidateContainers,
  });

  const unpauseMutation = useMutation({
    mutationFn: () => api.unpauseContainer(selectedAgent!, container!.container_id),
    onSuccess: invalidateContainers,
  });

  const killMutation = useMutation({
    mutationFn: (signal: string) => api.killContainer(selectedAgent!, container!.container_id, signal),
    onSuccess: () => {
      invalidateContainers();
      setShowKillModal(false);
    },
  });

  const renameMutation = useMutation({
    mutationFn: (name: string) => api.renameContainer(selectedAgent!, container!.container_id, name),
    onSuccess: () => {
      invalidateContainers();
      setShowRenameModal(false);
      setNewName("");
    },
  });

  const updateMutation = useMutation({
    mutationFn: (config: Parameters<typeof api.updateContainer>[2]) =>
      api.updateContainer(selectedAgent!, container!.container_id, config),
    onSuccess: () => {
      invalidateContainers();
      setShowRestartPolicyModal(false);
      setShowResourcesModal(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteContainer(selectedAgent!, container!.container_id, container!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowDeleteModal(false);
      closeContainerPanel();
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  // Initialize form values when container detail loads
  useEffect(() => {
    if (containerDetail?.config) {
      setRestartPolicy(containerDetail.config.restart_policy || "no");
    }
    if (containerDetail?.resources) {
      setMemoryLimit(containerDetail.resources.memory_limit ? String(containerDetail.resources.memory_limit / 1024 / 1024) : "");
      setCpuShares(containerDetail.resources.cpu_shares ? String(containerDetail.resources.cpu_shares) : "");
    }
  }, [containerDetail]);

  return (
    <>
      <SlideOver isOpen={!!containerPanelId} onClose={closeContainerPanel} size="lg">
        {containerLoading ? (
          <div className="flex items-center justify-center h-64">
            <Spinner.Logo size="lg" />
          </div>
        ) : container ? (
          <>
            <SlideOver.Header onClose={closeContainerPanel}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{container.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{container.image}</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-2 mb-6 border-b border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setTab("details")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    tab === "details"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Details
                </button>
                <button
                  onClick={() => setTab("config")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    tab === "config"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Config
                </button>
                <button
                  onClick={() => setTab("logs")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    tab === "logs"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Logs
                </button>
                {container.status === "running" && (
                  <button
                    onClick={() => setTab("terminal")}
                    className={cn(
                      "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                      tab === "terminal"
                        ? "border-primary-600 text-primary-600 dark:text-primary-400"
                        : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                    )}
                  >
                    Terminal
                  </button>
                )}
              </div>

              {tab === "details" && (
                <div className="space-y-6">
                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      {container.status === "running" ? (
                        <>
                          <button
                            onClick={() => pauseMutation.mutate()}
                            disabled={pauseMutation.isPending}
                            className="px-3 py-1.5 text-sm bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded-lg hover:bg-purple-200 dark:hover:bg-purple-900/50 disabled:opacity-50"
                          >
                            <Pause className="h-4 w-4 inline mr-1" />Pause
                          </button>
                          <button
                            onClick={() => setShowStopModal(true)}
                            disabled={stopMutation.isPending}
                            className="px-3 py-1.5 text-sm bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 rounded-lg hover:bg-yellow-200 dark:hover:bg-yellow-900/50 disabled:opacity-50"
                          >
                            <Square className="h-4 w-4 inline mr-1" />Stop
                          </button>
                          <button
                            onClick={() => setShowRestartModal(true)}
                            disabled={restartMutation.isPending}
                            className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50 disabled:opacity-50"
                          >
                            <RotateCcw className="h-4 w-4 inline mr-1" />Restart
                          </button>
                          <button
                            onClick={() => setShowKillModal(true)}
                            className="px-3 py-1.5 text-sm bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded-lg hover:bg-orange-200 dark:hover:bg-orange-900/50"
                          >
                            <Zap className="h-4 w-4 inline mr-1" />Signal
                          </button>
                        </>
                      ) : container.status === "paused" ? (
                        <button
                          onClick={() => unpauseMutation.mutate()}
                          disabled={unpauseMutation.isPending}
                          className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50 disabled:opacity-50"
                        >
                          <Play className="h-4 w-4 inline mr-1" />Unpause
                        </button>
                      ) : (
                        <button
                          onClick={() => startMutation.mutate()}
                          disabled={startMutation.isPending}
                          className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50 disabled:opacity-50"
                        >
                          <Play className="h-4 w-4 inline mr-1" />Start
                        </button>
                      )}
                      <button
                        onClick={() => {
                          setNewName(container.name);
                          setShowRenameModal(true);
                        }}
                        className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
                      >
                        <Edit3 className="h-4 w-4 inline mr-1" />Rename
                      </button>
                      <button
                        onClick={() => router.push(`/docker/containers/${selectedAgent}/${container.container_id}`)}
                        className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
                      >
                        <ExternalLink className="h-4 w-4 inline mr-1" />Full Details
                      </button>
                      <button
                        onClick={() => {
                          setDeleteError(null);
                          setForceDelete(false);
                          setShowDeleteModal(true);
                        }}
                        className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50"
                      >
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
                        <StatusIndicator status={getStatusLevel(container.status)} label={container.status} size="sm" />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Container ID</span>
                        <div className="flex items-center gap-1">
                          <code className="text-sm">{container.container_id.slice(0, 12)}</code>
                          <button
                            onClick={() => handleCopy(container.container_id, "container-id")}
                            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                          >
                            {copied === "container-id" ? (
                              <Check className="h-3 w-3 text-green-500" />
                            ) : (
                              <Copy className="h-3 w-3 text-gray-400" />
                            )}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Image</span>
                        <span className="text-sm text-gray-900 dark:text-white truncate max-w-[200px]">{container.image}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Stack</span>
                        <span className="text-sm text-gray-900 dark:text-white">{container.stack_name || "Standalone"}</span>
                      </div>
                      {containerDetail?.config && (
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Restart Policy</span>
                          <div className="flex items-center gap-2">
                            <Badge size="sm">{containerDetail.config.restart_policy || "no"}</Badge>
                            <button
                              onClick={() => setShowRestartPolicyModal(true)}
                              className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                            >
                              <Settings className="h-3 w-3 text-gray-400" />
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Resources */}
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Resources</h3>
                      <button
                        onClick={() => setShowResourcesModal(true)}
                        className="text-xs text-primary-600 dark:text-primary-400 hover:underline"
                      >
                        Edit Limits
                      </button>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <Cpu className="h-3 w-3" />CPU Usage
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">
                          {container.cpu_percent?.toFixed(1) || 0}%
                        </p>
                        {containerDetail?.resources?.cpu_shares ? (
                          <p className="text-xs text-gray-500">Shares: {containerDetail.resources.cpu_shares}</p>
                        ) : null}
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <MemoryStick className="h-3 w-3" />Memory
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">
                          {container.memory_mb || 0} MB
                        </p>
                        {containerDetail?.resources?.memory_limit ? (
                          <p className="text-xs text-gray-500">Limit: {formatSize(containerDetail.resources.memory_limit)}</p>
                        ) : null}
                      </div>
                    </div>
                  </div>

                  {/* Networks */}
                  {container.networks && container.networks.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Networks</h3>
                      <div className="flex flex-wrap gap-2">
                        {container.networks.map((network) => (
                          <Badge key={network} size="sm">
                            {network}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {tab === "config" && (
                <div className="space-y-4">
                  {containerDetail ? (
                    <>
                      {/* Entrypoint & CMD */}
                      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <Code className="h-4 w-4" />
                          Command
                        </h4>
                        <div className="space-y-3">
                          <div>
                            <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">Entrypoint</span>
                            <code className="text-sm bg-gray-900 text-gray-100 px-2 py-1 rounded block overflow-x-auto">
                              {containerDetail.config.entrypoint?.join(" ") || "(default)"}
                            </code>
                          </div>
                          <div>
                            <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">CMD</span>
                            <code className="text-sm bg-gray-900 text-gray-100 px-2 py-1 rounded block overflow-x-auto">
                              {containerDetail.config.cmd?.join(" ") || "(none)"}
                            </code>
                          </div>
                          {containerDetail.config.working_dir && (
                            <div>
                              <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">Working Dir</span>
                              <code className="text-sm bg-gray-900 text-gray-100 px-2 py-1 rounded">
                                {containerDetail.config.working_dir}
                              </code>
                            </div>
                          )}
                          {containerDetail.config.user && (
                            <div>
                              <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">User</span>
                              <code className="text-sm bg-gray-900 text-gray-100 px-2 py-1 rounded">
                                {containerDetail.config.user}
                              </code>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Environment Variables */}
                      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg overflow-hidden">
                        <button
                          onClick={() => toggleSection("env")}
                          className="w-full flex items-center justify-between p-4 hover:bg-gray-100 dark:hover:bg-gray-700/50"
                        >
                          <h4 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                            <HardDrive className="h-4 w-4" />
                            Environment Variables ({containerDetail.environment?.length || 0})
                          </h4>
                          {expandedSections.has("env") ? (
                            <ChevronDown className="h-4 w-4 text-gray-500" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-gray-500" />
                          )}
                        </button>
                        {expandedSections.has("env") && containerDetail.environment && (
                          <div className="px-4 pb-4 max-h-64 overflow-y-auto">
                            <div className="space-y-1">
                              {containerDetail.environment.map((env, idx) => (
                                <div key={idx} className="flex items-start gap-2 text-xs font-mono">
                                  <span className="text-blue-600 dark:text-blue-400 flex-shrink-0">{env.key}</span>
                                  <span className="text-gray-400">=</span>
                                  <span className="text-gray-700 dark:text-gray-300 break-all">
                                    {env.key.toLowerCase().includes("password") ||
                                    env.key.toLowerCase().includes("secret") ||
                                    env.key.toLowerCase().includes("key")
                                      ? "••••••••"
                                      : env.value}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Resource Limits */}
                      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <Cpu className="h-4 w-4" />
                          Resource Limits
                        </h4>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500 dark:text-gray-400 block text-xs">Memory Limit</span>
                            <span className="text-gray-900 dark:text-white">
                              {containerDetail.resources.memory_limit
                                ? formatSize(containerDetail.resources.memory_limit)
                                : "Unlimited"}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500 dark:text-gray-400 block text-xs">Memory Swap</span>
                            <span className="text-gray-900 dark:text-white">
                              {containerDetail.resources.memory_swap > 0
                                ? formatSize(containerDetail.resources.memory_swap)
                                : "Unlimited"}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500 dark:text-gray-400 block text-xs">CPU Shares</span>
                            <span className="text-gray-900 dark:text-white">
                              {containerDetail.resources.cpu_shares || "Default (1024)"}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500 dark:text-gray-400 block text-xs">CPU Set</span>
                            <span className="text-gray-900 dark:text-white">
                              {containerDetail.resources.cpuset_cpus || "All CPUs"}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500 dark:text-gray-400 block text-xs">PIDs Limit</span>
                            <span className="text-gray-900 dark:text-white">
                              {containerDetail.resources.pids_limit || "Unlimited"}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Container Flags */}
                      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <Settings className="h-4 w-4" />
                          Container Settings
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          {containerDetail.config.privileged && (
                            <Badge color="red" size="sm">
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Privileged
                            </Badge>
                          )}
                          {containerDetail.config.tty && (
                            <Badge size="sm">TTY</Badge>
                          )}
                          {containerDetail.config.open_stdin && (
                            <Badge size="sm">Stdin Open</Badge>
                          )}
                          <Badge size="sm">
                            Restart: {containerDetail.config.restart_policy || "no"}
                          </Badge>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="flex items-center justify-center h-32">
                      <Spinner size="lg" label="Loading config..." />
                    </div>
                  )}
                </div>
              )}

              {tab === "logs" && (
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
                    <button onClick={() => refetchLogs()} className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                      <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                    </button>
                  </div>
                  <div className="flex-1 bg-gray-900 overflow-y-auto min-h-0 px-6">
                    {logsLoading ? (
                      <div className="flex items-center justify-center h-32">
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-500" />
                      </div>
                    ) : logsData?.logs ? (
                      <div className="font-mono text-xs py-2">
                        {logsData.logs
                          .split("\n")
                          .filter((l: string) => l.trim())
                          .map((line: string, idx: number) => (
                            <div key={idx} className="text-gray-300 hover:bg-gray-800/50 py-0.5 px-3 -mx-3">
                              {line}
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="text-center text-gray-500 py-8 text-sm">No logs available</div>
                    )}
                  </div>
                </div>
              )}

              {tab === "terminal" &&
                (container.status !== "running" ? (
                  <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                    <TerminalIcon className="h-8 w-8 mb-2 opacity-50" />
                    <p className="text-sm">Container must be running to access terminal</p>
                  </div>
                ) : (
                  <div className="h-[500px] bg-gray-900 rounded-lg overflow-hidden -mx-6">
                    <Terminal containerId={container.container_id} agentId={selectedAgent!} onClose={() => setTab("details")} />
                  </div>
                ))}
            </SlideOver.Body>
          </>
        ) : (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <p className="text-sm">Container not found</p>
          </div>
        )}
      </SlideOver>

      {/* Confirmation Dialogs */}
      <ConfirmDialog
        isOpen={showStopModal && !!container}
        onClose={() => setShowStopModal(false)}
        onConfirm={() => stopMutation.mutate()}
        title="Stop Container"
        message={`Are you sure you want to stop ${container?.name}?`}
        confirmText="Stop Container"
        variant="warning"
        icon="stop"
        isLoading={stopMutation.isPending}
      />

      <ConfirmDialog
        isOpen={showRestartModal && !!container}
        onClose={() => setShowRestartModal(false)}
        onConfirm={() => restartMutation.mutate()}
        title="Restart Container"
        message={`Are you sure you want to restart ${container?.name}?`}
        confirmText="Restart Container"
        variant="default"
        icon="redeploy"
        isLoading={restartMutation.isPending}
      />

      <ConfirmDialog
        isOpen={showDeleteModal && !!container}
        onClose={() => {
          setShowDeleteModal(false);
          setDeleteError(null);
          setForceDelete(false);
        }}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Container"
        message={`Are you sure you want to delete ${container?.name}?`}
        confirmText="Delete Container"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
        error={deleteError}
      >
        {container?.status === "running" && (
          <label className="flex items-center gap-2 mt-4">
            <input
              type="checkbox"
              checked={forceDelete}
              onChange={(e) => setForceDelete(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="text-sm text-yellow-600">Force delete (container is running)</span>
          </label>
        )}
      </ConfirmDialog>

      {/* Kill/Signal Dialog */}
      <ConfirmDialog
        isOpen={showKillModal && !!container}
        onClose={() => setShowKillModal(false)}
        onConfirm={() => killMutation.mutate(selectedSignal)}
        title="Send Signal"
        message={`Send signal to ${container?.name}?`}
        confirmText={`Send ${selectedSignal}`}
        variant="warning"
        icon="stop"
        isLoading={killMutation.isPending}
      >
        <div className="mt-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Signal
          </label>
          <select
            value={selectedSignal}
            onChange={(e) => setSelectedSignal(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          >
            <option value="SIGTERM">SIGTERM (Graceful)</option>
            <option value="SIGKILL">SIGKILL (Force)</option>
            <option value="SIGHUP">SIGHUP (Reload)</option>
            <option value="SIGUSR1">SIGUSR1</option>
            <option value="SIGUSR2">SIGUSR2</option>
          </select>
        </div>
      </ConfirmDialog>

      {/* Rename Dialog */}
      <ConfirmDialog
        isOpen={showRenameModal && !!container}
        onClose={() => setShowRenameModal(false)}
        onConfirm={() => renameMutation.mutate(newName)}
        title="Rename Container"
        message={`Rename ${container?.name} to:`}
        confirmText="Rename"
        variant="default"
        isLoading={renameMutation.isPending}
      >
        <div className="mt-4">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="New container name"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          />
        </div>
      </ConfirmDialog>

      {/* Restart Policy Dialog */}
      <ConfirmDialog
        isOpen={showRestartPolicyModal && !!container}
        onClose={() => setShowRestartPolicyModal(false)}
        onConfirm={() => updateMutation.mutate({ restart_policy: restartPolicy, max_retries: maxRetries })}
        title="Update Restart Policy"
        message="Configure container restart behavior:"
        confirmText="Update"
        variant="default"
        isLoading={updateMutation.isPending}
      >
        <div className="mt-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Policy
            </label>
            <select
              value={restartPolicy}
              onChange={(e) => setRestartPolicy(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            >
              <option value="no">No - Never restart</option>
              <option value="always">Always - Always restart</option>
              <option value="on-failure">On Failure - Restart on error</option>
              <option value="unless-stopped">Unless Stopped - Restart unless manually stopped</option>
            </select>
          </div>
          {restartPolicy === "on-failure" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Max Retries
              </label>
              <input
                type="number"
                value={maxRetries}
                onChange={(e) => setMaxRetries(parseInt(e.target.value) || 0)}
                min={0}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              />
            </div>
          )}
        </div>
      </ConfirmDialog>

      {/* Resource Limits Dialog */}
      <ConfirmDialog
        isOpen={showResourcesModal && !!container}
        onClose={() => setShowResourcesModal(false)}
        onConfirm={() => updateMutation.mutate({
          memory_limit: memoryLimit ? parseInt(memoryLimit) * 1024 * 1024 : undefined,
          cpu_shares: cpuShares ? parseInt(cpuShares) : undefined,
        })}
        title="Update Resource Limits"
        message="Configure container resource limits:"
        confirmText="Update"
        variant="default"
        isLoading={updateMutation.isPending}
      >
        <div className="mt-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Memory Limit (MB)
            </label>
            <input
              type="number"
              value={memoryLimit}
              onChange={(e) => setMemoryLimit(e.target.value)}
              placeholder="e.g. 512"
              min={0}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            />
            <p className="text-xs text-gray-500 mt-1">Leave empty for unlimited</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              CPU Shares
            </label>
            <input
              type="number"
              value={cpuShares}
              onChange={(e) => setCpuShares(e.target.value)}
              placeholder="e.g. 1024"
              min={0}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            />
            <p className="text-xs text-gray-500 mt-1">Default is 1024. Higher = more CPU priority</p>
          </div>
        </div>
      </ConfirmDialog>
    </>
  );
}
