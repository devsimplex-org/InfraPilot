"use client";

import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Box,
  Plus,
  Trash2,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  Tag,
  Lock,
  ChevronRight,
  Package,
  Copy,
  Download,
  Shield,
  Rocket,
  HardDrive,
  Play,
} from "lucide-react";
import {
  api,
  ContainerRegistry,
  CreateRegistryRequest,
} from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { useDocker } from "@/lib/docker-context";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";
import { Card } from "@/components/ui/Card";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { cn } from "@/lib/utils";

type RegistryProvider = "ghcr" | "dockerhub";

const providerLabels: Record<RegistryProvider, string> = {
  ghcr: "GitHub Container Registry",
  dockerhub: "Docker Hub",
};

export default function DockerRegistriesPage() {
  const queryClient = useQueryClient();
  const { selectedAgent } = useDocker();

  // State
  const [subTab, setSubTab] = useState<"list" | "browse">("list");
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedRegistry, setSelectedRegistry] = useState<ContainerRegistry | null>(null);
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [copiedImage, setCopiedImage] = useState<string | null>(null);
  const [deployTarget, setDeployTarget] = useState<{ imageRef: string; repo: string; tag: string } | null>(null);
  const [deployServiceName, setDeployServiceName] = useState("");
  const [deployEnv, setDeployEnv] = useState<"dev" | "staging" | "prod">("dev");
  const [deployResult, setDeployResult] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: "",
    provider: "ghcr" as RegistryProvider,
    namespace: "",
    token: "",
    username: "",
    password: "",
  });

  // Fetch registries
  const { data: registries, isLoading: registriesLoading } = useQuery({
    queryKey: ["registries"],
    queryFn: () => api.getRegistries(),
  });

  // Fetch images for checking local status
  const { data: images } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && subTab === "browse",
  });

  // Fetch containers for checking running status
  const { data: containers } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () => selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && subTab === "browse",
  });

  // Connected registries
  const connectedRegistries = registries?.filter((r) => r.connection_status === "connected") || [];

  // Fetch repositories for selected registry
  const { data: reposData, isLoading: reposLoading } = useQuery({
    queryKey: ["registry-repositories", selectedRegistry?.id],
    queryFn: () => api.getRegistryRepositories(selectedRegistry!.id),
    enabled: !!selectedRegistry?.id && selectedRegistry.connection_status === "connected" && subTab === "browse",
  });

  // Fetch tags for selected repository
  const { data: tagsData, isLoading: tagsLoading } = useQuery({
    queryKey: ["registry-tags", selectedRegistry?.id, selectedRepo],
    queryFn: () => api.getRegistryTags(selectedRegistry!.id, selectedRepo!),
    enabled: !!selectedRegistry?.id && !!selectedRepo && subTab === "browse",
  });

  // Auto-select first connected registry in browse tab
  useEffect(() => {
    if (subTab === "browse" && connectedRegistries.length > 0 && !selectedRegistry) {
      setSelectedRegistry(connectedRegistries[0]);
    }
  }, [subTab, connectedRegistries, selectedRegistry]);

  // Stats
  const registryStats = {
    total: registries?.length || 0,
    connected: registries?.filter((r) => r.connection_status === "connected").length || 0,
    failed: registries?.filter((r) => r.connection_status === "failed").length || 0,
    pending: registries?.filter((r) => r.connection_status === "pending").length || 0,
  };

  // Helper functions
  const getStatusIndicator = (status: string): "healthy" | "warning" | "degraded" | "critical" => {
    if (status === "connected") return "healthy";
    if (status === "failed") return "critical";
    return "warning";
  };

  const getTagImageRef = (registry: ContainerRegistry, repo: string, tag: string) => {
    if (registry.provider === "ghcr") {
      return `ghcr.io/${registry.namespace}/${repo}:${tag}`;
    } else {
      return `${registry.namespace}/${repo}:${tag}`;
    }
  };

  const isImageLocal = (registry: ContainerRegistry, repo: string, tag: string) => {
    const imageRef = getTagImageRef(registry, repo, tag);
    return images?.some((img) =>
      img.tags.some((t) => t === imageRef || t.includes(`${repo}:${tag}`))
    ) || false;
  };

  const isImageRunning = (registry: ContainerRegistry, repo: string, tag: string) => {
    const imageRef = getTagImageRef(registry, repo, tag);
    return containers?.some((c) =>
      c.image === imageRef || c.image.includes(`${repo}:${tag}`)
    ) || false;
  };

  const copyImageReference = (registry: ContainerRegistry, repo: string, tag: string) => {
    const imageRef = getTagImageRef(registry, repo, tag);
    navigator.clipboard.writeText(imageRef);
    setCopiedImage(imageRef);
    setTimeout(() => setCopiedImage(null), 2000);
  };

  // Mutations
  const createRegistryMutation = useMutation({
    mutationFn: (data: CreateRegistryRequest) => api.createRegistry(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["registries"] });
      setShowAddModal(false);
      setFormData({ name: "", provider: "ghcr", namespace: "", token: "", username: "", password: "" });
    },
  });

  const deleteRegistryMutation = useMutation({
    mutationFn: (id: string) => api.deleteRegistry(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["registries"] });
      if (selectedRegistry?.id === deleteRegistryMutation.variables) {
        setSelectedRegistry(null);
      }
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: (id: string) => api.testRegistryConnection(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["registries"] });
    },
  });

  const deployFromRegistryMutation = useMutation({
    mutationFn: () => {
      if (!deployTarget || !deployServiceName.trim() || !selectedAgent) throw new Error("Missing required fields");
      // Derive tag from imageRef (last part after colon)
      const tag = deployTarget.tag;
      return api.deployService(deployServiceName.trim(), deployEnv, { image_tag: tag });
    },
    onSuccess: (data) => {
      setDeployResult(data.message ?? "Deployment started");
      queryClient.invalidateQueries({ queryKey: ["services"] });
    },
  });

  const handleRegistrySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data: CreateRegistryRequest = {
      name: formData.name,
      provider: formData.provider,
      namespace: formData.namespace,
      ...(formData.provider === "ghcr"
        ? { token: formData.token }
        : { username: formData.username, password: formData.password }),
    };
    createRegistryMutation.mutate(data);
  };

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-6">
      {/* Sub-tabs */}
      <div className="flex items-center justify-between">
        <div className="flex gap-2">
          <button
            onClick={() => setSubTab("list")}
            className={cn(
              "px-4 py-2 text-sm font-medium rounded-lg transition-colors",
              subTab === "list"
                ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
            )}
          >
            Registries ({registryStats.total})
          </button>
          <button
            onClick={() => setSubTab("browse")}
            className={cn(
              "px-4 py-2 text-sm font-medium rounded-lg transition-colors",
              subTab === "browse"
                ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
            )}
          >
            Browse Images ({connectedRegistries.length})
          </button>
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowAddModal(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Registry
        </Button>
      </div>

      {/* Registries List Tab */}
      {subTab === "list" && (
        <>
          <MetricsGrid columns={4}>
            <StatCard label="Total Registries" value={registryStats.total} icon={Box} iconColor="text-primary-600 dark:text-primary-400" />
            <StatCard label="Connected" value={registryStats.connected} icon={CheckCircle} iconColor="text-green-600 dark:text-green-400" />
            <StatCard label="Failed" value={registryStats.failed} icon={XCircle} iconColor="text-red-600 dark:text-red-400" />
            <StatCard label="Pending" value={registryStats.pending} icon={Clock} iconColor="text-yellow-600 dark:text-yellow-400" />
          </MetricsGrid>

          {registriesLoading ? (
            <Spinner.LogoPage label="Loading registries..." />
          ) : registries && registries.length > 0 ? (
            <div className="space-y-4">
              {registries.map((registry) => (
                <Card key={registry.id} className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-gray-100 dark:bg-gray-800 flex items-center justify-center overflow-hidden">
                        {registry.provider === "ghcr" ? (
                          <svg className="w-6 h-6" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                          </svg>
                        ) : (
                          <svg className="w-6 h-6 text-blue-500" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186h-2.12a.186.186 0 00-.185.185v1.888c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288z"/>
                          </svg>
                        )}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">{registry.name}</div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {providerLabels[registry.provider as RegistryProvider]}
                          {registry.namespace && ` - ${registry.namespace}`}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <StatusIndicator status={getStatusIndicator(registry.connection_status)} label={registry.connection_status} size="sm" />
                      {registry.last_connected_at && (
                        <div className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {formatRelativeTime(registry.last_connected_at)}
                        </div>
                      )}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => testConnectionMutation.mutate(registry.id)}
                          disabled={testConnectionMutation.isPending}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
                          title="Test Connection"
                        >
                          <RefreshCw className={cn("h-4 w-4", testConnectionMutation.isPending && "animate-spin")} />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm("Are you sure you want to delete this registry?")) {
                              deleteRegistryMutation.mutate(registry.id);
                            }
                          }}
                          className="p-2 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg transition-colors"
                          title="Delete Registry"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                  {registry.connection_error && (
                    <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 text-sm rounded-lg">
                      {registry.connection_error}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={Box}
              title="No Registries Connected"
              description="Connect to a container registry to browse and deploy images"
              action={
                <Button variant="primary" onClick={() => setShowAddModal(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Add Your First Registry
                </Button>
              }
            />
          )}
        </>
      )}

      {/* Browse Images Tab */}
      {subTab === "browse" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Registry & Repository Selection */}
          <div className="lg:col-span-1 space-y-4">
            <Card className="p-4">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Select Registry</label>
              <select
                value={selectedRegistry?.id || ""}
                onChange={(e) => {
                  const reg = connectedRegistries.find((r) => r.id === e.target.value);
                  setSelectedRegistry(reg || null);
                  setSelectedRepo(null);
                }}
                className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
              >
                {connectedRegistries.length === 0 ? (
                  <option value="">No connected registries</option>
                ) : (
                  connectedRegistries.map((reg) => (
                    <option key={reg.id} value={reg.id}>
                      {reg.name} ({providerLabels[reg.provider as RegistryProvider]})
                    </option>
                  ))
                )}
              </select>
            </Card>

            <Card className="p-4">
              <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Repositories</h3>
              {reposLoading ? (
                <div className="flex items-center justify-center h-32"><Spinner /></div>
              ) : reposData?.repositories && reposData.repositories.length > 0 ? (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {reposData.repositories.map((repo) => (
                    <button
                      key={repo.name}
                      onClick={() => setSelectedRepo(repo.name)}
                      className={cn(
                        "w-full p-3 text-left rounded-lg transition-colors flex items-center justify-between",
                        selectedRepo === repo.name
                          ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                          : "hover:bg-gray-100 dark:hover:bg-gray-800"
                      )}
                    >
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white text-sm">{repo.name}</div>
                        {repo.description && (
                          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-[180px]">{repo.description}</div>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {repo.is_private && <Lock className="h-3 w-3 text-gray-400" />}
                        <ChevronRight className="h-4 w-4 text-gray-400" />
                      </div>
                    </button>
                  ))}
                </div>
              ) : selectedRegistry ? (
                <div className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">No repositories found</div>
              ) : (
                <div className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">Select a registry to view repositories</div>
              )}
            </Card>
          </div>

          {/* Tags Panel */}
          <div className="lg:col-span-2">
            <Card className="p-4 h-full">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    {selectedRepo ? `Tags for ${selectedRepo}` : "Image Tags"}
                  </h3>
                  {selectedRepo && tagsData?.tags && tagsData.tags.length > 0 && (
                    <Badge size="sm">{tagsData.total_count || 0} tags</Badge>
                  )}
                </div>
              </div>

              {tagsLoading ? (
                <div className="flex items-center justify-center h-64"><Spinner /></div>
              ) : tagsData?.tags && tagsData.tags.length > 0 ? (
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {tagsData.tags.map((tag) => {
                    const isLocal = selectedRegistry && selectedRepo ? isImageLocal(selectedRegistry, selectedRepo, tag.name) : false;
                    const isRunning = selectedRegistry && selectedRepo ? isImageRunning(selectedRegistry, selectedRepo, tag.name) : false;
                    const imageRef = selectedRegistry && selectedRepo ? getTagImageRef(selectedRegistry, selectedRepo, tag.name) : "";

                    return (
                      <div
                        key={tag.name}
                        className={cn(
                          "p-3 rounded-lg flex items-center justify-between group",
                          isRunning ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
                            : isLocal ? "bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800/50"
                            : "bg-gray-50 dark:bg-gray-800"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <Tag className={cn("h-4 w-4", isRunning ? "text-green-600" : isLocal ? "text-blue-600" : "text-gray-400")} />
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-sm text-gray-900 dark:text-white">{tag.name}</span>
                              {isRunning && (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400 text-xs font-medium rounded-full">
                                  <Play className="h-2.5 w-2.5 fill-current" />Running
                                </span>
                              )}
                              {isLocal && !isRunning && (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-400 text-xs font-medium rounded-full">
                                  <HardDrive className="h-2.5 w-2.5" />Local
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                              {tag.size_bytes > 0 && <span>{(tag.size_bytes / 1024 / 1024).toFixed(1)} MB</span>}
                              {tag.pushed_at && <span>{formatRelativeTime(tag.pushed_at)}</span>}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={(e) => { e.stopPropagation(); if (selectedRegistry && selectedRepo) copyImageReference(selectedRegistry, selectedRepo, tag.name); }}
                            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                            title="Copy image reference"
                          >
                            {copiedImage === imageRef ? <CheckCircle className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (selectedRegistry && selectedRepo) {
                                setDeployTarget({ imageRef, repo: selectedRepo, tag: tag.name });
                                setDeployServiceName(selectedRepo.split("/").pop() ?? selectedRepo);
                                setDeployResult(null);
                                deployFromRegistryMutation.reset();
                              }
                            }}
                            className="p-2 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400"
                            title="Deploy this image"
                          >
                            <Rocket className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : selectedRepo ? (
                <div className="flex flex-col items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  <Tag className="h-8 w-8 mb-2" />
                  <p className="text-sm">No tags found</p>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  <Package className="h-8 w-8 mb-2" />
                  <p className="text-sm">Select a repository to view tags</p>
                </div>
              )}
            </Card>
          </div>
        </div>
      )}

      {/* Add Registry Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Add Container Registry</h2>
            <form onSubmit={handleRegistrySubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                  placeholder="My Registry"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Provider</label>
                <select
                  value={formData.provider}
                  onChange={(e) => setFormData({ ...formData, provider: e.target.value as RegistryProvider })}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                >
                  <option value="ghcr">GitHub Container Registry (ghcr.io)</option>
                  <option value="dockerhub">Docker Hub</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Namespace (Username/Organization)</label>
                <input
                  type="text"
                  value={formData.namespace}
                  onChange={(e) => setFormData({ ...formData, namespace: e.target.value })}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                  placeholder="my-org"
                />
              </div>
              {formData.provider === "ghcr" ? (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Personal Access Token</label>
                  <input
                    type="password"
                    value={formData.token}
                    onChange={(e) => setFormData({ ...formData, token: e.target.value })}
                    className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                    placeholder="ghp_xxxxxxxxxxxx"
                    required
                  />
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Token needs <code className="px-1 bg-gray-100 dark:bg-gray-800 rounded">read:packages</code> scope
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
                    <input
                      type="text"
                      value={formData.username}
                      onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                      placeholder="dockerhub-username"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password / Access Token</label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                      placeholder="dckr_pat_xxxxxxxxxxxx"
                      required
                    />
                  </div>
                </>
              )}
              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowAddModal(false);
                    setFormData({ name: "", provider: "ghcr", namespace: "", token: "", username: "", password: "" });
                  }}
                  className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createRegistryMutation.isPending}
                  className="flex-1 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {createRegistryMutation.isPending ? <Spinner size="sm" /> : <><Plus className="h-4 w-4" />Add Registry</>}
                </button>
              </div>
              {createRegistryMutation.isError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 text-sm rounded-lg">
                  {(createRegistryMutation.error as Error).message || "Failed to create registry"}
                </div>
              )}
            </form>
          </div>
        </div>
      )}
      {/* Deploy from Registry Modal */}
      {deployTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { if (!deployFromRegistryMutation.isPending) { setDeployTarget(null); setDeployResult(null); deployFromRegistryMutation.reset(); } }} />
          <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Rocket className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Deploy Image</h3>
                <p className="text-xs font-mono text-gray-500 dark:text-gray-400 truncate max-w-[280px]">{deployTarget.imageRef}</p>
              </div>
            </div>

            {deployResult ? (
              <div className="text-center py-4">
                <CheckCircle className="h-10 w-10 text-green-500 mx-auto mb-3" />
                <p className="font-medium text-gray-900 dark:text-white mb-1">Deployment started</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">{deployResult}</p>
                <button
                  onClick={() => { setDeployTarget(null); setDeployResult(null); deployFromRegistryMutation.reset(); }}
                  className="mt-5 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg text-sm font-medium"
                >
                  Close
                </button>
              </div>
            ) : (
              <>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Service Name</label>
                    <input
                      type="text"
                      value={deployServiceName}
                      onChange={(e) => setDeployServiceName(e.target.value)}
                      placeholder="e.g. my-app"
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-400 mt-1">Creates or updates the service definition</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Environment</label>
                    <div className="flex gap-2">
                      {(["dev", "staging", "prod"] as const).map((env) => (
                        <button
                          key={env}
                          type="button"
                          onClick={() => setDeployEnv(env)}
                          className={cn(
                            "flex-1 py-2 text-sm font-medium rounded-lg border transition-colors",
                            deployEnv === env
                              ? "bg-primary-600 border-primary-600 text-white"
                              : "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-primary-400"
                          )}
                        >
                          {env}
                        </button>
                      ))}
                    </div>
                  </div>
                  {deployFromRegistryMutation.isError && (
                    <p className="text-sm text-red-600 dark:text-red-400">
                      {(deployFromRegistryMutation.error as Error)?.message ?? "Deploy failed"}
                    </p>
                  )}
                </div>
                <div className="flex justify-end gap-3 mt-6">
                  <button
                    onClick={() => { setDeployTarget(null); setDeployResult(null); deployFromRegistryMutation.reset(); }}
                    className="px-4 py-2 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => deployFromRegistryMutation.mutate()}
                    disabled={deployFromRegistryMutation.isPending || !deployServiceName.trim() || !selectedAgent}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium disabled:opacity-50"
                  >
                    {deployFromRegistryMutation.isPending ? (
                      <><RefreshCw className="h-4 w-4 animate-spin" />Deploying...</>
                    ) : (
                      <><Rocket className="h-4 w-4" />Deploy</>
                    )}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
