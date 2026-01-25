"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  Image as ImageIcon,
  HardDrive,
  Network,
  Play,
  Square,
  Layers,
  Cpu,
  MemoryStick,
  Server,
  Box,
  RotateCcw,
  RefreshCw,
  Copy,
  Check,
  Trash2,
  ExternalLink,
  Terminal as TerminalIcon,
  FileText,
  Globe,
  FolderOpen,
} from "lucide-react";
import { api, Container, DockerImage, DockerVolume, DockerNetwork } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Tabs, Button } from "@/components/ui/page-layout";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Terminal } from "@/components/containers/Terminal";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "containers", label: "Containers" },
  { id: "images", label: "Images" },
  { id: "volumes", label: "Volumes" },
  { id: "networks", label: "Networks" },
];

type ContainerPanelTab = "details" | "logs" | "terminal";

export default function DockerPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const validTabIds = tabs.map(t => t.id);

  // Get initial tab from URL hash
  const getTabFromHash = () => {
    if (typeof window === "undefined") return "overview";
    const hash = window.location.hash.replace("#", "");
    return validTabIds.includes(hash) ? hash : "overview";
  };

  const [activeTab, setActiveTab] = useState(getTabFromHash);
  const [selectedAgent, setSelectedAgent] = useState<string>("");

  // Selected items for slide-over panels
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [selectedImage, setSelectedImage] = useState<DockerImage | null>(null);
  const [selectedVolume, setSelectedVolume] = useState<DockerVolume | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<DockerNetwork | null>(null);

  // Panel tabs and state
  const [containerPanelTab, setContainerPanelTab] = useState<ContainerPanelTab>("details");
  const [logsTail, setLogsTail] = useState(100);
  const [copied, setCopied] = useState<string | null>(null);

  // Delete modals
  const [showDeleteContainerModal, setShowDeleteContainerModal] = useState(false);
  const [showDeleteImageModal, setShowDeleteImageModal] = useState(false);
  const [showDeleteVolumeModal, setShowDeleteVolumeModal] = useState(false);
  const [showDeleteNetworkModal, setShowDeleteNetworkModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);

  // Container action modals
  const [showStopModal, setShowStopModal] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);

  // Sync tab with URL hash
  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", `#${activeTab}`);
    }

    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      if (validTabIds.includes(hash) && hash !== activeTab) {
        setActiveTab(hash);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [activeTab, validTabIds]);

  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    window.history.pushState(null, "", `#${tabId}`);
  };

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  // Fetch containers
  const { data: containers, isLoading: loadingContainers } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () => selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "containers"),
  });

  // Fetch images
  const { data: images, isLoading: loadingImages } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "images"),
  });

  // Fetch volumes
  const { data: volumes, isLoading: loadingVolumes } = useQuery({
    queryKey: ["docker-volumes", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerVolumes(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "volumes"),
  });

  // Fetch networks
  const { data: networks, isLoading: loadingNetworks } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "networks"),
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

  // Container mutations
  const startMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.startContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    },
  });

  const stopMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.stopContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowStopModal(false);
    },
  });

  const restartMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.restartContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowRestartModal(false);
    },
  });

  const deleteContainerMutation = useMutation({
    mutationFn: () =>
      api.deleteContainer(selectedAgent, selectedContainer!.container_id, selectedContainer!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowDeleteContainerModal(false);
      setSelectedContainer(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Image mutations
  const deleteImageMutation = useMutation({
    mutationFn: () => api.deleteDockerImage(selectedAgent, selectedImage!.id, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
      setShowDeleteImageModal(false);
      setSelectedImage(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Volume mutations
  const deleteVolumeMutation = useMutation({
    mutationFn: () => api.deleteDockerVolume(selectedAgent, selectedVolume!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowDeleteVolumeModal(false);
      setSelectedVolume(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Network mutations
  const deleteNetworkMutation = useMutation({
    mutationFn: () => api.deleteDockerNetwork(selectedAgent, selectedNetwork!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowDeleteNetworkModal(false);
      setSelectedNetwork(null);
      setDeleteError(null);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Update selected container from fresh data
  useEffect(() => {
    if (selectedContainer && containers) {
      const updated = containers.find(c => c.container_id === selectedContainer.container_id);
      if (updated) setSelectedContainer(updated);
    }
  }, [containers, selectedContainer]);

  // Metrics
  const containerMetrics = {
    total: containers?.length || 0,
    running: containers?.filter(c => c.status === "running").length || 0,
    stopped: containers?.filter(c => c.status === "exited").length || 0,
  };

  const imageMetrics = {
    total: images?.length || 0,
    totalSize: images?.reduce((sum, img) => sum + img.size, 0) || 0,
  };

  const volumeMetrics = {
    total: volumes?.length || 0,
    inUse: volumes?.filter((v) => v.used_by.length > 0).length || 0,
  };

  const networkMetrics = {
    total: networks?.length || 0,
    bridge: networks?.filter((n) => n.driver === "bridge").length || 0,
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const getStatusLevel = (status: string) => {
    if (status === "running") return "healthy";
    if (status === "exited") return "critical";
    if (status === "paused") return "warning";
    return "degraded";
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Table columns
  const containerColumns = [
    {
      key: "status",
      header: "Status",
      width: "100px",
      render: (value: string) => (
        <StatusIndicator status={getStatusLevel(value)} label={value} size="sm" />
      ),
    },
    {
      key: "name",
      header: "Name",
      render: (value: string, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-[200px]">{row.image}</div>
        </div>
      ),
    },
    {
      key: "cpu_percent",
      header: "CPU",
      align: "right" as const,
      render: (value: number) => <span className="text-sm">{value?.toFixed(1) || 0}%</span>,
    },
    {
      key: "memory_mb",
      header: "Memory",
      align: "right" as const,
      render: (value: number) => <span className="text-sm">{value || 0} MB</span>,
    },
  ];

  const imageColumns = [
    {
      key: "image_name",
      header: "Name",
      render: (_: unknown, row: DockerImage) => {
        const name = row.tags.length > 0 ? row.tags[0].split(":")[0] : "<none>";
        return (
          <div className="flex items-center gap-2">
            <ImageIcon className="h-4 w-4 text-gray-400" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">{name}</div>
              <div className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</div>
            </div>
          </div>
        );
      },
    },
    {
      key: "image_tag",
      header: "Tag",
      render: (_: unknown, row: DockerImage) => {
        if (row.tags.length === 0) return <span className="text-gray-400">-</span>;
        const tag = row.tags[0].includes(":") ? row.tags[0].split(":")[1] : "latest";
        return (
          <Badge className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">
            {tag}
          </Badge>
        );
      },
    },
    {
      key: "size",
      header: "Size",
      align: "right" as const,
      render: (value: number) => <span className="text-sm">{formatSize(value)}</span>,
    },
  ];

  const volumeColumns = [
    {
      key: "name",
      header: "Name",
      render: (value: string, row: DockerVolume) => (
        <div className="flex items-center gap-2">
          <HardDrive className="h-4 w-4 text-gray-400" />
          <div>
            <div className="font-medium text-gray-900 dark:text-white truncate max-w-[200px]">{value}</div>
            <div className="text-xs text-gray-500">{row.driver} driver</div>
          </div>
        </div>
      ),
    },
    {
      key: "used_by",
      header: "In Use",
      align: "center" as const,
      render: (value: string[]) => {
        return value.length > 0 ? (
          <Badge className="px-2 py-0.5 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
            {value.length} container{value.length !== 1 ? "s" : ""}
          </Badge>
        ) : (
          <span className="text-gray-400 text-xs">Unused</span>
        );
      },
    },
  ];

  const networkColumns = [
    {
      key: "name",
      header: "Name",
      render: (value: string, row: DockerNetwork) => (
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-gray-400" />
          <div>
            <div className="font-medium text-gray-900 dark:text-white">{value}</div>
            <div className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</div>
          </div>
        </div>
      ),
    },
    {
      key: "driver",
      header: "Driver",
      render: (value: string) => (
        <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">
          {value}
        </Badge>
      ),
    },
    {
      key: "containers",
      header: "Containers",
      align: "center" as const,
      render: (value: Record<string, string>) => (
        <span className="text-sm">{Object.keys(value || {}).length}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <Breadcrumb items={[{ label: "Run", href: "/" }, { label: "Docker" }]} />

      <PageHeader
        title="Docker"
        description="Manage containers, images, volumes, and networks"
        action={
          activeAgents.length > 0 && (
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
            >
              {activeAgents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name} ({agent.hostname || "unknown host"})
                </option>
              ))}
            </select>
          )
        }
      />

      <Tabs tabs={tabs} activeTab={activeTab} onChange={handleTabChange} />

      {!selectedAgent ? (
        <EmptyState icon={Server} title="No agents available" description="Add an agent to manage Docker resources" />
      ) : (
        <>
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              <MetricsGrid columns={4}>
                <StatCard label="Containers" value={containerMetrics.total} icon={ContainerIcon} description={`${containerMetrics.running} running`} iconColor="text-blue-600 dark:text-blue-400" onClick={() => handleTabChange("containers")} />
                <StatCard label="Images" value={imageMetrics.total} icon={ImageIcon} description={formatSize(imageMetrics.totalSize)} iconColor="text-purple-600 dark:text-purple-400" onClick={() => handleTabChange("images")} />
                <StatCard label="Volumes" value={volumeMetrics.total} icon={HardDrive} description={`${volumeMetrics.inUse} in use`} iconColor="text-green-600 dark:text-green-400" onClick={() => handleTabChange("volumes")} />
                <StatCard label="Networks" value={networkMetrics.total} icon={Network} description={`${networkMetrics.bridge} bridge`} iconColor="text-orange-600 dark:text-orange-400" onClick={() => handleTabChange("networks")} />
              </MetricsGrid>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Containers Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Containers</h3>
                    <button onClick={() => handleTabChange("containers")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingContainers ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : containers && containers.length > 0 ? (
                    <Table data={containers.slice(0, 5)} columns={containerColumns} keyExtractor={(row) => row.container_id} onRowClick={(row) => { setSelectedContainer(row); setContainerPanelTab("details"); }} hoverable />
                  ) : (
                    <EmptyState icon={ContainerIcon} title="No containers" description="No containers are running on this agent" />
                  )}
                </div>

                {/* Images Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Images</h3>
                    <button onClick={() => handleTabChange("images")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingImages ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : images && images.length > 0 ? (
                    <Table data={images.slice(0, 5)} columns={imageColumns} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedImage(row)} hoverable />
                  ) : (
                    <EmptyState icon={ImageIcon} title="No images" description="No images are available on this agent" />
                  )}
                </div>

                {/* Volumes Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Volumes</h3>
                    <button onClick={() => handleTabChange("volumes")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingVolumes ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : volumes && volumes.length > 0 ? (
                    <Table data={volumes.slice(0, 5)} columns={volumeColumns} keyExtractor={(row) => row.name} onRowClick={(row) => setSelectedVolume(row)} hoverable />
                  ) : (
                    <EmptyState icon={HardDrive} title="No volumes" description="No volumes are configured on this agent" />
                  )}
                </div>

                {/* Networks Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Networks</h3>
                    <button onClick={() => handleTabChange("networks")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingNetworks ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : networks && networks.length > 0 ? (
                    <Table data={networks.slice(0, 5)} columns={networkColumns} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedNetwork(row)} hoverable />
                  ) : (
                    <EmptyState icon={Network} title="No networks" description="No networks are configured on this agent" />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Containers Tab */}
          {activeTab === "containers" && (
            <div className="space-y-4">
              <MetricsGrid columns={4}>
                <StatCard label="Total" value={containerMetrics.total} icon={ContainerIcon} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Running" value={containerMetrics.running} icon={Play} iconColor="text-green-600 dark:text-green-400" />
                <StatCard label="Stopped" value={containerMetrics.stopped} icon={Square} iconColor="text-red-600 dark:text-red-400" />
                <StatCard label="CPU Usage" value={`${(containers?.reduce((sum, c) => sum + (c.cpu_percent || 0), 0) || 0).toFixed(1)}%`} icon={Cpu} iconColor="text-purple-600 dark:text-purple-400" />
              </MetricsGrid>

              {loadingContainers ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : containers && containers.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table data={containers} columns={containerColumns} keyExtractor={(row) => row.container_id} onRowClick={(row) => { setSelectedContainer(row); setContainerPanelTab("details"); }} hoverable />
                </div>
              ) : (
                <EmptyState icon={ContainerIcon} title="No containers" description="No containers are running on this agent" />
              )}
            </div>
          )}

          {/* Images Tab */}
          {activeTab === "images" && (
            <div className="space-y-4">
              <MetricsGrid columns={3}>
                <StatCard label="Total Images" value={imageMetrics.total} icon={ImageIcon} iconColor="text-purple-600 dark:text-purple-400" />
                <StatCard label="Total Size" value={formatSize(imageMetrics.totalSize)} icon={HardDrive} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="In Use" value={images?.filter(img => img.used_by && img.used_by.length > 0).length || 0} icon={Layers} iconColor="text-green-600 dark:text-green-400" />
              </MetricsGrid>

              {loadingImages ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : images && images.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table data={images} columns={imageColumns} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedImage(row)} hoverable />
                </div>
              ) : (
                <EmptyState icon={ImageIcon} title="No images" description="No images are available on this agent" />
              )}
            </div>
          )}

          {/* Volumes Tab */}
          {activeTab === "volumes" && (
            <div className="space-y-4">
              <MetricsGrid columns={3}>
                <StatCard label="Total Volumes" value={volumeMetrics.total} icon={HardDrive} iconColor="text-green-600 dark:text-green-400" />
                <StatCard label="In Use" value={volumeMetrics.inUse} icon={Layers} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Unused" value={volumeMetrics.total - volumeMetrics.inUse} icon={Box} iconColor="text-gray-600 dark:text-gray-400" />
              </MetricsGrid>

              {loadingVolumes ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : volumes && volumes.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table data={volumes} columns={volumeColumns} keyExtractor={(row) => row.name} onRowClick={(row) => setSelectedVolume(row)} hoverable />
                </div>
              ) : (
                <EmptyState icon={HardDrive} title="No volumes" description="No volumes are configured on this agent" />
              )}
            </div>
          )}

          {/* Networks Tab */}
          {activeTab === "networks" && (
            <div className="space-y-4">
              <MetricsGrid columns={3}>
                <StatCard label="Total Networks" value={networkMetrics.total} icon={Network} iconColor="text-orange-600 dark:text-orange-400" />
                <StatCard label="Bridge" value={networkMetrics.bridge} icon={Network} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Other" value={networkMetrics.total - networkMetrics.bridge} icon={Network} iconColor="text-purple-600 dark:text-purple-400" />
              </MetricsGrid>

              {loadingNetworks ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : networks && networks.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table data={networks} columns={networkColumns} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedNetwork(row)} hoverable />
                </div>
              ) : (
                <EmptyState icon={Network} title="No networks" description="No networks are configured on this agent" />
              )}
            </div>
          )}
        </>
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
                    <Terminal containerId={selectedContainer.container_id} agentId={selectedAgent} onClose={() => setContainerPanelTab("details")} />
                  </div>
                )
              )}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Image SlideOver */}
      <SlideOver isOpen={!!selectedImage} onClose={() => setSelectedImage(null)} size="md">
        {selectedImage && (
          <>
            <SlideOver.Header onClose={() => setSelectedImage(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedImage.tags.length > 0 ? selectedImage.tags[0].split(":")[0] : "<none>"}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 font-mono mt-1">{selectedImage.id.slice(0, 12)}</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <button onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteImageModal(true); }} className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50">
                    <Trash2 className="h-4 w-4 inline mr-1" />Delete Image
                  </button>
                </div>

                {/* Image Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Image Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                      <div className="flex items-center gap-1">
                        <code className="text-sm">{selectedImage.id.slice(0, 12)}</code>
                        <button onClick={() => handleCopy(selectedImage.id, "image-id")} className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded">
                          {copied === "image-id" ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Size</span>
                      <span className="text-sm text-gray-900 dark:text-white">{formatSize(selectedImage.size)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                      <span className="text-sm text-gray-900 dark:text-white">{new Date(selectedImage.created).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                {/* Tags */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Tags</h3>
                  {selectedImage.tags.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {selectedImage.tags.map((tag, idx) => (
                        <Badge key={idx} className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">{tag}</Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">No tags</span>
                  )}
                </div>

                {/* In Use By */}
                {selectedImage.used_by && selectedImage.used_by.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Used by Containers</h3>
                    <div className="space-y-2">
                      {selectedImage.used_by.map((containerName: string, idx: number) => (
                        <div key={idx} className="text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-3 py-2 rounded">{containerName}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Volume SlideOver */}
      <SlideOver isOpen={!!selectedVolume} onClose={() => setSelectedVolume(null)} size="md">
        {selectedVolume && (
          <>
            <SlideOver.Header onClose={() => setSelectedVolume(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white truncate max-w-[300px]">{selectedVolume.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedVolume.driver} driver</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <button onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteVolumeModal(true); }} disabled={selectedVolume.used_by.length > 0} className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50 disabled:opacity-50">
                    <Trash2 className="h-4 w-4 inline mr-1" />Delete Volume
                  </button>
                  {selectedVolume.used_by.length > 0 && <p className="text-xs text-gray-500 mt-2">Cannot delete volume that is in use</p>}
                </div>

                {/* Volume Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Volume Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                      <span className="text-sm text-gray-900 dark:text-white font-mono truncate max-w-[200px]">{selectedVolume.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.driver}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Mountpoint</span>
                      <span className="text-sm text-gray-900 dark:text-white font-mono truncate max-w-[200px]">{selectedVolume.mountpoint}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.scope}</span>
                    </div>
                  </div>
                </div>

                {/* Used By */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Used by Containers</h3>
                  {selectedVolume.used_by.length > 0 ? (
                    <div className="space-y-2">
                      {selectedVolume.used_by.map((containerName, idx) => (
                        <div key={idx} className="text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-3 py-2 rounded">{containerName}</div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">Not in use</span>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Network SlideOver */}
      <SlideOver isOpen={!!selectedNetwork} onClose={() => setSelectedNetwork(null)} size="md">
        {selectedNetwork && (
          <>
            <SlideOver.Header onClose={() => setSelectedNetwork(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedNetwork.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedNetwork.driver} network</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <button onClick={() => { setDeleteError(null); setShowDeleteNetworkModal(true); }} disabled={Object.keys(selectedNetwork.containers || {}).length > 0} className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50 disabled:opacity-50">
                    <Trash2 className="h-4 w-4 inline mr-1" />Delete Network
                  </button>
                  {Object.keys(selectedNetwork.containers || {}).length > 0 && <p className="text-xs text-gray-500 mt-2">Cannot delete network with connected containers</p>}
                </div>

                {/* Network Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Network Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.name}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                      <div className="flex items-center gap-1">
                        <code className="text-sm">{selectedNetwork.id.slice(0, 12)}</code>
                        <button onClick={() => handleCopy(selectedNetwork.id, "network-id")} className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded">
                          {copied === "network-id" ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                      <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">{selectedNetwork.driver}</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.scope}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Internal</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.internal ? "Yes" : "No"}</span>
                    </div>
                  </div>
                </div>

                {/* Connected Containers */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Connected Containers</h3>
                  {Object.entries(selectedNetwork.containers || {}).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(selectedNetwork.containers).map(([id, name]) => (
                        <div key={id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium text-gray-900 dark:text-white">{name}</span>
                          </div>
                          <span className="text-xs text-gray-500 font-mono">{id.slice(0, 12)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">No containers connected</span>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Confirmation Dialogs */}
      <ConfirmDialog isOpen={showStopModal && !!selectedContainer} onClose={() => setShowStopModal(false)} onConfirm={() => stopMutation.mutate({ containerId: selectedContainer!.container_id })} title="Stop Container" message={`Are you sure you want to stop ${selectedContainer?.name}?`} confirmText="Stop Container" variant="warning" icon="stop" isLoading={stopMutation.isPending} />

      <ConfirmDialog isOpen={showRestartModal && !!selectedContainer} onClose={() => setShowRestartModal(false)} onConfirm={() => restartMutation.mutate({ containerId: selectedContainer!.container_id })} title="Restart Container" message={`Are you sure you want to restart ${selectedContainer?.name}?`} confirmText="Restart Container" variant="default" icon="redeploy" isLoading={restartMutation.isPending} />

      <ConfirmDialog isOpen={showDeleteContainerModal && !!selectedContainer} onClose={() => { setShowDeleteContainerModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteContainerMutation.mutate()} title="Delete Container" message="This action cannot be undone." confirmText="Delete Container" variant="danger" icon="delete" isLoading={deleteContainerMutation.isPending} confirmLevel="name" confirmValue={selectedContainer?.name} error={deleteError} onInputChange={() => {}}>
        {selectedContainer?.status === "running" && (
          <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
            Force delete (stop container first)
          </label>
        )}
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteImageModal && !!selectedImage} onClose={() => { setShowDeleteImageModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteImageMutation.mutate()} title="Delete Image" message={`Are you sure you want to delete this image?`} confirmText="Delete Image" variant="danger" icon="delete" isLoading={deleteImageMutation.isPending} error={deleteError}>
        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
          Force delete (remove even if in use)
        </label>
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteVolumeModal && !!selectedVolume} onClose={() => { setShowDeleteVolumeModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteVolumeMutation.mutate()} title="Delete Volume" message={`Are you sure you want to delete volume "${selectedVolume?.name}"?`} confirmText="Delete Volume" variant="danger" icon="delete" isLoading={deleteVolumeMutation.isPending} error={deleteError}>
        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
          Force delete
        </label>
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteNetworkModal && !!selectedNetwork} onClose={() => { setShowDeleteNetworkModal(false); setDeleteError(null); }} onConfirm={() => deleteNetworkMutation.mutate()} title="Delete Network" message={`Are you sure you want to delete network "${selectedNetwork?.name}"?`} confirmText="Delete Network" variant="danger" icon="delete" isLoading={deleteNetworkMutation.isPending} error={deleteError} />
    </div>
  );
}
