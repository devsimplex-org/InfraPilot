"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
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
  Tag,
  Server,
  ExternalLink,
  Box,
} from "lucide-react";
import { api, Container, DockerImage, DockerVolume, DockerNetwork } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Tabs } from "@/components/ui/page-layout";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "containers", label: "Containers" },
  { id: "images", label: "Images" },
  { id: "volumes", label: "Volumes" },
  { id: "networks", label: "Networks" },
];

export default function DockerPage() {
  const router = useRouter();
  const validTabIds = tabs.map(t => t.id);

  // Get initial tab from URL hash
  const getTabFromHash = () => {
    if (typeof window === "undefined") return "overview";
    const hash = window.location.hash.replace("#", "");
    return validTabIds.includes(hash) ? hash : "overview";
  };

  const [activeTab, setActiveTab] = useState(getTabFromHash);
  const [selectedAgent, setSelectedAgent] = useState<string>("");

  // Sync tab with URL hash
  useEffect(() => {
    // Set initial hash if not present
    if (!window.location.hash) {
      window.history.replaceState(null, "", `#${activeTab}`);
    }

    // Listen for hash changes (browser back/forward)
    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      if (validTabIds.includes(hash) && hash !== activeTab) {
        setActiveTab(hash);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [activeTab, validTabIds]);

  // Update URL when tab changes
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

  // Auto-select first active agent
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

  // Calculate metrics
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

  // Container table columns
  const containerColumns = [
    {
      key: "status",
      header: "Status",
      width: "100px",
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
      header: "Name",
      render: (value: string, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-[200px]">
            {row.image}
          </div>
        </div>
      ),
    },
    {
      key: "cpu_percent",
      header: "CPU",
      align: "right" as const,
      render: (value: number) => (
        <span className="text-sm">{value?.toFixed(1) || 0}%</span>
      ),
    },
    {
      key: "memory_mb",
      header: "Memory",
      align: "right" as const,
      render: (value: number) => (
        <span className="text-sm">{value || 0} MB</span>
      ),
    },
  ];

  // Image table columns
  const imageColumns = [
    {
      key: "tags",
      header: "Name",
      render: (value: string[], row: DockerImage) => {
        const name = value.length > 0 ? value[0].split(":")[0] : "<none>";
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
      key: "tags",
      header: "Tag",
      render: (value: string[]) => {
        if (value.length === 0) return <span className="text-gray-400">-</span>;
        const tag = value[0].includes(":") ? value[0].split(":")[1] : "latest";
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

  // Volume table columns
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

  // Network table columns
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
      {/* Breadcrumb */}
      <Breadcrumb
        items={[
          { label: "Run", href: "/" },
          { label: "Docker" },
        ]}
      />

      {/* Header */}
      <PageHeader
        title="Docker Overview"
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

      {/* Tabs */}
      <Tabs tabs={tabs} activeTab={activeTab} onChange={handleTabChange} />

      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker resources"
        />
      ) : (
        <>
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Metrics Grid */}
              <MetricsGrid columns={4}>
                <StatCard
                  label="Containers"
                  value={containerMetrics.total}
                  icon={ContainerIcon}
                  description={`${containerMetrics.running} running`}
                  iconColor="text-blue-600 dark:text-blue-400"
                  onClick={() => router.push("/docker/containers")}
                />
                <StatCard
                  label="Images"
                  value={imageMetrics.total}
                  icon={ImageIcon}
                  description={formatSize(imageMetrics.totalSize)}
                  iconColor="text-purple-600 dark:text-purple-400"
                  onClick={() => router.push("/docker/images")}
                />
                <StatCard
                  label="Volumes"
                  value={volumeMetrics.total}
                  icon={HardDrive}
                  description={`${volumeMetrics.inUse} in use`}
                  iconColor="text-green-600 dark:text-green-400"
                  onClick={() => router.push("/docker/volumes")}
                />
                <StatCard
                  label="Networks"
                  value={networkMetrics.total}
                  icon={Network}
                  description={`${networkMetrics.bridge} bridge`}
                  iconColor="text-orange-600 dark:text-orange-400"
                  onClick={() => router.push("/docker/networks")}
                />
              </MetricsGrid>

              {/* Resource Summaries */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Containers Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Containers</h3>
                    <button
                      onClick={() => router.push("/docker/containers")}
                      className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                    >
                      View all
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                  {loadingContainers ? (
                    <div className="flex items-center justify-center h-32">
                      <Spinner size="md" />
                    </div>
                  ) : containers && containers.length > 0 ? (
                    <Table
                      data={containers.slice(0, 5)}
                      columns={containerColumns}
                      keyExtractor={(row) => row.container_id}
                      onRowClick={(row) => router.push(`/docker/containers/${selectedAgent}/${row.container_id}`)}
                      hoverable
                    />
                  ) : (
                    <EmptyState
                      icon={ContainerIcon}
                      title="No containers"
                      description="No containers are running on this agent"
                    />
                  )}
                </div>

                {/* Images Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Images</h3>
                    <button
                      onClick={() => router.push("/docker/images")}
                      className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                    >
                      View all
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                  {loadingImages ? (
                    <div className="flex items-center justify-center h-32">
                      <Spinner size="md" />
                    </div>
                  ) : images && images.length > 0 ? (
                    <Table
                      data={images.slice(0, 5)}
                      columns={imageColumns}
                      keyExtractor={(row) => row.id}
                      onRowClick={() => router.push("/docker/images")}
                      hoverable
                    />
                  ) : (
                    <EmptyState
                      icon={ImageIcon}
                      title="No images"
                      description="No images are available on this agent"
                    />
                  )}
                </div>

                {/* Volumes Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Volumes</h3>
                    <button
                      onClick={() => router.push("/docker/volumes")}
                      className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                    >
                      View all
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                  {loadingVolumes ? (
                    <div className="flex items-center justify-center h-32">
                      <Spinner size="md" />
                    </div>
                  ) : volumes && volumes.length > 0 ? (
                    <Table
                      data={volumes.slice(0, 5)}
                      columns={volumeColumns}
                      keyExtractor={(row) => row.name}
                      onRowClick={() => router.push("/docker/volumes")}
                      hoverable
                    />
                  ) : (
                    <EmptyState
                      icon={HardDrive}
                      title="No volumes"
                      description="No volumes are configured on this agent"
                    />
                  )}
                </div>

                {/* Networks Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Networks</h3>
                    <button
                      onClick={() => router.push("/docker/networks")}
                      className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                    >
                      View all
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                  {loadingNetworks ? (
                    <div className="flex items-center justify-center h-32">
                      <Spinner size="md" />
                    </div>
                  ) : networks && networks.length > 0 ? (
                    <Table
                      data={networks.slice(0, 5)}
                      columns={networkColumns}
                      keyExtractor={(row) => row.id}
                      onRowClick={() => router.push("/docker/networks")}
                      hoverable
                    />
                  ) : (
                    <EmptyState
                      icon={Network}
                      title="No networks"
                      description="No networks are configured on this agent"
                    />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Containers Tab */}
          {activeTab === "containers" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => router.push("/docker/containers")}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  <ExternalLink className="h-4 w-4" />
                  Full Container View
                </button>
              </div>
              {loadingContainers ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" />
                </div>
              ) : containers && containers.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={containers.slice(0, 10)}
                    columns={containerColumns}
                    keyExtractor={(row) => row.container_id}
                    onRowClick={(row) => router.push(`/docker/containers/${selectedAgent}/${row.container_id}`)}
                    hoverable
                  />
                </div>
              ) : (
                <EmptyState
                  icon={ContainerIcon}
                  title="No containers"
                  description="No containers are running on this agent"
                />
              )}
              {containers && containers.length > 10 && (
                <p className="text-center text-sm text-gray-500">
                  Showing 10 of {containers.length} containers.{" "}
                  <button
                    onClick={() => router.push("/docker/containers")}
                    className="text-primary-600 hover:underline"
                  >
                    View all
                  </button>
                </p>
              )}
            </div>
          )}

          {/* Images Tab */}
          {activeTab === "images" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => router.push("/docker/images")}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  <ExternalLink className="h-4 w-4" />
                  Full Images View
                </button>
              </div>
              {loadingImages ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" />
                </div>
              ) : images && images.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={images.slice(0, 10)}
                    columns={imageColumns}
                    keyExtractor={(row) => row.id}
                    onRowClick={() => router.push("/docker/images")}
                    hoverable
                  />
                </div>
              ) : (
                <EmptyState
                  icon={ImageIcon}
                  title="No images"
                  description="No images are available on this agent"
                />
              )}
              {images && images.length > 10 && (
                <p className="text-center text-sm text-gray-500">
                  Showing 10 of {images.length} images.{" "}
                  <button
                    onClick={() => router.push("/docker/images")}
                    className="text-primary-600 hover:underline"
                  >
                    View all
                  </button>
                </p>
              )}
            </div>
          )}

          {/* Volumes Tab */}
          {activeTab === "volumes" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => router.push("/docker/volumes")}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  <ExternalLink className="h-4 w-4" />
                  Full Volumes View
                </button>
              </div>
              {loadingVolumes ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" />
                </div>
              ) : volumes && volumes.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={volumes.slice(0, 10)}
                    columns={volumeColumns}
                    keyExtractor={(row) => row.name}
                    onRowClick={() => router.push("/docker/volumes")}
                    hoverable
                  />
                </div>
              ) : (
                <EmptyState
                  icon={HardDrive}
                  title="No volumes"
                  description="No volumes are configured on this agent"
                />
              )}
              {volumes && volumes.length > 10 && (
                <p className="text-center text-sm text-gray-500">
                  Showing 10 of {volumes.length} volumes.{" "}
                  <button
                    onClick={() => router.push("/docker/volumes")}
                    className="text-primary-600 hover:underline"
                  >
                    View all
                  </button>
                </p>
              )}
            </div>
          )}

          {/* Networks Tab */}
          {activeTab === "networks" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => router.push("/docker/networks")}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  <ExternalLink className="h-4 w-4" />
                  Full Networks View
                </button>
              </div>
              {loadingNetworks ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" />
                </div>
              ) : networks && networks.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={networks.slice(0, 10)}
                    columns={networkColumns}
                    keyExtractor={(row) => row.id}
                    onRowClick={() => router.push("/docker/networks")}
                    hoverable
                  />
                </div>
              ) : (
                <EmptyState
                  icon={Network}
                  title="No networks"
                  description="No networks are configured on this agent"
                />
              )}
              {networks && networks.length > 10 && (
                <p className="text-center text-sm text-gray-500">
                  Showing 10 of {networks.length} networks.{" "}
                  <button
                    onClick={() => router.push("/docker/networks")}
                    className="text-primary-600 hover:underline"
                  >
                    View all
                  </button>
                </p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
