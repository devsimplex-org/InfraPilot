"use client";

import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  Image as ImageIcon,
  HardDrive,
  Network,
  Layers,
  Server,
} from "lucide-react";
import { api, Container, DockerImage, DockerVolume, DockerNetwork } from "@/lib/api";
import { useDocker, formatSize, getStatusLevel } from "@/lib/docker-context";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function DockerOverviewPage() {
  const router = useRouter();
  const { selectedAgent } = useDocker();

  // Fetch data
  const { data: containers, isLoading: loadingContainers } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () => selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  const { data: images, isLoading: loadingImages } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  const { data: volumes, isLoading: loadingVolumes } = useQuery({
    queryKey: ["docker-volumes", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerVolumes(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  const { data: networks, isLoading: loadingNetworks } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Metrics
  const containerMetrics = {
    total: containers?.length || 0,
    running: containers?.filter(c => c.status === "running").length || 0,
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

  // Table columns
  const containerColumns = [
    {
      key: "status",
      header: "Status",
      width: "120px",
      render: (value: string) => (
        <StatusIndicator status={getStatusLevel(value)} label={value} size="sm" />
      ),
    },
    {
      key: "name",
      header: "Container",
      render: (value: string, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">{row.image}</div>
        </div>
      ),
    },
    {
      key: "stack_name",
      header: "Stack",
      render: (value: string) => value ? (
        <Badge className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">{value}</Badge>
      ) : (
        <span className="text-gray-400 text-sm">—</span>
      ),
    },
  ];

  const imageColumns = [
    {
      key: "tags",
      header: "Image",
      render: (value: string[], row: DockerImage) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <ImageIcon className="h-4 w-4 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{value[0]?.split(":")[0] || row.id.slice(0, 12)}</p>
            <p className="text-xs text-gray-500">{value[0]?.split(":")[1] || "latest"}</p>
          </div>
        </div>
      ),
    },
    {
      key: "size",
      header: "Size",
      render: (value: number) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{formatSize(value)}</span>
      ),
    },
  ];

  const volumeColumns = [
    {
      key: "name",
      header: "Volume",
      render: (value: string, row: DockerVolume) => (
        <div className="flex items-center gap-3">
          <HardDrive className="h-4 w-4 text-gray-400" />
          <div>
            <p className="font-medium text-gray-900 dark:text-white truncate max-w-[200px]">{value}</p>
            <p className="text-xs text-gray-500">{row.driver}</p>
          </div>
        </div>
      ),
    },
    {
      key: "used_by",
      header: "Status",
      render: (value: string[]) => value.length > 0 ? (
        <Badge className="px-2 py-0.5 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">In Use</Badge>
      ) : (
        <Badge className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">Unused</Badge>
      ),
    },
  ];

  const networkColumns = [
    {
      key: "name",
      header: "Network",
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
        <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">{value}</Badge>
      ),
    },
  ];

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-6">
      {/* Metrics */}
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

      {/* Summary Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Containers Summary */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Containers</h3>
            <button onClick={() => router.push("/docker/containers")} className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </button>
          </div>
          {loadingContainers ? (
            <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
          ) : containers && containers.length > 0 ? (
            <Table
              data={containers.slice(0, 5)}
              columns={containerColumns}
              keyExtractor={(row) => row.container_id}
              onRowClick={() => router.push("/docker/containers")}
              hoverable
            />
          ) : (
            <EmptyState icon={ContainerIcon} title="No containers" description="No containers are running" size="sm" />
          )}
        </div>

        {/* Images Summary */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Images</h3>
            <button onClick={() => router.push("/docker/images")} className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </button>
          </div>
          {loadingImages ? (
            <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
          ) : images && images.length > 0 ? (
            <Table
              data={images.slice(0, 5)}
              columns={imageColumns}
              keyExtractor={(row) => row.id}
              onRowClick={() => router.push("/docker/images")}
              hoverable
            />
          ) : (
            <EmptyState icon={ImageIcon} title="No images" description="Pull an image to get started" size="sm" />
          )}
        </div>

        {/* Volumes Summary */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Volumes</h3>
            <button onClick={() => router.push("/docker/volumes")} className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </button>
          </div>
          {loadingVolumes ? (
            <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
          ) : volumes && volumes.length > 0 ? (
            <Table
              data={volumes.slice(0, 5)}
              columns={volumeColumns}
              keyExtractor={(row) => row.name}
              onRowClick={() => router.push("/docker/volumes")}
              hoverable
            />
          ) : (
            <EmptyState icon={HardDrive} title="No volumes" description="Create a volume to persist data" size="sm" />
          )}
        </div>

        {/* Networks Summary */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Networks</h3>
            <button onClick={() => router.push("/docker/networks")} className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </button>
          </div>
          {loadingNetworks ? (
            <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
          ) : networks && networks.length > 0 ? (
            <Table
              data={networks.slice(0, 5)}
              columns={networkColumns}
              keyExtractor={(row) => row.id}
              onRowClick={() => router.push("/docker/networks")}
              hoverable
            />
          ) : (
            <EmptyState icon={Network} title="No networks" description="No custom networks configured" size="sm" />
          )}
        </div>
      </div>
    </div>
  );
}
