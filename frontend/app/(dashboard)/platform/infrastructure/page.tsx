"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  HardDrive,
  Network,
  Activity,
  CheckCircle2,
  XCircle,
  Database,
  Cpu,
  MemoryStick,
} from "lucide-react";
import { api } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Tabs } from "@/components/ui/page-layout";

type InfraTab = "networks" | "volumes" | "health";

export default function InfrastructurePage() {
  const [activeTab, setActiveTab] = useState<InfraTab>("networks");

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.[0]?.id;

  // Fetch networks
  const { data: networksData, isLoading: networksLoading } = useQuery({
    queryKey: ["docker-networks", defaultAgentId],
    queryFn: () => api.getDockerNetworks(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  // Fetch volumes
  const { data: volumesData, isLoading: volumesLoading } = useQuery({
    queryKey: ["docker-volumes", defaultAgentId],
    queryFn: () => api.getDockerVolumes(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  // Fetch health
  const { data: tlsHealth, isLoading: tlsLoading } = useQuery({
    queryKey: ["tls-health"],
    queryFn: () => api.getTLSHealth(),
  });

  const { data: dbHealth, isLoading: dbLoading } = useQuery({
    queryKey: ["db-health"],
    queryFn: () => api.getDBHealth(),
  });

  const { data: systemHealth, isLoading: systemLoading } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => api.getSystemHealth(),
  });

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatSize = (bytes: number) => {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  };

  // Tab configuration with counts
  const tabs = [
    { id: "networks", label: "Networks", count: networksData?.networks?.length || 0 },
    { id: "volumes", label: "Volumes", count: volumesData?.volumes?.length || 0 },
    { id: "health", label: "Health" },
  ];

  // Networks columns
  const networkColumns = [
    {
      key: "Name",
      header: "Network",
      render: (value: string, row: any) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Network className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white">{value}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400 font-mono">
              {row.Id?.substring(0, 12)}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "Driver",
      header: "Driver",
      render: (value: string) => <Badge color="gray">{value}</Badge>,
    },
    {
      key: "Scope",
      header: "Scope",
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "Created",
      header: "Created",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {value ? formatTimestamp(value) : "-"}
        </span>
      ),
    },
  ];

  // Volumes columns
  const volumeColumns = [
    {
      key: "Name",
      header: "Volume",
      render: (value: string, row: any) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <HardDrive className="h-4 w-4 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white truncate max-w-xs">
              {value}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {row.Driver}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "Driver",
      header: "Driver",
      render: (value: string) => <Badge color="gray">{value}</Badge>,
    },
    {
      key: "Mountpoint",
      header: "Mount Point",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400 font-mono truncate max-w-xs block">
          {value}
        </span>
      ),
    },
    {
      key: "CreatedAt",
      header: "Created",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {value ? formatTimestamp(value) : "-"}
        </span>
      ),
    },
  ];

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Platform", href: "/platform/jobs" },
        { label: "Infrastructure", current: true },
      ]}
    />
  );

  const isLoading =
    (activeTab === "networks" && networksLoading) ||
    (activeTab === "volumes" && volumesLoading) ||
    (activeTab === "health" && (tlsLoading || dbLoading || systemLoading));

  const renderHealthContent = () => {
    return (
      <div className="p-6 space-y-6">
        {/* TLS Health */}
        <div>
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">TLS Certificates</h3>
          <div className="grid grid-cols-4 gap-4">
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {tlsHealth?.total_certificates || 0}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">Total Certificates</div>
            </div>
            <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                {tlsHealth?.valid_certificates || 0}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">Valid</div>
            </div>
            <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                {tlsHealth?.expiring_soon || 0}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">Expiring Soon</div>
            </div>
            <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                {tlsHealth?.expired_certificates || 0}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">Expired</div>
            </div>
          </div>
        </div>

        {/* Database Health */}
        <div>
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Database</h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Database className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Status</span>
              </div>
              <div className="flex items-center gap-2">
                {dbHealth?.status === "healthy" ? (
                  <>
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                    <span className="text-green-600 dark:text-green-400">Healthy</span>
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4 text-red-500" />
                    <span className="text-red-600 dark:text-red-400">Unhealthy</span>
                  </>
                )}
              </div>
            </div>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Connections</span>
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {dbHealth?.active_connections || 0}
              </div>
            </div>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <HardDrive className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Size</span>
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {formatSize(dbHealth?.database_size || 0)}
              </div>
            </div>
          </div>
        </div>

        {/* System Health */}
        <div>
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">System Resources</h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">CPU Usage</span>
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {systemHealth?.cpu_usage?.toFixed(1) || 0}%
              </div>
            </div>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <MemoryStick className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Memory Usage</span>
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {systemHealth?.memory_usage?.toFixed(1) || 0}%
              </div>
            </div>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <HardDrive className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Disk Usage</span>
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {systemHealth?.disk_usage?.toFixed(1) || 0}%
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderContent = () => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" label={`Loading ${activeTab}...`} />
        </div>
      );
    }

    switch (activeTab) {
      case "networks":
        const networks = networksData?.networks || [];
        return networks.length > 0 ? (
          <Table
            columns={networkColumns}
            data={networks}
            keyExtractor={(row) => row.Id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Network}
            title="No networks found"
            description="Docker networks from your agents will appear here"
            size="sm"
          />
        );

      case "volumes":
        const volumes = volumesData?.volumes || [];
        return volumes.length > 0 ? (
          <Table
            columns={volumeColumns}
            data={volumes}
            keyExtractor={(row) => row.Name}
            hoverable
          />
        ) : (
          <EmptyState
            icon={HardDrive}
            title="No volumes found"
            description="Docker volumes from your agents will appear here"
            size="sm"
          />
        );

      case "health":
        return renderHealthContent();
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Infrastructure"
        description="Manage networks, volumes, and monitor system health"
        breadcrumbs={breadcrumbs}
      />

      {/* Summary Stats */}
      <MetricsGrid columns={3}>
        <StatCard
          label="Networks"
          value={networksData?.networks?.length || 0}
          icon={Network}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Volumes"
          value={volumesData?.volumes?.length || 0}
          icon={HardDrive}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Health Status"
          value={dbHealth?.status === "healthy" ? "Healthy" : "Check"}
          icon={Activity}
          iconColor={dbHealth?.status === "healthy" ? "text-green-600" : "text-yellow-600"}
        />
      </MetricsGrid>

      {/* Tabs and Content */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
        <div className="p-4 border-b border-gray-200 dark:border-gray-800">
          <Tabs
            tabs={tabs}
            activeTab={activeTab}
            onChange={(id) => setActiveTab(id as InfraTab)}
          />
        </div>

        <div className="p-0">{renderContent()}</div>
      </div>
    </div>
  );
}
