"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Plus,
  Trash2,
  AlertTriangle,
  Check,
  CheckCircle,
  Copy,
  Server,
  Globe,
  Link,
  Unlink,
  X,
} from "lucide-react";
import { api, DockerNetwork, DockerNetworkDetail, NginxNetworkAttachment } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";

type PanelTab = "details" | "containers";

export default function NetworksPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<DockerNetwork | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("details");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Create form state
  const [newNetworkName, setNewNetworkName] = useState("");
  const [newNetworkDriver, setNewNetworkDriver] = useState("bridge");
  const [createError, setCreateError] = useState<string | null>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch networks for selected agent
  const { data: networks, isLoading } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Fetch network details
  const { data: networkDetail } = useQuery({
    queryKey: ["docker-network-detail", selectedAgent, selectedNetwork?.id],
    queryFn: () =>
      selectedAgent && selectedNetwork
        ? api.getDockerNetwork(selectedAgent, selectedNetwork.id)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!selectedNetwork,
  });

  // Fetch nginx attachments
  const { data: attachments } = useQuery({
    queryKey: ["nginx-attachments", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getNginxNetworkAttachments(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Create network mutation
  const createMutation = useMutation({
    mutationFn: () =>
      api.createDockerNetwork(selectedAgent!, {
        name: newNetworkName,
        driver: newNetworkDriver,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowCreateModal(false);
      setNewNetworkName("");
      setNewNetworkDriver("bridge");
      setCreateError(null);
    },
    onError: (error: Error) => {
      setCreateError(error.message);
    },
  });

  // Delete network mutation
  const deleteMutation = useMutation({
    mutationFn: () =>
      api.deleteDockerNetwork(selectedAgent!, selectedNetwork!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowDeleteModal(false);
      setDeleteError(null);
      setSelectedNetwork(null);
    },
    onError: (error: Error) => {
      setDeleteError(error.message);
    },
  });

  // Attach nginx mutation
  const attachMutation = useMutation({
    mutationFn: (networkId: string) =>
      api.attachNginxNetwork(selectedAgent!, networkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["nginx-attachments", selectedAgent] });
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
    },
  });

  // Detach nginx mutation
  const detachMutation = useMutation({
    mutationFn: (networkId: string) =>
      api.detachNginxNetwork(selectedAgent!, networkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["nginx-attachments", selectedAgent] });
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
    },
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  // Check if nginx is attached to a network
  const isNginxAttached = (networkId: string) => {
    return attachments?.some(
      (a) => a.network_id === networkId && a.status === "attached"
    );
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getDriverColor = (driver: string) => {
    const colors: Record<string, string> = {
      bridge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
      host: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400",
      overlay: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
      macvlan: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
      none: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400",
    };
    return colors[driver] || colors.bridge;
  };

  // Calculate metrics
  const totalNetworks = networks?.length || 0;
  const connectedContainers = networks?.reduce(
    (sum, net) => sum + Object.keys(net.containers || {}).length,
    0
  ) || 0;
  const bridgeNetworks = networks?.filter((n) => n.driver === "bridge").length || 0;
  const overlayNetworks = networks?.filter((n) => n.driver === "overlay").length || 0;

  // Table columns
  const columns = [
    {
      key: "name",
      header: "Network Name",
      sortable: true,
      render: (value: string, row: DockerNetwork) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <Network className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{value}</p>
            <p className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</p>
          </div>
        </div>
      ),
    },
    {
      key: "driver",
      header: "Driver",
      sortable: true,
      render: (value: string) => (
        <Badge className={cn("px-2 py-0.5 text-xs rounded-full border-0", getDriverColor(value))}>
          {value}
        </Badge>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      sortable: true,
    },
    {
      key: "containers",
      header: "Containers",
      align: "center" as const,
      render: (value: Record<string, string>) => {
        const count = Object.keys(value || {}).length;
        return (
          <span className="text-sm text-gray-900 dark:text-white">
            {count}
          </span>
        );
      },
    },
    {
      key: "nginx",
      header: "Nginx",
      align: "center" as const,
      render: (_: any, row: DockerNetwork) => {
        const attached = isNginxAttached(row.id);
        return attached ? (
          <Badge className="px-2 py-1 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-full border-0">
            <Check className="h-3 w-3 mr-1" />
            Connected
          </Badge>
        ) : null;
      },
    },
  ];

  const panelTabs = [
    { id: "details" as const, label: "Details" },
    { id: "containers" as const, label: "Containers" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Docker Networks"
        description="Manage Docker networks and nginx proxy connections"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform", href: "/dashboard" },
              { label: "Networks", current: true },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-3">
            {activeAgents.length > 1 && (
              <select
                value={selectedAgent || ""}
                onChange={(e) => {
                  setSelectedAgent(e.target.value);
                  setSelectedNetwork(null);
                }}
                className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900"
              >
                {activeAgents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name || agent.hostname}
                  </option>
                ))}
              </select>
            )}
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowCreateModal(true)}
              disabled={!selectedAgent}
            >
              <Plus className="h-4 w-4 mr-1" />
              Create Network
            </Button>
          </div>
        }
      />

      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker networks"
        />
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" />
        </div>
      ) : (
        <>
          {/* Metrics */}
          <MetricsGrid columns={4} className="mb-6">
            <StatCard
              label="Total Networks"
              value={totalNetworks}
              icon={Network}
              iconColor="text-blue-600 dark:text-blue-400"
            />
            <StatCard
              label="Connected Containers"
              value={connectedContainers}
              icon={Server}
              iconColor="text-green-600 dark:text-green-400"
            />
            <StatCard
              label="Bridge Networks"
              value={bridgeNetworks}
              icon={Globe}
              iconColor="text-purple-600 dark:text-purple-400"
            />
            <StatCard
              label="Overlay Networks"
              value={overlayNetworks}
              icon={Globe}
              iconColor="text-orange-600 dark:text-orange-400"
            />
          </MetricsGrid>

          {/* Table */}
          {networks && networks.length > 0 ? (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
              <Table
                columns={columns}
                data={networks}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedNetwork(row)}
                hoverable
                rowClassName={(row) =>
                  selectedNetwork?.id === row.id
                    ? "bg-primary-50 dark:bg-primary-900/20"
                    : ""
                }
              />
            </div>
          ) : (
            <EmptyState
              icon={Network}
              title="No networks found"
              description="Create a Docker network to get started"
              action={
                <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Create Network
                </Button>
              }
            />
          )}
        </>
      )}

      {/* SlideOver for Network Details */}
      <SlideOver
        isOpen={!!selectedNetwork}
        onClose={() => setSelectedNetwork(null)}
        size="md"
      >
        {selectedNetwork && (
          <>
            <SlideOver.Header onClose={() => setSelectedNetwork(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedNetwork.name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {selectedNetwork.driver} network
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-1 mb-4">
                {panelTabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setPanelTab(tab.id)}
                    className={cn(
                      "px-3 py-1.5 text-sm rounded-lg transition-colors",
                      panelTab === tab.id
                        ? "bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-400"
                        : "text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
                    )}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {panelTab === "details" && (
                <div className="space-y-6">
                  {/* Nginx Connection Section */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Nginx Proxy Connection
                    </h3>
                    <div
                      className={cn(
                        "p-4 rounded-lg border-2",
                        isNginxAttached(selectedNetwork.id)
                          ? "bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800"
                          : "bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800"
                      )}
                    >
                      {isNginxAttached(selectedNetwork.id) ? (
                        <>
                          <div className="flex items-center gap-2 text-green-700 dark:text-green-400 mb-2">
                            <CheckCircle className="h-5 w-5" />
                            <span className="font-medium">Nginx is connected to this network</span>
                          </div>
                          <p className="text-sm text-green-600 dark:text-green-500 mb-3">
                            Containers on this network can be proxied by hostname (DNS resolution works)
                          </p>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => detachMutation.mutate(selectedNetwork.id)}
                            disabled={detachMutation.isPending}
                          >
                            <Unlink className="h-4 w-4 mr-1" />
                            {detachMutation.isPending ? "Disconnecting..." : "Disconnect Nginx"}
                          </Button>
                        </>
                      ) : (
                        <>
                          <div className="flex items-center gap-2 text-yellow-700 dark:text-yellow-400 mb-2">
                            <AlertTriangle className="h-5 w-5" />
                            <span className="font-medium">Nginx is not connected</span>
                          </div>
                          <p className="text-sm text-yellow-600 dark:text-yellow-500 mb-3">
                            Connect nginx to proxy containers by hostname (enables DNS resolution)
                          </p>
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={() => attachMutation.mutate(selectedNetwork.id)}
                            disabled={attachMutation.isPending}
                          >
                            <Link className="h-4 w-4 mr-1" />
                            {attachMutation.isPending ? "Connecting..." : "Connect Nginx to Network"}
                          </Button>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Network Info */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Network Info
                    </h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                        <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.name}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-gray-900 dark:text-white">
                            {selectedNetwork.id.slice(0, 12)}
                          </span>
                          <button
                            onClick={() => handleCopy(selectedNetwork.id)}
                            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                          >
                            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                        <Badge className={cn("px-2 py-0.5 text-xs rounded-full border-0", getDriverColor(selectedNetwork.driver))}>
                          {selectedNetwork.driver}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                        <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.scope}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Internal</span>
                        <span className="text-sm text-gray-900 dark:text-white">
                          {selectedNetwork.internal ? "Yes" : "No"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* IPAM */}
                  {networkDetail?.ipam && networkDetail.ipam.configs?.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        IP Address Management
                      </h3>
                      {networkDetail.ipam.configs.map((config, idx) => (
                        <div key={idx} className="space-y-3">
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Subnet</span>
                            <span className="text-sm font-mono text-gray-900 dark:text-white">
                              {config.subnet}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Gateway</span>
                            <span className="text-sm font-mono text-gray-900 dark:text-white">
                              {config.gateway}
                            </span>
                          </div>
                          {config.ip_range && (
                            <div className="flex justify-between">
                              <span className="text-sm text-gray-500 dark:text-gray-400">IP Range</span>
                              <span className="text-sm font-mono text-gray-900 dark:text-white">
                                {config.ip_range}
                              </span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Actions
                    </h3>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setShowDeleteModal(true)}
                      disabled={Object.keys(selectedNetwork.containers || {}).length > 0}
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      Delete Network
                    </Button>
                    {Object.keys(selectedNetwork.containers || {}).length > 0 && (
                      <p className="text-xs text-gray-500 mt-2">
                        Cannot delete network with connected containers
                      </p>
                    )}
                  </div>
                </div>
              )}

              {panelTab === "containers" && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Connected Containers
                  </h3>
                  {Object.entries(selectedNetwork.containers || {}).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(selectedNetwork.containers).map(([id, name]) => (
                        <div
                          key={id}
                          className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                        >
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium text-gray-900 dark:text-white">{name}</span>
                          </div>
                          <span className="text-xs text-gray-500 font-mono">{id.slice(0, 12)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">No containers connected to this network</p>
                  )}
                </div>
              )}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Create Network Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => {
              setShowCreateModal(false);
              setCreateError(null);
            }}
          />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Create Network</h3>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setCreateError(null);
                }}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <Input
                label="Network Name"
                value={newNetworkName}
                onChange={(e) => setNewNetworkName(e.target.value)}
                placeholder="my-network"
              />

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Driver
                </label>
                <select
                  value={newNetworkDriver}
                  onChange={(e) => setNewNetworkDriver(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900"
                >
                  <option value="bridge">bridge</option>
                  <option value="macvlan">macvlan</option>
                  <option value="ipvlan">ipvlan</option>
                </select>
              </div>

              {createError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{createError}</p>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <Button
                variant="secondary"
                onClick={() => {
                  setShowCreateModal(false);
                  setCreateError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={() => createMutation.mutate()}
                disabled={!newNetworkName || createMutation.isPending}
              >
                {createMutation.isPending ? "Creating..." : "Create"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Network Modal */}
      {showDeleteModal && selectedNetwork && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => {
              setShowDeleteModal(false);
              setDeleteError(null);
            }}
          />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold">Delete Network</h3>
            </div>

            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Are you sure you want to delete the network{" "}
              <span className="font-medium text-gray-900 dark:text-white">
                {selectedNetwork.name}
              </span>
              ? This action cannot be undone.
            </p>

            {deleteError && (
              <div className="p-3 mb-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{deleteError}</p>
              </div>
            )}

            <div className="flex justify-end gap-3">
              <Button
                variant="secondary"
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeleteError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete Network"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
