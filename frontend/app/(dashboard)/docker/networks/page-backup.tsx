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
import {
  PageLayout,
  ListCard,
  EmptyState,
  Button,
  Input,
} from "@/components/ui/page-layout";
import {
  DetailPanel,
  DetailSection,
  DetailRow,
} from "@/components/ui/detail-panel";

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

  const panelTabs = [
    { id: "details" as const, label: "Details" },
    { id: "containers" as const, label: "Containers" },
  ];

  return (
    <PageLayout
      title="Docker Networks"
      description="Manage Docker networks and nginx proxy connections"
      actions={
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
      panelOpen={!!selectedNetwork}
      panel={
        selectedNetwork && (
          <DetailPanel
            open={!!selectedNetwork}
            onClose={() => setSelectedNetwork(null)}
            title={selectedNetwork.name}
            subtitle={`${selectedNetwork.driver} network`}
            defaultWidth={520}
          >
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
              <>
                {/* Nginx Connection Section - PROMINENT */}
                <DetailSection title="Nginx Proxy Connection">
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
                </DetailSection>

                <DetailSection title="Network Info">
                  <DetailRow label="Name" value={selectedNetwork.name} />
                  <DetailRow
                    label="ID"
                    mono
                    value={
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs">{selectedNetwork.id}</span>
                        <button
                          onClick={() => handleCopy(selectedNetwork.id)}
                          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        >
                          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    }
                  />
                  <DetailRow
                    label="Driver"
                    value={
                      <span className={cn("px-2 py-0.5 text-xs rounded-full", getDriverColor(selectedNetwork.driver))}>
                        {selectedNetwork.driver}
                      </span>
                    }
                  />
                  <DetailRow label="Scope" value={selectedNetwork.scope} />
                  <DetailRow label="Internal" value={selectedNetwork.internal ? "Yes" : "No"} />
                </DetailSection>

                {networkDetail?.ipam && networkDetail.ipam.configs?.length > 0 && (
                  <DetailSection title="IP Address Management">
                    {networkDetail.ipam.configs.map((config, idx) => (
                      <div key={idx} className="space-y-1">
                        <DetailRow label="Subnet" mono value={config.subnet} />
                        <DetailRow label="Gateway" mono value={config.gateway} />
                        {config.ip_range && <DetailRow label="IP Range" mono value={config.ip_range} />}
                      </div>
                    ))}
                  </DetailSection>
                )}

                <DetailSection title="Actions">
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
                </DetailSection>
              </>
            )}

            {panelTab === "containers" && (
              <DetailSection title="Connected Containers">
                {Object.entries(selectedNetwork.containers || {}).length > 0 ? (
                  <div className="space-y-2">
                    {Object.entries(selectedNetwork.containers).map(([id, name]) => (
                      <div
                        key={id}
                        className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                      >
                        <div className="flex items-center gap-2">
                          <Server className="h-4 w-4 text-gray-400" />
                          <span className="text-sm font-medium">{name}</span>
                        </div>
                        <span className="text-xs text-gray-500 font-mono">{id}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">No containers connected to this network</p>
                )}
              </DetailSection>
            )}
          </DetailPanel>
        )
      }
    >
      {/* Main content */}
      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker networks"
        />
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
        </div>
      ) : networks && networks.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {networks.map((network) => {
            const isSelected = selectedNetwork?.id === network.id;
            const nginxConnected = isNginxAttached(network.id);
            const containerCount = Object.keys(network.containers || {}).length;

            return (
              <ListCard
                key={network.id}
                selected={isSelected}
                onClick={() => setSelectedNetwork(network)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        "p-2 rounded-lg",
                        isSelected
                          ? "bg-primary-100 dark:bg-primary-900/30"
                          : "bg-gray-100 dark:bg-gray-800"
                      )}
                    >
                      <Network
                        className={cn(
                          "h-5 w-5",
                          isSelected
                            ? "text-primary-600 dark:text-primary-400"
                            : "text-gray-500"
                        )}
                      />
                    </div>
                    <div>
                      <h3 className="font-medium text-gray-900 dark:text-white">
                        {network.name}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs rounded-full",
                            getDriverColor(network.driver)
                          )}
                        >
                          {network.driver}
                        </span>
                        <span className="text-xs text-gray-500">
                          {containerCount} container{containerCount !== 1 ? "s" : ""}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Nginx connection indicator */}
                  {nginxConnected && (
                    <span className="flex items-center gap-1 px-2 py-1 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-full">
                      <Check className="h-3 w-3" />
                      Nginx
                    </span>
                  )}
                </div>
              </ListCard>
            );
          })}
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
    </PageLayout>
  );
}
