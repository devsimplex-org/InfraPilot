"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Server,
  Trash2,
  Copy,
  Check,
  CheckSquare,
  MinusSquare,
  Square,
  Lock,
  AlertTriangle,
  Globe,
} from "lucide-react";
import { api, DockerNetwork } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { ContainerListPopover } from "@/components/docker/ContainerListPopover";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/page-layout";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FilterToolbar, ToggleOption } from "@/components/ui/FilterToolbar";
import { cn } from "@/lib/utils";

// Filter options
const NETWORK_STATUS_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "in-use", label: "In Use", color: "green" },
  { value: "unused", label: "Unused" },
];

// Default Docker networks that should not be deleted
const PROTECTED_NETWORKS = ["bridge", "host", "none"];

export default function DockerNetworksPage() {
  const queryClient = useQueryClient();
  const { selectedAgent, openContainerPanel } = useDocker();

  // Local state
  const [searchFilter, setSearchFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "in-use" | "unused">("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ total: number; completed: number; failed: string[] } | null>(null);

  // Single network selection for slide-over
  const [selectedNetwork, setSelectedNetwork] = useState<DockerNetwork | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Fetch networks
  const { data: networks, isLoading } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Helper to check if network is in use
  const isInUse = (network: DockerNetwork) => Object.keys(network.containers || {}).length > 0;

  // Helper to check if network is protected (default Docker networks)
  const isProtected = (network: DockerNetwork) => PROTECTED_NETWORKS.includes(network.name);

  // Filtered networks
  const filteredNetworks = useMemo(() => {
    if (!networks) return [];
    return networks.filter((n) => {
      const matchesSearch = !searchFilter ||
        n.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
        n.driver.toLowerCase().includes(searchFilter.toLowerCase()) ||
        n.id.toLowerCase().includes(searchFilter.toLowerCase());
      const matchesStatus = statusFilter === "all" ||
        (statusFilter === "in-use" && isInUse(n)) ||
        (statusFilter === "unused" && !isInUse(n));
      return matchesSearch && matchesStatus;
    });
  }, [networks, searchFilter, statusFilter]);

  // Selectable networks (not protected and not in use)
  const selectableNetworks = filteredNetworks.filter((n) => !isProtected(n) && !isInUse(n));

  // Selection helpers
  const toggleSelection = (id: string) => {
    setSelectedIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) newSet.delete(id);
      else newSet.add(id);
      return newSet;
    });
  };

  const selectAll = () => setSelectedIds(new Set(selectableNetworks.map((n) => n.id)));
  const selectNone = () => setSelectedIds(new Set());
  const selectUnused = () => {
    const unused = filteredNetworks.filter((n) => !isProtected(n) && !isInUse(n));
    setSelectedIds(new Set(unused.map((n) => n.id)));
  };

  const isAllSelected = selectableNetworks.length > 0 && selectedIds.size === selectableNetworks.length;
  const isSomeSelected = selectedIds.size > 0 && !isAllSelected;
  const selectedData = filteredNetworks.filter((n) => selectedIds.has(n.id));

  // Metrics
  const metrics = {
    total: networks?.length || 0,
    inUse: networks?.filter((n) => isInUse(n)).length || 0,
    unused: networks?.filter((n) => !isInUse(n)).length || 0,
    deletable: networks?.filter((n) => !isProtected(n) && !isInUse(n)).length || 0,
  };

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Delete single network mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteDockerNetwork(selectedAgent!, selectedNetwork!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowDeleteModal(false);
      setSelectedNetwork(null);
      setDeleteError(null);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Bulk delete
  const handleBulkDelete = async () => {
    const toDelete = selectedData.filter((n) => !isProtected(n) && !isInUse(n));
    if (toDelete.length === 0) return;
    setBulkProgress({ total: toDelete.length, completed: 0, failed: [] });
    const failed: string[] = [];
    for (let i = 0; i < toDelete.length; i++) {
      try {
        await api.deleteDockerNetwork(selectedAgent!, toDelete[i].id);
      } catch {
        failed.push(toDelete[i].name);
      }
      setBulkProgress({ total: toDelete.length, completed: i + 1, failed });
    }
    queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
    if (failed.length === 0) {
      setShowBulkDeleteModal(false);
      selectNone();
      setBulkProgress(null);
    }
  };

  // Table columns
  const columns = [
    {
      key: "checkbox",
      header: (
        <button
          onClick={(e) => { e.stopPropagation(); isAllSelected ? selectNone() : selectAll(); }}
          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
        >
          {isAllSelected ? <CheckSquare className="h-4 w-4 text-primary-600" /> : isSomeSelected ? <MinusSquare className="h-4 w-4 text-primary-600" /> : <Square className="h-4 w-4 text-gray-400" />}
        </button>
      ),
      width: "40px",
      render: (_: unknown, row: DockerNetwork) => {
        const canSelect = !isProtected(row) && !isInUse(row);
        return (
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (canSelect) toggleSelection(row.id);
            }}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            title={isProtected(row) ? "System network" : isInUse(row) ? "Network is in use" : undefined}
          >
            {isProtected(row) ? (
              <Lock className="h-4 w-4 text-gray-400" />
            ) : isInUse(row) ? (
              <Lock className="h-4 w-4 text-green-500" />
            ) : selectedIds.has(row.id) ? (
              <CheckSquare className="h-4 w-4 text-primary-600" />
            ) : (
              <Square className="h-4 w-4 text-gray-400" />
            )}
          </button>
        );
      },
    },
    {
      key: "name",
      header: "Name",
      sortable: true,
      render: (value: string, row: DockerNetwork) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <Network className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className="font-medium text-gray-900 dark:text-white">{value}</p>
              {isProtected(row) && (
                <Badge className="px-1.5 py-0.5 text-[10px] bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
                  system
                </Badge>
              )}
            </div>
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
        <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">
          {value}
        </Badge>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "containers",
      header: "Containers",
      align: "center" as const,
      render: (value: Record<string, string>) => (
        <ContainerListPopover containers={value} onContainerClick={openContainerPanel} label="connected" />
      ),
    },
    {
      key: "internal",
      header: "Internal",
      align: "center" as const,
      render: (value: boolean) => (
        <span className={cn("text-sm", value ? "text-yellow-600 dark:text-yellow-400" : "text-gray-400")}>
          {value ? "Yes" : "No"}
        </span>
      ),
    },
  ];

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-4">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard label="Total Networks" value={metrics.total} icon={Network} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="In Use" value={metrics.inUse} icon={Globe} iconColor="text-green-600 dark:text-green-400" />
        <StatCard label="Unused" value={metrics.unused} icon={Network} iconColor="text-purple-600 dark:text-purple-400" />
        <StatCard label="Orphaned" value={metrics.deletable} icon={AlertTriangle} iconColor="text-orange-600 dark:text-orange-400" />
      </MetricsGrid>

      {/* Filter Toolbar */}
      <FilterToolbar
        primaryToggle={{
          options: NETWORK_STATUS_OPTIONS,
          value: statusFilter,
          onChange: (v) => setStatusFilter(v as "all" | "in-use" | "unused"),
        }}
        searchQuery={searchFilter}
        onSearchChange={setSearchFilter}
        searchPlaceholder="Search networks..."
        showSearch={true}
        showRefresh={true}
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] })}
        singleRow={true}
      />

      {/* Selection Action Bar */}
      {networks && networks.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500 dark:text-gray-400">Quick select:</span>
            <button
              onClick={selectAll}
              disabled={selectableNetworks.length === 0}
              className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              All Deletable ({selectableNetworks.length})
            </button>
            <button
              onClick={selectUnused}
              disabled={metrics.deletable === 0}
              className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Orphaned ({metrics.deletable})
            </button>
            {selectedIds.size > 0 && (
              <button onClick={selectNone} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
                Clear
              </button>
            )}
          </div>

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-700 dark:text-gray-300">
                <strong>{selectedIds.size}</strong> selected
              </span>
              <Button variant="danger" size="sm" onClick={() => setShowBulkDeleteModal(true)}>
                <Trash2 className="h-4 w-4 mr-1" />
                Delete Selected
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <Spinner.LogoPage label="Loading networks..." />
      ) : filteredNetworks.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            data={filteredNetworks}
            columns={columns}
            keyExtractor={(row) => row.id}
            onRowClick={(row) => setSelectedNetwork(row)}
            hoverable
            rowClassName={(row) =>
              cn(
                selectedNetwork?.id === row.id && "bg-primary-50 dark:bg-primary-900/20",
                selectedIds.has(row.id) && "bg-blue-50 dark:bg-blue-900/10"
              )
            }
          />
        </div>
      ) : (
        <EmptyState
          icon={Network}
          title="No networks found"
          description={networks?.length === 0 ? "No networks are configured on this agent" : "No networks match the current filters"}
        />
      )}

      {/* Network SlideOver */}
      <SlideOver isOpen={!!selectedNetwork} onClose={() => setSelectedNetwork(null)} size="md">
        {selectedNetwork && (
          <>
            <SlideOver.Header onClose={() => setSelectedNetwork(null)}>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedNetwork.name}</h2>
                  {isProtected(selectedNetwork) && (
                    <Badge className="px-1.5 py-0.5 text-[10px] bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
                      system
                    </Badge>
                  )}
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedNetwork.driver} network</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
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
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                      {isInUse(selectedNetwork) ? (
                        <Badge className="px-2 py-0.5 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
                          In Use
                        </Badge>
                      ) : (
                        <Badge className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
                          Unused
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>

                {/* Connected Containers */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Connected Containers</h3>
                  {Object.entries(selectedNetwork.containers || {}).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(selectedNetwork.containers).map(([id, name]) => (
                        <button
                          key={id}
                          onClick={() => {
                            openContainerPanel(id);
                            setSelectedNetwork(null);
                          }}
                          className="w-full flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium text-gray-900 dark:text-white">{name}</span>
                          </div>
                          <span className="text-xs text-gray-500 font-mono">{id.slice(0, 12)}</span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">No containers connected</span>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => { setDeleteError(null); setShowDeleteModal(true); }}
                    disabled={isProtected(selectedNetwork) || isInUse(selectedNetwork)}
                  >
                    <Trash2 className="h-4 w-4 mr-1" />Delete Network
                  </Button>
                  {isProtected(selectedNetwork) && (
                    <p className="text-xs text-gray-500 mt-2">System networks cannot be deleted</p>
                  )}
                  {!isProtected(selectedNetwork) && isInUse(selectedNetwork) && (
                    <p className="text-xs text-gray-500 mt-2">Cannot delete network with connected containers</p>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Bulk Delete Modal */}
      {showBulkDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => !bulkProgress && setShowBulkDeleteModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-lg w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <Trash2 className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold">Delete {selectedIds.size} Networks</h3>
            </div>

            {!bulkProgress ? (
              <>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  Are you sure you want to delete <strong>{selectedIds.size}</strong> selected networks?
                  This action cannot be undone.
                </p>
                <div className="max-h-48 overflow-y-auto mb-4 space-y-1">
                  {selectedData.map((net) => {
                    const canDelete = !isProtected(net) && !isInUse(net);
                    return (
                      <div key={net.id} className={cn("flex items-center justify-between p-2 rounded text-sm", !canDelete ? "bg-yellow-50 dark:bg-yellow-900/20" : "bg-gray-50 dark:bg-gray-800")}>
                        <span className="font-mono truncate">{net.name}</span>
                        <span className="text-gray-500 text-xs">
                          {net.driver}
                          {isProtected(net) && <span className="ml-2 text-yellow-600 dark:text-yellow-400">(system - will skip)</span>}
                          {!isProtected(net) && isInUse(net) && <span className="ml-2 text-yellow-600 dark:text-yellow-400">(in use - will skip)</span>}
                        </span>
                      </div>
                    );
                  })}
                </div>
                {selectedData.some((net) => isProtected(net) || isInUse(net)) && (
                  <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <p className="text-sm text-yellow-700 dark:text-yellow-400">
                      {selectedData.filter((net) => isProtected(net) || isInUse(net)).length} network(s) are protected or in use and will be skipped.
                    </p>
                  </div>
                )}
                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => setShowBulkDeleteModal(false)}>Cancel</Button>
                  <Button variant="danger" onClick={handleBulkDelete} disabled={selectedData.filter((n) => !isProtected(n) && !isInUse(n)).length === 0}>
                    Delete {selectedData.filter((n) => !isProtected(n) && !isInUse(n)).length} Networks
                  </Button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Deleting networks...</span>
                    <span>{bulkProgress.completed} / {bulkProgress.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-red-600 h-2 rounded-full transition-all duration-300" style={{ width: `${(bulkProgress.completed / bulkProgress.total) * 100}%` }} />
                  </div>
                </div>
                {bulkProgress.failed.length > 0 && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm font-medium text-red-600 dark:text-red-400 mb-2">Failed to delete {bulkProgress.failed.length} networks:</p>
                    <ul className="text-xs text-red-600 dark:text-red-400 space-y-1">
                      {bulkProgress.failed.map((name, idx) => <li key={idx}>• {name}</li>)}
                    </ul>
                  </div>
                )}
                {bulkProgress.completed === bulkProgress.total && (
                  <div className="flex justify-end">
                    <Button variant="secondary" onClick={() => { setShowBulkDeleteModal(false); selectNone(); setBulkProgress(null); }}>
                      {bulkProgress.failed.length > 0 ? "Close" : "Done"}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Single Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteModal && !!selectedNetwork}
        onClose={() => { setShowDeleteModal(false); setDeleteError(null); }}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Network"
        message={`Are you sure you want to delete network "${selectedNetwork?.name}"?`}
        confirmText="Delete Network"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
        error={deleteError}
      />
    </div>
  );
}
