"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  HardDrive,
  CheckSquare,
  MinusSquare,
  Square,
  Trash2,
  Lock,
  Plus,
  Database,
  FolderOpen,
  AlertTriangle,
  Copy,
  Check,
  Server,
} from "lucide-react";
import { api, DockerVolume } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { ContainerListPopover } from "@/components/docker/ContainerListPopover";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FilterToolbar, ToggleOption } from "@/components/ui/FilterToolbar";
import { cn } from "@/lib/utils";

// Filter options
const VOLUME_STATUS_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "used", label: "In Use", color: "green" },
  { value: "unused", label: "Unused", color: "gray" },
];

export default function DockerVolumesPage() {
  const queryClient = useQueryClient();
  const { selectedAgent, forceDelete, setForceDelete, openContainerPanel } = useDocker();

  // Local state
  const [searchFilter, setSearchFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "used" | "unused">("all");
  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ total: number; completed: number; failed: string[] } | null>(null);

  // Single volume selection for slide-over
  const [selectedVolume, setSelectedVolume] = useState<DockerVolume | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Create volume modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newVolumeName, setNewVolumeName] = useState("");
  const [newVolumeDriver, setNewVolumeDriver] = useState("local");
  const [createError, setCreateError] = useState<string | null>(null);

  // Fetch volumes
  const { data: volumes, isLoading } = useQuery({
    queryKey: ["docker-volumes", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerVolumes(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Filtered volumes
  const filteredVolumes = useMemo(() => {
    if (!volumes) return [];
    return volumes.filter((v) => {
      const matchesSearch = !searchFilter ||
        v.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
        v.driver.toLowerCase().includes(searchFilter.toLowerCase());
      const matchesStatus = statusFilter === "all" ||
        (statusFilter === "used" && v.used_by.length > 0) ||
        (statusFilter === "unused" && v.used_by.length === 0);
      return matchesSearch && matchesStatus;
    });
  }, [volumes, searchFilter, statusFilter]);

  // Selectable volumes (only unused)
  const selectableVolumes = filteredVolumes.filter((v) => v.used_by.length === 0);

  // Selection helpers
  const toggleSelection = (name: string) => {
    setSelectedNames((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(name)) newSet.delete(name);
      else newSet.add(name);
      return newSet;
    });
  };

  const selectAll = () => setSelectedNames(new Set(selectableVolumes.map((v) => v.name)));
  const selectNone = () => setSelectedNames(new Set());
  const selectUnused = () => {
    const unused = filteredVolumes.filter((v) => v.used_by.length === 0);
    setSelectedNames(new Set(unused.map((v) => v.name)));
  };

  const isAllSelected = selectableVolumes.length > 0 && selectedNames.size === selectableVolumes.length;
  const isSomeSelected = selectedNames.size > 0 && !isAllSelected;
  const selectedData = filteredVolumes.filter((v) => selectedNames.has(v.name));

  // Metrics
  const metrics = {
    total: volumes?.length || 0,
    inUse: volumes?.filter((v) => v.used_by.length > 0).length || 0,
    unused: volumes?.filter((v) => v.used_by.length === 0).length || 0,
  };

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Create volume mutation
  const createMutation = useMutation({
    mutationFn: () => api.createDockerVolume(selectedAgent!, { name: newVolumeName, driver: newVolumeDriver }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowCreateModal(false);
      setNewVolumeName("");
      setNewVolumeDriver("local");
      setCreateError(null);
    },
    onError: (error: Error) => setCreateError(error.message),
  });

  // Delete single volume mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteDockerVolume(selectedAgent!, selectedVolume!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowDeleteModal(false);
      setSelectedVolume(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Bulk delete
  const handleBulkDelete = async () => {
    const toDelete = selectedData.filter((v) => v.used_by.length === 0);
    if (toDelete.length === 0) return;
    setBulkProgress({ total: toDelete.length, completed: 0, failed: [] });
    const failed: string[] = [];
    for (let i = 0; i < toDelete.length; i++) {
      try {
        await api.deleteDockerVolume(selectedAgent!, toDelete[i].name, forceDelete);
      } catch {
        failed.push(toDelete[i].name);
      }
      setBulkProgress({ total: toDelete.length, completed: i + 1, failed });
    }
    queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
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
      render: (_: unknown, row: DockerVolume) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            if (row.used_by.length === 0) toggleSelection(row.name);
          }}
          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
          title={row.used_by.length > 0 ? "Volume is in use" : undefined}
        >
          {row.used_by.length > 0 ? (
            <Lock className="h-4 w-4 text-green-500" />
          ) : selectedNames.has(row.name) ? (
            <CheckSquare className="h-4 w-4 text-primary-600" />
          ) : (
            <Square className="h-4 w-4 text-gray-400" />
          )}
        </button>
      ),
    },
    {
      key: "name",
      header: "Volume Name",
      sortable: true,
      render: (value: string, row: DockerVolume) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <HardDrive className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white truncate max-w-[200px]">{value}</p>
            <p className="text-xs text-gray-500">{row.driver} driver</p>
          </div>
        </div>
      ),
    },
    {
      key: "mountpoint",
      header: "Mount Point",
      render: (value: string) => (
        <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded font-mono border-0">
          {value.length > 40 ? `...${value.slice(-37)}` : value}
        </Badge>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      sortable: true,
    },
    {
      key: "used_by",
      header: "In Use",
      align: "center" as const,
      render: (value: string[]) => (
        <ContainerListPopover containers={value} onContainerClick={openContainerPanel} label="container" />
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
        <StatCard label="Total Volumes" value={metrics.total} icon={HardDrive} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="In Use" value={metrics.inUse} icon={Database} iconColor="text-green-600 dark:text-green-400" />
        <StatCard label="Unused" value={metrics.unused} icon={FolderOpen} iconColor="text-purple-600 dark:text-purple-400" />
        <StatCard label="Orphaned" value={metrics.unused} icon={AlertTriangle} iconColor="text-orange-600 dark:text-orange-400" />
      </MetricsGrid>

      {/* Filter Toolbar */}
      <FilterToolbar
        primaryToggle={{
          options: VOLUME_STATUS_OPTIONS,
          value: statusFilter,
          onChange: (v) => setStatusFilter(v as "all" | "used" | "unused"),
        }}
        searchQuery={searchFilter}
        onSearchChange={setSearchFilter}
        searchPlaceholder="Search volumes..."
        showSearch={true}
        showRefresh={true}
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] })}
        singleRow={true}
      />

      {/* Selection Action Bar */}
      {volumes && volumes.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500 dark:text-gray-400">Quick select:</span>
            <button
              onClick={selectAll}
              disabled={selectableVolumes.length === 0}
              className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              All Deletable ({selectableVolumes.length})
            </button>
            <button
              onClick={selectUnused}
              disabled={metrics.unused === 0}
              className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Unused ({metrics.unused})
            </button>
            {selectedNames.size > 0 && (
              <button onClick={selectNone} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
                Clear
              </button>
            )}
          </div>

          {selectedNames.size > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-700 dark:text-gray-300">
                <strong>{selectedNames.size}</strong> selected
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
        <Spinner.LogoPage label="Loading volumes..." />
      ) : filteredVolumes.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            data={filteredVolumes}
            columns={columns}
            keyExtractor={(row) => row.name}
            onRowClick={(row) => setSelectedVolume(row)}
            hoverable
            rowClassName={(row) =>
              cn(
                selectedVolume?.name === row.name && "bg-primary-50 dark:bg-primary-900/20",
                selectedNames.has(row.name) && "bg-blue-50 dark:bg-blue-900/10"
              )
            }
          />
        </div>
      ) : (
        <EmptyState
          icon={HardDrive}
          title="No volumes found"
          description={volumes?.length === 0 ? "Create a Docker volume to persist data" : "No volumes match the current filters"}
          action={
            volumes?.length === 0 ? (
              <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                <Plus className="h-4 w-4 mr-1" />
                Create Volume
              </Button>
            ) : undefined
          }
        />
      )}

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
                    <div className="flex flex-col gap-1">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Mountpoint</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-900 dark:text-white break-all">{selectedVolume.mountpoint}</span>
                        <button onClick={() => handleCopy(selectedVolume.mountpoint, "volume-mountpoint")} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 flex-shrink-0">
                          {copied === "volume-mountpoint" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
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
                        <button
                          key={idx}
                          onClick={() => {
                            openContainerPanel(containerName);
                            setSelectedVolume(null);
                          }}
                          className="w-full flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 px-3 py-2 rounded transition-colors text-left"
                        >
                          <Server className="h-4 w-4 text-gray-400 flex-shrink-0" />
                          <span className="truncate">{containerName}</span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">Not in use</span>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <Button variant="danger" size="sm" onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteModal(true); }}>
                    <Trash2 className="h-4 w-4 mr-1" />Delete Volume
                  </Button>
                  {selectedVolume.used_by.length > 0 && <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">Warning: Volume is in use. Deletion may require force.</p>}
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
              <h3 className="text-lg font-semibold">Delete {selectedNames.size} Volumes</h3>
            </div>

            {!bulkProgress ? (
              <>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  Are you sure you want to delete <strong>{selectedNames.size}</strong> selected volumes?
                  This action cannot be undone.
                </p>
                <div className="max-h-48 overflow-y-auto mb-4 space-y-1">
                  {selectedData.map((vol) => (
                    <div key={vol.name} className={cn("flex items-center justify-between p-2 rounded text-sm", vol.used_by.length > 0 ? "bg-yellow-50 dark:bg-yellow-900/20" : "bg-gray-50 dark:bg-gray-800")}>
                      <span className="font-mono truncate">{vol.name}</span>
                      <span className="text-gray-500 text-xs">
                        {vol.driver}
                        {vol.used_by.length > 0 && <span className="ml-2 text-yellow-600 dark:text-yellow-400">(in use - will skip)</span>}
                      </span>
                    </div>
                  ))}
                </div>
                {selectedData.some((vol) => vol.used_by.length > 0) && (
                  <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <p className="text-sm text-yellow-700 dark:text-yellow-400">
                      {selectedData.filter((vol) => vol.used_by.length > 0).length} volume(s) are in use and will be skipped.
                    </p>
                  </div>
                )}
                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => setShowBulkDeleteModal(false)}>Cancel</Button>
                  <Button variant="danger" onClick={handleBulkDelete} disabled={selectedData.filter((v) => v.used_by.length === 0).length === 0}>
                    Delete {selectedData.filter((v) => v.used_by.length === 0).length} Volumes
                  </Button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Deleting volumes...</span>
                    <span>{bulkProgress.completed} / {bulkProgress.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-red-600 h-2 rounded-full transition-all duration-300" style={{ width: `${(bulkProgress.completed / bulkProgress.total) * 100}%` }} />
                  </div>
                </div>
                {bulkProgress.failed.length > 0 && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm font-medium text-red-600 dark:text-red-400 mb-2">Failed to delete {bulkProgress.failed.length} volumes:</p>
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

      {/* Create Volume Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowCreateModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-full">
                <Plus className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <h3 className="text-lg font-semibold">Create Volume</h3>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Volume Name</label>
                <Input value={newVolumeName} onChange={(e) => setNewVolumeName(e.target.value)} placeholder="my-volume" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Driver</label>
                <select
                  value={newVolumeDriver}
                  onChange={(e) => setNewVolumeDriver(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="local">local</option>
                </select>
              </div>
              {createError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{createError}</p>
                </div>
              )}
              <div className="flex justify-end gap-3">
                <Button variant="secondary" onClick={() => { setShowCreateModal(false); setNewVolumeName(""); setCreateError(null); }}>Cancel</Button>
                <Button variant="primary" onClick={() => createMutation.mutate()} disabled={!newVolumeName || createMutation.isPending}>
                  {createMutation.isPending ? "Creating..." : "Create"}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Single Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteModal && !!selectedVolume}
        onClose={() => { setShowDeleteModal(false); setDeleteError(null); setForceDelete(false); }}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Volume"
        message={`Are you sure you want to delete volume "${selectedVolume?.name}"?`}
        confirmText="Delete Volume"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
        error={deleteError}
      >
        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
          Force delete
        </label>
      </ConfirmDialog>
    </div>
  );
}
