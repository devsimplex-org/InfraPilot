"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  HardDrive,
  Plus,
  Trash2,
  AlertTriangle,
  Copy,
  Check,
  Server,
  X,
  FolderOpen,
  Database,
} from "lucide-react";
import { api, DockerVolume } from "@/lib/api";
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

export default function VolumesPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedVolume, setSelectedVolume] = useState<DockerVolume | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);
  const [copied, setCopied] = useState(false);

  // Create form state
  const [newVolumeName, setNewVolumeName] = useState("");
  const [newVolumeDriver, setNewVolumeDriver] = useState("local");
  const [createError, setCreateError] = useState<string | null>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch volumes for selected agent
  const { data: volumes, isLoading } = useQuery({
    queryKey: ["docker-volumes", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getDockerVolumes(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Create volume mutation
  const createMutation = useMutation({
    mutationFn: () =>
      api.createDockerVolume(selectedAgent!, {
        name: newVolumeName,
        driver: newVolumeDriver,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowCreateModal(false);
      setNewVolumeName("");
      setNewVolumeDriver("local");
      setCreateError(null);
    },
    onError: (error: Error) => {
      setCreateError(error.message);
    },
  });

  // Delete volume mutation
  const deleteMutation = useMutation({
    mutationFn: () =>
      api.deleteDockerVolume(selectedAgent!, selectedVolume!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowDeleteModal(false);
      setDeleteError(null);
      setForceDelete(false);
      setSelectedVolume(null);
    },
    onError: (error: Error) => {
      setDeleteError(error.message);
    },
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Calculate metrics
  const totalVolumes = volumes?.length || 0;
  const inUse = volumes?.filter((v) => v.used_by.length > 0).length || 0;
  const orphaned = volumes?.filter((v) => v.used_by.length === 0).length || 0;
  const totalSize = "N/A"; // Size calculation would require additional data

  // Table columns
  const columns = [
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
            <p className="font-medium text-gray-900 dark:text-white">{value}</p>
            <p className="text-xs text-gray-500">{row.driver} driver</p>
          </div>
        </div>
      ),
    },
    {
      key: "mountpoint",
      header: "Mount Point",
      sortable: true,
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
      render: (value: string[]) => {
        const inUse = value.length > 0;
        return inUse ? (
          <Badge className="px-2 py-1 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
            {value.length} container{value.length !== 1 ? "s" : ""}
          </Badge>
        ) : (
          <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
            Unused
          </Badge>
        );
      },
    },
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Docker Volumes"
        description="Manage Docker volumes for persistent data storage"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform", href: "/dashboard" },
              { label: "Volumes", current: true },
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
                  setSelectedVolume(null);
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
              Create Volume
            </Button>
          </div>
        }
      />

      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker volumes"
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
              label="Total Volumes"
              value={totalVolumes}
              icon={HardDrive}
              iconColor="text-blue-600 dark:text-blue-400"
            />
            <StatCard
              label="In Use"
              value={inUse}
              icon={Database}
              iconColor="text-green-600 dark:text-green-400"
            />
            <StatCard
              label="Total Size"
              value={totalSize}
              icon={FolderOpen}
              iconColor="text-purple-600 dark:text-purple-400"
            />
            <StatCard
              label="Orphaned"
              value={orphaned}
              icon={AlertTriangle}
              iconColor="text-orange-600 dark:text-orange-400"
            />
          </MetricsGrid>

          {/* Table */}
          {volumes && volumes.length > 0 ? (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
              <Table
                columns={columns}
                data={volumes}
                keyExtractor={(row) => row.name}
                onRowClick={(row) => setSelectedVolume(row)}
                hoverable
                rowClassName={(row) =>
                  selectedVolume?.name === row.name
                    ? "bg-primary-50 dark:bg-primary-900/20"
                    : ""
                }
              />
            </div>
          ) : (
            <EmptyState
              icon={HardDrive}
              title="No volumes found"
              description="Create a Docker volume to persist data"
              action={
                <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Create Volume
                </Button>
              }
            />
          )}
        </>
      )}

      {/* SlideOver for Volume Details */}
      <SlideOver
        isOpen={!!selectedVolume}
        onClose={() => setSelectedVolume(null)}
        size="md"
      >
        {selectedVolume && (
          <>
            <SlideOver.Header onClose={() => setSelectedVolume(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedVolume.name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {selectedVolume.driver} driver
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Volume Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Volume Info
                  </h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.driver}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.scope}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Mountpoint</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-900 dark:text-white break-all">
                          {selectedVolume.mountpoint}
                        </span>
                        <button
                          onClick={() => handleCopy(selectedVolume.mountpoint)}
                          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 flex-shrink-0"
                        >
                          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                    {selectedVolume.created_at && (
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                        <span className="text-sm text-gray-900 dark:text-white">
                          {new Date(selectedVolume.created_at).toLocaleString()}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Used By */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Used By
                  </h3>
                  {selectedVolume.used_by.length > 0 ? (
                    <div className="space-y-2">
                      {selectedVolume.used_by.map((container) => (
                        <div
                          key={container}
                          className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                        >
                          <Server className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-900 dark:text-white">{container}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">Not used by any containers</p>
                  )}
                </div>

                {/* Labels */}
                {selectedVolume.labels && Object.keys(selectedVolume.labels).length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Labels
                    </h3>
                    <div className="space-y-2">
                      {Object.entries(selectedVolume.labels).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-sm font-mono text-gray-500 dark:text-gray-400">{key}</span>
                          <span className="text-sm font-mono text-gray-900 dark:text-white">{value}</span>
                        </div>
                      ))}
                    </div>
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
                  >
                    <Trash2 className="h-4 w-4 mr-1" />
                    Delete Volume
                  </Button>
                  {selectedVolume.used_by.length > 0 && (
                    <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">
                      Warning: Volume is in use. Deletion may require force.
                    </p>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Create Volume Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowCreateModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Create Volume</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <Input
                label="Volume Name"
                value={newVolumeName}
                onChange={(e) => setNewVolumeName(e.target.value)}
                placeholder="my-volume"
              />

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Driver
                </label>
                <select
                  value={newVolumeDriver}
                  onChange={(e) => setNewVolumeDriver(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900"
                >
                  <option value="local">local</option>
                </select>
              </div>

              {createError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{createError}</p>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={() => setShowCreateModal(false)}>Cancel</Button>
              <Button
                variant="primary"
                onClick={() => createMutation.mutate()}
                disabled={!newVolumeName || createMutation.isPending}
              >
                {createMutation.isPending ? "Creating..." : "Create"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Volume Modal */}
      {showDeleteModal && selectedVolume && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowDeleteModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold">Delete Volume</h3>
            </div>

            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Are you sure you want to delete <span className="font-medium text-gray-900 dark:text-white">{selectedVolume.name}</span>?
              This will permanently remove all data stored in this volume.
            </p>

            {selectedVolume.used_by.length > 0 && (
              <div className="mb-4">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={forceDelete}
                    onChange={(e) => setForceDelete(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm text-yellow-600 dark:text-yellow-400">
                    Force delete (volume is in use by {selectedVolume.used_by.length} container{selectedVolume.used_by.length !== 1 ? "s" : ""})
                  </span>
                </label>
              </div>
            )}

            {deleteError && (
              <div className="p-3 mb-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{deleteError}</p>
              </div>
            )}

            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={() => { setShowDeleteModal(false); setForceDelete(false); setDeleteError(null); }}>Cancel</Button>
              <Button
                variant="danger"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending || (selectedVolume.used_by.length > 0 && !forceDelete)}
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete Volume"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
