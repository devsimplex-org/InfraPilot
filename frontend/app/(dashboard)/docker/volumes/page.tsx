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
} from "lucide-react";
import { api, DockerVolume } from "@/lib/api";
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

  return (
    <PageLayout
      title="Docker Volumes"
      description="Manage Docker volumes for persistent data storage"
      actions={
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
      panelOpen={!!selectedVolume}
      panel={
        selectedVolume && (
          <DetailPanel
            open={!!selectedVolume}
            onClose={() => setSelectedVolume(null)}
            title={selectedVolume.name}
            subtitle={`${selectedVolume.driver} driver`}
            defaultWidth={480}
          >
            <DetailSection title="Volume Info">
              <DetailRow label="Name" value={selectedVolume.name} />
              <DetailRow label="Driver" value={selectedVolume.driver} />
              <DetailRow label="Scope" value={selectedVolume.scope} />
              <DetailRow
                label="Mountpoint"
                mono
                value={
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs truncate max-w-[200px]">
                      {selectedVolume.mountpoint}
                    </span>
                    <button
                      onClick={() => handleCopy(selectedVolume.mountpoint)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 flex-shrink-0"
                    >
                      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                }
              />
              {selectedVolume.created_at && (
                <DetailRow
                  label="Created"
                  value={new Date(selectedVolume.created_at).toLocaleString()}
                />
              )}
            </DetailSection>

            <DetailSection title="Used By">
              {selectedVolume.used_by.length > 0 ? (
                <div className="space-y-2">
                  {selectedVolume.used_by.map((container) => (
                    <div
                      key={container}
                      className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      <Server className="h-4 w-4 text-gray-400" />
                      <span className="text-sm">{container}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-gray-500">Not used by any containers</p>
              )}
            </DetailSection>

            {selectedVolume.labels && Object.keys(selectedVolume.labels).length > 0 && (
              <DetailSection title="Labels">
                {Object.entries(selectedVolume.labels).map(([key, value]) => (
                  <DetailRow key={key} label={key} mono value={value} />
                ))}
              </DetailSection>
            )}

            <DetailSection title="Actions">
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
            </DetailSection>
          </DetailPanel>
        )
      }
    >
      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker volumes"
        />
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
        </div>
      ) : volumes && volumes.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {volumes.map((volume) => {
            const isSelected = selectedVolume?.name === volume.name;
            const inUse = volume.used_by.length > 0;

            return (
              <ListCard
                key={volume.name}
                selected={isSelected}
                onClick={() => setSelectedVolume(volume)}
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
                      <HardDrive
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
                        {volume.name}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-gray-500">{volume.driver}</span>
                        {inUse && (
                          <span className="text-xs text-green-600 dark:text-green-400">
                            In use
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <span className="text-xs text-gray-500">
                    {volume.used_by.length} container{volume.used_by.length !== 1 ? "s" : ""}
                  </span>
                </div>
              </ListCard>
            );
          })}
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
    </PageLayout>
  );
}
