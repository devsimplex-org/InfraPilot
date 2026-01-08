"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Image as ImageIcon,
  Download,
  Trash2,
  AlertTriangle,
  Copy,
  Check,
  Server,
  X,
  Tag,
} from "lucide-react";
import { api, DockerImage } from "@/lib/api";
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

export default function ImagesPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedImage, setSelectedImage] = useState<DockerImage | null>(null);
  const [showPullModal, setShowPullModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);
  const [copied, setCopied] = useState(false);

  // Pull form state
  const [pullImageRef, setPullImageRef] = useState("");
  const [pullError, setPullError] = useState<string | null>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch images for selected agent
  const { data: images, isLoading } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Pull image mutation
  const pullMutation = useMutation({
    mutationFn: () => api.pullDockerImage(selectedAgent!, pullImageRef),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
      setShowPullModal(false);
      setPullImageRef("");
      setPullError(null);
    },
    onError: (error: Error) => {
      setPullError(error.message);
    },
  });

  // Delete image mutation
  const deleteMutation = useMutation({
    mutationFn: () =>
      api.deleteDockerImage(selectedAgent!, selectedImage!.id, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
      setShowDeleteModal(false);
      setDeleteError(null);
      setForceDelete(false);
      setSelectedImage(null);
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

  const formatSize = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const getImageName = (image: DockerImage) => {
    if (image.tags.length > 0) {
      return image.tags[0].split(":")[0];
    }
    return `<none>`;
  };

  const getImageTag = (image: DockerImage) => {
    if (image.tags.length > 0) {
      const parts = image.tags[0].split(":");
      return parts.length > 1 ? parts[1] : "latest";
    }
    return image.id.slice(0, 12);
  };

  return (
    <PageLayout
      title="Docker Images"
      description="Manage Docker images on your server"
      actions={
        <div className="flex items-center gap-3">
          {activeAgents.length > 1 && (
            <select
              value={selectedAgent || ""}
              onChange={(e) => {
                setSelectedAgent(e.target.value);
                setSelectedImage(null);
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
            onClick={() => setShowPullModal(true)}
            disabled={!selectedAgent}
          >
            <Download className="h-4 w-4 mr-1" />
            Pull Image
          </Button>
        </div>
      }
      panelOpen={!!selectedImage}
      panel={
        selectedImage && (
          <DetailPanel
            open={!!selectedImage}
            onClose={() => setSelectedImage(null)}
            title={getImageName(selectedImage)}
            subtitle={formatSize(selectedImage.size)}
            defaultWidth={480}
          >
            <DetailSection title="Image Info">
              <DetailRow
                label="ID"
                mono
                value={
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs">{selectedImage.id}</span>
                    <button
                      onClick={() => handleCopy(selectedImage.id)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                }
              />
              <DetailRow label="Size" value={formatSize(selectedImage.size)} />
              <DetailRow
                label="Created"
                value={new Date(selectedImage.created).toLocaleString()}
              />
            </DetailSection>

            <DetailSection title="Tags">
              {selectedImage.tags.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {selectedImage.tags.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-full"
                    >
                      <Tag className="h-3 w-3" />
                      {tag}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-gray-500">No tags</p>
              )}
            </DetailSection>

            <DetailSection title="Used By">
              {selectedImage.used_by.length > 0 ? (
                <div className="space-y-2">
                  {selectedImage.used_by.map((container) => (
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

            {selectedImage.repo_digests.length > 0 && (
              <DetailSection title="Digests">
                <div className="space-y-1">
                  {selectedImage.repo_digests.map((digest, idx) => (
                    <p key={idx} className="text-xs font-mono text-gray-500 break-all">
                      {digest}
                    </p>
                  ))}
                </div>
              </DetailSection>
            )}

            <DetailSection title="Actions">
              <Button
                variant="danger"
                size="sm"
                onClick={() => setShowDeleteModal(true)}
              >
                <Trash2 className="h-4 w-4 mr-1" />
                Delete Image
              </Button>
              {selectedImage.used_by.length > 0 && (
                <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">
                  Warning: Image is in use. Deletion may require force.
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
          description="Add an agent to manage Docker images"
        />
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
        </div>
      ) : images && images.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {images.map((image) => {
            const isSelected = selectedImage?.id === image.id;
            const inUse = image.used_by.length > 0;

            return (
              <ListCard
                key={image.id}
                selected={isSelected}
                onClick={() => setSelectedImage(image)}
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
                      <ImageIcon
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
                        {getImageName(image)}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 rounded">
                          {getImageTag(image)}
                        </span>
                        <span className="text-xs text-gray-500">{formatSize(image.size)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    {inUse && (
                      <span className="text-xs text-green-600 dark:text-green-400">In use</span>
                    )}
                    <p className="text-xs text-gray-500 mt-1">
                      {image.used_by.length} container{image.used_by.length !== 1 ? "s" : ""}
                    </p>
                  </div>
                </div>
              </ListCard>
            );
          })}
        </div>
      ) : (
        <EmptyState
          icon={ImageIcon}
          title="No images found"
          description="Pull a Docker image to get started"
          action={
            <Button variant="primary" onClick={() => setShowPullModal(true)}>
              <Download className="h-4 w-4 mr-1" />
              Pull Image
            </Button>
          }
        />
      )}

      {/* Pull Image Modal */}
      {showPullModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowPullModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Pull Image</h3>
              <button onClick={() => setShowPullModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <Input
                label="Image Reference"
                value={pullImageRef}
                onChange={(e) => setPullImageRef(e.target.value)}
                placeholder="nginx:latest or ubuntu:22.04"
              />
              <p className="text-xs text-gray-500">
                Enter the image name and tag (e.g., nginx:latest, postgres:15)
              </p>

              {pullError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{pullError}</p>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={() => setShowPullModal(false)}>Cancel</Button>
              <Button
                variant="primary"
                onClick={() => pullMutation.mutate()}
                disabled={!pullImageRef || pullMutation.isPending}
              >
                {pullMutation.isPending ? "Pulling..." : "Pull Image"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Image Modal */}
      {showDeleteModal && selectedImage && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowDeleteModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold">Delete Image</h3>
            </div>

            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Are you sure you want to delete{" "}
              <span className="font-medium text-gray-900 dark:text-white">
                {selectedImage.tags[0] || selectedImage.id}
              </span>
              ?
            </p>

            {selectedImage.used_by.length > 0 && (
              <div className="mb-4">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={forceDelete}
                    onChange={(e) => setForceDelete(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm text-yellow-600 dark:text-yellow-400">
                    Force delete (image is in use by {selectedImage.used_by.length} container{selectedImage.used_by.length !== 1 ? "s" : ""})
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
                disabled={deleteMutation.isPending || (selectedImage.used_by.length > 0 && !forceDelete)}
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete Image"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
