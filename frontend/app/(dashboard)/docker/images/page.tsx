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
  Layers,
  Shield,
} from "lucide-react";
import { api, DockerImage } from "@/lib/api";
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

  // Calculate metrics
  const totalImages = images?.length || 0;
  const totalSize = images?.reduce((sum, img) => sum + img.size, 0) || 0;
  const totalTags = images?.reduce((sum, img) => sum + img.tags.length, 0) || 0;
  const vulnerabilities = 0; // Would require vulnerability scanning data

  // Table columns
  const columns = [
    {
      key: "name",
      header: "Image Name",
      sortable: true,
      render: (_: any, row: DockerImage) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <ImageIcon className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{getImageName(row)}</p>
            <p className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</p>
          </div>
        </div>
      ),
    },
    {
      key: "tags",
      header: "Tags",
      render: (value: string[]) => {
        if (value.length === 0) {
          return (
            <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
              No tags
            </Badge>
          );
        }
        const tag = getImageTag({ tags: value } as DockerImage);
        return (
          <Badge className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">
            <Tag className="h-3 w-3 mr-1" />
            {tag}
            {value.length > 1 && ` +${value.length - 1}`}
          </Badge>
        );
      },
    },
    {
      key: "size",
      header: "Size",
      sortable: true,
      align: "right" as const,
      render: (value: number) => (
        <span className="text-sm text-gray-900 dark:text-white">{formatSize(value)}</span>
      ),
    },
    {
      key: "created",
      header: "Created",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-500">
          {new Date(value).toLocaleDateString()}
        </span>
      ),
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
        ) : null;
      },
    },
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Docker Images"
        description="Manage Docker images on your server"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Deploy", href: "/dashboard" },
              { label: "Images", current: true },
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
      />

      {!selectedAgent ? (
        <EmptyState
          icon={Server}
          title="No agents available"
          description="Add an agent to manage Docker images"
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
              label="Total Images"
              value={totalImages}
              icon={ImageIcon}
              iconColor="text-blue-600 dark:text-blue-400"
            />
            <StatCard
              label="Total Size"
              value={formatSize(totalSize)}
              icon={Layers}
              iconColor="text-purple-600 dark:text-purple-400"
            />
            <StatCard
              label="Total Tags"
              value={totalTags}
              icon={Tag}
              iconColor="text-green-600 dark:text-green-400"
            />
            <StatCard
              label="Vulnerabilities"
              value={vulnerabilities}
              icon={Shield}
              iconColor="text-orange-600 dark:text-orange-400"
            />
          </MetricsGrid>

          {/* Table */}
          {images && images.length > 0 ? (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
              <Table
                columns={columns}
                data={images}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedImage(row)}
                hoverable
                rowClassName={(row) =>
                  selectedImage?.id === row.id
                    ? "bg-primary-50 dark:bg-primary-900/20"
                    : ""
                }
              />
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
        </>
      )}

      {/* SlideOver for Image Details */}
      <SlideOver
        isOpen={!!selectedImage}
        onClose={() => setSelectedImage(null)}
        size="md"
      >
        {selectedImage && (
          <>
            <SlideOver.Header onClose={() => setSelectedImage(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {getImageName(selectedImage)}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {formatSize(selectedImage.size)}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Image Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Image Info
                  </h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-900 dark:text-white">
                          {selectedImage.id.slice(0, 12)}
                        </span>
                        <button
                          onClick={() => handleCopy(selectedImage.id)}
                          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        >
                          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Size</span>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {formatSize(selectedImage.size)}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {new Date(selectedImage.created).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Tags */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Tags
                  </h3>
                  {selectedImage.tags.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {selectedImage.tags.map((tag) => (
                        <Badge
                          key={tag}
                          className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0"
                        >
                          <Tag className="h-3 w-3 mr-1" />
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">No tags</p>
                  )}
                </div>

                {/* Used By */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Used By
                  </h3>
                  {selectedImage.used_by.length > 0 ? (
                    <div className="space-y-2">
                      {selectedImage.used_by.map((container) => (
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

                {/* Layers (Placeholder) */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Layers
                  </h3>
                  <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="flex items-center gap-2 text-gray-500">
                      <Layers className="h-4 w-4" />
                      <span className="text-sm">Layer information not available</span>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities (Placeholder) */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Vulnerabilities
                  </h3>
                  <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="flex items-center gap-2 text-gray-500">
                      <Shield className="h-4 w-4" />
                      <span className="text-sm">Vulnerability scanning not configured</span>
                    </div>
                  </div>
                </div>

                {/* Digests */}
                {selectedImage.repo_digests.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Digests
                    </h3>
                    <div className="space-y-1">
                      {selectedImage.repo_digests.map((digest, idx) => (
                        <p key={idx} className="text-xs font-mono text-gray-500 break-all">
                          {digest}
                        </p>
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
                    Delete Image
                  </Button>
                  {selectedImage.used_by.length > 0 && (
                    <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">
                      Warning: Image is in use. Deletion may require force.
                    </p>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

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
    </div>
  );
}
