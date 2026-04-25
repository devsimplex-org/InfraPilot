"use client";

import { useState, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Image as ImageIcon,
  CheckSquare,
  MinusSquare,
  Square,
  Trash2,
  Tag,
  Layers,
  Shield,
  Download,
  Lock,
} from "lucide-react";
import { api, DockerImage } from "@/lib/api";
import { useDocker, formatSize } from "@/lib/docker-context";
import { ContainerListPopover } from "@/components/docker/ContainerListPopover";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";
import { FilterToolbar } from "@/components/ui/FilterToolbar";

export default function DockerImagesPage() {
  const queryClient = useQueryClient();
  const { selectedAgent, forceDelete, setForceDelete, openContainerPanel } = useDocker();

  // Local state
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ total: number; completed: number; failed: string[] } | null>(null);

  // Fetch images
  const { data: images, isLoading } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Filtered images
  const filteredImages = useMemo(() => {
    if (!images) return [];
    if (!searchFilter) return images;
    return images.filter((img) =>
      img.tags.some((t) => t.toLowerCase().includes(searchFilter.toLowerCase())) ||
      img.id.toLowerCase().includes(searchFilter.toLowerCase())
    );
  }, [images, searchFilter]);

  // Selection helpers
  const toggleSelection = (id: string) => {
    setSelectedIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) newSet.delete(id);
      else newSet.add(id);
      return newSet;
    });
  };

  // Only unused images can be selected
  const selectableImages = filteredImages.filter((img) => img.used_by.length === 0);

  const selectAll = () => setSelectedIds(new Set(selectableImages.map((img) => img.id)));
  const selectNone = () => setSelectedIds(new Set());
  const selectUnused = () => setSelectedIds(new Set(filteredImages.filter((img) => img.used_by.length === 0).map((img) => img.id)));
  const selectDangling = () => setSelectedIds(new Set(filteredImages.filter((img) => img.tags.length === 0 && img.used_by.length === 0).map((img) => img.id)));

  const isAllSelected = selectableImages.length > 0 && selectedIds.size === selectableImages.length;
  const isSomeSelected = selectedIds.size > 0 && !isAllSelected;
  const selectedData = filteredImages.filter((img) => selectedIds.has(img.id));
  const selectedSize = selectedData.reduce((sum, img) => sum + img.size, 0);

  // Metrics
  const metrics = {
    total: images?.length || 0,
    totalSize: images?.reduce((sum, img) => sum + img.size, 0) || 0,
    inUse: images?.filter((img) => img.used_by.length > 0).length || 0,
    unused: images?.filter((img) => img.used_by.length === 0).length || 0,
    dangling: images?.filter((img) => img.tags.length === 0).length || 0,
  };

  // Bulk delete
  const handleBulkDelete = async () => {
    const toDelete = selectedData.filter((img) => img.used_by.length === 0 || forceDelete);
    if (toDelete.length === 0) return;
    setBulkProgress({ total: toDelete.length, completed: 0, failed: [] });
    const failed: string[] = [];
    for (let i = 0; i < toDelete.length; i++) {
      try {
        await api.deleteDockerImage(selectedAgent!, toDelete[i].id, forceDelete);
      } catch {
        failed.push(toDelete[i].tags[0] || toDelete[i].id.slice(0, 12));
      }
      setBulkProgress({ total: toDelete.length, completed: i + 1, failed });
    }
    queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
    if (failed.length === 0) {
      setShowBulkDeleteModal(false);
      selectNone();
      setBulkProgress(null);
      setForceDelete(false);
    }
  };

  // Table columns
  const columns = [
    {
      key: "checkbox",
      header: (
        <button onClick={(e) => { e.stopPropagation(); isAllSelected ? selectNone() : selectAll(); }} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded">
          {isAllSelected ? <CheckSquare className="h-4 w-4 text-primary-600" /> : isSomeSelected ? <MinusSquare className="h-4 w-4 text-primary-600" /> : <Square className="h-4 w-4 text-gray-400" />}
        </button>
      ),
      width: "40px",
      render: (_: unknown, row: DockerImage) => (
        <button
          onClick={(e) => { e.stopPropagation(); if (row.used_by.length === 0) toggleSelection(row.id); }}
          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
          title={row.used_by.length > 0 ? "Image is in use" : undefined}
        >
          {row.used_by.length > 0 ? (
            <Lock className="h-4 w-4 text-green-500" />
          ) : selectedIds.has(row.id) ? (
            <CheckSquare className="h-4 w-4 text-primary-600" />
          ) : (
            <Square className="h-4 w-4 text-gray-400" />
          )}
        </button>
      ),
    },
    {
      key: "name",
      header: "Image",
      sortable: true,
      render: (_: unknown, row: DockerImage) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <ImageIcon className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{row.tags[0]?.split(":")[0] || row.id.slice(0, 12)}</p>
            <p className="text-xs text-gray-500 font-mono">{row.id.slice(7, 19)}</p>
          </div>
        </div>
      ),
    },
    {
      key: "tags",
      header: "Tags",
      render: (value: string[]) => {
        if (value.length === 0) {
          return <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">No tags</Badge>;
        }
        const tag = value[0].split(":")[1] || "latest";
        return (
          <Badge className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">
            <Tag className="h-3 w-3 mr-1" />
            {tag}{value.length > 1 && ` +${value.length - 1}`}
          </Badge>
        );
      },
    },
    {
      key: "size",
      header: "Size",
      sortable: true,
      render: (value: number) => <span className="text-sm text-gray-600 dark:text-gray-400">{formatSize(value)}</span>,
    },
    {
      key: "used_by",
      header: "Status",
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
        <StatCard label="Total Images" value={metrics.total} icon={ImageIcon} iconColor="text-purple-600 dark:text-purple-400" />
        <StatCard label="Total Size" value={formatSize(metrics.totalSize)} icon={Layers} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="In Use" value={metrics.inUse} icon={Tag} iconColor="text-green-600 dark:text-green-400" />
        <StatCard label="Unused" value={metrics.unused} icon={Shield} iconColor="text-orange-600 dark:text-orange-400" />
      </MetricsGrid>

      {/* Filter Toolbar */}
      <FilterToolbar
        searchQuery={searchFilter}
        onSearchChange={setSearchFilter}
        searchPlaceholder="Search images..."
        showSearch={true}
        showRefresh={true}
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] })}
        singleRow={true}
      />

      {/* Selection Bar */}
      {images && images.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500 dark:text-gray-400">Quick select:</span>
            <button onClick={selectAll} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg">All ({filteredImages.length})</button>
            <button onClick={selectUnused} disabled={metrics.unused === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50">Unused ({metrics.unused})</button>
            <button onClick={selectDangling} disabled={metrics.dangling === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50">Dangling ({metrics.dangling})</button>
            {selectedIds.size > 0 && <button onClick={selectNone} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400">Clear</button>}
          </div>
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-700 dark:text-gray-300"><strong>{selectedIds.size}</strong> selected ({formatSize(selectedSize)})</span>
              <Button variant="danger" size="sm" onClick={() => setShowBulkDeleteModal(true)}>
                <Trash2 className="h-4 w-4 mr-1" />Delete Selected
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <Spinner.LogoPage label="Loading images..." />
      ) : filteredImages.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            data={filteredImages}
            columns={columns}
            keyExtractor={(row) => row.id}
            hoverable
            rowClassName={(row) => cn(selectedIds.has(row.id) && "bg-blue-50 dark:bg-blue-900/10")}
          />
        </div>
      ) : (
        <EmptyState
          icon={ImageIcon}
          title="No images found"
          description={images?.length === 0 ? "Pull an image to get started" : "No images match the search"}
          action={
            images?.length === 0 ? (
              <Button variant="primary">
                <Download className="h-4 w-4 mr-1" />Pull Image
              </Button>
            ) : undefined
          }
        />
      )}

      {/* Bulk Delete Modal */}
      {showBulkDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => !bulkProgress && setShowBulkDeleteModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-lg w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <Trash2 className="h-5 w-5 text-red-600" />
              </div>
              <h3 className="text-lg font-semibold">Delete {selectedIds.size} Images</h3>
            </div>
            {!bulkProgress ? (
              <>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  Delete <strong>{selectedIds.size}</strong> images? This will free up <strong>{formatSize(selectedSize)}</strong>.
                </p>
                {selectedData.some((img) => img.used_by.length > 0) && (
                  <label className="flex items-center gap-2 mb-4">
                    <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300" />
                    <span className="text-sm text-yellow-600">Force delete images in use</span>
                  </label>
                )}
                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => { setShowBulkDeleteModal(false); setForceDelete(false); }}>Cancel</Button>
                  <Button variant="danger" onClick={handleBulkDelete} disabled={selectedData.some((img) => img.used_by.length > 0) && !forceDelete}>Delete</Button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Deleting...</span>
                    <span>{bulkProgress.completed} / {bulkProgress.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-red-600 h-2 rounded-full transition-all" style={{ width: `${(bulkProgress.completed / bulkProgress.total) * 100}%` }} />
                  </div>
                </div>
                {bulkProgress.failed.length > 0 && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm font-medium text-red-600 mb-2">Failed: {bulkProgress.failed.length}</p>
                    <ul className="text-xs text-red-600">{bulkProgress.failed.map((n, i) => <li key={i}>• {n}</li>)}</ul>
                  </div>
                )}
                {bulkProgress.completed === bulkProgress.total && (
                  <div className="flex justify-end">
                    <Button variant="secondary" onClick={() => { setShowBulkDeleteModal(false); selectNone(); setBulkProgress(null); setForceDelete(false); }}>
                      {bulkProgress.failed.length > 0 ? "Close" : "Done"}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
