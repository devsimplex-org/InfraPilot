"use client";

import { useQuery } from "@tanstack/react-query";
import { Image } from "lucide-react";
import { api, DockerImage } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

const formatSize = (sizeMb: number) => {
  if (!sizeMb) return "0 MB";
  if (sizeMb >= 1024) return `${(sizeMb / 1024).toFixed(1)} GB`;
  return `${sizeMb.toFixed(1)} MB`;
};

const imageColumns = [
  {
    key: "tags",
    header: "Image",
    render: (value: string[]) => (
      <div className="flex items-center gap-3">
        <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
          <Image className="h-4 w-4 text-blue-600 dark:text-blue-400" />
        </div>
        <div>
          <div className="font-medium text-gray-900 dark:text-white">
            {value?.[0]?.split(":")[0] || "Unknown"}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            {value?.[0]?.split(":")[1] || "latest"}
          </div>
        </div>
      </div>
    ),
  },
  {
    key: "size_mb",
    header: "Size",
    render: (value: number) => (
      <span className="text-sm text-gray-600 dark:text-gray-400">{formatSize(value)}</span>
    ),
  },
  {
    key: "created",
    header: "Created",
    render: (value: string) => (
      <span className="text-sm text-gray-500 dark:text-gray-400">
        {new Date(value).toLocaleDateString()}
      </span>
    ),
  },
];

export default function ArtifactImagesPage() {
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });
  const defaultAgentId = agents?.[0]?.id;

  const { data: imagesData, isLoading } = useQuery({
    queryKey: ["docker-images", defaultAgentId],
    queryFn: () => api.getDockerImages(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading images..." />
      </div>
    );
  }

  const images = imagesData || [];
  return images.length > 0 ? (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      <Table
        columns={imageColumns}
        data={images}
        keyExtractor={(row: DockerImage) => row.id}
        hoverable
      />
    </div>
  ) : (
    <EmptyState
      icon={Image}
      title="No images found"
      description="Docker images from your agents will appear here"
    />
  );
}
