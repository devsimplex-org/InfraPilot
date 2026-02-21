"use client";

import { useQuery } from "@tanstack/react-query";
import { Package } from "lucide-react";
import { api } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

const formatTimestamp = (timestamp: string) =>
  new Date(timestamp).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

const sbomColumns = [
  {
    key: "image_name",
    header: "Image",
    render: (value: string, row: any) => (
      <div className="flex items-center gap-3">
        <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
          <Package className="h-4 w-4 text-green-600 dark:text-green-400" />
        </div>
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{row.image_tag}</div>
        </div>
      </div>
    ),
  },
  {
    key: "format",
    header: "Format",
    render: (value: string) => <Badge color="gray">{value?.toUpperCase() || "SPDX"}</Badge>,
  },
  {
    key: "package_count",
    header: "Packages",
    render: (value: number) => (
      <span className="text-sm text-gray-600 dark:text-gray-400">{value || 0}</span>
    ),
  },
  {
    key: "created_at",
    header: "Generated",
    render: (value: string) => (
      <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
    ),
  },
];

export default function ArtifactSBOMsPage() {
  const { data: sbomsData, isLoading } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => api.listSBOMs(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading SBOMs..." />
      </div>
    );
  }

  const sboms = sbomsData || [];
  return sboms.length > 0 ? (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      <Table
        columns={sbomColumns}
        data={sboms}
        keyExtractor={(row) => row.id}
        hoverable
      />
    </div>
  ) : (
    <EmptyState
      icon={Package}
      title="No SBOMs found"
      description="Software Bill of Materials will appear here after generation"
    />
  );
}
