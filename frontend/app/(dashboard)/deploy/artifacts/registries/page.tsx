"use client";

import { useQuery } from "@tanstack/react-query";
import { Box, CheckCircle2 } from "lucide-react";
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

const registryColumns = [
  {
    key: "name",
    header: "Registry",
    render: (value: string, row: any) => (
      <div className="flex items-center gap-3">
        <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
          <Box className="h-4 w-4 text-orange-600 dark:text-orange-400" />
        </div>
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{row.url}</div>
        </div>
      </div>
    ),
  },
  {
    key: "type",
    header: "Type",
    render: (value: string) => <Badge color="blue">{value}</Badge>,
  },
  {
    key: "is_default",
    header: "Default",
    render: (value: boolean) =>
      value ? (
        <CheckCircle2 className="h-4 w-4 text-green-500" />
      ) : (
        <span className="text-gray-400">-</span>
      ),
  },
  {
    key: "created_at",
    header: "Added",
    render: (value: string) => (
      <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
    ),
  },
];

export default function ArtifactRegistriesPage() {
  const { data: registriesData, isLoading } = useQuery({
    queryKey: ["registries"],
    queryFn: () => api.getRegistries(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading registries..." />
      </div>
    );
  }

  const registries = registriesData || [];
  return registries.length > 0 ? (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      <Table
        columns={registryColumns}
        data={registries}
        keyExtractor={(row) => row.id}
        hoverable
      />
    </div>
  ) : (
    <EmptyState
      icon={Box}
      title="No registries configured"
      description="Add container registries to pull and manage images"
    />
  );
}
