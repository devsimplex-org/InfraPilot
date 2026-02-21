"use client";

import { useQuery } from "@tanstack/react-query";
import { Shield } from "lucide-react";
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

const scanColumns = [
  {
    key: "image_name",
    header: "Image",
    render: (value: string, row: any) => (
      <div className="flex items-center gap-3">
        <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
          <Shield className="h-4 w-4 text-purple-600 dark:text-purple-400" />
        </div>
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{row.image_tag}</div>
        </div>
      </div>
    ),
  },
  {
    key: "vulnerability_counts",
    header: "Vulnerabilities",
    render: (value: any) => (
      <div className="flex items-center gap-2">
        {value?.critical > 0 && <Badge color="red">{value.critical} Critical</Badge>}
        {value?.high > 0 && <Badge color="yellow">{value.high} High</Badge>}
        {value?.medium > 0 && <Badge color="blue">{value.medium} Medium</Badge>}
        {!value?.critical && !value?.high && !value?.medium && (
          <Badge color="green">Clean</Badge>
        )}
      </div>
    ),
  },
  {
    key: "status",
    header: "Status",
    render: (value: string) => {
      switch (value) {
        case "completed": return <Badge color="green">Completed</Badge>;
        case "running": return <Badge color="blue">Running</Badge>;
        case "failed": return <Badge color="red">Failed</Badge>;
        default: return <Badge>{value}</Badge>;
      }
    },
  },
  {
    key: "scanned_at",
    header: "Scanned",
    render: (value: string) => (
      <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
    ),
  },
];

export default function ArtifactScansPage() {
  const { data: scansData, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading scans..." />
      </div>
    );
  }

  const scans = scansData || [];
  return scans.length > 0 ? (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      <Table
        columns={scanColumns}
        data={scans}
        keyExtractor={(row) => row.id}
        hoverable
      />
    </div>
  ) : (
    <EmptyState
      icon={Shield}
      title="No scans found"
      description="Vulnerability scans will appear here after scanning images"
    />
  );
}
