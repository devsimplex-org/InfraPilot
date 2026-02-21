"use client";

import { useQuery } from "@tanstack/react-query";
import { Shield } from "lucide-react";
import { api, RateLimitProfile } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

const profileColumns = [
  {
    key: "name",
    header: "Profile Name",
    sortable: true,
    render: (value: string, row: RateLimitProfile) => (
      <div>
        <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
        {row.is_default && (
          <Badge color="blue" className="ml-2">Default</Badge>
        )}
      </div>
    ),
  },
  {
    key: "requests_per_second",
    header: "Rate (req/s)",
    render: (value: number | undefined, row: RateLimitProfile) => (
      <span className="text-sm text-gray-700 dark:text-gray-300">
        {value || row.requests_per_minute
          ? `${row.requests_per_minute}/min`
          : row.requests_per_hour
          ? `${row.requests_per_hour}/hr`
          : "N/A"}
      </span>
    ),
  },
  {
    key: "burst_size",
    header: "Burst",
    render: (value: number) => (
      <span className="text-sm text-gray-700 dark:text-gray-300">{value}</span>
    ),
  },
  {
    key: "key_type",
    header: "Key Type",
    render: (value: string) => <Badge color="gray">{value}</Badge>,
  },
  {
    key: "exceeded_action",
    header: "Action",
    render: (value: string) => (
      <Badge color={value === "reject" ? "red" : value === "throttle" ? "yellow" : "blue"}>
        {value}
      </Badge>
    ),
  },
  {
    key: "enabled",
    header: "Enabled",
    render: (value: boolean) =>
      value ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>,
  },
];

export default function RateLimitsPage() {
  const { data: profilesData, isLoading } = useQuery({
    queryKey: ["ratelimit-profiles"],
    queryFn: () => api.listRateLimitProfiles(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading rate limit profiles..." />
      </div>
    );
  }

  return (profilesData?.profiles?.length ?? 0) > 0 ? (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      <Table
        columns={profileColumns}
        data={profilesData!.profiles}
        keyExtractor={(row) => row.id}
        hoverable
      />
    </div>
  ) : (
    <EmptyState
      icon={Shield}
      title="No rate limit profiles"
      description="Create rate limit profiles to control traffic to your endpoints"
    />
  );
}
