"use client";

import { useQuery } from "@tanstack/react-query";
import { Globe, Lock, CheckCircle2, AlertTriangle, Shield } from "lucide-react";
import { api, TLSScanResult } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { cn } from "@/lib/utils";

const tlsColumns = [
  {
    key: "domain",
    header: "Domain",
    sortable: true,
    render: (value: string) => (
      <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
    ),
  },
  {
    key: "cert_valid",
    header: "Certificate",
    render: (value: boolean) =>
      value ? <Badge color="green">Valid</Badge> : <Badge color="red">Invalid</Badge>,
  },
  {
    key: "grade",
    header: "Grade",
    render: (value: string | undefined) => {
      const gradeColor = value?.startsWith("A")
        ? "green"
        : value?.startsWith("B")
        ? "yellow"
        : "red";
      return value ? (
        <Badge color={gradeColor}>{value}</Badge>
      ) : (
        <Badge color="gray">N/A</Badge>
      );
    },
  },
  {
    key: "protocol_version",
    header: "Protocol",
    render: (value: string | undefined) => (
      <span className="text-sm text-gray-700 dark:text-gray-300">{value || "N/A"}</span>
    ),
  },
  {
    key: "cert_days_left",
    header: "Expires In",
    render: (value: number | undefined) => {
      if (value === undefined) return <span className="text-gray-500">N/A</span>;
      const color =
        value <= 7 ? "text-red-600" : value <= 30 ? "text-yellow-600" : "text-green-600";
      return <span className={cn("text-sm font-medium", color)}>{value} days</span>;
    },
  },
  {
    key: "hsts_enabled",
    header: "HSTS",
    render: (value: boolean) =>
      value ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>,
  },
  {
    key: "scanned_at",
    header: "Scanned",
    render: (value: string) => (
      <span className="text-sm text-gray-500 dark:text-gray-400">
        {new Date(value).toLocaleString()}
      </span>
    ),
  },
];

export default function TLSPosturePage() {
  const { data: tlsPosture } = useQuery({
    queryKey: ["tls-posture"],
    queryFn: () => api.getTLSPosture(),
  });

  const { data: tlsScans } = useQuery({
    queryKey: ["tls-scans"],
    queryFn: () => api.listTLSScans({ limit: 50 }),
  });

  return (
    <div className="space-y-6">
      <MetricsGrid columns={4}>
        <StatCard
          label="Total Domains"
          value={tlsPosture?.total_domains || 0}
          icon={Globe}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Valid Certificates"
          value={tlsPosture?.valid_certs || 0}
          icon={CheckCircle2}
          iconColor="text-green-600"
        />
        <StatCard
          label="Self-Signed"
          value={tlsPosture?.self_signed || 0}
          icon={AlertTriangle}
          iconColor="text-yellow-600"
        />
        <StatCard
          label="Average Score"
          value={tlsPosture?.avg_score || 0}
          icon={Shield}
          iconColor="text-blue-600"
        />
      </MetricsGrid>

      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
        {tlsScans && tlsScans.scans.length > 0 ? (
          <Table
            columns={tlsColumns}
            data={tlsScans.scans}
            keyExtractor={(row) => row.id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Lock}
            title="No TLS scans available"
            description="TLS scans will appear here after scanning your endpoints"
            size="sm"
          />
        )}
      </div>
    </div>
  );
}
