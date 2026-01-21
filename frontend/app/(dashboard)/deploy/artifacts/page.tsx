"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  Image,
  Shield,
  Package,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Tabs } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";

type ArtifactTab = "images" | "scans" | "sboms" | "registries";

export default function ArtifactsPage() {
  const [activeTab, setActiveTab] = useState<ArtifactTab>("images");
  const [searchQuery, setSearchQuery] = useState("");

  // Fetch agents to get images
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.[0]?.id;

  // Fetch images
  const { data: imagesData, isLoading: imagesLoading } = useQuery({
    queryKey: ["docker-images", defaultAgentId],
    queryFn: () => api.getDockerImages(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  // Fetch scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
  });

  // Fetch SBOMs
  const { data: sbomsData, isLoading: sbomsLoading } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => api.listSBOMs(),
  });

  // Fetch registries
  const { data: registriesData, isLoading: registriesLoading } = useQuery({
    queryKey: ["registries"],
    queryFn: () => api.getRegistries(),
  });

  const formatSize = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Tab configuration with counts
  const tabs = [
    { id: "images", label: "Images", count: imagesData?.length || 0 },
    { id: "scans", label: "Scans", count: scansData?.length || 0 },
    { id: "sboms", label: "SBOMs", count: sbomsData?.length || 0 },
    { id: "registries", label: "Registries", count: registriesData?.length || 0 },
  ];

  // Images columns
  const imageColumns = [
    {
      key: "RepoTags",
      header: "Image",
      render: (value: string[], row: any) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Image className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white">
              {value?.[0]?.split(":")[0] || row.Id?.substring(7, 19) || "Unknown"}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {value?.[0]?.split(":")[1] || "latest"}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "Size",
      header: "Size",
      render: (value: number) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{formatSize(value)}</span>
      ),
    },
    {
      key: "Created",
      header: "Created",
      render: (value: number) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {new Date(value * 1000).toLocaleDateString()}
        </span>
      ),
    },
  ];

  // Scans columns
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
          case "completed":
            return <Badge color="green">Completed</Badge>;
          case "running":
            return <Badge color="blue">Running</Badge>;
          case "failed":
            return <Badge color="red">Failed</Badge>;
          default:
            return <Badge>{value}</Badge>;
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

  // SBOMs columns
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

  // Registries columns
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

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Deploy", href: "/deployments" },
        { label: "Artifacts", current: true },
      ]}
    />
  );

  const isLoading =
    (activeTab === "images" && imagesLoading) ||
    (activeTab === "scans" && scansLoading) ||
    (activeTab === "sboms" && sbomsLoading) ||
    (activeTab === "registries" && registriesLoading);

  const renderContent = () => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" label={`Loading ${activeTab}...`} />
        </div>
      );
    }

    switch (activeTab) {
      case "images":
        const images = imagesData || [];
        return images.length > 0 ? (
          <Table
            columns={imageColumns}
            data={images}
            keyExtractor={(row) => row.id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Image}
            title="No images found"
            description="Docker images from your agents will appear here"
            size="sm"
          />
        );

      case "scans":
        const scans = scansData || [];
        return scans.length > 0 ? (
          <Table
            columns={scanColumns}
            data={scans}
            keyExtractor={(row) => row.id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Shield}
            title="No scans found"
            description="Vulnerability scans will appear here after scanning images"
            size="sm"
          />
        );

      case "sboms":
        const sboms = sbomsData || [];
        return sboms.length > 0 ? (
          <Table
            columns={sbomColumns}
            data={sboms}
            keyExtractor={(row) => row.id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Package}
            title="No SBOMs found"
            description="Software Bill of Materials will appear here after generation"
            size="sm"
          />
        );

      case "registries":
        const registries = registriesData || [];
        return registries.length > 0 ? (
          <Table
            columns={registryColumns}
            data={registries}
            keyExtractor={(row) => row.id}
            hoverable
          />
        ) : (
          <EmptyState
            icon={Box}
            title="No registries configured"
            description="Add container registries to pull and manage images"
            action={
              <Link
                href="/registries"
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
              >
                Add Registry
              </Link>
            }
            size="sm"
          />
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Artifacts"
        description="Manage container images, security scans, SBOMs, and registries"
        breadcrumbs={breadcrumbs}
      />

      {/* Summary Stats */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Images"
          value={imagesData?.length || 0}
          icon={Image}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Scans"
          value={scansData?.length || 0}
          icon={Shield}
          iconColor="text-purple-600"
        />
        <StatCard
          label="SBOMs"
          value={sbomsData?.length || 0}
          icon={Package}
          iconColor="text-green-600"
        />
        <StatCard
          label="Registries"
          value={registriesData?.length || 0}
          icon={Box}
          iconColor="text-orange-600"
        />
      </MetricsGrid>

      {/* Tabs and Content */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
        <div className="p-4 border-b border-gray-200 dark:border-gray-800">
          <Tabs
            tabs={tabs}
            activeTab={activeTab}
            onChange={(id) => setActiveTab(id as ArtifactTab)}
          />
        </div>

        <div className="p-0">{renderContent()}</div>
      </div>
    </div>
  );
}
