"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Shield,
  Lock,
  Unlock,
  AlertTriangle,
  RefreshCw,
  Plus,
  Trash2,
  ExternalLink,
  Network,
  Server,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { api, ExposedEndpoint, RateLimitProfile, TLSScanResult } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

type TabType = "overview" | "endpoints" | "ratelimits" | "tls";

export default function ExposurePage() {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [selectedEndpoint, setSelectedEndpoint] = useState<ExposedEndpoint | null>(null);
  const [endpointFilters, setEndpointFilters] = useState({
    exposure_type: "",
    status: "",
    min_risk_score: undefined as number | undefined,
  });
  const queryClient = useQueryClient();

  // Query exposure summary
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["exposure-summary"],
    queryFn: () => api.getExposureSummary(),
  });

  // Query endpoints
  const { data: endpointsData, isLoading: endpointsLoading } = useQuery({
    queryKey: ["exposed-endpoints", endpointFilters],
    queryFn: () => api.listExposedEndpoints(endpointFilters),
  });

  // Query rate limit profiles
  const { data: profilesData, isLoading: profilesLoading } = useQuery({
    queryKey: ["ratelimit-profiles"],
    queryFn: () => api.listRateLimitProfiles(),
  });

  // Query TLS posture
  const { data: tlsPosture, isLoading: tlsLoading } = useQuery({
    queryKey: ["tls-posture"],
    queryFn: () => api.getTLSPosture(),
  });

  // Query TLS scans
  const { data: tlsScans } = useQuery({
    queryKey: ["tls-scans"],
    queryFn: () => api.listTLSScans({ limit: 50 }),
  });

  // Delete endpoint mutation
  const deleteEndpointMutation = useMutation({
    mutationFn: (endpointId: string) => api.deleteExposedEndpoint(endpointId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exposed-endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
      setSelectedEndpoint(null);
    },
  });

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-red-600 dark:text-red-400";
    if (score >= 40) return "text-yellow-600 dark:text-yellow-400";
    return "text-green-600 dark:text-green-400";
  };

  const getRiskBadge = (score: number) => {
    if (score >= 70) return <Badge color="red">High Risk</Badge>;
    if (score >= 40) return <Badge color="yellow">Medium Risk</Badge>;
    return <Badge color="green">Low Risk</Badge>;
  };

  const getExposureBadge = (type: string) => {
    switch (type) {
      case "public":
        return <Badge color="red">Public</Badge>;
      case "partner":
        return <Badge color="yellow">Partner</Badge>;
      case "internal":
        return <Badge color="blue">Internal</Badge>;
      case "private":
        return <Badge color="gray">Private</Badge>;
      default:
        return <Badge>{type}</Badge>;
    }
  };

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Run", href: "#" },
        { label: "Traffic Exposure", current: true },
      ]}
    />
  );

  // Page Header Action
  const headerAction = (
    <button
      onClick={() => {
        queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
        queryClient.invalidateQueries({ queryKey: ["exposed-endpoints"] });
        queryClient.invalidateQueries({ queryKey: ["tls-posture"] });
      }}
      className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
    >
      <RefreshCw className="h-4 w-4" />
      Refresh
    </button>
  );

  // Endpoint Table Columns
  const endpointColumns = [
    {
      key: "domain",
      header: "Domain",
      sortable: true,
      render: (value: string, row: ExposedEndpoint) => (
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-gray-400" />
          <div>
            <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
            <span className="text-xs text-gray-500 dark:text-gray-400 ml-1">{row.path}</span>
          </div>
        </div>
      ),
    },
    {
      key: "exposure_type",
      header: "Exposure",
      render: (value: string) => getExposureBadge(value),
    },
    {
      key: "protocol",
      header: "Protocol",
      render: (value: string, row: ExposedEndpoint) => (
        <div className="flex items-center gap-1">
          {value === "https" ? (
            <Lock className="h-3 w-3 text-green-500" />
          ) : (
            <Unlock className="h-3 w-3 text-red-500" />
          )}
          <span className="text-sm uppercase">{value}:{row.port}</span>
        </div>
      ),
    },
    {
      key: "authentication_required",
      header: "Auth",
      render: (value: boolean) =>
        value ? (
          <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-sm">
            <CheckCircle2 className="h-3 w-3" />
            Required
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400 text-sm">
            <XCircle className="h-3 w-3" />
            None
          </span>
        ),
    },
    {
      key: "risk_score",
      header: "Risk Score",
      sortable: true,
      render: (value: number) => (
        <div className="flex items-center gap-2">
          <span className={cn("text-sm font-medium", getRiskColor(value))}>{value}</span>
          {getRiskBadge(value)}
        </div>
      ),
    },
    {
      key: "service_name",
      header: "Service",
      render: (value: string | undefined) => (
        <span className="text-sm text-gray-700 dark:text-gray-300">{value || "N/A"}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (value: string) =>
        value === "active" ? (
          <Badge color="green">Active</Badge>
        ) : value === "deprecated" ? (
          <Badge color="yellow">Deprecated</Badge>
        ) : (
          <Badge color="gray">{value}</Badge>
        ),
    },
  ];

  // Rate Limit Profile Table Columns
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
          {value || row.requests_per_minute ? `${row.requests_per_minute}/min` : row.requests_per_hour ? `${row.requests_per_hour}/hr` : "N/A"}
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
      render: (value: string) => (
        <Badge color="gray">{value}</Badge>
      ),
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
        value ? (
          <Badge color="green">Enabled</Badge>
        ) : (
          <Badge color="gray">Disabled</Badge>
        ),
    },
  ];

  // TLS Scan Table Columns
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
        value ? (
          <Badge color="green">Valid</Badge>
        ) : (
          <Badge color="red">Invalid</Badge>
        ),
    },
    {
      key: "grade",
      header: "Grade",
      render: (value: string | undefined) => {
        const gradeColor = value?.startsWith("A") ? "green" : value?.startsWith("B") ? "yellow" : "red";
        return value ? <Badge color={gradeColor}>{value}</Badge> : <Badge color="gray">N/A</Badge>;
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
        const color = value <= 7 ? "text-red-600" : value <= 30 ? "text-yellow-600" : "text-green-600";
        return <span className={cn("text-sm font-medium", color)}>{value} days</span>;
      },
    },
    {
      key: "hsts_enabled",
      header: "HSTS",
      render: (value: boolean) =>
        value ? (
          <Badge color="green">Enabled</Badge>
        ) : (
          <Badge color="gray">Disabled</Badge>
        ),
    },
    {
      key: "scanned_at",
      header: "Scanned",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
      ),
    },
  ];

  // Endpoint Filter Configuration
  const endpointFilterGroups = [
    {
      id: "exposure_type",
      label: "Exposure Type",
      type: "radio" as const,
      value: endpointFilters.exposure_type,
      onChange: (value: string | string[]) =>
        setEndpointFilters({ ...endpointFilters, exposure_type: value as string }),
      options: [
        { label: "All Types", value: "" },
        { label: "Public", value: "public" },
        { label: "Partner", value: "partner" },
        { label: "Internal", value: "internal" },
        { label: "Private", value: "private" },
      ],
    },
    {
      id: "status",
      label: "Status",
      type: "radio" as const,
      value: endpointFilters.status,
      onChange: (value: string | string[]) =>
        setEndpointFilters({ ...endpointFilters, status: value as string }),
      options: [
        { label: "All Status", value: "" },
        { label: "Active", value: "active" },
        { label: "Inactive", value: "inactive" },
        { label: "Deprecated", value: "deprecated" },
        { label: "Blocked", value: "blocked" },
      ],
    },
    {
      id: "risk",
      label: "Minimum Risk Score",
      type: "radio" as const,
      value: endpointFilters.min_risk_score?.toString() || "",
      onChange: (value: string | string[]) =>
        setEndpointFilters({
          ...endpointFilters,
          min_risk_score: value ? parseInt(value as string) : undefined,
        }),
      options: [
        { label: "All Scores", value: "" },
        { label: "High Risk (70+)", value: "70" },
        { label: "Medium Risk (40+)", value: "40" },
        { label: "Low Risk (0+)", value: "0" },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Traffic & Exposure Governance"
        description="Monitor and manage exposed endpoints, rate limiting, and TLS posture"
        breadcrumbs={breadcrumbs}
        action={headerAction}
      />

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-800">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab("overview")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "overview"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab("endpoints")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "endpoints"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            Exposed Endpoints
            {summary && summary.total_endpoints > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 text-xs rounded-full">
                {summary.total_endpoints}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab("ratelimits")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "ratelimits"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            Rate Limits
          </button>
          <button
            onClick={() => setActiveTab("tls")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "tls"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            TLS Posture
            {tlsPosture && tlsPosture.expiring_critical > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 text-xs rounded-full">
                {tlsPosture.expiring_critical}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {summaryLoading || tlsLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading exposure data..." />
            </div>
          ) : (
            <>
              {/* Key Metrics */}
              <MetricsGrid columns={4}>
                <StatCard
                  label="Total Endpoints"
                  value={summary?.total_endpoints || 0}
                  icon={Globe}
                  iconColor="text-blue-600"
                />
                <StatCard
                  label="Public Endpoints"
                  value={summary?.public_endpoints || 0}
                  icon={ExternalLink}
                  iconColor="text-red-600"
                  valueColor="text-red-600 dark:text-red-400"
                />
                <StatCard
                  label="Unauthenticated Public"
                  value={summary?.unauthenticated_public || 0}
                  icon={Unlock}
                  iconColor="text-orange-600"
                  valueColor="text-orange-600 dark:text-orange-400"
                />
                <StatCard
                  label="High Risk Endpoints"
                  value={summary?.high_risk_endpoints || 0}
                  icon={AlertTriangle}
                  iconColor="text-red-600"
                  valueColor="text-red-600 dark:text-red-400"
                />
              </MetricsGrid>

              {/* TLS Metrics */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">TLS/SSL Health</h2>
                <div className="grid grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{tlsPosture?.valid_certs || 0}</div>
                    <div className="text-sm text-gray-500">Valid Certs</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{tlsPosture?.invalid_certs || 0}</div>
                    <div className="text-sm text-gray-500">Invalid Certs</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{tlsPosture?.expiring_warning || 0}</div>
                    <div className="text-sm text-gray-500">Expiring Soon</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{tlsPosture?.expiring_critical || 0}</div>
                    <div className="text-sm text-gray-500">Critical Expiry</div>
                  </div>
                </div>
              </div>

              {/* Risk Score Distribution */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Exposure by Type</h2>
                <div className="flex items-center gap-8">
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded bg-red-500"></div>
                    <span className="text-sm text-gray-700 dark:text-gray-300">Public: {summary?.public_endpoints || 0}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded bg-blue-500"></div>
                    <span className="text-sm text-gray-700 dark:text-gray-300">Internal: {summary?.internal_endpoints || 0}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded bg-green-500"></div>
                    <span className="text-sm text-gray-700 dark:text-gray-300">Active: {summary?.active_endpoints || 0}</span>
                  </div>
                </div>
                <div className="mt-4">
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    Average Risk Score: <span className={cn("font-medium", getRiskColor(summary?.avg_risk_score || 0))}>{summary?.avg_risk_score || 0}</span>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {activeTab === "endpoints" && (
        <div className="space-y-6">
          {/* Filters */}
          <FilterPanel
            filters={endpointFilterGroups}
            onReset={() =>
              setEndpointFilters({
                exposure_type: "",
                status: "",
                min_risk_score: undefined,
              })
            }
          />

          {/* Endpoints Table */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {endpointsLoading ? (
              <div className="flex items-center justify-center h-64">
                <Spinner size="lg" label="Loading endpoints..." />
              </div>
            ) : endpointsData && endpointsData.endpoints.length > 0 ? (
              <Table
                columns={endpointColumns}
                data={endpointsData.endpoints}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedEndpoint(row)}
                hoverable
              />
            ) : (
              <EmptyState
                icon={Globe}
                title="No exposed endpoints found"
                description="No endpoints match your current filters"
                size="sm"
              />
            )}
          </div>
        </div>
      )}

      {activeTab === "ratelimits" && (
        <div className="space-y-6">
          {/* Rate Limits Table */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {profilesLoading ? (
              <div className="flex items-center justify-center h-64">
                <Spinner size="lg" label="Loading rate limit profiles..." />
              </div>
            ) : profilesData && profilesData.profiles.length > 0 ? (
              <Table
                columns={profileColumns}
                data={profilesData.profiles}
                keyExtractor={(row) => row.id}
                hoverable
              />
            ) : (
              <EmptyState
                icon={Shield}
                title="No rate limit profiles"
                description="Create rate limit profiles to control traffic to your endpoints"
                action={{
                  label: "Create Profile",
                  onClick: () => {/* TODO: Open create modal */},
                }}
                size="sm"
              />
            )}
          </div>
        </div>
      )}

      {activeTab === "tls" && (
        <div className="space-y-6">
          {/* TLS Summary */}
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

          {/* TLS Scans Table */}
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
      )}

      {/* Endpoint Detail SlideOver */}
      <SlideOver isOpen={!!selectedEndpoint} onClose={() => setSelectedEndpoint(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedEndpoint(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Endpoint Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {selectedEndpoint?.domain}{selectedEndpoint?.path}
            </p>
          </div>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedEndpoint && (
            <div className="space-y-6">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Overview</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Exposure Type</span>
                    {getExposureBadge(selectedEndpoint.exposure_type)}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Protocol</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white uppercase">
                      {selectedEndpoint.protocol}:{selectedEndpoint.port}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Authentication</span>
                    {selectedEndpoint.authentication_required ? (
                      <Badge color="green">Required ({selectedEndpoint.authentication_type || "Unknown"})</Badge>
                    ) : (
                      <Badge color="red">None</Badge>
                    )}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Risk Score</span>
                    <div className="flex items-center gap-2">
                      <span className={cn("text-sm font-medium", getRiskColor(selectedEndpoint.risk_score))}>
                        {selectedEndpoint.risk_score}
                      </span>
                      {getRiskBadge(selectedEndpoint.risk_score)}
                    </div>
                  </div>
                </div>
              </div>

              {selectedEndpoint.service_name && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Service Info</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-700 dark:text-gray-300">Service Name</span>
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {selectedEndpoint.service_name}
                      </span>
                    </div>
                    {selectedEndpoint.service_owner && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-700 dark:text-gray-300">Owner</span>
                        <span className="text-sm text-gray-900 dark:text-white">
                          {selectedEndpoint.service_owner}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {selectedEndpoint.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                  <p className="text-sm text-gray-900 dark:text-white">{selectedEndpoint.description}</p>
                </div>
              )}

              {selectedEndpoint.tags && selectedEndpoint.tags.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Tags</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedEndpoint.tags.map((tag) => (
                      <Badge key={tag} color="gray">{tag}</Badge>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Risk Factors</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(selectedEndpoint.risk_factors, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Timestamps</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Discovered</span>
                    <span className="text-gray-900 dark:text-white">{formatTimestamp(selectedEndpoint.discovered_at)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Last Updated</span>
                    <span className="text-gray-900 dark:text-white">{formatTimestamp(selectedEndpoint.updated_at)}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </SlideOver.Body>

        <SlideOver.Footer>
          <button
            onClick={() => setSelectedEndpoint(null)}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Close
          </button>
          <button
            onClick={() => {
              if (selectedEndpoint && confirm("Are you sure you want to delete this endpoint?")) {
                deleteEndpointMutation.mutate(selectedEndpoint.id);
              }
            }}
            className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
          >
            Delete Endpoint
          </button>
        </SlideOver.Footer>
      </SlideOver>
    </div>
  );
}
