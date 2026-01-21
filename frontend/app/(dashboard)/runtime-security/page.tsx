"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Activity,
  RefreshCw,
  FileWarning,
  Container,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { api, DriftEvent, BehavioralAnomaly } from "@/lib/api";

// New component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SeverityBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Skeleton } from "@/components/ui/Skeleton";
import { Spinner } from "@/components/ui/Spinner";
import { Timeline } from "@/components/ui/Timeline";
import { cn } from "@/lib/utils";

type TabType = "overview" | "drift" | "anomalies";

export default function RuntimeSecurityPage() {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [selectedDrift, setSelectedDrift] = useState<DriftEvent | null>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<BehavioralAnomaly | null>(null);
  const [driftFilters, setDriftFilters] = useState({
    severity: "",
    drift_type: "",
    resolved: undefined as boolean | undefined,
    container_name: "",
  });
  const [anomalyFilters, setAnomalyFilters] = useState({
    severity: "",
    anomaly_type: "",
    resolved: undefined as boolean | undefined,
    container_name: "",
  });
  const queryClient = useQueryClient();

  // Query posture
  const { data: posture, isLoading: postureLoading } = useQuery({
    queryKey: ["runtime-security-posture"],
    queryFn: () => api.getRuntimeSecurityPosture(),
  });

  // Query drift events
  const { data: driftData, isLoading: driftLoading } = useQuery({
    queryKey: ["drift-events", driftFilters],
    queryFn: () => api.listDriftEvents(driftFilters),
  });

  // Query anomalies
  const { data: anomalyData, isLoading: anomalyLoading } = useQuery({
    queryKey: ["behavioral-anomalies", anomalyFilters],
    queryFn: () => api.listBehavioralAnomalies(anomalyFilters),
  });

  // Resolve drift mutation
  const resolveDriftMutation = useMutation({
    mutationFn: ({ eventId, notes }: { eventId: string; notes: string }) =>
      api.resolveDriftEvent(eventId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["drift-events"] });
      queryClient.invalidateQueries({ queryKey: ["runtime-security-posture"] });
      setSelectedDrift(null);
    },
  });

  // Resolve anomaly mutation
  const resolveAnomalyMutation = useMutation({
    mutationFn: ({ anomalyId, notes }: { anomalyId: string; notes: string }) =>
      api.resolveBehavioralAnomaly(anomalyId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavioral-anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["runtime-security-posture"] });
      setSelectedAnomaly(null);
    },
  });

  const handleResolveDrift = (eventId: string) => {
    const notes = prompt("Enter resolution notes:");
    if (notes) {
      resolveDriftMutation.mutate({ eventId, notes });
    }
  };

  const handleResolveAnomaly = (anomalyId: string) => {
    const notes = prompt("Enter resolution notes:");
    if (notes) {
      resolveAnomalyMutation.mutate({ anomalyId, notes });
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Security", href: "#" },
        { label: "Runtime Security", current: true },
      ]}
    />
  );

  // Page Header Action
  const headerAction = (
    <button
      onClick={() => {
        queryClient.invalidateQueries({ queryKey: ["runtime-security-posture"] });
        queryClient.invalidateQueries({ queryKey: ["drift-events"] });
        queryClient.invalidateQueries({ queryKey: ["behavioral-anomalies"] });
      }}
      className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
    >
      <RefreshCw className="h-4 w-4" />
      Refresh
    </button>
  );

  // Drift Table Columns
  const driftColumns = [
    {
      key: "container_name",
      header: "Container",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
    {
      key: "drift_type",
      header: "Drift Type",
      render: (value: string) => (
        <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
          {value.replace(/_/g, " ")}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (value: string) => <SeverityBadge severity={value as any} size="sm" />,
    },
    {
      key: "resolved",
      header: "Status",
      render: (value: boolean) =>
        value ? (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded text-xs">
            <CheckCircle2 className="h-3 w-3" />
            Resolved
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs">
            <Clock className="h-3 w-3" />
            Unresolved
          </span>
        ),
    },
    {
      key: "detected_at",
      header: "Detected At",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
      ),
    },
    {
      key: "id",
      header: "Actions",
      render: (value: string, row: DriftEvent) =>
        !row.resolved ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleResolveDrift(value);
            }}
            className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            Resolve
          </button>
        ) : null,
    },
  ];

  // Anomaly Table Columns
  const anomalyColumns = [
    {
      key: "container_name",
      header: "Container",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm font-medium text-gray-900 dark:text-white">{value || "N/A"}</span>
      ),
    },
    {
      key: "anomaly_type",
      header: "Anomaly Type",
      render: (value: string) => (
        <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
          {value.replace(/_/g, " ")}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (value: string) => <SeverityBadge severity={value as any} size="sm" />,
    },
    {
      key: "occurrence_count",
      header: "Occurrences",
      render: (value: number) => <span className="text-sm text-gray-700 dark:text-gray-300">{value}</span>,
    },
    {
      key: "resolved",
      header: "Status",
      render: (value: boolean) =>
        value ? (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded text-xs">
            <CheckCircle2 className="h-3 w-3" />
            Resolved
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs">
            <Clock className="h-3 w-3" />
            Unresolved
          </span>
        ),
    },
    {
      key: "detected_at",
      header: "Detected At",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
      ),
    },
    {
      key: "id",
      header: "Actions",
      render: (value: string, row: BehavioralAnomaly) =>
        !row.resolved ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleResolveAnomaly(value);
            }}
            className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            Resolve
          </button>
        ) : null,
    },
  ];

  // Drift Filter Configuration
  const driftFilterGroups = [
    {
      id: "severity",
      label: "Severity",
      type: "radio" as const,
      value: driftFilters.severity,
      onChange: (value: string | string[]) =>
        setDriftFilters({ ...driftFilters, severity: value as string }),
      options: [
        { label: "All Severities", value: "" },
        { label: "Critical", value: "critical" },
        { label: "High", value: "high" },
        { label: "Medium", value: "medium" },
        { label: "Low", value: "low" },
        { label: "Info", value: "info" },
      ],
    },
    {
      id: "drift_type",
      label: "Drift Type",
      type: "radio" as const,
      value: driftFilters.drift_type,
      onChange: (value: string | string[]) =>
        setDriftFilters({ ...driftFilters, drift_type: value as string }),
      options: [
        { label: "All Types", value: "" },
        { label: "Image Changed", value: "image_changed" },
        { label: "Port Added", value: "port_added" },
        { label: "Port Removed", value: "port_removed" },
        { label: "Privilege Escalation", value: "privilege_escalation" },
        { label: "Config Modified", value: "config_modified" },
        { label: "Container Restarted", value: "container_restarted" },
        { label: "Volume Added", value: "volume_added" },
        { label: "Volume Removed", value: "volume_removed" },
      ],
    },
    {
      id: "status",
      label: "Status",
      type: "radio" as const,
      value: driftFilters.resolved === undefined ? "" : driftFilters.resolved.toString(),
      onChange: (value: string | string[]) =>
        setDriftFilters({
          ...driftFilters,
          resolved: value === "" ? undefined : (value as string) === "true",
        }),
      options: [
        { label: "All Status", value: "" },
        { label: "Unresolved", value: "false" },
        { label: "Resolved", value: "true" },
      ],
    },
    {
      id: "container_name",
      label: "Container",
      type: "search" as const,
      value: driftFilters.container_name,
      onChange: (value: string | string[]) =>
        setDriftFilters({ ...driftFilters, container_name: value as string }),
    },
  ];

  // Anomaly Filter Configuration
  const anomalyFilterGroups = [
    {
      id: "severity",
      label: "Severity",
      type: "radio" as const,
      value: anomalyFilters.severity,
      onChange: (value: string | string[]) =>
        setAnomalyFilters({ ...anomalyFilters, severity: value as string }),
      options: [
        { label: "All Severities", value: "" },
        { label: "Critical", value: "critical" },
        { label: "High", value: "high" },
        { label: "Medium", value: "medium" },
        { label: "Low", value: "low" },
        { label: "Info", value: "info" },
      ],
    },
    {
      id: "anomaly_type",
      label: "Anomaly Type",
      type: "radio" as const,
      value: anomalyFilters.anomaly_type,
      onChange: (value: string | string[]) =>
        setAnomalyFilters({ ...anomalyFilters, anomaly_type: value as string }),
      options: [
        { label: "All Types", value: "" },
        { label: "Crash Loop", value: "crash_loop" },
        { label: "Log Volume Spike", value: "log_volume_spike" },
        { label: "Error Rate Spike", value: "error_rate_spike" },
        { label: "CPU Exhaustion", value: "cpu_exhaustion" },
        { label: "Memory Exhaustion", value: "memory_exhaustion" },
        { label: "Disk Exhaustion", value: "disk_exhaustion" },
        { label: "Network Spike", value: "network_spike" },
      ],
    },
    {
      id: "status",
      label: "Status",
      type: "radio" as const,
      value: anomalyFilters.resolved === undefined ? "" : anomalyFilters.resolved.toString(),
      onChange: (value: string | string[]) =>
        setAnomalyFilters({
          ...anomalyFilters,
          resolved: value === "" ? undefined : (value as string) === "true",
        }),
      options: [
        { label: "All Status", value: "" },
        { label: "Unresolved", value: "false" },
        { label: "Resolved", value: "true" },
      ],
    },
    {
      id: "container_name",
      label: "Container",
      type: "search" as const,
      value: anomalyFilters.container_name,
      onChange: (value: string | string[]) =>
        setAnomalyFilters({ ...anomalyFilters, container_name: value as string }),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Section 1: Page Header with Breadcrumbs */}
      <PageHeader
        title="Runtime Security"
        description="Monitor runtime drift detection and behavioral anomalies"
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
            onClick={() => setActiveTab("drift")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "drift"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            Drift Events
            {posture && posture.unresolved_drift > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 text-xs rounded-full">
                {posture.unresolved_drift}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab("anomalies")}
            className={cn(
              "py-4 px-1 border-b-2 font-medium text-sm",
              activeTab === "anomalies"
                ? "border-primary-600 text-primary-600"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            Behavioral Anomalies
            {posture && posture.unresolved_anomalies > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 text-xs rounded-full">
                {posture.unresolved_anomalies}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {postureLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading security posture..." />
            </div>
          ) : posture ? (
            <>
              {/* Section 2: Overall Status */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Overall Status</h2>
                <StatusIndicator status={posture.overall_status as any} size="lg" pulse />
              </div>

              {/* Section 3: Key Metrics Grid */}
              <MetricsGrid columns={4}>
                <StatCard
                  label="Drift Events (24h)"
                  value={posture.drift_events_last_24h}
                  icon={Activity}
                  iconColor="text-blue-600"
                />
                <StatCard
                  label="Anomalies (24h)"
                  value={posture.anomalies_last_24h}
                  icon={AlertTriangle}
                  iconColor="text-yellow-600"
                />
                <StatCard
                  label="Unresolved Drift"
                  value={posture.unresolved_drift}
                  icon={FileWarning}
                  iconColor="text-orange-600"
                  valueColor="text-orange-600 dark:text-orange-400"
                />
                <StatCard
                  label="Critical Issues"
                  value={posture.critical_drift + posture.critical_anomalies}
                  icon={ShieldX}
                  iconColor="text-red-600"
                  valueColor="text-red-600 dark:text-red-400"
                />
              </MetricsGrid>

              {/* Drift by Type */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Drift by Type (24h)</h2>
                {Object.keys(posture.drift_by_type).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(posture.drift_by_type).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                          {type.replace(/_/g, " ")}
                        </span>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500 dark:text-gray-400">No drift detected in the last 24 hours</p>
                )}
              </div>

              {/* Anomaly by Type */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                  Anomalies by Type (24h)
                </h2>
                {Object.keys(posture.anomaly_by_type).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(posture.anomaly_by_type).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                          {type.replace(/_/g, " ")}
                        </span>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    No anomalies detected in the last 24 hours
                  </p>
                )}
              </div>

              {/* Section 4: Top Affected Containers Table */}
              {posture.top_affected_containers.length > 0 && (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                      Top Affected Containers (7 days)
                    </h2>
                  </div>
                  <Table
                    columns={[
                      {
                        key: "container_name",
                        header: "Container",
                        render: (value: string) => (
                          <div className="flex items-center gap-2">
                            <Container className="h-4 w-4 text-gray-400" />
                            <span className="text-sm text-gray-900 dark:text-white font-medium">{value}</span>
                          </div>
                        ),
                      },
                      {
                        key: "total_drift",
                        header: "Total Drift",
                        render: (value: number) => (
                          <span className="text-sm text-gray-700 dark:text-gray-300">{value}</span>
                        ),
                      },
                      {
                        key: "unresolved_drift",
                        header: "Unresolved",
                        render: (value: number) => (
                          <span className="text-sm font-medium text-orange-600 dark:text-orange-400">{value}</span>
                        ),
                      },
                      {
                        key: "last_drift_at",
                        header: "Last Drift",
                        render: (value: string) => (
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            {formatTimestamp(value)}
                          </span>
                        ),
                      },
                    ]}
                    data={posture.top_affected_containers}
                    keyExtractor={(row) => row.deployment_id}
                  />
                </div>
              )}
            </>
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="No runtime security data available"
              description="Start monitoring your containers to see runtime security insights"
            />
          )}
        </div>
      )}

      {activeTab === "drift" && (
        <div className="flex gap-6">
          {/* Filters Sidebar */}
          <div className="w-64 flex-shrink-0">
            <FilterPanel
              filters={driftFilterGroups}
              onReset={() =>
                setDriftFilters({
                  severity: "",
                  drift_type: "",
                  resolved: undefined,
                  container_name: "",
                })
              }
            />
          </div>

          {/* Drift Events Table */}
          <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {driftLoading ? (
              <div className="flex items-center justify-center h-64">
                <Spinner size="lg" label="Loading drift events..." />
              </div>
            ) : (driftData?.drift_events?.length ?? 0) > 0 ? (
              <Table
                columns={driftColumns}
                data={driftData!.drift_events}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedDrift(row)}
                hoverable
              />
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title="No drift events found"
                description="No drift events match your current filters"
                size="sm"
              />
            )}
          </div>
        </div>
      )}

      {activeTab === "anomalies" && (
        <div className="flex gap-6">
          {/* Filters Sidebar */}
          <div className="w-64 flex-shrink-0">
            <FilterPanel
              filters={anomalyFilterGroups}
              onReset={() =>
                setAnomalyFilters({
                  severity: "",
                  anomaly_type: "",
                  resolved: undefined,
                  container_name: "",
                })
              }
            />
          </div>

          {/* Anomalies Table */}
          <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {anomalyLoading ? (
              <div className="flex items-center justify-center h-64">
                <Spinner size="lg" label="Loading anomalies..." />
              </div>
            ) : (anomalyData?.anomalies?.length ?? 0) > 0 ? (
              <Table
                columns={anomalyColumns}
                data={anomalyData!.anomalies}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedAnomaly(row)}
                hoverable
              />
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title="No behavioral anomalies found"
                description="No anomalies match your current filters"
                size="sm"
              />
            )}
          </div>
        </div>
      )}

      {/* Drift Detail SlideOver */}
      <SlideOver isOpen={!!selectedDrift} onClose={() => setSelectedDrift(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedDrift(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Drift Event Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {selectedDrift?.container_name}
            </p>
          </div>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedDrift && (
            <div className="space-y-6">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Overview</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Severity</span>
                    <SeverityBadge severity={selectedDrift.severity as any} />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Type</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                      {selectedDrift.drift_type.replace(/_/g, " ")}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Detected At</span>
                    <span className="text-sm text-gray-900 dark:text-white">
                      {formatTimestamp(selectedDrift.detected_at)}
                    </span>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                <p className="text-sm text-gray-900 dark:text-white">{selectedDrift.description}</p>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Expected State</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(selectedDrift.expected_state, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Actual State</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(selectedDrift.actual_state, null, 2)}
                </pre>
              </div>

              {selectedDrift.resolved && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Resolution</h4>
                  <Timeline>
                    <Timeline.Item
                      icon={CheckCircle2}
                      iconColor="text-green-600 dark:text-green-400"
                      title="Resolved"
                      timestamp={selectedDrift.resolved_at ? formatTimestamp(selectedDrift.resolved_at) : undefined}
                      description={selectedDrift.resolution_notes}
                    />
                  </Timeline>
                </div>
              )}
            </div>
          )}
        </SlideOver.Body>

        {selectedDrift && !selectedDrift.resolved && (
          <SlideOver.Footer>
            <button
              onClick={() => setSelectedDrift(null)}
              className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Close
            </button>
            <button
              onClick={() => {
                if (selectedDrift) handleResolveDrift(selectedDrift.id);
              }}
              className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
            >
              Mark as Resolved
            </button>
          </SlideOver.Footer>
        )}
      </SlideOver>

      {/* Anomaly Detail SlideOver */}
      <SlideOver isOpen={!!selectedAnomaly} onClose={() => setSelectedAnomaly(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedAnomaly(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Anomaly Details</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {selectedAnomaly?.container_name || "N/A"}
            </p>
          </div>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedAnomaly && (
            <div className="space-y-6">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Overview</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Severity</span>
                    <SeverityBadge severity={selectedAnomaly.severity as any} />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Type</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                      {selectedAnomaly.anomaly_type.replace(/_/g, " ")}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Occurrences</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {selectedAnomaly.occurrence_count}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 dark:text-gray-300">Detected At</span>
                    <span className="text-sm text-gray-900 dark:text-white">
                      {formatTimestamp(selectedAnomaly.detected_at)}
                    </span>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                <p className="text-sm text-gray-900 dark:text-white">{selectedAnomaly.description}</p>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Metrics</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(selectedAnomaly.metrics, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Threshold</h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(selectedAnomaly.threshold, null, 2)}
                </pre>
              </div>

              {selectedAnomaly.resolved && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Resolution</h4>
                  <Timeline>
                    <Timeline.Item
                      icon={CheckCircle2}
                      iconColor="text-green-600 dark:text-green-400"
                      title="Resolved"
                      timestamp={
                        selectedAnomaly.resolved_at ? formatTimestamp(selectedAnomaly.resolved_at) : undefined
                      }
                      description={selectedAnomaly.resolution_notes}
                    />
                  </Timeline>
                </div>
              )}
            </div>
          )}
        </SlideOver.Body>

        {selectedAnomaly && !selectedAnomaly.resolved && (
          <SlideOver.Footer>
            <button
              onClick={() => setSelectedAnomaly(null)}
              className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Close
            </button>
            <button
              onClick={() => {
                if (selectedAnomaly) handleResolveAnomaly(selectedAnomaly.id);
              }}
              className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
            >
              Mark as Resolved
            </button>
          </SlideOver.Footer>
        )}
      </SlideOver>
    </div>
  );
}
