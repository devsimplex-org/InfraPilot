"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Activity,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  TrendingUp,
  Container,
  AlertCircle,
  FileWarning,
  Filter,
  X as XIcon,
} from "lucide-react";
import { api, DriftEvent, BehavioralAnomaly } from "@/lib/api";
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

  const getStatusBadge = (status: string) => {
    const badges = {
      healthy: {
        icon: ShieldCheck,
        color: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
        label: "Healthy",
      },
      warning: {
        icon: AlertTriangle,
        color: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
        label: "Warning",
      },
      degraded: {
        icon: AlertCircle,
        color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
        label: "Degraded",
      },
      critical: {
        icon: ShieldX,
        color: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
        label: "Critical",
      },
    };

    const badge = badges[status as keyof typeof badges] || badges.warning;

    return (
      <div className={cn("inline-flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium", badge.color)}>
        <badge.icon className="h-4 w-4" />
        {badge.label}
      </div>
    );
  };

  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
      high: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
      medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
      low: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
      info: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
    };

    return (
      <span className={cn("px-2 py-1 rounded text-xs font-medium", colors[severity as keyof typeof colors] || colors.info)}>
        {severity.toUpperCase()}
      </span>
    );
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Runtime Security</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Monitor runtime drift detection and behavioral anomalies
          </p>
        </div>
        <button
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["runtime-security-posture"] });
            queryClient.invalidateQueries({ queryKey: ["drift-events"] });
            queryClient.invalidateQueries({ queryKey: ["behavioral-anomalies"] });
          }}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

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
              <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
            </div>
          ) : posture ? (
            <>
              {/* Overall Status */}
              <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Overall Status</h2>
                {getStatusBadge(posture.overall_status)}
              </div>

              {/* Key Metrics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Drift Events (24h)</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {posture.drift_events_last_24h}
                      </p>
                    </div>
                    <Activity className="h-8 w-8 text-blue-500" />
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Anomalies (24h)</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {posture.anomalies_last_24h}
                      </p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-yellow-500" />
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Unresolved Drift</p>
                      <p className="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-1">
                        {posture.unresolved_drift}
                      </p>
                    </div>
                    <FileWarning className="h-8 w-8 text-orange-500" />
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Critical Issues</p>
                      <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
                        {posture.critical_drift + posture.critical_anomalies}
                      </p>
                    </div>
                    <ShieldX className="h-8 w-8 text-red-500" />
                  </div>
                </div>
              </div>

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

              {/* Top Affected Containers */}
              {posture.top_affected_containers.length > 0 && (
                <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Top Affected Containers (7 days)
                  </h2>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="border-b border-gray-200 dark:border-gray-800">
                        <tr>
                          <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                            Container
                          </th>
                          <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                            Total Drift
                          </th>
                          <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                            Unresolved
                          </th>
                          <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                            Last Drift
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                        {posture.top_affected_containers.map((container) => (
                          <tr key={container.deployment_id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                            <td className="py-3 px-4">
                              <div className="flex items-center gap-2">
                                <Container className="h-4 w-4 text-gray-400" />
                                <span className="text-sm text-gray-900 dark:text-white font-medium">
                                  {container.container_name}
                                </span>
                              </div>
                            </td>
                            <td className="py-3 px-4">
                              <span className="text-sm text-gray-700 dark:text-gray-300">{container.total_drift}</span>
                            </td>
                            <td className="py-3 px-4">
                              <span className="text-sm font-medium text-orange-600 dark:text-orange-400">
                                {container.unresolved_drift}
                              </span>
                            </td>
                            <td className="py-3 px-4">
                              <span className="text-sm text-gray-500 dark:text-gray-400">
                                {formatTimestamp(container.last_drift_at)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="bg-white dark:bg-gray-900 rounded-lg p-8 border border-gray-200 dark:border-gray-800 text-center">
              <p className="text-gray-500 dark:text-gray-400">No runtime security data available</p>
            </div>
          )}
        </div>
      )}

      {activeTab === "drift" && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white dark:bg-gray-900 rounded-lg p-4 border border-gray-200 dark:border-gray-800">
            <div className="flex items-center gap-2 mb-3">
              <Filter className="h-4 w-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filters</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <select
                value={driftFilters.severity}
                onChange={(e) => setDriftFilters({ ...driftFilters, severity: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>

              <select
                value={driftFilters.drift_type}
                onChange={(e) => setDriftFilters({ ...driftFilters, drift_type: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Types</option>
                <option value="image_changed">Image Changed</option>
                <option value="port_added">Port Added</option>
                <option value="port_removed">Port Removed</option>
                <option value="privilege_escalation">Privilege Escalation</option>
                <option value="config_modified">Config Modified</option>
                <option value="container_restarted">Container Restarted</option>
                <option value="volume_added">Volume Added</option>
                <option value="volume_removed">Volume Removed</option>
              </select>

              <select
                value={driftFilters.resolved === undefined ? "" : driftFilters.resolved.toString()}
                onChange={(e) =>
                  setDriftFilters({
                    ...driftFilters,
                    resolved: e.target.value === "" ? undefined : e.target.value === "true",
                  })
                }
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Status</option>
                <option value="false">Unresolved</option>
                <option value="true">Resolved</option>
              </select>

              <input
                type="text"
                placeholder="Container name..."
                value={driftFilters.container_name}
                onChange={(e) => setDriftFilters({ ...driftFilters, container_name: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              />
            </div>
          </div>

          {/* Drift Events Table */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {driftLoading ? (
              <div className="flex items-center justify-center h-64">
                <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : driftData && driftData.drift_events.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Container
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Drift Type
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Severity
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Status
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Detected At
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                    {driftData.drift_events.map((event) => (
                      <tr
                        key={event.id}
                        onClick={() => setSelectedDrift(event)}
                        className="hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer"
                      >
                        <td className="py-3 px-4">
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {event.container_name}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                            {event.drift_type.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="py-3 px-4">{getSeverityBadge(event.severity)}</td>
                        <td className="py-3 px-4">
                          {event.resolved ? (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded text-xs">
                              <CheckCircle2 className="h-3 w-3" />
                              Resolved
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs">
                              <Clock className="h-3 w-3" />
                              Unresolved
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            {formatTimestamp(event.detected_at)}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {!event.resolved && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleResolveDrift(event.id);
                              }}
                              className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                            >
                              Resolve
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center">
                <p className="text-gray-500 dark:text-gray-400">No drift events found</p>
              </div>
            )}
          </div>

          {/* Detail Panel */}
          {selectedDrift && (
            <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Drift Event Details</h3>
                <button
                  onClick={() => setSelectedDrift(null)}
                  className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                >
                  <XIcon className="h-5 w-5" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Container:</span>
                  <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedDrift.container_name}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Description:</span>
                  <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedDrift.description}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Expected State:</span>
                  <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded mt-1 overflow-x-auto">
                    {JSON.stringify(selectedDrift.expected_state, null, 2)}
                  </pre>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Actual State:</span>
                  <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded mt-1 overflow-x-auto">
                    {JSON.stringify(selectedDrift.actual_state, null, 2)}
                  </pre>
                </div>
                {selectedDrift.resolved && selectedDrift.resolution_notes && (
                  <div>
                    <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Resolution Notes:</span>
                    <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedDrift.resolution_notes}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === "anomalies" && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white dark:bg-gray-900 rounded-lg p-4 border border-gray-200 dark:border-gray-800">
            <div className="flex items-center gap-2 mb-3">
              <Filter className="h-4 w-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filters</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <select
                value={anomalyFilters.severity}
                onChange={(e) => setAnomalyFilters({ ...anomalyFilters, severity: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>

              <select
                value={anomalyFilters.anomaly_type}
                onChange={(e) => setAnomalyFilters({ ...anomalyFilters, anomaly_type: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Types</option>
                <option value="crash_loop">Crash Loop</option>
                <option value="log_volume_spike">Log Volume Spike</option>
                <option value="error_rate_spike">Error Rate Spike</option>
                <option value="cpu_exhaustion">CPU Exhaustion</option>
                <option value="memory_exhaustion">Memory Exhaustion</option>
                <option value="disk_exhaustion">Disk Exhaustion</option>
                <option value="network_spike">Network Spike</option>
              </select>

              <select
                value={anomalyFilters.resolved === undefined ? "" : anomalyFilters.resolved.toString()}
                onChange={(e) =>
                  setAnomalyFilters({
                    ...anomalyFilters,
                    resolved: e.target.value === "" ? undefined : e.target.value === "true",
                  })
                }
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">All Status</option>
                <option value="false">Unresolved</option>
                <option value="true">Resolved</option>
              </select>

              <input
                type="text"
                placeholder="Container name..."
                value={anomalyFilters.container_name}
                onChange={(e) => setAnomalyFilters({ ...anomalyFilters, container_name: e.target.value })}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
              />
            </div>
          </div>

          {/* Anomalies Table */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {anomalyLoading ? (
              <div className="flex items-center justify-center h-64">
                <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : anomalyData && anomalyData.anomalies.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Container
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Anomaly Type
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Severity
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Occurrences
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Status
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Detected At
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-gray-700 dark:text-gray-300">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                    {anomalyData.anomalies.map((anomaly) => (
                      <tr
                        key={anomaly.id}
                        onClick={() => setSelectedAnomaly(anomaly)}
                        className="hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer"
                      >
                        <td className="py-3 px-4">
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {anomaly.container_name || "N/A"}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                            {anomaly.anomaly_type.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="py-3 px-4">{getSeverityBadge(anomaly.severity)}</td>
                        <td className="py-3 px-4">
                          <span className="text-sm text-gray-700 dark:text-gray-300">
                            {anomaly.occurrence_count}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {anomaly.resolved ? (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded text-xs">
                              <CheckCircle2 className="h-3 w-3" />
                              Resolved
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs">
                              <Clock className="h-3 w-3" />
                              Unresolved
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            {formatTimestamp(anomaly.detected_at)}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {!anomaly.resolved && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleResolveAnomaly(anomaly.id);
                              }}
                              className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                            >
                              Resolve
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center">
                <p className="text-gray-500 dark:text-gray-400">No behavioral anomalies found</p>
              </div>
            )}
          </div>

          {/* Detail Panel */}
          {selectedAnomaly && (
            <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Anomaly Details</h3>
                <button
                  onClick={() => setSelectedAnomaly(null)}
                  className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                >
                  <XIcon className="h-5 w-5" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Container:</span>
                  <p className="text-sm text-gray-900 dark:text-white mt-1">
                    {selectedAnomaly.container_name || "N/A"}
                  </p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Description:</span>
                  <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedAnomaly.description}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Occurrence Count:</span>
                  <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedAnomaly.occurrence_count}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Metrics:</span>
                  <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded mt-1 overflow-x-auto">
                    {JSON.stringify(selectedAnomaly.metrics, null, 2)}
                  </pre>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Threshold:</span>
                  <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded mt-1 overflow-x-auto">
                    {JSON.stringify(selectedAnomaly.threshold, null, 2)}
                  </pre>
                </div>
                {selectedAnomaly.resolved && selectedAnomaly.resolution_notes && (
                  <div>
                    <span className="text-sm font-medium text-gray-500 dark:text-gray-400">Resolution Notes:</span>
                    <p className="text-sm text-gray-900 dark:text-white mt-1">{selectedAnomaly.resolution_notes}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
