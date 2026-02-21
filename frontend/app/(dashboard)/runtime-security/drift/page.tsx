"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, CheckCircle2, Clock } from "lucide-react";
import { api, DriftEvent } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { SeverityBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Timeline } from "@/components/ui/Timeline";

export default function DriftEventsPage() {
  const [selectedDrift, setSelectedDrift] = useState<DriftEvent | null>(null);
  const [filters, setFilters] = useState({
    severity: "",
    drift_type: "",
    resolved: undefined as boolean | undefined,
    container_name: "",
  });
  const queryClient = useQueryClient();

  const { data: driftData, isLoading } = useQuery({
    queryKey: ["drift-events", filters],
    queryFn: () => api.listDriftEvents(filters),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ eventId, notes }: { eventId: string; notes: string }) =>
      api.resolveDriftEvent(eventId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["drift-events"] });
      queryClient.invalidateQueries({ queryKey: ["runtime-security-posture"] });
      setSelectedDrift(null);
    },
  });

  const handleResolve = (eventId: string) => {
    const notes = prompt("Enter resolution notes:");
    if (notes) resolveMutation.mutate({ eventId, notes });
  };

  const formatTimestamp = (ts: string) => new Date(ts).toLocaleString();

  const columns = [
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
            <CheckCircle2 className="h-3 w-3" /> Resolved
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs">
            <Clock className="h-3 w-3" /> Unresolved
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
              handleResolve(value);
            }}
            className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            Resolve
          </button>
        ) : null,
    },
  ];

  const filterGroups = [
    {
      id: "severity",
      label: "Severity",
      type: "radio" as const,
      value: filters.severity,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, severity: value as string }),
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
      value: filters.drift_type,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, drift_type: value as string }),
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
      value: filters.resolved === undefined ? "" : filters.resolved.toString(),
      onChange: (value: string | string[]) =>
        setFilters({
          ...filters,
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
      value: filters.container_name,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, container_name: value as string }),
    },
  ];

  return (
    <div className="flex gap-6">
      {/* Filters Sidebar */}
      <div className="w-64 flex-shrink-0">
        <FilterPanel
          filters={filterGroups}
          onReset={() =>
            setFilters({ severity: "", drift_type: "", resolved: undefined, container_name: "" })
          }
        />
      </div>

      {/* Table */}
      <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <Spinner size="lg" label="Loading drift events..." />
          </div>
        ) : (driftData?.drift_events?.length ?? 0) > 0 ? (
          <Table
            columns={columns}
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

      {/* Detail SlideOver */}
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
                      timestamp={
                        selectedDrift.resolved_at ? formatTimestamp(selectedDrift.resolved_at) : undefined
                      }
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
                if (selectedDrift) handleResolve(selectedDrift.id);
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
