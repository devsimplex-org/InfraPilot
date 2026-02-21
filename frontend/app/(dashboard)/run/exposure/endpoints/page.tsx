"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { api, ExposedEndpoint } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

export default function ExposureEndpointsPage() {
  const [selectedEndpoint, setSelectedEndpoint] = useState<ExposedEndpoint | null>(null);
  const [filters, setFilters] = useState({
    exposure_type: "",
    status: "",
    min_risk_score: undefined as number | undefined,
  });
  const queryClient = useQueryClient();

  const { data: endpointsData, isLoading } = useQuery({
    queryKey: ["exposed-endpoints", filters],
    queryFn: () => api.listExposedEndpoints(filters),
  });

  const deleteEndpointMutation = useMutation({
    mutationFn: (endpointId: string) => api.deleteExposedEndpoint(endpointId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exposed-endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
      setSelectedEndpoint(null);
    },
  });

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
      case "public": return <Badge color="red">Public</Badge>;
      case "partner": return <Badge color="yellow">Partner</Badge>;
      case "internal": return <Badge color="blue">Internal</Badge>;
      case "private": return <Badge color="gray">Private</Badge>;
      default: return <Badge>{type}</Badge>;
    }
  };

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
          <span className="text-sm uppercase">
            {value}:{row.port}
          </span>
        </div>
      ),
    },
    {
      key: "authentication_required",
      header: "Auth",
      render: (value: boolean) =>
        value ? (
          <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-sm">
            <CheckCircle2 className="h-3 w-3" />Required
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400 text-sm">
            <XCircle className="h-3 w-3" />None
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

  const filterGroups = [
    {
      id: "exposure_type",
      label: "Exposure Type",
      type: "radio" as const,
      value: filters.exposure_type,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, exposure_type: value as string }),
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
      value: filters.status,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, status: value as string }),
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
      value: filters.min_risk_score?.toString() || "",
      onChange: (value: string | string[]) =>
        setFilters({
          ...filters,
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
    <>
      <div className="flex gap-6">
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filterGroups}
            onReset={() => setFilters({ exposure_type: "", status: "", min_risk_score: undefined })}
          />
        </div>

        <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading endpoints..." />
            </div>
          ) : (endpointsData?.endpoints?.length ?? 0) > 0 ? (
            <Table
              columns={endpointColumns}
              data={endpointsData!.endpoints}
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
                    <span className="text-gray-900 dark:text-white">
                      {new Date(selectedEndpoint.discovered_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Last Updated</span>
                    <span className="text-gray-900 dark:text-white">
                      {new Date(selectedEndpoint.updated_at).toLocaleString()}
                    </span>
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
              if (
                selectedEndpoint &&
                confirm("Are you sure you want to delete this endpoint?")
              ) {
                deleteEndpointMutation.mutate(selectedEndpoint.id);
              }
            }}
            className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
          >
            Delete Endpoint
          </button>
        </SlideOver.Footer>
      </SlideOver>
    </>
  );
}
