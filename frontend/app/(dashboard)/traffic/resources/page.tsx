"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Server,
  Globe,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  Search,
} from "lucide-react";
import Link from "next/link";
import { api, TrafficResource } from "@/lib/api";

// Component library imports
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Input } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";

export default function TrafficResourcesPage() {
  const [selectedResource, setSelectedResource] = useState<TrafficResource | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [filters, setFilters] = useState({
    status: "",
    gateway_type: "",
    agent_id: "",
  });
  const queryClient = useQueryClient();

  // Query resources
  const { data: resourcesData, isLoading } = useQuery({
    queryKey: ["traffic-resources", filters],
    queryFn: () => api.listTrafficResources({
      status: filters.status || undefined,
      gateway_type: filters.gateway_type || undefined,
      agent_id: filters.agent_id || undefined,
    }),
  });

  // Query agents for filter
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (resourceId: string) => api.deleteTrafficResource(resourceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-resources"] });
      queryClient.invalidateQueries({ queryKey: ["traffic-summary"] });
      setSelectedResource(null);
    },
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return <Badge color="green">Active</Badge>;
      case "draft":
        return <Badge color="gray">Draft</Badge>;
      case "pending":
        return <Badge color="yellow">Pending</Badge>;
      case "disabled":
        return <Badge color="gray">Disabled</Badge>;
      case "error":
        return <Badge color="red">Error</Badge>;
      default:
        return <Badge>{status}</Badge>;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "draft":
        return <Clock className="h-4 w-4 text-gray-400" />;
      case "pending":
        return <RefreshCw className="h-4 w-4 text-yellow-500 animate-spin" />;
      case "disabled":
        return <XCircle className="h-4 w-4 text-gray-400" />;
      case "error":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const getGatewayBadge = (type: string) => {
    return type === "system" ? (
      <Badge color="purple">System</Badge>
    ) : (
      <Badge color="blue">Application</Badge>
    );
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

  // Table columns
  const columns = [
    {
      key: "name",
      header: "Resource",
      sortable: true,
      render: (value: string, row: TrafficResource) => (
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
            {row.gateway_type === "system" ? (
              <Server className="h-4 w-4 text-purple-600 dark:text-purple-400" />
            ) : (
              <Globe className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            )}
          </div>
          <div>
            <Link
              href={`/traffic/resources/${row.id}`}
              className="font-medium text-gray-900 dark:text-white hover:text-primary-600"
            >
              {value}
            </Link>
            {row.description && (
              <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                {row.description}
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "domains",
      header: "Domains",
      render: (value: string[]) => (
        <div className="space-y-1">
          {value.slice(0, 2).map((domain, i) => (
            <div key={i} className="text-sm text-gray-700 dark:text-gray-300">
              {domain}
            </div>
          ))}
          {value.length > 2 && (
            <div className="text-xs text-gray-500 dark:text-gray-400">
              +{value.length - 2} more
            </div>
          )}
        </div>
      ),
    },
    {
      key: "gateway_type",
      header: "Type",
      render: (value: string) => getGatewayBadge(value),
    },
    {
      key: "status",
      header: "Status",
      render: (value: string) => (
        <div className="flex items-center gap-2">
          {getStatusIcon(value)}
          {getStatusBadge(value)}
        </div>
      ),
    },
    {
      key: "last_applied_at",
      header: "Last Applied",
      render: (value: string | undefined) =>
        value ? (
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {formatTimestamp(value)}
          </span>
        ) : (
          <span className="text-sm text-gray-400">Never</span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {formatTimestamp(value)}
        </span>
      ),
    },
  ];

  // Filter configuration
  const filterGroups = [
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
        { label: "Draft", value: "draft" },
        { label: "Pending", value: "pending" },
        { label: "Disabled", value: "disabled" },
        { label: "Error", value: "error" },
      ],
    },
    {
      id: "gateway_type",
      label: "Gateway Type",
      type: "radio" as const,
      value: filters.gateway_type,
      onChange: (value: string | string[]) =>
        setFilters({ ...filters, gateway_type: value as string }),
      options: [
        { label: "All Types", value: "" },
        { label: "System", value: "system" },
        { label: "Application", value: "application" },
      ],
    },
  ];

  if (isLoading) {
    return <Spinner.LogoPage label="Loading traffic resources..." />;
  }

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder="Search resources..."
            className="pl-10"
          />
        </div>

        <div className="flex items-center gap-2">
          {filterGroups[0].options.slice(1).map((option) => (
            <button
              key={option.value}
              onClick={() => setFilters({ ...filters, status: filters.status === option.value ? "" : option.value })}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                filters.status === option.value
                  ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
              )}
            >
              {option.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {filterGroups[1].options.slice(1).map((option) => (
            <button
              key={option.value}
              onClick={() => setFilters({ ...filters, gateway_type: filters.gateway_type === option.value ? "" : option.value })}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                filters.gateway_type === option.value
                  ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {/* Resources Table */}
      {resourcesData?.resources && resourcesData.resources.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            columns={columns}
            data={resourcesData.resources}
            keyExtractor={(row) => row.id}
            onRowClick={(row) => setSelectedResource(row)}
            hoverable
          />
        </div>
      ) : (
        <EmptyState
          icon={Network}
          title="No traffic resources"
          description="Create your first traffic resource to manage routing and load balancing"
          action={
            <Link
              href="/traffic/resources/create"
              className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
            >
              Create Resource
            </Link>
          }
        />
      )}

      {/* Resource Detail SlideOver */}
      <SlideOver isOpen={!!selectedResource} onClose={() => setSelectedResource(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedResource(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Resource Details
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {selectedResource?.name}
            </p>
          </div>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedResource && (
            <div className="space-y-6">
              {/* Status */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Status</h4>
                <div className="flex items-center gap-2">
                  {getStatusIcon(selectedResource.status)}
                  {getStatusBadge(selectedResource.status)}
                  {getGatewayBadge(selectedResource.gateway_type)}
                </div>
              </div>

              {/* Domains */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Domains</h4>
                <div className="space-y-1">
                  {selectedResource.domains.map((domain, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      <Globe className="h-4 w-4 text-gray-400" />
                      <span className="text-sm text-gray-700 dark:text-gray-300">{domain}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Paths */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Paths</h4>
                <div className="space-y-1">
                  {selectedResource.paths.map((pathConfig, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      <span className="text-sm text-gray-700 dark:text-gray-300 font-mono">
                        {pathConfig.path}
                      </span>
                      <Badge color="gray">{pathConfig.match}</Badge>
                    </div>
                  ))}
                </div>
              </div>

              {/* Description */}
              {selectedResource.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Description</h4>
                  <p className="text-sm text-gray-700 dark:text-gray-300">
                    {selectedResource.description}
                  </p>
                </div>
              )}

              {/* Labels */}
              {selectedResource.labels && Object.keys(selectedResource.labels).length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Labels</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(selectedResource.labels).map(([key, value]) => (
                      <Badge key={key} color="gray">
                        {key}: {value}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Error */}
              {selectedResource.last_error && (
                <div>
                  <h4 className="text-sm font-medium text-red-500 mb-2">Last Error</h4>
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm text-red-700 dark:text-red-300">
                      {selectedResource.last_error}
                    </p>
                  </div>
                </div>
              )}

              {/* Timestamps */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Timestamps</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Created</span>
                    <span className="text-gray-900 dark:text-white">
                      {formatTimestamp(selectedResource.created_at)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Updated</span>
                    <span className="text-gray-900 dark:text-white">
                      {formatTimestamp(selectedResource.updated_at)}
                    </span>
                  </div>
                  {selectedResource.last_applied_at && (
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Last Applied</span>
                      <span className="text-gray-900 dark:text-white">
                        {formatTimestamp(selectedResource.last_applied_at)}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </SlideOver.Body>

        <SlideOver.Footer>
          <button
            onClick={() => setSelectedResource(null)}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Close
          </button>
          <Link
            href={`/traffic/resources/${selectedResource?.id}`}
            className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
          >
            View Full Details
          </Link>
          <button
            onClick={() => {
              if (selectedResource && confirm("Are you sure you want to delete this resource?")) {
                deleteMutation.mutate(selectedResource.id);
              }
            }}
            className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
          >
            Delete
          </button>
        </SlideOver.Footer>
      </SlideOver>
    </div>
  );
}
