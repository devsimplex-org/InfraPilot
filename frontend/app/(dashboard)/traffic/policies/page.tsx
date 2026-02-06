"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Globe,
  Zap,
  Bot,
  Lock,
  MapPin,
  Settings,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { api, TrafficPolicy, TrafficPolicyType } from "@/lib/api";

// Component library imports
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { FilterToolbar, ToggleOption } from "@/components/ui/FilterToolbar";

// Filter options
const POLICY_TYPE_OPTIONS: ToggleOption[] = [
  { value: "", label: "All Types" },
  { value: "rate_limit", label: "Rate Limit", color: "blue" },
  { value: "bot_protection", label: "Bot Protection" },
  { value: "geo_blocking", label: "Geo Blocking", color: "yellow" },
  { value: "ip_filtering", label: "IP Filtering", color: "red" },
  { value: "cors", label: "CORS" },
  { value: "authentication", label: "Auth", color: "green" },
];

export default function TrafficPoliciesPage() {
  const [selectedPolicy, setSelectedPolicy] = useState<TrafficPolicy | null>(null);
  const [filters, setFilters] = useState({
    type: "" as TrafficPolicyType | "",
  });
  const queryClient = useQueryClient();

  // Query policies
  const { data: policiesData, isLoading } = useQuery({
    queryKey: ["traffic-policies", filters],
    queryFn: () => api.listTrafficPolicies({
      type: filters.type || undefined,
    }),
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (policyId: string) => api.deleteTrafficPolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-policies"] });
      setSelectedPolicy(null);
    },
  });

  const getPolicyTypeIcon = (type: string) => {
    const icons: Record<string, typeof Shield> = {
      rate_limit: Zap,
      bot_protection: Bot,
      geo_blocking: MapPin,
      captcha: Lock,
      ip_filtering: Shield,
      header_transform: Settings,
      cors: Globe,
      authentication: Lock,
    };
    const Icon = icons[type] || Shield;
    return <Icon className="h-4 w-4" />;
  };

  const getPolicyTypeBadge = (type: string) => {
    const colors: Record<string, "blue" | "green" | "yellow" | "red" | "purple" | "gray"> = {
      rate_limit: "blue",
      bot_protection: "purple",
      geo_blocking: "yellow",
      captcha: "green",
      ip_filtering: "red",
      header_transform: "gray",
      cors: "blue",
      authentication: "green",
    };
    const labels: Record<string, string> = {
      rate_limit: "Rate Limit",
      bot_protection: "Bot Protection",
      geo_blocking: "Geo Blocking",
      captcha: "CAPTCHA",
      ip_filtering: "IP Filtering",
      header_transform: "Header Transform",
      cors: "CORS",
      authentication: "Authentication",
    };
    return <Badge color={colors[type] || "gray"}>{labels[type] || type}</Badge>;
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

  const formatConfigSummary = (type: string, config: Record<string, unknown>): string => {
    switch (type) {
      case "rate_limit":
        return config.requests_per_second
          ? `${config.requests_per_second} req/s`
          : config.requests_per_minute
          ? `${config.requests_per_minute} req/min`
          : "Configured";
      case "geo_blocking":
        return `${(config.countries as string[])?.length || 0} countries`;
      case "ip_filtering":
        return `${(config.rules as unknown[])?.length || 0} rules`;
      case "bot_protection":
        return typeof config.mode === "string" ? config.mode : "Configured";
      default:
        return "Configured";
    }
  };

  // Table columns
  const columns = [
    {
      key: "name",
      header: "Policy",
      sortable: true,
      render: (value: string, row: TrafficPolicy) => (
        <div className="flex items-center gap-3">
          <div className={cn(
            "p-2 rounded-lg",
            row.enabled
              ? "bg-gray-100 dark:bg-gray-800"
              : "bg-gray-50 dark:bg-gray-800/50"
          )}>
            {getPolicyTypeIcon(row.policy_type)}
          </div>
          <div>
            <div className={cn(
              "font-medium",
              row.enabled
                ? "text-gray-900 dark:text-white"
                : "text-gray-500 dark:text-gray-400"
            )}>
              {value}
            </div>
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
      key: "policy_type",
      header: "Type",
      render: (value: string) => getPolicyTypeBadge(value),
    },
    {
      key: "config",
      header: "Configuration",
      render: (value: Record<string, unknown>, row: TrafficPolicy) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {formatConfigSummary(row.policy_type, value)}
        </span>
      ),
    },
    {
      key: "is_global",
      header: "Scope",
      render: (value: boolean) =>
        value ? (
          <Badge color="yellow">Global</Badge>
        ) : (
          <Badge color="gray">Assignment</Badge>
        ),
    },
    {
      key: "priority",
      header: "Priority",
      render: (value: number) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (value: boolean) =>
        value ? (
          <div className="flex items-center gap-1">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <Badge color="green">Enabled</Badge>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <XCircle className="h-4 w-4 text-gray-400" />
            <Badge color="gray">Disabled</Badge>
          </div>
        ),
    },
  ];

  const [searchQuery, setSearchQuery] = useState("");

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["traffic-policies"] });
  };

  if (isLoading) {
    return <Spinner.LogoPage label="Loading policies..." />;
  }

  return (
    <div className="space-y-6">
      {/* Filter Toolbar */}
      <FilterToolbar
        primaryToggle={{
          options: POLICY_TYPE_OPTIONS,
          value: filters.type,
          onChange: (v) => setFilters({ ...filters, type: v as TrafficPolicyType | "" }),
        }}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search policies..."
        showSearch={true}
        showRefresh={true}
        onRefresh={handleRefresh}
        singleRow={true}
      />

      {/* Policies Table */}
      {policiesData?.policies && policiesData.policies.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            columns={columns}
            data={policiesData.policies}
            keyExtractor={(row) => row.id}
            onRowClick={(row) => setSelectedPolicy(row)}
            hoverable
          />
        </div>
      ) : (
        <EmptyState
          icon={Shield}
          title="No traffic policies"
          description="Create policies to control traffic flow, rate limiting, and security"
          action={
            <Link
              href="/traffic/policies/create"
              className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium"
            >
              Create Policy
            </Link>
          }
        />
      )}

      {/* Policy Detail SlideOver */}
      <SlideOver isOpen={!!selectedPolicy} onClose={() => setSelectedPolicy(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedPolicy(null)}>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Policy Details
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {selectedPolicy?.name}
            </p>
          </div>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedPolicy && (
            <div className="space-y-6">
              {/* Type & Status */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Type & Status
                </h4>
                <div className="flex items-center gap-2">
                  {getPolicyTypeBadge(selectedPolicy.policy_type)}
                  {selectedPolicy.is_global && <Badge color="yellow">Global</Badge>}
                  {selectedPolicy.enabled ? (
                    <Badge color="green">Enabled</Badge>
                  ) : (
                    <Badge color="gray">Disabled</Badge>
                  )}
                </div>
              </div>

              {/* Description */}
              {selectedPolicy.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                    Description
                  </h4>
                  <p className="text-sm text-gray-700 dark:text-gray-300">
                    {selectedPolicy.description}
                  </p>
                </div>
              )}

              {/* Configuration */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Configuration
                </h4>
                <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded-lg overflow-x-auto">
                  {JSON.stringify(selectedPolicy.config, null, 2)}
                </pre>
              </div>

              {/* Priority */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Priority
                </h4>
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  {selectedPolicy.priority} (higher values take precedence)
                </p>
              </div>

              {/* Timestamps */}
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Timestamps
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Created</span>
                    <span className="text-gray-900 dark:text-white">
                      {formatTimestamp(selectedPolicy.created_at)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Updated</span>
                    <span className="text-gray-900 dark:text-white">
                      {formatTimestamp(selectedPolicy.updated_at)}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </SlideOver.Body>

        <SlideOver.Footer>
          <button
            onClick={() => setSelectedPolicy(null)}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Close
          </button>
          <button
            className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
          >
            Edit Policy
          </button>
          <button
            onClick={() => {
              if (selectedPolicy && confirm("Are you sure you want to delete this policy?")) {
                deleteMutation.mutate(selectedPolicy.id);
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
