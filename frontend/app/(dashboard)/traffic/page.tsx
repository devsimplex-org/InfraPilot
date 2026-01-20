"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Network,
  Server,
  Shield,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Plus,
  ArrowRight,
  Globe,
  Zap,
  Lock,
} from "lucide-react";
import Link from "next/link";
import { api, TrafficResourceSummary, TrafficResource, TrafficPolicy } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { cn } from "@/lib/utils";

export default function TrafficDashboardPage() {
  // Query traffic summary
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["traffic-summary"],
    queryFn: () => api.getTrafficSummary(),
  });

  // Query recent resources
  const { data: resourcesData, isLoading: resourcesLoading } = useQuery({
    queryKey: ["traffic-resources", { limit: 5 }],
    queryFn: () => api.listTrafficResources({ limit: 5 }),
  });

  // Query policies
  const { data: policiesData, isLoading: policiesLoading } = useQuery({
    queryKey: ["traffic-policies", { limit: 5 }],
    queryFn: () => api.listTrafficPolicies({ limit: 5 }),
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

  const getGatewayBadge = (type: string) => {
    return type === "system" ? (
      <Badge color="purple">System</Badge>
    ) : (
      <Badge color="blue">Application</Badge>
    );
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
    return <Badge color={colors[type] || "gray"}>{type.replace(/_/g, " ")}</Badge>;
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Traffic", current: true },
      ]}
    />
  );

  // Page Header Action
  const headerAction = (
    <Link
      href="/traffic/resources"
      className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
    >
      <Plus className="h-4 w-4" />
      New Resource
    </Link>
  );

  const isLoading = summaryLoading || resourcesLoading || policiesLoading;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Traffic Management"
        description="Manage traffic resources, load balancing, and security policies"
        breadcrumbs={breadcrumbs}
        action={headerAction}
      />

      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" label="Loading traffic data..." />
        </div>
      ) : (
        <>
          {/* Summary Metrics */}
          <MetricsGrid columns={4}>
            <StatCard
              label="Total Resources"
              value={summary?.total_resources || 0}
              icon={Network}
              iconColor="text-blue-600"
            />
            <StatCard
              label="Active Resources"
              value={summary?.active_resources || 0}
              icon={CheckCircle2}
              iconColor="text-green-600"
              valueColor="text-green-600 dark:text-green-400"
            />
            <StatCard
              label="Draft Resources"
              value={summary?.draft_resources || 0}
              icon={Clock}
              iconColor="text-gray-600"
            />
            <StatCard
              label="Error Resources"
              value={summary?.error_resources || 0}
              icon={XCircle}
              iconColor="text-red-600"
              valueColor={summary?.error_resources ? "text-red-600 dark:text-red-400" : undefined}
            />
          </MetricsGrid>

          {/* Gateway Types */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Server className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">System Gateways</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Infrastructure-level traffic</p>
                </div>
              </div>
              <div className="text-3xl font-bold text-gray-900 dark:text-white">
                {summary?.system_gateways || 0}
              </div>
            </div>

            <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                  <Globe className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">Application Gateways</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Application-level routing</p>
                </div>
              </div>
              <div className="text-3xl font-bold text-gray-900 dark:text-white">
                {summary?.application_gateways || 0}
              </div>
            </div>
          </div>

          {/* Recent Resources & Policies */}
          <div className="grid grid-cols-2 gap-6">
            {/* Recent Resources */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
              <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
                <h3 className="font-semibold text-gray-900 dark:text-white">Recent Resources</h3>
                <Link
                  href="/traffic/resources"
                  className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                >
                  View all
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
              <div className="divide-y divide-gray-200 dark:divide-gray-800">
                {resourcesData?.resources && resourcesData.resources.length > 0 ? (
                  resourcesData.resources.map((resource) => (
                    <Link
                      key={resource.id}
                      href={`/traffic/resources/${resource.id}`}
                      className="flex items-center justify-between px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                          <Network className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                        </div>
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {resource.name}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {resource.domains.slice(0, 2).join(", ")}
                            {resource.domains.length > 2 && ` +${resource.domains.length - 2}`}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getGatewayBadge(resource.gateway_type)}
                        {getStatusBadge(resource.status)}
                      </div>
                    </Link>
                  ))
                ) : (
                  <div className="px-6 py-8 text-center">
                    <Network className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-500 dark:text-gray-400">No traffic resources yet</p>
                  </div>
                )}
              </div>
            </div>

            {/* Recent Policies */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
              <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
                <h3 className="font-semibold text-gray-900 dark:text-white">Traffic Policies</h3>
                <Link
                  href="/traffic/policies"
                  className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                >
                  View all
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
              <div className="divide-y divide-gray-200 dark:divide-gray-800">
                {policiesData?.policies && policiesData.policies.length > 0 ? (
                  policiesData.policies.map((policy) => (
                    <div
                      key={policy.id}
                      className="flex items-center justify-between px-6 py-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                          <Shield className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                        </div>
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {policy.name}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {policy.description || "No description"}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getPolicyTypeBadge(policy.policy_type)}
                        {policy.is_global && <Badge color="yellow">Global</Badge>}
                        {!policy.enabled && <Badge color="gray">Disabled</Badge>}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="px-6 py-8 text-center">
                    <Shield className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-500 dark:text-gray-400">No policies defined yet</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Quick Actions</h3>
            <div className="grid grid-cols-4 gap-4">
              <Link
                href="/traffic/resources"
                className="flex items-center gap-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                  <Network className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Manage Resources</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">View and edit traffic resources</div>
                </div>
              </Link>

              <Link
                href="/traffic/policies"
                className="flex items-center gap-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Shield className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Policy Library</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Configure traffic policies</div>
                </div>
              </Link>

              <Link
                href="/run/exposure"
                className="flex items-center gap-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                  <Globe className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Exposure Map</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">View exposed endpoints</div>
                </div>
              </Link>

              <Link
                href="/traffic/resources"
                className="flex items-center gap-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
                  <Lock className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">TLS Settings</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Manage certificates</div>
                </div>
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
