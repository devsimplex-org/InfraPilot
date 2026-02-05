"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Network,
  Server,
  Shield,
  CheckCircle2,
  ArrowRight,
  Globe,
  Lock,
} from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

// Component library imports
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

interface ProxyHost {
  id: string;
  agent_id: string;
  domain: string;
  upstream_target: string;
  ssl_enabled: boolean;
  ssl_expires_at: string | null;
  force_ssl: boolean;
  http2_enabled: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

export default function TrafficOverviewPage() {
  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.filter((a) => a.status === "active")[0]?.id;

  // Query traffic summary
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["traffic-summary"],
    queryFn: () => api.getTrafficSummary(),
  });

  // Query resources
  const { data: resourcesData, isLoading: resourcesLoading } = useQuery({
    queryKey: ["traffic-resources"],
    queryFn: () => api.listTrafficResources({}),
  });

  // Query policies
  const { data: policiesData, isLoading: policiesLoading } = useQuery({
    queryKey: ["traffic-policies"],
    queryFn: () => api.listTrafficPolicies({}),
  });

  // Query proxies
  const { data: proxiesData, isLoading: proxiesLoading } = useQuery({
    queryKey: ["proxies", defaultAgentId],
    queryFn: () => api.getProxyHosts(defaultAgentId!),
    enabled: !!defaultAgentId,
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

  const isLoading = summaryLoading || resourcesLoading || policiesLoading || proxiesLoading;

  if (isLoading) {
    return <Spinner.LogoPage label="Loading traffic overview..." />;
  }

  return (
    <div className="space-y-6">
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
        />
        <StatCard
          label="Policies"
          value={policiesData?.policies?.length || 0}
          icon={Shield}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Proxies"
          value={proxiesData?.length || 0}
          icon={Globe}
          iconColor="text-orange-600"
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

      {/* Recent Resources & Proxies */}
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
              resourcesData.resources.slice(0, 5).map((resource) => (
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
                      <div className="font-medium text-gray-900 dark:text-white">{resource.name}</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {resource.domains?.slice(0, 2).join(", ")}
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

        {/* Recent Proxies */}
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h3 className="font-semibold text-gray-900 dark:text-white">Active Proxies</h3>
            <Link
              href="/proxies"
              className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
            >
              View all
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {proxiesData && proxiesData.length > 0 ? (
              proxiesData.slice(0, 5).map((proxy: ProxyHost) => (
                <div
                  key={proxy.id}
                  className="flex items-center justify-between px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      "p-2 rounded-lg",
                      proxy.ssl_enabled ? "bg-green-100 dark:bg-green-900/30" : "bg-gray-100 dark:bg-gray-800"
                    )}>
                      {proxy.ssl_enabled ? (
                        <Lock className="h-4 w-4 text-green-600 dark:text-green-400" />
                      ) : (
                        <Globe className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                      )}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">{proxy.domain}</div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">→ {proxy.upstream_target}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {proxy.ssl_enabled && <Badge color="green">SSL</Badge>}
                    {getStatusBadge(proxy.status)}
                  </div>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center">
                <Globe className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No proxies configured yet</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
