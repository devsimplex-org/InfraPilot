"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  AlertTriangle,
  ShieldCheck,
  Activity,
  ArrowRight,
} from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { Card, CardBody } from "@/components/ui/Card";
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
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.filter((a) => a.status === "active")[0]?.id;

  const { data: proxiesData, isLoading: proxiesLoading } = useQuery({
    queryKey: ["proxies", defaultAgentId],
    queryFn: () => api.getProxyHosts(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  const activeProxies = proxiesData?.filter((p: ProxyHost) => p.status === "active")?.length || 0;
  const sslEnabledProxies = proxiesData?.filter((p: ProxyHost) => p.ssl_enabled)?.length || 0;
  const expiringCerts = proxiesData?.filter((p: ProxyHost) => {
    if (!p.ssl_expires_at) return false;
    const expiresAt = new Date(p.ssl_expires_at);
    const thirtyDaysFromNow = new Date();
    thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);
    return expiresAt <= thirtyDaysFromNow && expiresAt > new Date();
  })?.length || 0;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active": return <Badge color="green">Active</Badge>;
      case "draft": return <Badge color="gray">Draft</Badge>;
      case "pending": return <Badge color="yellow">Pending</Badge>;
      case "disabled": return <Badge color="gray">Disabled</Badge>;
      case "error": return <Badge color="red">Error</Badge>;
      default: return <Badge>{status}</Badge>;
    }
  };

  if (proxiesLoading) {
    return <Spinner.LogoPage label="Loading traffic overview..." />;
  }

  return (
    <div className="space-y-8">
      {/* Reverse Proxy Section */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-orange-600 dark:text-orange-400" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Reverse Proxy</h2>
          <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">Domain-to-upstream mapping with SSL</span>
        </div>

        <MetricsGrid columns={4}>
          <StatCard
            label="Total Proxies"
            value={proxiesData?.length || 0}
            icon={Globe}
            iconColor="text-orange-600"
            onClick={() => window.location.href = "/traffic/proxies"}
          />
          <StatCard
            label="Active Proxies"
            value={activeProxies}
            icon={Activity}
            iconColor="text-green-600"
          />
          <StatCard
            label="SSL Enabled"
            value={sslEnabledProxies}
            icon={ShieldCheck}
            iconColor="text-emerald-600"
            description={proxiesData?.length ? `${Math.round((sslEnabledProxies / proxiesData.length) * 100)}% coverage` : undefined}
          />
          <StatCard
            label="Expiring Certs"
            value={expiringCerts}
            icon={AlertTriangle}
            iconColor={expiringCerts > 0 ? "text-yellow-600" : "text-gray-400"}
            description={expiringCerts > 0 ? "Within 30 days" : "All certificates healthy"}
            valueColor={expiringCerts > 0 ? "text-yellow-600" : undefined}
          />
        </MetricsGrid>
      </div>

      {/* Recent Proxies */}
      <Card>
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-orange-600 dark:text-orange-400" />
            <h3 className="font-semibold text-gray-900 dark:text-white">Recent Proxies</h3>
          </div>
          <Link
            href="/traffic/proxies"
            className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
          >
            View all
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
        <CardBody noPadding>
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {proxiesData && proxiesData.length > 0 ? (
              proxiesData.slice(0, 5).map((proxy: ProxyHost) => {
                const isExpiringSoon = proxy.ssl_expires_at && (() => {
                  const expiresAt = new Date(proxy.ssl_expires_at!);
                  const thirtyDaysFromNow = new Date();
                  thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);
                  return expiresAt <= thirtyDaysFromNow && expiresAt > new Date();
                })();

                return (
                  <div
                    key={proxy.id}
                    className="flex items-center justify-between px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "p-2 rounded-lg",
                        proxy.ssl_enabled
                          ? isExpiringSoon
                            ? "bg-yellow-100 dark:bg-yellow-900/30"
                            : "bg-green-100 dark:bg-green-900/30"
                          : "bg-gray-100 dark:bg-gray-800"
                      )}>
                        {proxy.ssl_enabled ? (
                          isExpiringSoon ? (
                            <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
                          ) : (
                            <Lock className="h-4 w-4 text-green-600 dark:text-green-400" />
                          )
                        ) : (
                          <Globe className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                        )}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">{proxy.domain}</div>
                        <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-[200px]">
                          → {proxy.upstream_target}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {proxy.ssl_enabled && (
                        isExpiringSoon ? (
                          <Badge color="yellow">SSL Expiring</Badge>
                        ) : (
                          <Badge color="green">SSL</Badge>
                        )
                      )}
                      {getStatusBadge(proxy.status)}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="px-6 py-8 text-center">
                <Globe className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No proxies configured yet</p>
                <Link
                  href="/traffic/proxies"
                  className="inline-flex items-center gap-1 mt-3 text-sm text-primary-600 hover:text-primary-700"
                >
                  Add your first proxy
                  <ArrowRight className="h-3 w-3" />
                </Link>
              </div>
            )}
          </div>
        </CardBody>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardBody>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">Quick Actions</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Common traffic management tasks</p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/traffic/proxies"
                className="inline-flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors text-sm font-medium"
              >
                <Globe className="w-4 h-4" />
                Add Proxy
              </Link>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
