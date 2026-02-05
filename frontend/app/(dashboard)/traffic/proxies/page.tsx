"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  Unlock,
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Trash2,
  Edit,
  ExternalLink,
  MoreVertical,
  Plus,
  Search,
  RefreshCw,
} from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

// Component library imports
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Input, Button } from "@/components/ui/page-layout";
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
  basic_auth_enabled?: boolean;
  basic_auth_realm?: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export default function ProxiesPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [proxyToDelete, setProxyToDelete] = useState<ProxyHost | null>(null);
  const queryClient = useQueryClient();

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.filter((a) => a.status === "active")[0]?.id;

  // Fetch proxies
  const { data: proxiesData, isLoading } = useQuery({
    queryKey: ["proxies", defaultAgentId],
    queryFn: () => api.getProxyHosts(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  const proxies = proxiesData || [];

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (proxyId: string) => api.deleteProxyHost(defaultAgentId!, proxyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxies"] });
      setProxyToDelete(null);
    },
  });

  // Filter proxies
  const filteredProxies = proxies.filter((proxy: ProxyHost) => {
    const matchesSearch =
      searchQuery === "" ||
      proxy.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      proxy.upstream_target.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === "all" ||
      (statusFilter === "ssl" && proxy.ssl_enabled) ||
      (statusFilter === "no-ssl" && !proxy.ssl_enabled) ||
      (statusFilter === "auth" && proxy.basic_auth_enabled);

    return matchesSearch && matchesStatus;
  });

  // Calculate metrics
  const metrics = {
    total: proxies.length,
    sslEnabled: proxies.filter((p: ProxyHost) => p.ssl_enabled).length,
    http2Enabled: proxies.filter((p: ProxyHost) => p.http2_enabled).length,
    authEnabled: proxies.filter((p: ProxyHost) => p.basic_auth_enabled).length,
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  // Status filters
  const statusFilters = [
    { id: "all", label: "All", count: proxies.length },
    { id: "ssl", label: "SSL Enabled", count: metrics.sslEnabled },
    { id: "no-ssl", label: "No SSL", count: proxies.length - metrics.sslEnabled },
    { id: "auth", label: "Auth Enabled", count: metrics.authEnabled },
  ];

  // Table columns
  const columns = [
    {
      key: "domain",
      header: "Domain",
      render: (value: string, row: ProxyHost) => (
        <div className="flex items-center gap-3">
          <div className={cn(
            "p-2 rounded-lg",
            row.ssl_enabled
              ? "bg-green-100 dark:bg-green-900/30"
              : "bg-yellow-100 dark:bg-yellow-900/30"
          )}>
            {row.ssl_enabled ? (
              <Lock className="h-4 w-4 text-green-600 dark:text-green-400" />
            ) : (
              <Unlock className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
            )}
          </div>
          <div>
            <a
              href={`${row.ssl_enabled ? "https" : "http"}://${value}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-gray-900 dark:text-white hover:text-primary-600 dark:hover:text-primary-400 flex items-center gap-1"
            >
              {value}
              <ExternalLink className="h-3 w-3" />
            </a>
            <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
              → {row.upstream_target}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "ssl_enabled",
      header: "SSL",
      render: (value: boolean, row: ProxyHost) => (
        <div className="flex flex-col gap-1">
          {value ? (
            <Badge color="green">SSL</Badge>
          ) : (
            <Badge color="yellow">No SSL</Badge>
          )}
          {row.http2_enabled && <Badge color="blue">HTTP/2</Badge>}
        </div>
      ),
    },
    {
      key: "basic_auth_enabled",
      header: "Auth",
      render: (value: boolean, row: ProxyHost) =>
        value ? (
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-purple-500" />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {row.basic_auth_realm || "Protected"}
            </span>
          </div>
        ) : (
          <span className="text-sm text-gray-400">-</span>
        ),
    },
    {
      key: "ssl_expires_at",
      header: "SSL Expires",
      render: (value: string | null) =>
        value ? (
          <span className="text-sm text-gray-600 dark:text-gray-400">
            {formatDate(value)}
          </span>
        ) : (
          <span className="text-sm text-gray-400">-</span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {formatDate(value)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (_: unknown, row: ProxyHost) => (
        <div className="flex items-center gap-2 justify-end">
          <Link
            href={`/traffic/proxies/${row.id}`}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <Edit className="h-4 w-4" />
          </Link>
          <button
            onClick={() => setProxyToDelete(row)}
            className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ];

  if (isLoading) {
    return <Spinner.LogoPage label="Loading proxies..." />;
  }

  return (
    <div className="space-y-6">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Total Proxies"
          value={metrics.total}
          icon={Globe}
          iconColor="text-blue-600"
        />
        <StatCard
          label="SSL Enabled"
          value={metrics.sslEnabled}
          icon={Lock}
          iconColor="text-green-600"
          description={`${Math.round((metrics.sslEnabled / Math.max(metrics.total, 1)) * 100)}% coverage`}
        />
        <StatCard
          label="HTTP/2 Enabled"
          value={metrics.http2Enabled}
          icon={RefreshCw}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Auth Protected"
          value={metrics.authEnabled}
          icon={Shield}
          iconColor="text-orange-600"
        />
      </MetricsGrid>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder="Search domains or upstreams..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        <div className="flex items-center gap-2">
          {statusFilters.map((filter) => (
            <button
              key={filter.id}
              onClick={() => setStatusFilter(filter.id)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                statusFilter === filter.id
                  ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
              )}
            >
              {filter.label}
              <span className="ml-1.5 text-xs">({filter.count})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {filteredProxies.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            columns={columns}
            data={filteredProxies}
            keyExtractor={(row) => row.id}
            hoverable
          />
        </div>
      ) : (
        <EmptyState
          icon={Globe}
          title={searchQuery ? "No proxies match your search" : "No proxies configured"}
          description={
            searchQuery
              ? "Try adjusting your search terms"
              : "Add a proxy to route traffic to your services"
          }
          action={
            !searchQuery && (
              <Link
                href="/traffic/proxies/create"
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
              >
                <Plus className="w-4 h-4" />
                Add Proxy
              </Link>
            )
          }
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={!!proxyToDelete}
        onClose={() => setProxyToDelete(null)}
        onConfirm={() => {
          if (proxyToDelete) {
            deleteMutation.mutate(proxyToDelete.id);
          }
        }}
        title={`Delete Proxy "${proxyToDelete?.domain}"?`}
        message="This will remove the nginx configuration for this domain. Traffic will no longer be routed."
        confirmText={deleteMutation.isPending ? "Deleting..." : "Delete Proxy"}
        variant="danger"
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
