"use client";

import { useState, useEffect, ReactNode } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  Shield,
  ShieldCheck,
  Trash2,
  Code,
  FileText,
  RefreshCw,
  Check,
  AlertTriangle,
  Copy,
  Activity,
  ChevronDown,
  ChevronRight,
  Loader2,
  Play,
  Save,
  ExternalLink,
  Settings,
} from "lucide-react";
import { api, ProxyHost, SecurityHeaders, RateLimit, TrafficResource, TrafficTLSConfig } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Spinner } from "@/components/ui/Spinner";
import { SSLWizard } from "@/components/ssl-wizard";
import { Button, Input } from "@/components/ui/page-layout";

// ============================================================================
// Shared Types
// ============================================================================

export type ResourceType = "proxy" | "resource";

export interface DomainConfig {
  id: string;
  type: ResourceType;
  domain: string;
  domains?: string[]; // For traffic resources with multiple domains
  target?: string; // Upstream target (proxy) or first upstream (resource)
  sslEnabled: boolean;
  sslExpiresAt?: string | null;
  status: string;
  agentId?: string;
  accessLog?: boolean;
  errorLog?: boolean;
}

export interface DomainConfigPanelProps {
  /** The resource type */
  type: ResourceType;
  /** Resource ID (proxyId or resourceId) */
  resourceId: string | null;
  /** Agent ID (required for proxies) */
  agentId?: string | null;
  /** Whether the panel is open */
  isOpen: boolean;
  /** Callback when panel closes */
  onClose: () => void;
  /** Callback when resource is deleted */
  onDelete?: () => void;
  /** Callback when resource is updated */
  onUpdate?: () => void;
}

// ============================================================================
// Collapsible Section Component
// ============================================================================

export function Section({
  title,
  icon: Icon,
  children,
  defaultOpen = true,
  badge,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  defaultOpen?: boolean;
  badge?: React.ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-gray-500" />
          <span className="text-sm font-medium text-gray-900 dark:text-white">{title}</span>
          {badge}
        </div>
        {isOpen ? (
          <ChevronDown className="h-4 w-4 text-gray-400" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-400" />
        )}
      </button>
      {isOpen && <div className="p-4 space-y-4">{children}</div>}
    </div>
  );
}

// ============================================================================
// Shared Status Helpers
// ============================================================================

export function getSSLStatus(config: { ssl_enabled?: boolean; sslEnabled?: boolean; ssl_expires_at?: string | null; sslExpiresAt?: string | null }): "healthy" | "warning" | "critical" {
  const sslEnabled = config.ssl_enabled ?? config.sslEnabled;
  const expiresAt = config.ssl_expires_at ?? config.sslExpiresAt;

  if (!sslEnabled) return "warning";
  if (expiresAt) {
    const daysUntilExpiry = Math.ceil((new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysUntilExpiry < 7) return "critical";
    if (daysUntilExpiry < 30) return "warning";
  }
  return "healthy";
}

export function getResourceStatus(status: string): "healthy" | "warning" | "critical" | "degraded" {
  switch (status) {
    case "active":
      return "healthy";
    case "ssl_pending":
    case "pending":
    case "draft":
      return "warning";
    case "error":
      return "critical";
    default:
      return "degraded";
  }
}

// ============================================================================
// Domain Info Card (Shared component for displaying domain details)
// ============================================================================

export function DomainInfoCard({
  domain,
  domains,
  target,
  sslEnabled,
  status,
  createdAt,
  onViewExternal,
}: {
  domain: string;
  domains?: string[];
  target?: string;
  sslEnabled: boolean;
  status: string;
  createdAt?: string;
  onViewExternal?: () => void;
}) {
  const allDomains = domains && domains.length > 0 ? domains : [domain];

  return (
    <div className="space-y-3">
      {/* Domain(s) */}
      <div>
        <label className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
          {allDomains.length > 1 ? "Domains" : "Domain"}
        </label>
        <div className="mt-1 space-y-1">
          {allDomains.map((d) => (
            <a
              key={d}
              href={`http${sslEnabled ? "s" : ""}://${d}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-sm text-primary-600 hover:text-primary-500"
            >
              {d}
              <ExternalLink className="h-3 w-3" />
            </a>
          ))}
        </div>
      </div>

      {/* Target */}
      {target && (
        <div>
          <label className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
            Target
          </label>
          <div className="mt-1">
            <code className="text-sm text-gray-900 dark:text-white font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
              {target}
            </code>
          </div>
        </div>
      )}

      {/* Status */}
      <div className="flex justify-between items-center">
        <label className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
          Status
        </label>
        <StatusIndicator status={getResourceStatus(status)} />
      </div>

      {/* Created */}
      {createdAt && (
        <div className="flex justify-between items-center">
          <label className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
            Created
          </label>
          <span className="text-sm text-gray-900 dark:text-white">
            {formatRelativeTime(createdAt)}
          </span>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// SSL Section (Shared component for SSL status and wizard trigger)
// ============================================================================

export function SSLSection({
  domain,
  domains,
  sslEnabled,
  sslExpiresAt,
  status,
  onSetupSSL,
}: {
  domain: string;
  domains?: string[];
  sslEnabled: boolean;
  sslExpiresAt?: string | null;
  status: string;
  onSetupSSL: () => void;
}) {
  const sslStatus = getSSLStatus({ sslEnabled, sslExpiresAt });

  return (
    <Section
      title="SSL / TLS"
      icon={Lock}
      defaultOpen={true}
      badge={
        sslEnabled ? (
          <Badge color="green" size="sm">Enabled</Badge>
        ) : (
          <Badge color="gray" size="sm">Not configured</Badge>
        )
      }
    >
      <div className="space-y-3">
        <StatusIndicator
          status={sslStatus}
          label={sslEnabled
            ? sslExpiresAt
              ? `Expires ${formatRelativeTime(sslExpiresAt)}`
              : "SSL Enabled"
            : status === "ssl_pending"
            ? "SSL Certificate Pending"
            : "SSL Not Enabled"}
        />

        {domains && domains.length > 1 && (
          <div className="text-xs text-gray-500">
            Certificate will be requested for: {domains.join(", ")}
          </div>
        )}

        {!sslEnabled && status !== "ssl_pending" && (
          <Button
            variant="primary"
            size="sm"
            icon={ShieldCheck}
            onClick={onSetupSSL}
          >
            Setup SSL Certificate
          </Button>
        )}
      </div>
    </Section>
  );
}

// ============================================================================
// Logs Section (Shared component for log configuration and viewing)
// ============================================================================

export function LogsSection({
  domain,
  agentId,
  accessLog,
  errorLog,
  onAccessLogChange,
  onErrorLogChange,
}: {
  domain: string;
  agentId?: string;
  accessLog: boolean;
  errorLog: boolean;
  onAccessLogChange: (enabled: boolean) => void;
  onErrorLogChange: (enabled: boolean) => void;
}) {
  const [logsTail, setLogsTail] = useState(100);

  // Fetch logs for this domain
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["domain-logs", agentId, domain, logsTail],
    queryFn: async () => {
      if (!agentId || !domain) return null;
      const response = await fetch(
        `/api/v1/agents/${agentId}/nginx/logs?domain=${encodeURIComponent(domain)}&tail=${logsTail}`,
        {
          headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
        }
      );
      return response.json();
    },
    enabled: !!agentId && !!domain,
  });

  return (
    <Section title="Logging" icon={FileText} defaultOpen={false}>
      <div className="space-y-4">
        {/* Log toggles */}
        <div className="grid grid-cols-2 gap-3">
          <label className="flex items-center gap-2 p-3 border border-gray-200 dark:border-gray-700 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50">
            <input
              type="checkbox"
              checked={accessLog}
              onChange={(e) => onAccessLogChange(e.target.checked)}
              className="w-4 h-4 rounded text-primary-600"
            />
            <div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">Access Log</span>
              <p className="text-xs text-gray-500">Log all requests</p>
            </div>
          </label>

          <label className="flex items-center gap-2 p-3 border border-gray-200 dark:border-gray-700 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50">
            <input
              type="checkbox"
              checked={errorLog}
              onChange={(e) => onErrorLogChange(e.target.checked)}
              className="w-4 h-4 rounded text-primary-600"
            />
            <div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">Error Log</span>
              <p className="text-xs text-gray-500">Log errors and warnings</p>
            </div>
          </label>
        </div>

        {/* Log viewer */}
        {agentId && (
          <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 bg-gray-800 border-b border-gray-700">
              <span className="text-xs text-gray-400">Recent logs for {domain}</span>
              <div className="flex items-center gap-2">
                <select
                  value={logsTail}
                  onChange={(e) => setLogsTail(Number(e.target.value))}
                  className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs text-gray-200"
                >
                  <option value={50}>50 lines</option>
                  <option value={100}>100 lines</option>
                  <option value={500}>500 lines</option>
                </select>
                <button onClick={() => refetchLogs()} className="p-1 hover:bg-gray-700 rounded">
                  <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                </button>
              </div>
            </div>
            <div className="bg-gray-900 max-h-48 overflow-y-auto">
              {logsLoading ? (
                <div className="flex items-center justify-center h-24">
                  <Spinner size="sm" />
                </div>
              ) : logsData?.logs ? (
                <div className="font-mono text-xs p-2">
                  {logsData.logs
                    .split("\n")
                    .filter((l: string) => l.trim())
                    .slice(0, 20)
                    .map((line: string, idx: number) => (
                      <div key={idx} className="text-gray-300 hover:bg-gray-800/50 py-0.5 px-2 -mx-2">
                        {line}
                      </div>
                    ))}
                </div>
              ) : (
                <div className="text-center text-gray-500 py-6 text-xs">
                  {accessLog ? "No logs available yet" : "Logging is disabled"}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}

// ============================================================================
// Config Preview Section (Shared component for nginx config preview)
// ============================================================================

export function ConfigPreviewSection({
  config,
  isLoading,
  onRefresh,
}: {
  config?: string;
  isLoading: boolean;
  onRefresh: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (config) {
      navigator.clipboard.writeText(config);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Section title="Nginx Configuration" icon={Code} defaultOpen={false}>
      <div className="space-y-3">
        <div className="bg-gray-900 rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <Spinner size="lg" />
            </div>
          ) : (
            <pre className="p-3 text-xs text-green-400 font-mono overflow-auto max-h-[300px]">
              {config || "No configuration generated"}
            </pre>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isLoading && "animate-spin")} />
            Refresh
          </button>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
      </div>
    </Section>
  );
}

// ============================================================================
// Export all components for use
// ============================================================================

export default {
  Section,
  DomainInfoCard,
  SSLSection,
  LogsSection,
  ConfigPreviewSection,
  getSSLStatus,
  getResourceStatus,
};
