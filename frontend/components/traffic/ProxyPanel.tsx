"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  Shield,
  ShieldCheck,
  ExternalLink,
  Trash2,
  Pencil,
  Code,
  FileText,
  RefreshCw,
  Check,
  AlertTriangle,
  Copy,
  ArrowRight,
  Settings,
  Activity,
} from "lucide-react";
import { api, ProxyHost, SecurityHeaders, RateLimit } from "@/lib/api";
import { useTraffic, getSSLStatus, getProxyStatus } from "@/lib/traffic-context";
import { formatRelativeTime, cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Spinner } from "@/components/ui/Spinner";
import { SSLWizard } from "@/components/ssl-wizard";
import { ProxyConfigForm } from "@/components/ProxyConfigForm";
import {
  Button,
  Tabs,
  Input,
} from "@/components/ui/page-layout";

type PanelTab = "details" | "security" | "ratelimits" | "config" | "logs";

export function ProxyPanel() {
  const queryClient = useQueryClient();
  const { selectedAgent, proxyPanelId, closeProxyPanel, forceDelete, setForceDelete } = useTraffic();

  // Local state
  const [tab, setTab] = useState<PanelTab>("details");
  const [isEditing, setIsEditing] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [logsTail, setLogsTail] = useState(100);

  // SSL Wizard state
  const [showSSLWizard, setShowSSLWizard] = useState(false);

  // Edit form state
  const [editProxy, setEditProxy] = useState({
    domain: "",
    upstream_target: "",
    force_ssl: true,
    http2_enabled: true,
    include_www: false,
  });

  // Security headers state
  const [securityHeaders, setSecurityHeaders] = useState<SecurityHeaders>({
    hsts_enabled: false,
    hsts_max_age: 31536000,
    x_frame_options: "SAMEORIGIN",
    x_content_type_options: true,
    x_xss_protection: true,
    content_security_policy: null,
  });

  // Rate limits state
  const [rateLimits, setRateLimits] = useState<RateLimit[]>([]);
  const [newRateLimit, setNewRateLimit] = useState({
    zone_name: "default",
    requests_per: 100,
    time_window: "1m",
    burst: 50,
    enabled: true,
  });
  const [editingRateLimit, setEditingRateLimit] = useState<RateLimit | null>(null);

  // Reset tab when panel opens
  useEffect(() => {
    if (proxyPanelId) {
      setTab("details");
      setIsEditing(false);
    }
  }, [proxyPanelId]);

  // Fetch proxy details
  const { data: proxy, isLoading: proxyLoading } = useQuery({
    queryKey: ["proxy-detail", selectedAgent, proxyPanelId],
    queryFn: async () => {
      if (!selectedAgent || !proxyPanelId) return null;
      const proxies = await api.getProxyHosts(selectedAgent);
      return proxies.find((p: ProxyHost) => p.id === proxyPanelId) || null;
    },
    enabled: !!selectedAgent && !!proxyPanelId,
  });

  // Fetch nginx config
  const { data: configData, isLoading: configLoading, refetch: refetchConfig } = useQuery({
    queryKey: ["proxy-config", selectedAgent, proxyPanelId],
    queryFn: async () => {
      if (!selectedAgent || !proxyPanelId) return null;
      const response = await fetch(`/api/v1/agents/${selectedAgent}/proxies/${proxyPanelId}/config`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
      });
      return response.json();
    },
    enabled: !!selectedAgent && !!proxyPanelId && tab === "config",
  });

  // Fetch proxy logs
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["proxy-logs", selectedAgent, proxyPanelId, logsTail],
    queryFn: async () => {
      if (!selectedAgent || !proxyPanelId || !proxy?.domain) return null;
      const response = await fetch(
        `/api/v1/agents/${selectedAgent}/nginx/logs?domain=${encodeURIComponent(proxy.domain)}&tail=${logsTail}`,
        {
          headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
        }
      );
      return response.json();
    },
    enabled: !!selectedAgent && !!proxyPanelId && !!proxy?.domain && tab === "logs",
  });

  // Load proxy details when selected
  useEffect(() => {
    if (proxy && selectedAgent) {
      setEditProxy({
        domain: proxy.domain,
        upstream_target: proxy.upstream_target,
        force_ssl: proxy.force_ssl,
        http2_enabled: proxy.http2_enabled,
        include_www: proxy.include_www,
      });

      // Load security headers
      api.getSecurityHeaders(selectedAgent, proxy.id)
        .then((headers) => {
          setSecurityHeaders({
            hsts_enabled: headers.hsts_enabled,
            hsts_max_age: headers.hsts_max_age,
            x_frame_options: headers.x_frame_options,
            x_content_type_options: headers.x_content_type_options,
            x_xss_protection: headers.x_xss_protection,
            content_security_policy: headers.content_security_policy ?? null,
          });
        })
        .catch(() => {
          setSecurityHeaders({
            hsts_enabled: false,
            hsts_max_age: 31536000,
            x_frame_options: "SAMEORIGIN",
            x_content_type_options: true,
            x_xss_protection: true,
            content_security_policy: null,
          });
        });

      // Load rate limits
      api.getRateLimits(selectedAgent, proxy.id)
        .then(setRateLimits)
        .catch(() => setRateLimits([]));
    }
  }, [proxy, selectedAgent]);

  // Mutations
  const invalidateProxies = () => {
    queryClient.invalidateQueries({ queryKey: ["proxies", selectedAgent] });
    queryClient.invalidateQueries({ queryKey: ["proxy-detail", selectedAgent, proxyPanelId] });
  };

  const updateMutation = useMutation({
    mutationFn: ({ proxyId, data }: { proxyId: string; data: typeof editProxy }) =>
      api.updateProxyHost(selectedAgent!, proxyId, data),
    onSuccess: () => {
      invalidateProxies();
      setIsEditing(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (proxyId: string) => api.deleteProxyHost(selectedAgent!, proxyId),
    onSuccess: () => {
      invalidateProxies();
      setShowDeleteConfirm(false);
      closeProxyPanel();
    },
  });

  const sslMutation = useMutation({
    mutationFn: (proxyId: string) => api.requestSSL(selectedAgent!, proxyId),
    onSuccess: invalidateProxies,
  });

  const securityHeadersMutation = useMutation({
    mutationFn: ({ proxyId, data }: { proxyId: string; data: Omit<SecurityHeaders, "id" | "proxy_host_id"> }) =>
      api.updateSecurityHeaders(selectedAgent!, proxyId, data),
    onSuccess: invalidateProxies,
  });

  const createRateLimitMutation = useMutation({
    mutationFn: (data: typeof newRateLimit) =>
      api.createRateLimit(selectedAgent!, proxy!.id, data),
    onSuccess: (createdLimit) => {
      setRateLimits([createdLimit, ...rateLimits]);
      setNewRateLimit({ zone_name: "default", requests_per: 100, time_window: "1m", burst: 50, enabled: true });
    },
  });

  const updateRateLimitMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof newRateLimit }) =>
      api.updateRateLimit(selectedAgent!, proxy!.id, id, data),
    onSuccess: (updatedLimit) => {
      setRateLimits(rateLimits.map((rl) => (rl.id === updatedLimit.id ? updatedLimit : rl)));
      setEditingRateLimit(null);
    },
  });

  const deleteRateLimitMutation = useMutation({
    mutationFn: (id: string) => api.deleteRateLimit(selectedAgent!, proxy!.id, id),
    onSuccess: (_, deletedId) => {
      setRateLimits(rateLimits.filter((rl) => rl.id !== deletedId));
    },
  });

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const panelTabs = [
    { id: "details", label: "Details", icon: Globe },
    { id: "security", label: "Security", icon: Shield },
    { id: "ratelimits", label: "Rate Limits", icon: Activity },
    { id: "config", label: "Config", icon: Code },
    { id: "logs", label: "Logs", icon: FileText },
  ] as { id: PanelTab; label: string; icon: any }[];

  // Render tab content
  const renderTabContent = () => {
    if (!proxy) return null;

    switch (tab) {
      case "security":
        return (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              securityHeadersMutation.mutate({ proxyId: proxy.id, data: securityHeaders });
            }}
            className="space-y-4"
          >
            {/* HSTS */}
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">HSTS</h3>
                  <p className="text-xs text-gray-500 mt-0.5">Force HTTPS connections</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={securityHeaders.hsts_enabled}
                    onChange={(e) => setSecurityHeaders({ ...securityHeaders, hsts_enabled: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-5 bg-gray-300 dark:bg-gray-600 rounded-full peer peer-checked:bg-primary-600 peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all"></div>
                </label>
              </div>
              {securityHeaders.hsts_enabled && (
                <div className="mt-3">
                  <label className="block text-xs text-gray-500 mb-1">Max Age (seconds)</label>
                  <input
                    type="number"
                    value={securityHeaders.hsts_max_age}
                    onChange={(e) => setSecurityHeaders({ ...securityHeaders, hsts_max_age: parseInt(e.target.value) || 31536000 })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
                  />
                </div>
              )}
            </div>

            {/* X-Frame-Options */}
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">X-Frame-Options</h3>
              <select
                value={securityHeaders.x_frame_options}
                onChange={(e) => setSecurityHeaders({ ...securityHeaders, x_frame_options: e.target.value })}
                className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
              >
                <option value="">Disabled</option>
                <option value="DENY">DENY</option>
                <option value="SAMEORIGIN">SAMEORIGIN</option>
              </select>
            </div>

            {/* Toggle options */}
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">X-Content-Type-Options</p>
                  <p className="text-xs text-gray-500">Prevent MIME sniffing</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={securityHeaders.x_content_type_options}
                    onChange={(e) => setSecurityHeaders({ ...securityHeaders, x_content_type_options: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-5 bg-gray-300 dark:bg-gray-600 rounded-full peer peer-checked:bg-primary-600 peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all"></div>
                </label>
              </div>

              <div className="flex items-center justify-between p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">X-XSS-Protection</p>
                  <p className="text-xs text-gray-500">XSS filter (legacy)</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={securityHeaders.x_xss_protection}
                    onChange={(e) => setSecurityHeaders({ ...securityHeaders, x_xss_protection: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-5 bg-gray-300 dark:bg-gray-600 rounded-full peer peer-checked:bg-primary-600 peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all"></div>
                </label>
              </div>
            </div>

            {/* CSP */}
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Content-Security-Policy</h3>
              <textarea
                value={securityHeaders.content_security_policy || ""}
                onChange={(e) => setSecurityHeaders({ ...securityHeaders, content_security_policy: e.target.value || null })}
                placeholder="e.g., default-src 'self'"
                rows={2}
                className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm font-mono"
              />
            </div>

            <Button
              type="submit"
              variant="primary"
              disabled={securityHeadersMutation.isPending}
              className="w-full"
            >
              {securityHeadersMutation.isPending ? "Saving..." : "Save Security Headers"}
            </Button>
          </form>
        );

      case "ratelimits":
        return (
          <div className="space-y-4">
            {/* Existing limits */}
            {rateLimits.length > 0 && (
              <div className="space-y-2">
                {rateLimits.map((rl) => (
                  <div
                    key={rl.id}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-lg border",
                      editingRateLimit?.id === rl.id
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700"
                    )}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900 dark:text-white text-sm">{rl.zone_name}</span>
                        {!rl.enabled && <Badge size="sm">Disabled</Badge>}
                      </div>
                      <p className="text-xs text-gray-500">
                        {rl.requests_per} req / {rl.time_window} (burst: {rl.burst})
                      </p>
                    </div>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => {
                          setEditingRateLimit(rl);
                          setNewRateLimit({
                            zone_name: rl.zone_name,
                            requests_per: rl.requests_per,
                            time_window: rl.time_window,
                            burst: rl.burst,
                            enabled: rl.enabled,
                          });
                        }}
                        className="p-1.5 text-gray-400 hover:text-gray-900 dark:hover:text-white rounded"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => deleteRateLimitMutation.mutate(rl.id)}
                        className="p-1.5 text-gray-400 hover:text-red-500 rounded"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Add/Edit form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (editingRateLimit) {
                  updateRateLimitMutation.mutate({ id: editingRateLimit.id, data: newRateLimit });
                } else {
                  createRateLimitMutation.mutate(newRateLimit);
                }
              }}
              className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-3"
            >
              <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                {editingRateLimit ? "Edit Rate Limit" : "Add Rate Limit"}
              </h4>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Zone Name</label>
                  <input
                    type="text"
                    value={newRateLimit.zone_name}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, zone_name: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Time Window</label>
                  <select
                    value={newRateLimit.time_window}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, time_window: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
                  >
                    <option value="1s">1 second</option>
                    <option value="10s">10 seconds</option>
                    <option value="1m">1 minute</option>
                    <option value="5m">5 minutes</option>
                    <option value="1h">1 hour</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Requests/Window</label>
                  <input
                    type="number"
                    value={newRateLimit.requests_per}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, requests_per: parseInt(e.target.value) || 1 })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Burst</label>
                  <input
                    type="number"
                    value={newRateLimit.burst}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, burst: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="rate-limit-enabled"
                  checked={newRateLimit.enabled}
                  onChange={(e) => setNewRateLimit({ ...newRateLimit, enabled: e.target.checked })}
                  className="w-4 h-4 rounded"
                />
                <label htmlFor="rate-limit-enabled" className="text-sm text-gray-700 dark:text-gray-300">
                  Enable this limit
                </label>
              </div>

              <div className="flex gap-2">
                {editingRateLimit && (
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      setEditingRateLimit(null);
                      setNewRateLimit({ zone_name: "default", requests_per: 100, time_window: "1m", burst: 50, enabled: true });
                    }}
                  >
                    Cancel
                  </Button>
                )}
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={createRateLimitMutation.isPending || updateRateLimitMutation.isPending}
                >
                  {editingRateLimit ? "Update" : "Add"}
                </Button>
              </div>
            </form>
          </div>
        );

      case "config":
        return (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">Nginx Configuration</h3>
              <button
                onClick={() => refetchConfig()}
                className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
              >
                <RefreshCw className={cn("h-4 w-4 text-gray-500", configLoading && "animate-spin")} />
              </button>
            </div>
            <div className="bg-gray-900 rounded-lg overflow-hidden">
              {configLoading ? (
                <div className="flex items-center justify-center h-48">
                  <Spinner size="lg" />
                </div>
              ) : (
                <pre className="p-4 text-xs text-green-400 font-mono overflow-auto max-h-[500px]">
                  {configData?.config || "No configuration generated"}
                </pre>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(configData?.config || "", "config")}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
              >
                {copied === "config" ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                {copied === "config" ? "Copied!" : "Copy Config"}
              </button>
            </div>
          </div>
        );

      case "logs":
        return (
          <div className="flex flex-col -mx-6 h-[calc(100vh-300px)]">
            <div className="flex items-center justify-between px-6 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Domain:</span>
                <code className="text-xs text-green-400">{proxy.domain}</code>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={logsTail}
                  onChange={(e) => setLogsTail(Number(e.target.value))}
                  className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs text-gray-200"
                >
                  <option value={50}>50 lines</option>
                  <option value={100}>100 lines</option>
                  <option value={500}>500 lines</option>
                  <option value={1000}>1000 lines</option>
                </select>
                <button onClick={() => refetchLogs()} className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                  <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                </button>
              </div>
            </div>
            <div className="flex-1 bg-gray-900 overflow-y-auto min-h-0 px-6">
              {logsLoading ? (
                <div className="flex items-center justify-center h-32">
                  <Spinner size="lg" />
                </div>
              ) : logsData?.logs ? (
                <div className="font-mono text-xs py-2">
                  {logsData.logs
                    .split("\n")
                    .filter((l: string) => l.trim())
                    .map((line: string, idx: number) => (
                      <div key={idx} className="text-gray-300 hover:bg-gray-800/50 py-0.5 px-3 -mx-3">
                        {line}
                      </div>
                    ))}
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8 text-sm">
                  No logs available for this domain
                </div>
              )}
            </div>
          </div>
        );

      default:
        return (
          <>
            {isEditing ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  updateMutation.mutate({ proxyId: proxy.id, data: editProxy });
                }}
                className="space-y-4"
              >
                <Input
                  label="Domain"
                  value={editProxy.domain}
                  onChange={(e) => setEditProxy({ ...editProxy, domain: e.target.value })}
                  required
                />
                <Input
                  label="Upstream Target"
                  value={editProxy.upstream_target}
                  onChange={(e) => setEditProxy({ ...editProxy, upstream_target: e.target.value })}
                  required
                />
                <div className="flex flex-wrap items-center gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={editProxy.force_ssl}
                      onChange={(e) => setEditProxy({ ...editProxy, force_ssl: e.target.checked })}
                      className="w-4 h-4 rounded"
                    />
                    <span className="text-sm">Force SSL</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={editProxy.http2_enabled}
                      onChange={(e) => setEditProxy({ ...editProxy, http2_enabled: e.target.checked })}
                      className="w-4 h-4 rounded"
                    />
                    <span className="text-sm">HTTP/2</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={editProxy.include_www}
                      onChange={(e) => setEditProxy({ ...editProxy, include_www: e.target.checked })}
                      className="w-4 h-4 rounded"
                    />
                    <span className="text-sm">Include www</span>
                  </label>
                </div>
                <div className="flex gap-2">
                  <Button type="button" variant="secondary" onClick={() => setIsEditing(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" variant="primary" disabled={updateMutation.isPending}>
                    {updateMutation.isPending ? "Saving..." : "Save"}
                  </Button>
                </div>
              </form>
            ) : (
              <div className="space-y-6">
                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="secondary" size="sm" icon={Pencil} onClick={() => setIsEditing(true)}>
                      Edit
                    </Button>
                    {!proxy.ssl_enabled && proxy.status !== "ssl_pending" && (
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={ShieldCheck}
                        onClick={() => setShowSSLWizard(true)}
                      >
                        Setup SSL
                      </Button>
                    )}
                    <Button
                      variant="danger"
                      size="sm"
                      icon={Trash2}
                      onClick={() => setShowDeleteConfirm(true)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>

                {/* Proxy Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Proxy Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Domain</span>
                      <a
                        href={`http${proxy.ssl_enabled ? "s" : ""}://${proxy.domain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary-600 hover:text-primary-500 flex items-center gap-1"
                      >
                        {proxy.domain}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                      <StatusIndicator status={getProxyStatus(proxy.status)} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                      <span className="text-sm text-gray-900 dark:text-white">{formatRelativeTime(proxy.created_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Proxy ID</span>
                      <div className="flex items-center gap-1">
                        <code className="text-xs text-gray-600 dark:text-gray-400">{proxy.id.slice(0, 8)}</code>
                        <button
                          onClick={() => handleCopy(proxy.id, "proxy-id")}
                          className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                        >
                          {copied === "proxy-id" ? (
                            <Check className="h-3 w-3 text-green-500" />
                          ) : (
                            <Copy className="h-3 w-3 text-gray-400" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Target / Upstream */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    {proxy.proxy_type === "redirect" ? "Redirect Target" : "Upstream"}
                  </h3>
                  {proxy.proxy_type === "redirect" ? (
                    <div className="space-y-2">
                      <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-3 border border-purple-200 dark:border-purple-800">
                        <div className="flex items-center gap-2 text-purple-700 dark:text-purple-400">
                          <ArrowRight className="h-4 w-4" />
                          <code className="text-sm font-mono break-all">
                            {proxy.redirect_url}
                          </code>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge color="purple" size="sm">
                          {proxy.redirect_code === 301 ? "301 Permanent" :
                           proxy.redirect_code === 302 ? "302 Temporary" :
                           proxy.redirect_code === 307 ? "307 Temporary" :
                           proxy.redirect_code === 308 ? "308 Permanent" :
                           `${proxy.redirect_code}`}
                        </Badge>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                      <code className="text-sm text-gray-900 dark:text-white font-mono break-all">
                        {proxy.upstream_target}
                      </code>
                    </div>
                  )}
                </div>

                {/* SSL / TLS */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">SSL / TLS</h3>
                  <div className="space-y-3">
                    <StatusIndicator
                      status={getSSLStatus(proxy)}
                      label={proxy.ssl_enabled
                        ? proxy.ssl_expires_at
                          ? `Expires ${formatRelativeTime(proxy.ssl_expires_at)}`
                          : "SSL Enabled"
                        : proxy.status === "ssl_pending"
                        ? "SSL Certificate Pending"
                        : "SSL Not Enabled"}
                    />
                    <div className="flex flex-wrap gap-2">
                      {proxy.force_ssl && <Badge>Force SSL</Badge>}
                      {proxy.http2_enabled && <Badge>HTTP/2</Badge>}
                      {proxy.include_www && <Badge>Include www</Badge>}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        );
    }
  };

  return (
    <>
      <SlideOver isOpen={!!proxyPanelId} onClose={closeProxyPanel} size="lg">
        {proxyLoading ? (
          <div className="flex items-center justify-center h-64">
            <Spinner.Logo size="lg" />
          </div>
        ) : proxy ? (
          <>
            <SlideOver.Header onClose={closeProxyPanel}>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{proxy.domain}</h2>
                  {proxy.is_system_proxy && <Badge color="blue" size="sm">InfraPilot</Badge>}
                  {proxy.proxy_type === "redirect" && <Badge color="purple" size="sm">Redirect</Badge>}
                  <StatusIndicator status={getSSLStatus(proxy)} showLabel={false} size="sm" />
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {proxy.proxy_type === "redirect" ? proxy.redirect_url : proxy.upstream_target}
                </p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-1 mb-6 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
                {panelTabs.map((t) => {
                  const Icon = t.icon;
                  return (
                    <button
                      key={t.id}
                      onClick={() => setTab(t.id)}
                      className={cn(
                        "flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap",
                        tab === t.id
                          ? "border-primary-600 text-primary-600 dark:text-primary-400"
                          : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                      )}
                    >
                      <Icon className="h-4 w-4" />
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* Tab content */}
              {renderTabContent()}
            </SlideOver.Body>
          </>
        ) : (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <p className="text-sm">Proxy not found</p>
          </div>
        )}
      </SlideOver>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteConfirm && !!proxy}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={() => {
          if (proxy) {
            deleteMutation.mutate(proxy.id);
          }
        }}
        title="Delete Proxy"
        message={`Are you sure you want to delete the proxy for "${proxy?.domain}"?\n\nThis will remove the nginx configuration and SSL certificates.`}
        confirmText="Delete Proxy"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
      />

      {/* SSL Wizard */}
      {proxy && (
        <SSLWizard
          domain={proxy.domain}
          open={showSSLWizard}
          onOpenChange={setShowSSLWizard}
          agentId={selectedAgent || undefined}
          proxyId={proxy.id}
          includeWWW={proxy.include_www}
          onSuccess={() => {
            invalidateProxies();
          }}
        />
      )}
    </>
  );
}
