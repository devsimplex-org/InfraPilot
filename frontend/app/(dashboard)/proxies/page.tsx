"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Plus,
  Trash2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ExternalLink,
  Code,
  MoreVertical,
  AlertTriangle,
  Container as ContainerIcon,
  Network,
  Check,
  Pencil,
  X,
  Lock,
  Gauge,
} from "lucide-react";
import { api, Container, ContainerNetworkInfo, SecurityHeaders, RateLimit } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";

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

interface Agent {
  id: string;
  name: string;
  status: string;
}

type UpstreamMode = "manual" | "container";

export default function ProxiesPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState<ProxyHost | null>(null);
  const [showConfigModal, setShowConfigModal] = useState<string | null>(null);
  const [configContent, setConfigContent] = useState<string>("");

  // Form state
  const [upstreamMode, setUpstreamMode] = useState<UpstreamMode>("manual");
  const [selectedContainer, setSelectedContainer] = useState<string | null>(null);
  const [containerPort, setContainerPort] = useState<string>("80");
  const [newProxy, setNewProxy] = useState({
    domain: "",
    upstream_target: "",
    force_ssl: true,
    http2_enabled: true,
  });

  // Edit form state
  const [editProxy, setEditProxy] = useState({
    domain: "",
    upstream_target: "",
    force_ssl: true,
    http2_enabled: true,
  });

  // Network warning modal state
  const [showNetworkWarning, setShowNetworkWarning] = useState(false);
  const [networkToAttach, setNetworkToAttach] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [pendingProxySubmit, setPendingProxySubmit] = useState(false);

  // Security headers modal state
  const [showSecurityModal, setShowSecurityModal] = useState<ProxyHost | null>(null);
  const [securityHeaders, setSecurityHeaders] = useState<SecurityHeaders>({
    hsts_enabled: false,
    hsts_max_age: 31536000,
    x_frame_options: "SAMEORIGIN",
    x_content_type_options: true,
    x_xss_protection: true,
    content_security_policy: null,
  });

  // Rate limit modal state
  const [showRateLimitModal, setShowRateLimitModal] = useState<ProxyHost | null>(null);
  const [rateLimits, setRateLimits] = useState<RateLimit[]>([]);
  const [newRateLimit, setNewRateLimit] = useState({
    zone_name: "default",
    requests_per: 100,
    time_window: "1m",
    burst: 50,
    enabled: true,
  });
  const [editingRateLimit, setEditingRateLimit] = useState<RateLimit | null>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch proxies for selected agent
  const { data: proxies, isLoading: proxiesLoading } = useQuery({
    queryKey: ["proxies", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getProxyHosts(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Fetch containers for selected agent (for container mode)
  const { data: containers } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && showCreateModal,
  });

  // Fetch networks for selected container
  const { data: containerNetworks } = useQuery({
    queryKey: ["containerNetworks", selectedAgent, selectedContainer],
    queryFn: () =>
      selectedAgent && selectedContainer
        ? api.getContainerNetworks(selectedAgent, selectedContainer)
        : Promise.resolve([]),
    enabled: !!selectedAgent && !!selectedContainer,
  });

  // Check if nginx is on the container's network
  const { data: nginxNetworkCheck } = useQuery({
    queryKey: ["nginxNetworkCheck", selectedAgent, containerNetworks?.[0]?.network_id],
    queryFn: () =>
      selectedAgent && containerNetworks?.[0]?.network_id
        ? api.checkNginxNetwork(selectedAgent, containerNetworks[0].network_id)
        : Promise.resolve({ connected: true, network_id: "" }),
    enabled: !!selectedAgent && !!containerNetworks?.[0]?.network_id,
  });

  // Attach network mutation
  const attachNetworkMutation = useMutation({
    mutationFn: (networkId: string) =>
      api.attachNginxNetwork(selectedAgent!, networkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["nginxNetworkCheck"] });
      setShowNetworkWarning(false);
      setNetworkToAttach(null);
      // After successful attach, proceed with proxy creation if pending
      if (pendingProxySubmit) {
        createMutation.mutate(newProxy);
        setPendingProxySubmit(false);
      }
    },
    onError: (error) => {
      console.error("Failed to attach network:", error);
    },
  });

  // Create proxy mutation
  const createMutation = useMutation({
    mutationFn: (data: typeof newProxy) =>
      api.createProxyHost(selectedAgent!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxies", selectedAgent] });
      setShowCreateModal(false);
      resetForm();
    },
  });

  // Update proxy mutation
  const updateMutation = useMutation({
    mutationFn: ({ proxyId, data }: { proxyId: string; data: typeof editProxy }) =>
      api.updateProxyHost(selectedAgent!, proxyId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxies", selectedAgent] });
      setShowEditModal(null);
    },
  });

  // Security headers mutation
  const securityHeadersMutation = useMutation({
    mutationFn: ({ proxyId, data }: { proxyId: string; data: Omit<SecurityHeaders, "id" | "proxy_host_id"> }) =>
      api.updateSecurityHeaders(selectedAgent!, proxyId, data),
    onSuccess: () => {
      setShowSecurityModal(null);
    },
  });

  // Open security headers modal and fetch current settings
  const openSecurityModal = async (proxy: ProxyHost) => {
    setShowSecurityModal(proxy);
    try {
      const headers = await api.getSecurityHeaders(selectedAgent!, proxy.id);
      setSecurityHeaders({
        hsts_enabled: headers.hsts_enabled,
        hsts_max_age: headers.hsts_max_age,
        x_frame_options: headers.x_frame_options,
        x_content_type_options: headers.x_content_type_options,
        x_xss_protection: headers.x_xss_protection,
        content_security_policy: headers.content_security_policy ?? null,
      });
    } catch {
      // Use defaults if fetch fails
      setSecurityHeaders({
        hsts_enabled: false,
        hsts_max_age: 31536000,
        x_frame_options: "SAMEORIGIN",
        x_content_type_options: true,
        x_xss_protection: true,
        content_security_policy: null,
      });
    }
  };

  // Handle security headers form submission
  const handleSecuritySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (showSecurityModal) {
      securityHeadersMutation.mutate({
        proxyId: showSecurityModal.id,
        data: securityHeaders,
      });
    }
  };

  // Rate limit mutations
  const createRateLimitMutation = useMutation({
    mutationFn: (data: typeof newRateLimit) =>
      api.createRateLimit(selectedAgent!, showRateLimitModal!.id, data),
    onSuccess: (createdLimit) => {
      setRateLimits([createdLimit, ...rateLimits]);
      setNewRateLimit({
        zone_name: "default",
        requests_per: 100,
        time_window: "1m",
        burst: 50,
        enabled: true,
      });
    },
  });

  const updateRateLimitMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof newRateLimit }) =>
      api.updateRateLimit(selectedAgent!, showRateLimitModal!.id, id, data),
    onSuccess: (updatedLimit) => {
      setRateLimits(rateLimits.map(rl => rl.id === updatedLimit.id ? updatedLimit : rl));
      setEditingRateLimit(null);
    },
  });

  const deleteRateLimitMutation = useMutation({
    mutationFn: (id: string) =>
      api.deleteRateLimit(selectedAgent!, showRateLimitModal!.id, id),
    onSuccess: (_, deletedId) => {
      setRateLimits(rateLimits.filter(rl => rl.id !== deletedId));
    },
  });

  // Open rate limit modal and fetch current limits
  const openRateLimitModal = async (proxy: ProxyHost) => {
    setShowRateLimitModal(proxy);
    try {
      const limits = await api.getRateLimits(selectedAgent!, proxy.id);
      setRateLimits(limits);
    } catch {
      setRateLimits([]);
    }
  };

  // Handle rate limit form submission
  const handleRateLimitSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRateLimit) {
      updateRateLimitMutation.mutate({
        id: editingRateLimit.id,
        data: newRateLimit,
      });
    } else {
      createRateLimitMutation.mutate(newRateLimit);
    }
  };

  // Reset form helper
  const resetForm = () => {
    setNewProxy({
      domain: "",
      upstream_target: "",
      force_ssl: true,
      http2_enabled: true,
    });
    setUpstreamMode("manual");
    setSelectedContainer(null);
    setContainerPort("80");
    setPendingProxySubmit(false);
  };

  // Open edit modal with proxy data
  const openEditModal = (proxy: ProxyHost) => {
    setEditProxy({
      domain: proxy.domain,
      upstream_target: proxy.upstream_target,
      force_ssl: proxy.force_ssl,
      http2_enabled: proxy.http2_enabled,
    });
    setShowEditModal(proxy);
  };

  // Handle edit form submission
  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (showEditModal) {
      updateMutation.mutate({ proxyId: showEditModal.id, data: editProxy });
    }
  };

  // Build upstream target from container selection
  const buildContainerUpstream = (container: Container | undefined) => {
    if (!container) return "";
    // Use container name as DNS name (Docker internal DNS)
    const containerName = container.name.startsWith("/")
      ? container.name.slice(1)
      : container.name;
    return `http://${containerName}:${containerPort}`;
  };

  // Handle form submission with network check
  const handleProxySubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // If in container mode, check network first
    if (upstreamMode === "container" && selectedContainer) {
      const container = containers?.find((c) => c.container_id === selectedContainer);
      const upstream = buildContainerUpstream(container);

      // Update the upstream target
      const proxyData = { ...newProxy, upstream_target: upstream };
      setNewProxy(proxyData);

      // Check if nginx needs to be attached to the network
      if (containerNetworks?.[0] && !nginxNetworkCheck?.connected) {
        setNetworkToAttach({
          id: containerNetworks[0].network_id,
          name: containerNetworks[0].network_name,
        });
        setShowNetworkWarning(true);
        setPendingProxySubmit(true);
        return;
      }

      createMutation.mutate(proxyData);
    } else {
      createMutation.mutate(newProxy);
    }
  };

  // Delete proxy mutation
  const deleteMutation = useMutation({
    mutationFn: (proxyId: string) =>
      api.deleteProxyHost(selectedAgent!, proxyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxies", selectedAgent] });
    },
  });

  // Request SSL mutation
  const sslMutation = useMutation({
    mutationFn: (proxyId: string) =>
      api.requestSSL(selectedAgent!, proxyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxies", selectedAgent] });
    },
  });

  // View config
  const viewConfig = async (proxyId: string) => {
    try {
      const response = await fetch(
        `/api/v1/agents/${selectedAgent}/proxies/${proxyId}/config`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        }
      );
      const data = await response.json();
      setConfigContent(data.config || "No config generated");
      setShowConfigModal(proxyId);
    } catch {
      setConfigContent("Failed to load config");
      setShowConfigModal(proxyId);
    }
  };

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  if (!selectedAgent && activeAgents.length > 0) {
    setSelectedAgent(activeAgents[0].id);
  }

  const getSSLIcon = (proxy: ProxyHost) => {
    if (!proxy.ssl_enabled) {
      return <ShieldAlert className="h-4 w-4 text-yellow-400" />;
    }
    if (proxy.ssl_expires_at) {
      const expiresAt = new Date(proxy.ssl_expires_at);
      const daysUntilExpiry = Math.ceil(
        (expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
      );
      if (daysUntilExpiry < 7) {
        return <ShieldAlert className="h-4 w-4 text-red-400" />;
      }
    }
    return <ShieldCheck className="h-4 w-4 text-green-400" />;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-green-500/10 text-green-400 border-green-500/30";
      case "ssl_pending":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      case "error":
        return "bg-red-500/10 text-red-400 border-red-500/30";
      default:
        return "bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/30";
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Proxy Hosts</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Manage nginx reverse proxy configurations
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          disabled={!selectedAgent}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-gray-900 dark:text-white rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Proxy Host
        </button>
      </div>

      {/* Agent selector */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Select Agent
        </label>
        <select
          value={selectedAgent || ""}
          onChange={(e) => setSelectedAgent(e.target.value || null)}
          className="w-full max-w-xs px-4 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
        >
          <option value="">Select an agent...</option>
          {agents?.map((agent) => (
            <option
              key={agent.id}
              value={agent.id}
              disabled={agent.status !== "active"}
            >
              {agent.name} ({agent.status})
            </option>
          ))}
        </select>
      </div>

      {/* Proxies list */}
      {selectedAgent ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          {proxiesLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
            </div>
          ) : proxies && proxies.length > 0 ? (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-800">
                  <th className="text-left py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Domain
                  </th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Upstream
                  </th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    SSL
                  </th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Status
                  </th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Created
                  </th>
                  <th className="text-right py-4 px-6 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {proxies.map((proxy: ProxyHost) => (
                  <tr
                    key={proxy.id}
                    className="border-b border-gray-200 dark:border-gray-800 last:border-0"
                  >
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-3">
                        <Globe className="h-5 w-5 text-gray-500" />
                        <div>
                          <a
                            href={`http${proxy.ssl_enabled ? "s" : ""}://${proxy.domain}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-gray-900 dark:text-white font-medium hover:text-primary-400 flex items-center gap-1"
                          >
                            {proxy.domain}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                          <div className="text-xs text-gray-500 mt-0.5">
                            {proxy.http2_enabled && "HTTP/2"}{" "}
                            {proxy.force_ssl && "• Force SSL"}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <code className="text-sm text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                        {proxy.upstream_target}
                      </code>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-2">
                        {getSSLIcon(proxy)}
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                          {proxy.ssl_enabled
                            ? proxy.ssl_expires_at
                              ? `Expires ${formatRelativeTime(proxy.ssl_expires_at)}`
                              : "Enabled"
                            : "Not enabled"}
                        </span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span
                        className={cn(
                          "px-2 py-1 text-xs font-medium rounded border",
                          getStatusColor(proxy.status)
                        )}
                      >
                        {proxy.status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-gray-600 dark:text-gray-400 text-sm">
                      {formatRelativeTime(proxy.created_at)}
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEditModal(proxy)}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:bg-gray-800"
                          title="Edit"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => openSecurityModal(proxy)}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:bg-gray-800"
                          title="Security headers"
                        >
                          <Lock className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => openRateLimitModal(proxy)}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:bg-gray-800"
                          title="Rate limits"
                        >
                          <Gauge className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => viewConfig(proxy.id)}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:bg-gray-800"
                          title="View config"
                        >
                          <Code className="h-4 w-4" />
                        </button>
                        {!proxy.ssl_enabled && (
                          <button
                            onClick={() => sslMutation.mutate(proxy.id)}
                            disabled={sslMutation.isPending || proxy.status === "ssl_pending"}
                            className="p-2 text-gray-600 dark:text-gray-400 hover:text-green-500 rounded-lg hover:bg-gray-100 dark:bg-gray-800 disabled:opacity-50"
                            title="Request SSL Certificate"
                          >
                            <ShieldCheck className="h-4 w-4" />
                          </button>
                        )}
                        <button
                          onClick={() => deleteMutation.mutate(proxy.id)}
                          className="p-2 text-gray-600 dark:text-gray-400 hover:text-red-400 rounded-lg hover:bg-gray-100 dark:bg-gray-800"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="py-12 text-center text-gray-500">
              <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No proxy hosts configured</p>
              <p className="text-sm mt-1">
                Click "Add Proxy Host" to create your first reverse proxy
              </p>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 py-12 text-center text-gray-500">
          <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Select an agent to manage proxy hosts</p>
          {activeAgents.length === 0 && (
            <p className="text-sm mt-1">
              No active agents available. Register an agent first.
            </p>
          )}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-md border border-gray-200 dark:border-gray-800">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Add Proxy Host
            </h2>
            <form onSubmit={handleProxySubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Domain
                </label>
                <input
                  type="text"
                  value={newProxy.domain}
                  onChange={(e) =>
                    setNewProxy({ ...newProxy, domain: e.target.value })
                  }
                  required
                  placeholder="example.com"
                  className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                />
              </div>

              {/* Upstream Mode Toggle */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Upstream Type
                </label>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setUpstreamMode("manual")}
                    className={cn(
                      "flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg border transition-colors",
                      upstreamMode === "manual"
                        ? "bg-primary-600/20 border-primary-500 text-primary-400"
                        : "bg-gray-100 dark:bg-gray-800 border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:border-gray-600"
                    )}
                  >
                    <Globe className="h-4 w-4" />
                    Manual URL
                  </button>
                  <button
                    type="button"
                    onClick={() => setUpstreamMode("container")}
                    className={cn(
                      "flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg border transition-colors",
                      upstreamMode === "container"
                        ? "bg-primary-600/20 border-primary-500 text-primary-400"
                        : "bg-gray-100 dark:bg-gray-800 border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:border-gray-600"
                    )}
                  >
                    <ContainerIcon className="h-4 w-4" />
                    Container
                  </button>
                </div>
              </div>

              {/* Manual URL Input */}
              {upstreamMode === "manual" && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Upstream Target
                  </label>
                  <input
                    type="text"
                    value={newProxy.upstream_target}
                    onChange={(e) =>
                      setNewProxy({ ...newProxy, upstream_target: e.target.value })
                    }
                    required
                    placeholder="http://localhost:3000"
                    className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    e.g., http://container:port or http://127.0.0.1:8080
                  </p>
                </div>
              )}

              {/* Container Selector */}
              {upstreamMode === "container" && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Container
                    </label>
                    <select
                      value={selectedContainer || ""}
                      onChange={(e) => setSelectedContainer(e.target.value || null)}
                      required
                      className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    >
                      <option value="">Select a container...</option>
                      {containers
                        ?.filter((c) => c.status === "running")
                        .map((container) => (
                          <option key={container.container_id} value={container.container_id}>
                            {container.name} ({container.image})
                          </option>
                        ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Container Port
                    </label>
                    <input
                      type="text"
                      value={containerPort}
                      onChange={(e) => setContainerPort(e.target.value)}
                      required
                      placeholder="80"
                      className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Internal port the container listens on
                    </p>
                  </div>

                  {/* Network Status Indicator */}
                  {selectedContainer && containerNetworks?.[0] && (
                    <div
                      className={cn(
                        "flex items-center gap-2 px-3 py-2 rounded-lg border text-sm",
                        nginxNetworkCheck?.connected
                          ? "bg-green-500/10 border-green-500/30 text-green-400"
                          : "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                      )}
                    >
                      {nginxNetworkCheck?.connected ? (
                        <>
                          <Check className="h-4 w-4" />
                          <span>Nginx is connected to network: {containerNetworks[0].network_name}</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="h-4 w-4" />
                          <span>Nginx not on network: {containerNetworks[0].network_name}</span>
                        </>
                      )}
                    </div>
                  )}

                  {/* Preview upstream URL */}
                  {selectedContainer && (
                    <div className="text-sm text-gray-500">
                      Upstream will be:{" "}
                      <code className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                        {buildContainerUpstream(
                          containers?.find((c) => c.container_id === selectedContainer)
                        )}
                      </code>
                    </div>
                  )}
                </>
              )}

              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newProxy.force_ssl}
                    onChange={(e) =>
                      setNewProxy({ ...newProxy, force_ssl: e.target.checked })
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Force SSL</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newProxy.http2_enabled}
                    onChange={(e) =>
                      setNewProxy({
                        ...newProxy,
                        http2_enabled: e.target.checked,
                      })
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">HTTP/2</span>
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    resetForm();
                  }}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-800 text-gray-900 dark:text-white rounded-lg transition-colors"
                >
                  {createMutation.isPending ? "Creating..." : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Config Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-2xl border border-gray-200 dark:border-gray-800">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Nginx Configuration
              </h2>
              <button
                onClick={() => setShowConfigModal(null)}
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              >
                &times;
              </button>
            </div>
            <pre className="bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800 rounded-lg p-4 overflow-x-auto text-sm text-gray-700 dark:text-gray-300 font-mono max-h-96 overflow-y-auto">
              {configContent}
            </pre>
            <div className="flex justify-end mt-4">
              <button
                onClick={() => setShowConfigModal(null)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Network Warning Modal */}
      {showNetworkWarning && networkToAttach && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-md border border-gray-200 dark:border-gray-800">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-yellow-500/10 rounded-lg">
                <AlertTriangle className="h-6 w-6 text-yellow-400" />
              </div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Network Attachment Required
              </h2>
            </div>

            <p className="text-gray-700 dark:text-gray-300 mb-4">
              The Nginx container is not connected to the network{" "}
              <code className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded text-primary-400">
                {networkToAttach.name}
              </code>
              . To proxy traffic to this container, Nginx must be attached to
              the same Docker network.
            </p>

            <div className="bg-gray-100 dark:bg-gray-800/50 border border-gray-300 dark:border-gray-700 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                <Network className="h-4 w-4" />
                <span>Network ID:</span>
                <code className="text-gray-700 dark:text-gray-300">{networkToAttach.id.slice(0, 12)}</code>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  setShowNetworkWarning(false);
                  setNetworkToAttach(null);
                  setPendingProxySubmit(false);
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => attachNetworkMutation.mutate(networkToAttach.id)}
                disabled={attachNetworkMutation.isPending}
                className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-800 text-gray-900 dark:text-white rounded-lg transition-colors flex items-center gap-2"
              >
                {attachNetworkMutation.isPending ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                    Attaching...
                  </>
                ) : (
                  <>
                    <Network className="h-4 w-4" />
                    Attach Nginx to Network
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-md border border-gray-200 dark:border-gray-800">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Edit Proxy Host</h2>
              <button
                onClick={() => setShowEditModal(null)}
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Domain
                </label>
                <input
                  type="text"
                  value={editProxy.domain}
                  onChange={(e) =>
                    setEditProxy({ ...editProxy, domain: e.target.value })
                  }
                  required
                  placeholder="example.com"
                  className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Upstream Target
                </label>
                <input
                  type="text"
                  value={editProxy.upstream_target}
                  onChange={(e) =>
                    setEditProxy({ ...editProxy, upstream_target: e.target.value })
                  }
                  required
                  placeholder="http://localhost:3000"
                  className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                />
                <p className="text-xs text-gray-500 mt-1">
                  e.g., http://container:port or http://127.0.0.1:8080
                </p>
              </div>

              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editProxy.force_ssl}
                    onChange={(e) =>
                      setEditProxy({ ...editProxy, force_ssl: e.target.checked })
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Force SSL</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editProxy.http2_enabled}
                    onChange={(e) =>
                      setEditProxy({
                        ...editProxy,
                        http2_enabled: e.target.checked,
                      })
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">HTTP/2</span>
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowEditModal(null)}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updateMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-800 text-gray-900 dark:text-white rounded-lg transition-colors"
                >
                  {updateMutation.isPending ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Security Headers Modal */}
      {showSecurityModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-lg border border-gray-200 dark:border-gray-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">Security Headers</h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{showSecurityModal.domain}</p>
              </div>
              <button
                onClick={() => setShowSecurityModal(null)}
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleSecuritySubmit} className="space-y-4">
              {/* HSTS */}
              <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white">Strict-Transport-Security (HSTS)</h3>
                    <p className="text-xs text-gray-500 mt-1">Force browsers to use HTTPS</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={securityHeaders.hsts_enabled}
                      onChange={(e) =>
                        setSecurityHeaders({ ...securityHeaders, hsts_enabled: e.target.checked })
                      }
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                  </label>
                </div>
                {securityHeaders.hsts_enabled && (
                  <div className="mt-3">
                    <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Max Age (seconds)</label>
                    <input
                      type="number"
                      value={securityHeaders.hsts_max_age}
                      onChange={(e) =>
                        setSecurityHeaders({ ...securityHeaders, hsts_max_age: parseInt(e.target.value) || 31536000 })
                      }
                      className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                    />
                    <p className="text-xs text-gray-500 mt-1">31536000 = 1 year (recommended)</p>
                  </div>
                )}
              </div>

              {/* X-Frame-Options */}
              <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">X-Frame-Options</h3>
                  <p className="text-xs text-gray-500 mt-1">Control iframe embedding</p>
                </div>
                <select
                  value={securityHeaders.x_frame_options}
                  onChange={(e) =>
                    setSecurityHeaders({ ...securityHeaders, x_frame_options: e.target.value })
                  }
                  className="mt-2 w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                >
                  <option value="">Disabled</option>
                  <option value="DENY">DENY - Never allow framing</option>
                  <option value="SAMEORIGIN">SAMEORIGIN - Only same origin</option>
                </select>
              </div>

              {/* X-Content-Type-Options */}
              <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white">X-Content-Type-Options</h3>
                    <p className="text-xs text-gray-500 mt-1">Prevent MIME type sniffing</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={securityHeaders.x_content_type_options}
                      onChange={(e) =>
                        setSecurityHeaders({ ...securityHeaders, x_content_type_options: e.target.checked })
                      }
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                  </label>
                </div>
              </div>

              {/* X-XSS-Protection */}
              <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white">X-XSS-Protection</h3>
                    <p className="text-xs text-gray-500 mt-1">Enable XSS filter (legacy browsers)</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={securityHeaders.x_xss_protection}
                      onChange={(e) =>
                        setSecurityHeaders({ ...securityHeaders, x_xss_protection: e.target.checked })
                      }
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                  </label>
                </div>
              </div>

              {/* Content-Security-Policy */}
              <div className="border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">Content-Security-Policy</h3>
                  <p className="text-xs text-gray-500 mt-1">Control resource loading (advanced)</p>
                </div>
                <textarea
                  value={securityHeaders.content_security_policy || ""}
                  onChange={(e) =>
                    setSecurityHeaders({
                      ...securityHeaders,
                      content_security_policy: e.target.value || null,
                    })
                  }
                  placeholder="e.g., default-src 'self'; script-src 'self'"
                  rows={2}
                  className="mt-2 w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowSecurityModal(null)}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={securityHeadersMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-800 text-gray-900 dark:text-white rounded-lg transition-colors"
                >
                  {securityHeadersMutation.isPending ? "Saving..." : "Save Headers"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rate Limit Modal */}
      {showRateLimitModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-lg border border-gray-200 dark:border-gray-800 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">Rate Limits</h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{showRateLimitModal.domain}</p>
              </div>
              <button
                onClick={() => {
                  setShowRateLimitModal(null);
                  setEditingRateLimit(null);
                }}
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Existing rate limits */}
            {rateLimits.length > 0 && (
              <div className="mb-6 space-y-2">
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">Current Limits</h3>
                {rateLimits.map((rl) => (
                  <div
                    key={rl.id}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-lg border",
                      editingRateLimit?.id === rl.id
                        ? "border-primary-500 bg-primary-500/5"
                        : "border-gray-300 dark:border-gray-700"
                    )}
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900 dark:text-white">{rl.zone_name}</span>
                        {!rl.enabled && (
                          <span className="px-1.5 py-0.5 text-xs bg-gray-500/20 text-gray-400 rounded">Disabled</span>
                        )}
                      </div>
                      <p className="text-sm text-gray-500">
                        {rl.requests_per} requests / {rl.time_window} (burst: {rl.burst})
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
                        className="p-1.5 text-gray-500 hover:text-gray-900 dark:hover:text-white rounded"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteRateLimitMutation.mutate(rl.id)}
                        className="p-1.5 text-gray-500 hover:text-red-400 rounded"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Add/Edit form */}
            <form onSubmit={handleRateLimitSubmit} className="space-y-4">
              <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {editingRateLimit ? "Edit Rate Limit" : "Add Rate Limit"}
              </h3>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Zone Name
                  </label>
                  <input
                    type="text"
                    value={newRateLimit.zone_name}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, zone_name: e.target.value })}
                    placeholder="default"
                    required
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Time Window
                  </label>
                  <select
                    value={newRateLimit.time_window}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, time_window: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                  >
                    <option value="1s">1 second</option>
                    <option value="10s">10 seconds</option>
                    <option value="1m">1 minute</option>
                    <option value="5m">5 minutes</option>
                    <option value="10m">10 minutes</option>
                    <option value="1h">1 hour</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Requests Per Window
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={newRateLimit.requests_per}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, requests_per: parseInt(e.target.value) || 1 })}
                    required
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Burst Allowance
                  </label>
                  <input
                    type="number"
                    min="0"
                    value={newRateLimit.burst}
                    onChange={(e) => setNewRateLimit({ ...newRateLimit, burst: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white text-sm"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="rate-limit-enabled"
                  checked={newRateLimit.enabled}
                  onChange={(e) => setNewRateLimit({ ...newRateLimit, enabled: e.target.checked })}
                  className="w-4 h-4 text-primary-600 focus:ring-primary-500 rounded"
                />
                <label htmlFor="rate-limit-enabled" className="text-sm text-gray-700 dark:text-gray-300">
                  Enable this rate limit
                </label>
              </div>

              <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3 text-xs text-gray-600 dark:text-gray-400">
                <p className="font-medium text-gray-700 dark:text-gray-300 mb-1">How rate limiting works:</p>
                <ul className="list-disc list-inside space-y-1">
                  <li>Limits are applied per client IP address</li>
                  <li>Burst allows temporary spikes above the limit</li>
                  <li>Excess requests return HTTP 429 (Too Many Requests)</li>
                </ul>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                {editingRateLimit && (
                  <button
                    type="button"
                    onClick={() => {
                      setEditingRateLimit(null);
                      setNewRateLimit({
                        zone_name: "default",
                        requests_per: 100,
                        time_window: "1m",
                        burst: 50,
                        enabled: true,
                      });
                    }}
                    className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                  >
                    Cancel Edit
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowRateLimitModal(null)}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={createRateLimitMutation.isPending || updateRateLimitMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-800 text-white rounded-lg transition-colors"
                >
                  {createRateLimitMutation.isPending || updateRateLimitMutation.isPending
                    ? "Saving..."
                    : editingRateLimit
                    ? "Update Limit"
                    : "Add Limit"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
