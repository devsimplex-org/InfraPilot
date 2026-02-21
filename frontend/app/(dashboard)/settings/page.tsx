"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings as SettingsIcon,
  Server,
  Shield,
  Network,
  Check,
  AlertTriangle,
  ExternalLink,
  Smartphone,
  Copy,
  Key,
  X,
  Globe,
  Lock,
  Trash2,
  Loader2,
  RefreshCw,
  Crown,
  Sparkles,
  Clock,
  Plus,
  Users,
  KeyRound,
  Building2,
  FileText,
  Download,
  Play,
  Archive,
  FileCheck,
  Send,
  ShieldCheck,
} from "lucide-react";
import { api, Agent, User, MFASetupResponse, InfraPilotDomainSettings, LicenseInfo, LicenseSettingsResponse, SSOProvider, SSOProviderType, CreateSSOProviderRequest, AuditConfig, AuditExport, ComplianceReport, DefaultPage, DefaultPageType } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/lib/auth";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";

type ProxyMode = "managed" | "external";

interface ProxySettings {
  proxy_mode: ProxyMode;
  nginx_container_id?: string;
  nginx_container_name?: string;
  external_proxy_type?: string;
  external_proxy_notes?: string;
}

// InfraPilot Domain Section
function InfraPilotDomainSection() {
  const queryClient = useQueryClient();
  const [domain, setDomain] = useState("");
  const [sslEnabled, setSSLEnabled] = useState(true);
  const [forceSSL, setForceSSL] = useState(true);
  const [http2Enabled, setHTTP2Enabled] = useState(true);
  const [hasChanges, setHasChanges] = useState(false);
  const [showDelete, setShowDelete] = useState(false);

  // Fetch current domain settings
  const { data: domainSettings, isLoading } = useQuery({
    queryKey: ["infrapilotDomain"],
    queryFn: () => api.getInfraPilotDomain(),
  });

  // Update form when data loads
  useEffect(() => {
    if (domainSettings?.domain) {
      setDomain(domainSettings.domain);
      setSSLEnabled(domainSettings.ssl_enabled);
      setForceSSL(domainSettings.force_ssl);
      setHTTP2Enabled(domainSettings.http2_enabled);
    }
  }, [domainSettings]);

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: () =>
      api.updateInfraPilotDomain({
        domain,
        ssl_enabled: sslEnabled,
        force_ssl: forceSSL,
        http2_enabled: http2Enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["infrapilotDomain"] });
      setHasChanges(false);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteInfraPilotDomain(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["infrapilotDomain"] });
      setDomain("");
      setSSLEnabled(true);
      setForceSSL(true);
      setHTTP2Enabled(true);
      setShowDelete(false);
      setHasChanges(false);
    },
  });

  const handleDomainChange = (value: string) => {
    setDomain(value);
    setHasChanges(true);
  };

  const isConfigured = domainSettings?.domain && domainSettings.domain.length > 0;

  return (
    <Card>
      <Card.Header>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Globe className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">InfraPilot Domain</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Configure a custom domain to access InfraPilot
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-6">
            {/* Current status */}
            {isConfigured && (
              <div className="flex items-center justify-between p-4 bg-green-500/5 border border-green-500/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {domainSettings.domain}
                    </p>
                    <p className="text-sm text-gray-500">
                      {domainSettings.ssl_enabled ? "HTTPS enabled" : "HTTP only"}
                    </p>
                  </div>
                </div>
                <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
                  Active
                </Badge>
              </div>
            )}

            {/* Domain input */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Domain Name
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => handleDomainChange(e.target.value)}
                placeholder="infrapilot.example.com"
                className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
              <p className="mt-1.5 text-xs text-gray-500">
                Make sure DNS is pointed to this server before enabling SSL
              </p>
            </div>

            {/* SSL Options */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Lock className="h-4 w-4 text-gray-500" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">Enable SSL/HTTPS</p>
                    <p className="text-xs text-gray-500">Automatically provision Let's Encrypt certificate</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSSLEnabled(!sslEnabled);
                    setHasChanges(true);
                  }}
                  className={cn(
                    "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                    sslEnabled ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                      sslEnabled ? "translate-x-6" : "translate-x-1"
                    )}
                  />
                </button>
              </div>

              {sslEnabled && (
                <>
                  <div className="flex items-center justify-between pl-7">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">Force HTTPS</p>
                      <p className="text-xs text-gray-500">Redirect all HTTP requests to HTTPS</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setForceSSL(!forceSSL);
                        setHasChanges(true);
                      }}
                      className={cn(
                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                        forceSSL ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                          forceSSL ? "translate-x-6" : "translate-x-1"
                        )}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between pl-7">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">HTTP/2</p>
                      <p className="text-xs text-gray-500">Enable HTTP/2 protocol for better performance</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setHTTP2Enabled(!http2Enabled);
                        setHasChanges(true);
                      }}
                      className={cn(
                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                        http2Enabled ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                          http2Enabled ? "translate-x-6" : "translate-x-1"
                        )}
                      />
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* Error display */}
            {(saveMutation.isError || deleteMutation.isError) && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                {saveMutation.error?.message || deleteMutation.error?.message || "An error occurred"}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-between pt-2">
              {isConfigured && !showDelete ? (
                <button
                  onClick={() => setShowDelete(true)}
                  className="text-sm text-red-400 hover:text-red-300 flex items-center gap-1.5"
                >
                  <Trash2 className="h-4 w-4" />
                  Remove Domain
                </button>
              ) : showDelete ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500">Are you sure?</span>
                  <button
                    onClick={() => deleteMutation.mutate()}
                    disabled={deleteMutation.isPending}
                    className="px-3 py-1.5 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
                  >
                    {deleteMutation.isPending ? "Removing..." : "Yes, Remove"}
                  </button>
                  <button
                    onClick={() => setShowDelete(false)}
                    className="px-3 py-1.5 text-sm text-gray-500 hover:text-gray-300"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div />
              )}

              {hasChanges && domain && (
                <button
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending || !domain}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white rounded-lg transition-colors flex items-center gap-2"
                >
                  {saveMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Check className="h-4 w-4" />
                  )}
                  {saveMutation.isPending ? "Saving..." : "Save Domain"}
                </button>
              )}
            </div>
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

// Nginx Configuration Section
function NginxConfigSection({ agentId }: { agentId: string | null }) {
  const [selectedProxy, setSelectedProxy] = useState<string | null>(null);
  const [configContent, setConfigContent] = useState<string>("");
  const [copied, setCopied] = useState(false);

  // Fetch proxies for this agent
  const { data: proxies, isLoading: proxiesLoading } = useQuery({
    queryKey: ["proxies", agentId],
    queryFn: () => (agentId ? api.getProxyHosts(agentId) : Promise.resolve([])),
    enabled: !!agentId,
  });

  // Fetch config for selected proxy
  const { data: proxyConfig, isLoading: configLoading } = useQuery({
    queryKey: ["proxyConfig", agentId, selectedProxy],
    queryFn: () =>
      agentId && selectedProxy
        ? api.getProxyConfig(agentId, selectedProxy)
        : Promise.resolve(null),
    enabled: !!agentId && !!selectedProxy,
  });

  useEffect(() => {
    if (proxyConfig?.config) {
      setConfigContent(proxyConfig.config);
    }
  }, [proxyConfig]);

  // Test nginx config
  const testMutation = useMutation({
    mutationFn: () => (agentId ? api.testNginxConfig(agentId) : Promise.reject("No agent")),
  });

  // Reload nginx
  const reloadMutation = useMutation({
    mutationFn: () => (agentId ? api.reloadNginx(agentId) : Promise.reject("No agent")),
  });

  const handleCopyConfig = () => {
    navigator.clipboard.writeText(configContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!agentId) {
    return null;
  }

  return (
    <Card>
      <Card.Header
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
              className={cn(
                "px-3 py-1.5 text-sm rounded-lg transition-colors flex items-center gap-1.5",
                testMutation.isSuccess && testMutation.data?.success
                  ? "bg-green-500/10 text-green-400 border border-green-500/30"
                  : testMutation.isError || (testMutation.isSuccess && !testMutation.data?.success)
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
              )}
            >
              {testMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : testMutation.isSuccess && testMutation.data?.success ? (
                <Check className="h-4 w-4" />
              ) : (
                <AlertTriangle className="h-4 w-4" />
              )}
              {testMutation.isPending ? "Testing..." : "Test Config"}
            </button>
            <button
              onClick={() => reloadMutation.mutate()}
              disabled={reloadMutation.isPending}
              className={cn(
                "px-3 py-1.5 text-sm rounded-lg transition-colors flex items-center gap-1.5",
                reloadMutation.isSuccess && reloadMutation.data?.success
                  ? "bg-green-500/10 text-green-400 border border-green-500/30"
                  : reloadMutation.isError
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : "bg-primary-600 hover:bg-primary-700 text-white"
              )}
            >
              {reloadMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              {reloadMutation.isPending ? "Reloading..." : "Reload Nginx"}
            </button>
          </div>
        }
      >
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-500/10 rounded-lg">
            <SettingsIcon className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Nginx Configuration</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              View and manage proxy configurations
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {/* Status messages */}
        {(testMutation.isSuccess || reloadMutation.isSuccess) && (
          <div
            className={cn(
              "mb-4 p-3 rounded-lg text-sm",
              (testMutation.data?.success || reloadMutation.data?.success)
                ? "bg-green-500/10 border border-green-500/30 text-green-400"
                : "bg-red-500/10 border border-red-500/30 text-red-400"
            )}
          >
            {testMutation.data?.message || reloadMutation.data?.message}
          </div>
        )}

        {/* Proxy list */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Proxy Hosts ({proxies?.length || 0})
            </label>
            {proxiesLoading ? (
              <div className="flex items-center justify-center py-4">
                <Loader2 className="h-5 w-5 text-gray-400 animate-spin" />
              </div>
            ) : proxies && proxies.length > 0 ? (
              <div className="space-y-2">
                {proxies.map((proxy) => (
                  <div
                    key={proxy.id}
                    onClick={() => setSelectedProxy(proxy.id === selectedProxy ? null : proxy.id)}
                    className={cn(
                      "p-3 rounded-lg border cursor-pointer transition-colors",
                      selectedProxy === proxy.id
                        ? "border-primary-500 bg-primary-500/5"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className={cn(
                            "w-2 h-2 rounded-full",
                            proxy.status === "active" ? "bg-green-500" : "bg-yellow-500"
                          )}
                        />
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{proxy.domain}</p>
                          <p className="text-xs text-gray-500">{proxy.upstream_target}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {proxy.ssl_enabled && (
                          <Badge size="sm" className="bg-green-500/10 text-green-400 border-green-500/30">
                            SSL
                          </Badge>
                        )}
                        <Badge
                          size="sm"
                          className={cn(
                            proxy.status === "active"
                              ? "bg-green-500/10 text-green-400"
                              : "bg-yellow-500/10 text-yellow-400"
                          )}
                        >
                          {proxy.status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500 py-4 text-center">
                No proxy hosts configured. Add proxies from the Proxies page.
              </p>
            )}
          </div>

          {/* Config viewer */}
          {selectedProxy && (
            <div className="mt-4">
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Generated Nginx Config
                </label>
                <button
                  onClick={handleCopyConfig}
                  className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1"
                >
                  <Copy className="h-3 w-3" />
                  {copied ? "Copied!" : "Copy"}
                </button>
              </div>
              {configLoading ? (
                <div className="flex items-center justify-center py-8 bg-gray-900 rounded-lg">
                  <Loader2 className="h-5 w-5 text-gray-400 animate-spin" />
                </div>
              ) : (
                <pre className="p-4 bg-gray-900 rounded-lg overflow-x-auto text-xs text-gray-300 font-mono max-h-80 overflow-y-auto">
                  {configContent || "No config available"}
                </pre>
              )}
            </div>
          )}
        </div>
      </Card.Body>
    </Card>
  );
}

// Tier display config
const TIER_CONFIG: Record<string, { label: string; color: string; badgeClass: string; iconClass: string }> = {
  community: {
    label: "Community Edition",
    color: "green",
    badgeClass: "bg-green-500/10 text-green-400 border-green-500/30",
    iconClass: "text-green-400",
  },
  professional: {
    label: "Professional Edition",
    color: "blue",
    badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    iconClass: "text-blue-400",
  },
  enterprise: {
    label: "Enterprise Edition",
    color: "purple",
    badgeClass: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    iconClass: "text-purple-400",
  },
};

const FEATURE_LABELS: Record<string, string> = {
  core_monitoring: "Core Monitoring",
  proxy_management: "Proxy Management",
  container_ops: "Container Operations",
  unified_logs: "Unified Logs",
  alert_channels: "Alerts & Notifications",
  user_management: "User Management",
  supply_chain_security: "Supply Chain Security",
  runtime_security: "Runtime Security",
  policy_as_code: "Policy-as-Code",
  secrets_management: "Secrets Management",
  data_governance: "Data Governance",
  code_quality: "Code Quality",
};

function LicenseSection() {
  const queryClient = useQueryClient();
  const [newKey, setNewKey] = useState("");
  const [showUpdateForm, setShowUpdateForm] = useState(false);
  const [updateError, setUpdateError] = useState("");
  const [updateSuccess, setUpdateSuccess] = useState(false);

  const { data: license, isLoading } = useQuery({
    queryKey: ["licenseSettings"],
    queryFn: () => api.getLicenseSettings(),
  });

  const updateMutation = useMutation({
    mutationFn: (key: string) => api.updateLicenseKey(key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["licenseSettings"] });
      setNewKey("");
      setShowUpdateForm(false);
      setUpdateError("");
      setUpdateSuccess(true);
      setTimeout(() => setUpdateSuccess(false), 4000);
    },
    onError: (err: Error) => {
      setUpdateError(err.message);
    },
  });

  const tier = license?.tier ?? "community";
  const tierCfg = TIER_CONFIG[tier] ?? TIER_CONFIG.community;
  const isEnvLocked = license?.key_source === "env";
  const isOffline = license?.key_source === "offline";

  return (
    <Card>
      <Card.Header>
        <div className="flex items-center gap-3">
          <div className={cn("p-2 rounded-lg", tier === "enterprise" ? "bg-purple-500/10" : tier === "professional" ? "bg-blue-500/10" : "bg-green-500/10")}>
            <Crown className={cn("h-5 w-5", tierCfg.iconClass)} />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">License</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Manage your InfraPilot license
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-6">
            {/* Success banner */}
            {updateSuccess && (
              <div className="flex items-center gap-3 p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400 text-sm">
                <Check className="h-4 w-4 flex-shrink-0" />
                License key updated successfully. Your new license is active immediately.
              </div>
            )}

            {/* Current license status */}
            <div className={cn("p-4 rounded-lg border", tier === "enterprise" ? "bg-purple-500/5 border-purple-500/30" : tier === "professional" ? "bg-blue-500/5 border-blue-500/30" : "bg-green-500/5 border-green-500/30")}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn("w-3 h-3 rounded-full", license?.valid ? "bg-green-500" : "bg-yellow-500")} />
                  <div>
                    <span className="font-semibold text-gray-900 dark:text-white">
                      {tierCfg.label}
                    </span>
                    <p className="text-sm text-gray-500 mt-0.5">
                      {license?.max_agents === -1
                        ? "Unlimited agents"
                        : `Up to ${license?.max_agents ?? 1} agent${(license?.max_agents ?? 1) !== 1 ? "s" : ""}`}
                      {license?.expires_at && ` · Expires ${new Date(license.expires_at).toLocaleDateString()}`}
                    </p>
                  </div>
                </div>
                <Badge className={tierCfg.badgeClass}>
                  {license?.valid ? "Active" : "Invalid"}
                </Badge>
              </div>
            </div>

            {/* Active key display */}
            {(license?.key_display || isEnvLocked || isOffline) && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Active License Key
                </label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 flex items-center gap-2 px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <KeyRound className="h-4 w-4 text-gray-400 flex-shrink-0" />
                    <code className="text-sm font-mono text-gray-700 dark:text-gray-300 flex-1">
                      {isOffline ? "Offline Mode (dev)" : license?.key_display || "—"}
                    </code>
                    {isEnvLocked && (
                      <Badge className="bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400 text-xs border-0">
                        ENV
                      </Badge>
                    )}
                    {license?.key_source === "database" && (
                      <Badge className="bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400 text-xs border-0">
                        DB
                      </Badge>
                    )}
                  </div>
                </div>
                {isEnvLocked && (
                  <p className="mt-1.5 text-xs text-gray-500">
                    Locked via <code className="font-mono">LICENSE_KEY</code> environment variable. Remove the env var to manage the license from here.
                  </p>
                )}
              </div>
            )}

            {/* Features grid */}
            {license?.features && license.features.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Included Features</h3>
                <div className="grid sm:grid-cols-2 gap-2">
                  {license.features.map((f) => (
                    <div key={f} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                      <Check className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />
                      {FEATURE_LABELS[f] ?? f.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Update key section */}
            {!isEnvLocked && !isOffline && (
              <div className="pt-4 border-t border-gray-200 dark:border-gray-800">
                {!showUpdateForm ? (
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        {license?.key_source === "setup_mode" ? "No license key configured" : "Update license key"}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {license?.key_source === "setup_mode"
                          ? "Enter a license key to enable full validation"
                          : "Change or renew your license key"}
                      </p>
                    </div>
                    <button
                      onClick={() => setShowUpdateForm(true)}
                      className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm transition-colors flex items-center gap-2"
                    >
                      <Key className="h-4 w-4" />
                      {license?.key_source === "setup_mode" ? "Add License Key" : "Update Key"}
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        New License Key
                      </label>
                      <input
                        type="text"
                        value={newKey}
                        onChange={(e) => {
                          setNewKey(e.target.value);
                          setUpdateError("");
                        }}
                        placeholder="IP-CE-XXXX-XXXX-XXXX"
                        className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white font-mono placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                        autoFocus
                      />
                      <p className="mt-1.5 text-xs text-gray-500">
                        Get a free key at{" "}
                        <a href="https://infrapilot.sh/signup" target="_blank" rel="noopener noreferrer" className="text-primary-400 hover:underline">
                          infrapilot.sh/signup
                        </a>
                      </p>
                    </div>

                    {updateError && (
                      <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                        {updateError}
                      </div>
                    )}

                    <div className="flex gap-2 justify-end">
                      <button
                        onClick={() => {
                          setShowUpdateForm(false);
                          setNewKey("");
                          setUpdateError("");
                        }}
                        className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => updateMutation.mutate(newKey)}
                        disabled={!newKey.trim() || updateMutation.isPending}
                        className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white rounded-lg text-sm transition-colors flex items-center gap-2"
                      >
                        {updateMutation.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Check className="h-4 w-4" />
                        )}
                        {updateMutation.isPending ? "Validating..." : "Validate & Save"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Upgrade link for non-enterprise tiers */}
            {tier !== "enterprise" && (
              <div className="p-4 bg-gray-50 dark:bg-gray-800/50 border border-gray-200 dark:border-gray-700 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-gray-900 dark:text-white">Need more?</h4>
                    <p className="text-sm text-gray-500 mt-0.5">
                      Upgrade to Professional or Enterprise for more agents and advanced features
                    </p>
                  </div>
                  <a
                    href={license?.upgrade_url ?? "https://infrapilot.sh/billing"}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors flex items-center gap-2 text-sm flex-shrink-0"
                  >
                    <Sparkles className="h-4 w-4" />
                    Upgrade
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
            )}
          </div>
        )}
      </Card.Body>
    </Card>
  );
}


// MFA Setup Component
function MFASection() {
  const queryClient = useQueryClient();
  const { user, setUser } = useAuthStore();
  const [showSetup, setShowSetup] = useState(false);
  const [showDisable, setShowDisable] = useState(false);
  const [setupData, setSetupData] = useState<MFASetupResponse | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  // Fetch current user
  const { data: currentUser, refetch: refetchUser } = useQuery({
    queryKey: ["currentUser"],
    queryFn: () => api.getCurrentUser(),
  });

  const mfaEnabled = currentUser?.mfa_enabled || false;

  // Setup MFA mutation
  const setupMutation = useMutation({
    mutationFn: () => api.setupMFA(),
    onSuccess: (data) => {
      setSetupData(data);
      setShowSetup(true);
      setError("");
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  // Confirm MFA mutation
  const confirmMutation = useMutation({
    mutationFn: (code: string) => api.confirmMFA(code),
    onSuccess: (data) => {
      setBackupCodes(data.backup_codes);
      refetchUser();
      setVerifyCode("");
      setSetupData(null);
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  // Disable MFA mutation
  const disableMutation = useMutation({
    mutationFn: ({ password, code }: { password: string; code: string }) =>
      api.disableMFA(password, code),
    onSuccess: () => {
      setShowDisable(false);
      setDisablePassword("");
      setDisableCode("");
      refetchUser();
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  const handleCopySecret = () => {
    if (setupData) {
      navigator.clipboard.writeText(setupData.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCopyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card>
      <Card.Header>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-green-500/10 rounded-lg">
            <Shield className="h-5 w-5 text-green-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Two-Factor Authentication</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Add an extra layer of security to your account
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Backup codes display after setup */}
        {backupCodes.length > 0 && (
          <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
            <div className="flex items-start gap-3 mb-3">
              <Key className="h-5 w-5 text-yellow-400 mt-0.5" />
              <div>
                <h3 className="font-medium text-yellow-300">Save Your Backup Codes</h3>
                <p className="text-sm text-yellow-400/80 mt-1">
                  These codes can be used to access your account if you lose your authenticator.
                  Each code can only be used once.
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-4 p-3 bg-gray-900 rounded font-mono text-sm">
              {backupCodes.map((code, i) => (
                <div key={i} className="text-gray-300">{code}</div>
              ))}
            </div>
            <button
              onClick={handleCopyBackupCodes}
              className="mt-3 flex items-center gap-2 text-sm text-yellow-400 hover:text-yellow-300"
            >
              <Copy className="h-4 w-4" />
              {copied ? "Copied!" : "Copy all codes"}
            </button>
            <button
              onClick={() => setBackupCodes([])}
              className="mt-3 ml-4 text-sm text-gray-400 hover:text-gray-300"
            >
              I've saved these codes
            </button>
          </div>
        )}

        {/* Current status */}
        {!showSetup && !showDisable && (
          <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Smartphone className="h-5 w-5 text-gray-500" />
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  Authenticator App
                </p>
                <p className="text-sm text-gray-500">
                  {mfaEnabled
                    ? "Two-factor authentication is enabled"
                    : "Not configured"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {mfaEnabled ? (
                <>
                  <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
                    Enabled
                  </Badge>
                  <button
                    onClick={() => setShowDisable(true)}
                    className="px-3 py-1.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
                  >
                    Disable
                  </button>
                </>
              ) : (
                <button
                  onClick={() => setupMutation.mutate()}
                  disabled={setupMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors text-sm"
                >
                  {setupMutation.isPending ? "Setting up..." : "Set Up MFA"}
                </button>
              )}
            </div>
          </div>
        )}

        {/* Setup flow */}
        {showSetup && setupData && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="font-medium text-gray-900 dark:text-white">Set Up Authenticator</h3>
              <button
                onClick={() => {
                  setShowSetup(false);
                  setSetupData(null);
                  setVerifyCode("");
                }}
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* QR Code */}
              <div className="p-4 bg-white rounded-lg border border-gray-200 dark:border-gray-700 text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  Scan this QR code with your authenticator app
                </p>
                <div className="inline-block p-4 bg-white rounded-lg">
                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(setupData.otpauth)}`}
                    alt="QR Code"
                    className="w-48 h-48"
                  />
                </div>
                <p className="text-xs text-gray-500 mt-3">
                  Works with Google Authenticator, Authy, 1Password, etc.
                </p>
              </div>

              {/* Manual entry */}
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    Or enter this code manually:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 px-3 py-2 bg-gray-100 dark:bg-gray-800 rounded font-mono text-sm text-gray-900 dark:text-white break-all">
                      {setupData.secret}
                    </code>
                    <button
                      onClick={handleCopySecret}
                      className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                    >
                      <Copy className="h-4 w-4 text-gray-500" />
                    </button>
                  </div>
                  {copied && (
                    <p className="text-xs text-green-400 mt-1">Copied to clipboard!</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Enter verification code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={verifyCode}
                    onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000"
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-center text-xl font-mono tracking-widest text-gray-900 dark:text-white"
                  />
                </div>

                <button
                  onClick={() => confirmMutation.mutate(verifyCode)}
                  disabled={verifyCode.length !== 6 || confirmMutation.isPending}
                  className="w-full px-4 py-3 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                >
                  {confirmMutation.isPending ? "Verifying..." : "Verify and Enable MFA"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Disable flow */}
        {showDisable && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-medium text-gray-900 dark:text-white">Disable Two-Factor Authentication</h3>
              <button
                onClick={() => {
                  setShowDisable(false);
                  setDisablePassword("");
                  setDisableCode("");
                }}
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>

            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <p className="text-sm text-yellow-400">
                This will remove two-factor authentication from your account. You'll need to set it up again if you want to re-enable it.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Your Password
              </label>
              <input
                type="password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Verification Code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
                className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-center font-mono tracking-widest text-gray-900 dark:text-white"
              />
            </div>

            <button
              onClick={() => disableMutation.mutate({ password: disablePassword, code: disableCode })}
              disabled={!disablePassword || disableCode.length < 6 || disableMutation.isPending}
              className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
            >
              {disableMutation.isPending ? "Disabling..." : "Disable MFA"}
            </button>
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

// Default Pages Section
function DefaultPagesSection() {
  const queryClient = useQueryClient();
  const [selectedPage, setSelectedPage] = useState<DefaultPageType | null>(null);
  const [editingPage, setEditingPage] = useState<DefaultPage | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);

  // Fetch all default pages
  const { data: pages, isLoading } = useQuery({
    queryKey: ["defaultPages"],
    queryFn: () => api.getDefaultPages(),
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ pageType, data }: { pageType: string; data: Partial<DefaultPage> }) =>
      api.updateDefaultPage(pageType, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["defaultPages"] });
      setEditingPage(null);
    },
  });

  const pageTypeLabels: Record<DefaultPageType, { label: string; description: string }> = {
    welcome: { label: "Welcome Page", description: "Shown when domain is first configured" },
    "404": { label: "404 Not Found", description: "Page not found error" },
    "500": { label: "500 Server Error", description: "Internal server error" },
    "502": { label: "502 Bad Gateway", description: "Backend server unavailable" },
    "503": { label: "503 Service Unavailable", description: "Service temporarily unavailable" },
    maintenance: { label: "Maintenance", description: "Scheduled maintenance page" },
  };

  const handlePreview = async (pageType: DefaultPageType) => {
    try {
      const result = await api.previewDefaultPage(pageType);
      setPreviewHtml(result.html);
    } catch {
      setPreviewHtml(null);
    }
  };

  const handleEditPage = (page: DefaultPage) => {
    setEditingPage({ ...page });
    setSelectedPage(page.page_type);
  };

  const handleSave = () => {
    if (!editingPage) return;
    updateMutation.mutate({
      pageType: editingPage.page_type,
      data: {
        enabled: editingPage.enabled,
        title: editingPage.title,
        heading: editingPage.heading,
        message: editingPage.message,
        show_logo: editingPage.show_logo,
        custom_css: editingPage.custom_css,
      },
    });
  };

  return (
    <Card>
      <Card.Header>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/10 rounded-lg">
            <FileText className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Default Pages</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Configure welcome and error pages served by InfraPilot
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-4">
            {/* Page List */}
            {pages?.map((page) => (
              <div
                key={page.page_type}
                className={cn(
                  "p-4 rounded-lg border transition-colors",
                  selectedPage === page.page_type
                    ? "border-primary-500 bg-primary-500/5"
                    : "border-gray-200 dark:border-gray-700"
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() =>
                        updateMutation.mutate({
                          pageType: page.page_type,
                          data: { enabled: !page.enabled },
                        })
                      }
                      className={cn(
                        "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                        page.enabled ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-3 w-3 transform rounded-full bg-white transition-transform",
                          page.enabled ? "translate-x-5" : "translate-x-1"
                        )}
                      />
                    </button>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {pageTypeLabels[page.page_type]?.label || page.page_type}
                      </p>
                      <p className="text-xs text-gray-500">
                        {pageTypeLabels[page.page_type]?.description}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handlePreview(page.page_type)}
                      className="px-3 py-1.5 text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 rounded transition-colors"
                    >
                      Preview
                    </button>
                    <button
                      onClick={() => handleEditPage(page)}
                      className="px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
                    >
                      Edit
                    </button>
                  </div>
                </div>

                {/* Edit Form */}
                {editingPage && selectedPage === page.page_type && (
                  <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-4">
                    <div className="grid sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Page Title
                        </label>
                        <input
                          type="text"
                          value={editingPage.title}
                          onChange={(e) =>
                            setEditingPage({ ...editingPage, title: e.target.value })
                          }
                          className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Heading
                        </label>
                        <input
                          type="text"
                          value={editingPage.heading}
                          onChange={(e) =>
                            setEditingPage({ ...editingPage, heading: e.target.value })
                          }
                          className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Message
                      </label>
                      <textarea
                        value={editingPage.message}
                        onChange={(e) =>
                          setEditingPage({ ...editingPage, message: e.target.value })
                        }
                        rows={2}
                        className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                      />
                    </div>
                    <div className="flex items-center gap-4">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={editingPage.show_logo}
                          onChange={(e) =>
                            setEditingPage({ ...editingPage, show_logo: e.target.checked })
                          }
                          className="w-4 h-4 rounded"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">Show logo</span>
                      </label>
                    </div>
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={() => {
                          setEditingPage(null);
                          setSelectedPage(null);
                        }}
                        className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleSave}
                        disabled={updateMutation.isPending}
                        className="px-4 py-1.5 text-sm bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
                      >
                        {updateMutation.isPending ? "Saving..." : "Save Changes"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Preview Modal */}
        {previewHtml && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
                <h3 className="font-semibold text-gray-900 dark:text-white">Page Preview</h3>
                <button
                  onClick={() => setPreviewHtml(null)}
                  className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <div className="h-[70vh]">
                <iframe
                  srcDoc={previewHtml}
                  className="w-full h-full border-0"
                  title="Page Preview"
                />
              </div>
            </div>
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure InfraPilot for your infrastructure"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform", href: "/" },
              { label: "Settings", current: true },
            ]}
          />
        }
      />

      {/* InfraPilot Domain Setup */}
      <InfraPilotDomainSection />

      {/* License Section */}
      <LicenseSection />

      {/* Security Section - MFA */}
      <MFASection />

      {/* Default Pages Section */}
      <DefaultPagesSection />
    </div>
  );
}
