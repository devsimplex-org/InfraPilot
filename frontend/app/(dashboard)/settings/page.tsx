"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings,
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
import { api, Agent, User, MFASetupResponse, InfraPilotDomainSettings, LicenseInfo, SSOProvider, SSOProviderType, CreateSSOProviderRequest, AuditConfig, AuditExport, ComplianceReport } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/lib/auth";

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
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center gap-3 mb-6">
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
              <span className="px-2 py-1 text-xs bg-green-500/10 text-green-400 border border-green-500/30 rounded">
                Active
              </span>
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
    </section>
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
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-500/10 rounded-lg">
            <Settings className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Nginx Configuration</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              View and manage proxy configurations
            </p>
          </div>
        </div>
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
      </div>

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
                        <span className="px-2 py-0.5 text-xs bg-green-500/10 text-green-400 border border-green-500/30 rounded">
                          SSL
                        </span>
                      )}
                      <span
                        className={cn(
                          "px-2 py-0.5 text-xs rounded",
                          proxy.status === "active"
                            ? "bg-green-500/10 text-green-400"
                            : "bg-yellow-500/10 text-yellow-400"
                        )}
                      >
                        {proxy.status}
                      </span>
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
    </section>
  );
}

// License Status Section
function LicenseSection() {
  const { data: license, isLoading, error } = useQuery({
    queryKey: ["license"],
    queryFn: () => api.getLicenseInfo(),
  });

  const isEnterprise = license?.edition === "enterprise";
  const isExpired = license?.expires_at && new Date(license.expires_at) < new Date();

  const formatExpiryDate = (dateStr: string | null) => {
    if (!dateStr) return "Never";
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  const daysUntilExpiry = (dateStr: string | null) => {
    if (!dateStr) return null;
    const date = new Date(dateStr);
    const now = new Date();
    const diff = Math.ceil((date.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return diff;
  };

  const expiryDays = license?.expires_at ? daysUntilExpiry(license.expires_at) : null;

  return (
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className={cn(
          "p-2 rounded-lg",
          isEnterprise ? "bg-purple-500/10" : "bg-blue-500/10"
        )}>
          {isEnterprise ? (
            <Crown className="h-5 w-5 text-purple-400" />
          ) : (
            <Sparkles className="h-5 w-5 text-blue-400" />
          )}
        </div>
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">License</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            View your InfraPilot license and available features
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
        </div>
      ) : error ? (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          Failed to load license information
        </div>
      ) : license ? (
        <div className="space-y-6">
          {/* License Status Card */}
          <div className={cn(
            "p-4 rounded-lg border",
            isEnterprise
              ? isExpired
                ? "bg-red-500/5 border-red-500/30"
                : "bg-purple-500/5 border-purple-500/30"
              : "bg-blue-500/5 border-blue-500/30"
          )}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={cn(
                  "w-3 h-3 rounded-full",
                  isExpired ? "bg-red-500" : license.valid ? "bg-green-500" : "bg-yellow-500"
                )} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-gray-900 dark:text-white capitalize">
                      {license.edition} Edition
                    </span>
                    {isEnterprise && (
                      <span className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded">
                        Enterprise
                      </span>
                    )}
                  </div>
                  {license.organization && (
                    <p className="text-sm text-gray-500 mt-0.5">{license.organization}</p>
                  )}
                </div>
              </div>
              <div className="text-right">
                {isExpired ? (
                  <span className="px-2 py-1 text-xs bg-red-500/10 text-red-400 border border-red-500/30 rounded">
                    Expired
                  </span>
                ) : license.valid ? (
                  <span className="px-2 py-1 text-xs bg-green-500/10 text-green-400 border border-green-500/30 rounded">
                    Active
                  </span>
                ) : (
                  <span className="px-2 py-1 text-xs bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 rounded">
                    Invalid
                  </span>
                )}
              </div>
            </div>

            {/* Expiry info */}
            {license.expires_at && (
              <div className={cn(
                "mt-3 pt-3 border-t flex items-center gap-2 text-sm",
                isEnterprise ? "border-purple-500/20" : "border-blue-500/20"
              )}>
                <Clock className="h-4 w-4 text-gray-500" />
                <span className="text-gray-500">
                  {isExpired ? "Expired on " : "Expires "}
                  {formatExpiryDate(license.expires_at)}
                </span>
                {expiryDays !== null && expiryDays > 0 && expiryDays <= 30 && (
                  <span className="px-2 py-0.5 text-xs bg-yellow-500/10 text-yellow-400 rounded">
                    {expiryDays} days left
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Limits */}
          {license.limits && (
            <div>
              <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Usage Limits</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {license.limits.max_users === -1 ? "∞" : license.limits.max_users}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">Max Users</p>
                </div>
                <div className="p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {license.limits.max_agents === -1 ? "∞" : license.limits.max_agents}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">Max Agents</p>
                </div>
                <div className="p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {license.limits.max_resources === -1 ? "∞" : license.limits.max_resources}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">Max Resources</p>
                </div>
              </div>
            </div>
          )}

          {/* Features */}
          {license.features && license.features.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Enterprise Features</h3>
              <div className="grid sm:grid-cols-2 gap-3">
                {license.features.map((feature, index) => (
                  <div
                    key={feature.feature || `feature-${index}`}
                    className={cn(
                      "p-3 rounded-lg border transition-colors",
                      feature.licensed
                        ? "bg-green-500/5 border-green-500/20"
                        : "bg-gray-50 dark:bg-gray-800/50 border-gray-200 dark:border-gray-700"
                    )}
                  >
                    <div className="flex items-start gap-2">
                      {feature.licensed ? (
                        <Check className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
                      ) : (
                        <Lock className="h-4 w-4 text-gray-400 mt-0.5 flex-shrink-0" />
                      )}
                      <div>
                        <p className={cn(
                          "text-sm font-medium",
                          feature.licensed ? "text-gray-900 dark:text-white" : "text-gray-500"
                        )}>
                          {feature.name}
                        </p>
                        <p className="text-xs text-gray-500 mt-0.5">{feature.description}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Upgrade CTA for Community */}
          {!isEnterprise && (
            <div className="p-4 bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/20 rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">Upgrade to Enterprise</h4>
                  <p className="text-sm text-gray-500 mt-1">
                    Unlock SSO, multi-tenancy, advanced audit, and more
                  </p>
                </div>
                <a
                  href="https://infrapilot.io/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors flex items-center gap-2 text-sm"
                >
                  <Crown className="h-4 w-4" />
                  View Plans
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </section>
  );
}

// SSO Providers Section (Enterprise)
function SSOSection() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingProvider, setEditingProvider] = useState<SSOProvider | null>(null);
  const [providerType, setProviderType] = useState<SSOProviderType>("oidc");

  const { data: license } = useQuery({
    queryKey: ["license"],
    queryFn: () => api.getLicenseInfo(),
  });

  const { data: providers, isLoading } = useQuery({
    queryKey: ["sso-providers"],
    queryFn: () => api.getSSOProviders(),
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateSSOProviderRequest) => api.createSSOProvider(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
      setShowAddModal(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSSOProvider(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.updateSSOProvider(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
    },
  });

  const isEnterprise = license?.edition === "enterprise";
  const hasSSOFeature = license?.features?.some(f => f.feature.startsWith("sso_") && f.licensed);

  const getProviderIcon = (type: SSOProviderType) => {
    switch (type) {
      case "saml": return <Shield className="h-5 w-5" />;
      case "oidc": return <KeyRound className="h-5 w-5" />;
      case "ldap": return <Building2 className="h-5 w-5" />;
    }
  };

  const getProviderColor = (type: SSOProviderType) => {
    switch (type) {
      case "saml": return "text-blue-400 bg-blue-500/10";
      case "oidc": return "text-green-400 bg-green-500/10";
      case "ldap": return "text-yellow-400 bg-yellow-500/10";
    }
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    const data: CreateSSOProviderRequest = {
      name: formData.get("name") as string,
      provider_type: providerType,
      enabled: true,
      default_role: formData.get("default_role") as string || "viewer",
      auto_create_users: formData.get("auto_create_users") === "on",
    };

    // Add type-specific fields
    if (providerType === "oidc") {
      data.oidc_issuer = formData.get("oidc_issuer") as string;
      data.oidc_client_id = formData.get("oidc_client_id") as string;
      data.oidc_client_secret = formData.get("oidc_client_secret") as string;
      data.oidc_scopes = formData.get("oidc_scopes") as string || "openid profile email";
    } else if (providerType === "saml") {
      data.saml_entity_id = formData.get("saml_entity_id") as string;
      data.saml_sso_url = formData.get("saml_sso_url") as string;
      data.saml_certificate = formData.get("saml_certificate") as string;
    } else if (providerType === "ldap") {
      data.ldap_host = formData.get("ldap_host") as string;
      data.ldap_port = parseInt(formData.get("ldap_port") as string) || 389;
      data.ldap_use_tls = formData.get("ldap_use_tls") === "on";
      data.ldap_bind_dn = formData.get("ldap_bind_dn") as string;
      data.ldap_bind_password = formData.get("ldap_bind_password") as string;
      data.ldap_base_dn = formData.get("ldap_base_dn") as string;
      data.ldap_user_filter = formData.get("ldap_user_filter") as string || "(uid=%s)";
    }

    createMutation.mutate(data);
  };

  return (
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/10">
            <Users className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">SSO Providers</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Configure Single Sign-On with SAML, OIDC, or LDAP
            </p>
          </div>
        </div>
        {hasSSOFeature && (
          <button
            onClick={() => setShowAddModal(true)}
            className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm flex items-center gap-1.5"
          >
            <Plus className="h-4 w-4" />
            Add Provider
          </button>
        )}
      </div>

      {!isEnterprise ? (
        <div className="p-4 bg-purple-500/5 border border-purple-500/20 rounded-lg">
          <div className="flex items-center gap-3">
            <Lock className="h-5 w-5 text-purple-400" />
            <div>
              <p className="font-medium text-gray-900 dark:text-white">Enterprise Feature</p>
              <p className="text-sm text-gray-500">
                SSO (SAML, OIDC, LDAP) requires an Enterprise license.
              </p>
            </div>
          </div>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
        </div>
      ) : providers && providers.length > 0 ? (
        <div className="space-y-3">
          {providers.map((provider) => (
            <div
              key={provider.id}
              className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn("p-2 rounded-lg", getProviderColor(provider.provider_type))}>
                    {getProviderIcon(provider.provider_type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-gray-900 dark:text-white">
                        {provider.name}
                      </span>
                      <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded uppercase">
                        {provider.provider_type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 mt-0.5">
                      {provider.provider_type === "oidc" && provider.oidc_issuer}
                      {provider.provider_type === "saml" && provider.saml_entity_id}
                      {provider.provider_type === "ldap" && `${provider.ldap_host}:${provider.ldap_port}`}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => toggleMutation.mutate({ id: provider.id, enabled: !provider.enabled })}
                    className={cn(
                      "px-3 py-1 text-xs rounded-full border transition-colors",
                      provider.enabled
                        ? "bg-green-500/10 border-green-500/30 text-green-400"
                        : "bg-gray-100 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-500"
                    )}
                  >
                    {provider.enabled ? "Enabled" : "Disabled"}
                  </button>
                  <button
                    onClick={() => {
                      if (confirm("Delete this SSO provider?")) {
                        deleteMutation.mutate(provider.id);
                      }
                    }}
                    className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-gray-500">
          <Users className="h-12 w-12 mx-auto mb-3 opacity-50" />
          <p>No SSO providers configured</p>
          <p className="text-sm mt-1">Add a provider to enable Single Sign-On</p>
        </div>
      )}

      {/* Add Provider Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 dark:text-white">Add SSO Provider</h3>
              <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-4 space-y-4">
              {/* Provider Type */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Provider Type
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {(["oidc", "saml", "ldap"] as SSOProviderType[]).map((type) => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => setProviderType(type)}
                      className={cn(
                        "p-3 rounded-lg border text-center transition-colors",
                        providerType === type
                          ? "border-purple-500 bg-purple-500/10"
                          : "border-gray-200 dark:border-gray-700 hover:border-gray-300"
                      )}
                    >
                      <div className={cn("flex justify-center mb-1", getProviderColor(type))}>
                        {getProviderIcon(type)}
                      </div>
                      <span className="text-sm font-medium uppercase">{type}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Common Fields */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Name
                </label>
                <input
                  name="name"
                  type="text"
                  required
                  placeholder="e.g., Corporate Okta"
                  className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                />
              </div>

              {/* OIDC Fields */}
              {providerType === "oidc" && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Issuer URL
                    </label>
                    <input
                      name="oidc_issuer"
                      type="url"
                      required
                      placeholder="https://accounts.google.com"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Client ID
                    </label>
                    <input
                      name="oidc_client_id"
                      type="text"
                      required
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Client Secret
                    </label>
                    <input
                      name="oidc_client_secret"
                      type="password"
                      required
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                </>
              )}

              {/* SAML Fields */}
              {providerType === "saml" && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      IdP Entity ID
                    </label>
                    <input
                      name="saml_entity_id"
                      type="text"
                      required
                      placeholder="https://idp.example.com/saml"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      SSO URL
                    </label>
                    <input
                      name="saml_sso_url"
                      type="url"
                      required
                      placeholder="https://idp.example.com/sso"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      IdP Certificate (PEM)
                    </label>
                    <textarea
                      name="saml_certificate"
                      rows={4}
                      required
                      placeholder="-----BEGIN CERTIFICATE-----"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 font-mono text-sm"
                    />
                  </div>
                </>
              )}

              {/* LDAP Fields */}
              {providerType === "ldap" && (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        LDAP Host
                      </label>
                      <input
                        name="ldap_host"
                        type="text"
                        required
                        placeholder="ldap.example.com"
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Port
                      </label>
                      <input
                        name="ldap_port"
                        type="number"
                        defaultValue={389}
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Bind DN
                    </label>
                    <input
                      name="ldap_bind_dn"
                      type="text"
                      placeholder="cn=admin,dc=example,dc=com"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Bind Password
                    </label>
                    <input
                      name="ldap_bind_password"
                      type="password"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Base DN
                    </label>
                    <input
                      name="ldap_base_dn"
                      type="text"
                      required
                      placeholder="dc=example,dc=com"
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <input name="ldap_use_tls" type="checkbox" id="ldap_use_tls" className="rounded" />
                    <label htmlFor="ldap_use_tls" className="text-sm text-gray-700 dark:text-gray-300">
                      Use TLS/SSL
                    </label>
                  </div>
                </>
              )}

              {/* Common Settings */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Default Role
                  </label>
                  <select
                    name="default_role"
                    defaultValue="viewer"
                    className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="operator">Operator</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                <div className="flex items-center gap-2 mt-3">
                  <input name="auto_create_users" type="checkbox" id="auto_create_users" defaultChecked className="rounded" />
                  <label htmlFor="auto_create_users" className="text-sm text-gray-700 dark:text-gray-300">
                    Auto-create users on first login (JIT provisioning)
                  </label>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                >
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create Provider
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}

// Enterprise Audit & Compliance Section
function AuditComplianceSection() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"config" | "exports" | "reports">("config");
  const [showExportModal, setShowExportModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);

  const { data: license } = useQuery({
    queryKey: ["license"],
    queryFn: () => api.getLicenseInfo(),
  });

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ["audit-config"],
    queryFn: () => api.getAuditConfig(),
    enabled: license?.edition === "enterprise",
  });

  const { data: exports, isLoading: exportsLoading } = useQuery({
    queryKey: ["audit-exports"],
    queryFn: () => api.getAuditExports(),
    enabled: license?.edition === "enterprise",
  });

  const { data: reports, isLoading: reportsLoading } = useQuery({
    queryKey: ["compliance-reports"],
    queryFn: () => api.getComplianceReports(),
    enabled: license?.edition === "enterprise",
  });

  const updateConfigMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.updateAuditConfig>[0]) => api.updateAuditConfig(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit-config"] });
    },
  });

  const createExportMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.createAuditExport>[0]) => api.createAuditExport(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit-exports"] });
      setShowExportModal(false);
    },
  });

  const createReportMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.createComplianceReport>[0]) => api.createComplianceReport(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-reports"] });
      setShowReportModal(false);
    },
  });

  const testForwardingMutation = useMutation({
    mutationFn: () => api.testAuditForwarding(),
  });

  const verifyIntegrityMutation = useMutation({
    mutationFn: () => api.verifyAuditIntegrity(1000),
  });

  const isEnterprise = license?.edition === "enterprise";
  const hasAuditFeature = license?.features?.some(f => f.feature === "audit_compliance" && f.licensed);

  const handleExportSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    createExportMutation.mutate({
      format: formData.get("format") as "csv" | "json" | "cef" | "syslog",
      start_date: formData.get("start_date") as string || undefined,
      end_date: formData.get("end_date") as string || undefined,
    });
  };

  const handleReportSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    createReportMutation.mutate({
      report_type: formData.get("report_type") as "soc2" | "hipaa" | "access" | "activity" | "security",
      start_date: formData.get("start_date") as string,
      end_date: formData.get("end_date") as string,
    });
  };

  return (
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10">
            <FileCheck className="h-5 w-5 text-indigo-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Audit & Compliance</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Configure retention, exports, and compliance reports
            </p>
          </div>
        </div>
      </div>

      {!isEnterprise ? (
        <div className="p-4 bg-indigo-500/5 border border-indigo-500/20 rounded-lg">
          <div className="flex items-center gap-3">
            <Lock className="h-5 w-5 text-indigo-400" />
            <div>
              <p className="font-medium text-gray-900 dark:text-white">Enterprise Feature</p>
              <p className="text-sm text-gray-500">
                Advanced audit logging, exports, and compliance reports require an Enterprise license.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Tabs */}
          <div className="flex border-b border-gray-200 dark:border-gray-700">
            {(["config", "exports", "reports"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors",
                  activeTab === tab
                    ? "border-indigo-500 text-indigo-400"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                )}
              >
                {tab === "config" && "Configuration"}
                {tab === "exports" && "Exports"}
                {tab === "reports" && "Compliance Reports"}
              </button>
            ))}
          </div>

          {/* Configuration Tab */}
          {activeTab === "config" && (
            <div className="space-y-6">
              {configLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
                </div>
              ) : (
                <>
                  {/* Retention Settings */}
                  <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <h3 className="font-medium text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                      <Archive className="h-4 w-4" />
                      Retention Policy
                    </h3>
                    <div className="grid sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                          Retention Days
                        </label>
                        <select
                          value={config?.retention_days || 90}
                          onChange={(e) => updateConfigMutation.mutate({ retention_days: parseInt(e.target.value) })}
                          className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                        >
                          <option value={30}>30 days</option>
                          <option value={90}>90 days</option>
                          <option value={180}>180 days</option>
                          <option value={365}>1 year</option>
                          <option value={0}>Unlimited</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                          Retention Action
                        </label>
                        <select
                          value={config?.retention_policy || "delete"}
                          onChange={(e) => updateConfigMutation.mutate({ retention_policy: e.target.value as "delete" | "archive" | "export" })}
                          className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                        >
                          <option value="delete">Delete</option>
                          <option value="archive">Archive</option>
                          <option value="export">Export before delete</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Compliance Mode */}
                  <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <h3 className="font-medium text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4" />
                      Compliance Mode
                    </h3>
                    <div className="grid sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                          Compliance Framework
                        </label>
                        <select
                          value={config?.compliance_mode || ""}
                          onChange={(e) => updateConfigMutation.mutate({ compliance_mode: e.target.value as "soc2" | "hipaa" | "gdpr" | "pci" | null })}
                          className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                        >
                          <option value="">None</option>
                          <option value="soc2">SOC 2</option>
                          <option value="hipaa">HIPAA</option>
                          <option value="gdpr">GDPR</option>
                          <option value="pci">PCI-DSS</option>
                        </select>
                      </div>
                      <div className="space-y-3">
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={config?.immutable_logs || false}
                            onChange={(e) => updateConfigMutation.mutate({ immutable_logs: e.target.checked })}
                            className="rounded"
                          />
                          <span className="text-sm text-gray-700 dark:text-gray-300">Immutable logs</span>
                        </label>
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={config?.hash_chain_enabled || false}
                            onChange={(e) => updateConfigMutation.mutate({ hash_chain_enabled: e.target.checked })}
                            className="rounded"
                          />
                          <span className="text-sm text-gray-700 dark:text-gray-300">Hash chain integrity</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  {/* Forwarding */}
                  <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <h3 className="font-medium text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                      <Send className="h-4 w-4" />
                      Log Forwarding
                    </h3>
                    <div className="space-y-4">
                      <label className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={config?.forwarding_enabled || false}
                          onChange={(e) => updateConfigMutation.mutate({ forwarding_enabled: e.target.checked })}
                          className="rounded"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">Enable log forwarding</span>
                      </label>
                      {config?.forwarding_enabled && (
                        <div className="grid sm:grid-cols-2 gap-4 pt-2">
                          <div>
                            <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">
                              Forwarding Type
                            </label>
                            <select
                              value={config?.forwarding_type || "webhook"}
                              onChange={(e) => updateConfigMutation.mutate({ forwarding_type: e.target.value as "syslog" | "webhook" | "splunk" | "s3" })}
                              className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800"
                            >
                              <option value="webhook">Webhook</option>
                              <option value="syslog">Syslog</option>
                              <option value="splunk">Splunk</option>
                              <option value="s3">S3</option>
                            </select>
                          </div>
                          <div className="flex items-end">
                            <button
                              onClick={() => testForwardingMutation.mutate()}
                              disabled={testForwardingMutation.isPending}
                              className="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2"
                            >
                              {testForwardingMutation.isPending ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Play className="h-4 w-4" />
                              )}
                              Test Forwarding
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Integrity Check */}
                  <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium text-gray-900 dark:text-white">Integrity Verification</h3>
                        <p className="text-sm text-gray-500 mt-1">Verify the hash chain integrity of audit logs</p>
                      </div>
                      <button
                        onClick={() => verifyIntegrityMutation.mutate()}
                        disabled={verifyIntegrityMutation.isPending}
                        className="px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm flex items-center gap-2"
                      >
                        {verifyIntegrityMutation.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <ShieldCheck className="h-4 w-4" />
                        )}
                        Verify Integrity
                      </button>
                    </div>
                    {verifyIntegrityMutation.isSuccess && (
                      <div className={cn(
                        "mt-4 p-3 rounded-lg text-sm",
                        verifyIntegrityMutation.data.status === "valid"
                          ? "bg-green-500/10 text-green-400 border border-green-500/30"
                          : "bg-red-500/10 text-red-400 border border-red-500/30"
                      )}>
                        {verifyIntegrityMutation.data.status === "valid" ? (
                          <span>All {verifyIntegrityMutation.data.verified} logs verified successfully</span>
                        ) : (
                          <span>Integrity compromised! {verifyIntegrityMutation.data.broken_chain} broken chain entries</span>
                        )}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          {/* Exports Tab */}
          {activeTab === "exports" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => setShowExportModal(true)}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm flex items-center gap-1.5"
                >
                  <Download className="h-4 w-4" />
                  New Export
                </button>
              </div>

              {exportsLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
                </div>
              ) : exports && exports.length > 0 ? (
                <div className="space-y-2">
                  {exports.map((exp) => (
                    <div key={exp.id} className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <FileText className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {exp.format.toUpperCase()} Export
                          </p>
                          <p className="text-xs text-gray-500">
                            {new Date(exp.created_at).toLocaleString()}
                            {exp.row_count && ` • ${exp.row_count} rows`}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          "px-2 py-0.5 text-xs rounded",
                          exp.status === "completed" ? "bg-green-500/10 text-green-400" :
                          exp.status === "processing" ? "bg-yellow-500/10 text-yellow-400" :
                          exp.status === "failed" ? "bg-red-500/10 text-red-400" :
                          "bg-gray-500/10 text-gray-400"
                        )}>
                          {exp.status}
                        </span>
                        {exp.status === "completed" && (
                          <a
                            href={api.downloadAuditExport(exp.id)}
                            className="p-1.5 text-gray-400 hover:text-indigo-400"
                          >
                            <Download className="h-4 w-4" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <FileText className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No exports yet</p>
                </div>
              )}
            </div>
          )}

          {/* Reports Tab */}
          {activeTab === "reports" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => setShowReportModal(true)}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm flex items-center gap-1.5"
                >
                  <FileCheck className="h-4 w-4" />
                  Generate Report
                </button>
              </div>

              {reportsLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
                </div>
              ) : reports && reports.length > 0 ? (
                <div className="space-y-2">
                  {reports.map((report) => (
                    <div key={report.id} className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <ShieldCheck className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white uppercase">
                            {report.report_type} Report
                          </p>
                          <p className="text-xs text-gray-500">
                            {new Date(report.start_date).toLocaleDateString()} - {new Date(report.end_date).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <span className={cn(
                        "px-2 py-0.5 text-xs rounded",
                        report.status === "completed" ? "bg-green-500/10 text-green-400" :
                        report.status === "generating" ? "bg-yellow-500/10 text-yellow-400" :
                        report.status === "failed" ? "bg-red-500/10 text-red-400" :
                        "bg-gray-500/10 text-gray-400"
                      )}>
                        {report.status}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No compliance reports yet</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-md">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 dark:text-white">Export Audit Logs</h3>
              <button onClick={() => setShowExportModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleExportSubmit} className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Format</label>
                <select name="format" required className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800">
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                  <option value="cef">CEF (SIEM)</option>
                  <option value="syslog">Syslog</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Start Date</label>
                  <input type="date" name="start_date" className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">End Date</label>
                  <input type="date" name="end_date" className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800" />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowExportModal(false)} className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg">Cancel</button>
                <button type="submit" disabled={createExportMutation.isPending} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg flex items-center gap-2">
                  {createExportMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Export
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Report Modal */}
      {showReportModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-md">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 dark:text-white">Generate Compliance Report</h3>
              <button onClick={() => setShowReportModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleReportSubmit} className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Report Type</label>
                <select name="report_type" required className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800">
                  <option value="soc2">SOC 2</option>
                  <option value="hipaa">HIPAA</option>
                  <option value="access">Access Review</option>
                  <option value="activity">Activity Summary</option>
                  <option value="security">Security Events</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Start Date</label>
                  <input type="date" name="start_date" required className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">End Date</label>
                  <input type="date" name="end_date" required className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800" />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowReportModal(false)} className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg">Cancel</button>
                <button type="submit" disabled={createReportMutation.isPending} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg flex items-center gap-2">
                  {createReportMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Generate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
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
    <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
      <div className="flex items-center gap-3 mb-6">
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
                <span className="px-2 py-1 text-xs bg-green-500/10 text-green-400 border border-green-500/30 rounded">
                  Enabled
                </span>
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
                {/* QR Code - using a simple image URL approach */}
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
    </section>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [proxyMode, setProxyMode] = useState<ProxyMode>("managed");
  const [externalProxyType, setExternalProxyType] = useState<string>("");
  const [hasChanges, setHasChanges] = useState(false);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  if (!selectedAgent && activeAgents.length > 0) {
    setSelectedAgent(activeAgents[0].id);
  }

  // In a full implementation, we'd fetch/save proxy settings via API
  // For now, this is a UI demonstration

  const handleModeChange = (mode: ProxyMode) => {
    setProxyMode(mode);
    setHasChanges(true);
  };

  const handleSave = () => {
    // TODO: Save to backend via API
    console.log("Saving proxy settings:", {
      agent_id: selectedAgent,
      proxy_mode: proxyMode,
      external_proxy_type: externalProxyType,
    });
    setHasChanges(false);
  };

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Configure InfraPilot for your infrastructure
        </p>
      </div>

      {/* License Section */}
      <div className="mb-8">
        <LicenseSection />
      </div>

      {/* SSO Providers Section (Enterprise) */}
      <div className="mb-8">
        <SSOSection />
      </div>

      {/* Audit & Compliance Section (Enterprise) */}
      <div className="mb-8">
        <AuditComplianceSection />
      </div>

      {/* InfraPilot Domain Section */}
      <div className="mb-8">
        <InfraPilotDomainSection />
      </div>

      {/* Security Section - MFA */}
      <div className="mb-8">
        <MFASection />
      </div>

      {/* Agent selector */}
      <div className="mb-8">
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

      {selectedAgent && (
        <div className="space-y-8">
          {/* Proxy Settings Section */}
          <section className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-primary-500/10 rounded-lg">
                <Network className="h-5 w-5 text-primary-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Reverse Proxy</h2>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Choose how InfraPilot manages your reverse proxy
                </p>
              </div>
            </div>

            {/* Proxy Mode Toggle */}
            <div className="space-y-4">
              {/* Managed Mode */}
              <label
                className={cn(
                  "flex items-start gap-4 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                  proxyMode === "managed"
                    ? "border-primary-500 bg-primary-500/5"
                    : "border-gray-300 dark:border-gray-700 hover:border-gray-600"
                )}
              >
                <input
                  type="radio"
                  name="proxy_mode"
                  value="managed"
                  checked={proxyMode === "managed"}
                  onChange={() => handleModeChange("managed")}
                  className="mt-1 w-4 h-4 text-primary-600 focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-900 dark:text-white">
                      Use InfraPilot Managed Proxy
                    </span>
                    <span className="px-2 py-0.5 text-xs bg-green-500/10 text-green-400 border border-green-500/30 rounded">
                      Recommended
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    InfraPilot runs and fully manages NGINX for you. Automatic config
                    generation, zero-downtime reloads, and built-in SSL with Let's Encrypt.
                  </p>
                  <div className="flex flex-wrap gap-2 mt-3">
                    <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded">
                      Auto config
                    </span>
                    <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded">
                      Auto SSL
                    </span>
                    <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded">
                      Zero-downtime reloads
                    </span>
                    <span className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded">
                      No setup required
                    </span>
                  </div>
                </div>
              </label>

              {/* External Mode */}
              <label
                className={cn(
                  "flex items-start gap-4 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                  proxyMode === "external"
                    ? "border-primary-500 bg-primary-500/5"
                    : "border-gray-300 dark:border-gray-700 hover:border-gray-600"
                )}
              >
                <input
                  type="radio"
                  name="proxy_mode"
                  value="external"
                  checked={proxyMode === "external"}
                  onChange={() => handleModeChange("external")}
                  className="mt-1 w-4 h-4 text-primary-600 focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-900 dark:text-white">
                      I already have my own reverse proxy
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    Use your existing NGINX, Traefik, Caddy, HAProxy, or cloud load balancer.
                    InfraPilot will NOT manage configs, reloads, or TLS.
                  </p>

                  {proxyMode === "external" && (
                    <div className="mt-4 space-y-4">
                      <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-4 w-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                          <div className="text-sm text-yellow-300">
                            <p className="font-medium">You are responsible for:</p>
                            <ul className="mt-1 list-disc list-inside text-yellow-400/80">
                              <li>Configuring your proxy to route traffic</li>
                              <li>Managing SSL/TLS certificates</li>
                              <li>Reloading your proxy after changes</li>
                              <li>Network connectivity between proxy and services</li>
                            </ul>
                          </div>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          What proxy are you using? (optional)
                        </label>
                        <select
                          value={externalProxyType}
                          onChange={(e) => {
                            setExternalProxyType(e.target.value);
                            setHasChanges(true);
                          }}
                          className="w-full max-w-xs px-4 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                        >
                          <option value="">Select...</option>
                          <option value="nginx">NGINX</option>
                          <option value="nginx-proxy-manager">NGINX Proxy Manager</option>
                          <option value="traefik">Traefik</option>
                          <option value="caddy">Caddy</option>
                          <option value="haproxy">HAProxy</option>
                          <option value="aws-alb">AWS ALB</option>
                          <option value="cloudflare">Cloudflare</option>
                          <option value="other">Other</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>
              </label>
            </div>

            {/* Save Button */}
            {hasChanges && (
              <div className="mt-6 flex justify-end">
                <button
                  onClick={handleSave}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-gray-900 dark:text-white rounded-lg transition-colors flex items-center gap-2"
                >
                  <Check className="h-4 w-4" />
                  Save Changes
                </button>
              </div>
            )}
          </section>

          {/* Info Section */}
          <section className="bg-gray-900/50 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Need help deciding?
            </h3>
            <div className="grid md:grid-cols-2 gap-4 text-sm">
              <div className="space-y-2">
                <p className="text-gray-600 dark:text-gray-400">
                  <strong className="text-gray-900 dark:text-white">Choose Managed Proxy if:</strong>
                </p>
                <ul className="list-disc list-inside text-gray-500 space-y-1">
                  <li>You want things to just work</li>
                  <li>You don't have an existing proxy setup</li>
                  <li>You want automatic HTTPS</li>
                  <li>You prefer a simple UI for routing</li>
                </ul>
              </div>
              <div className="space-y-2">
                <p className="text-gray-600 dark:text-gray-400">
                  <strong className="text-gray-900 dark:text-white">Choose External Proxy if:</strong>
                </p>
                <ul className="list-disc list-inside text-gray-500 space-y-1">
                  <li>You already have infrastructure</li>
                  <li>You need custom proxy configuration</li>
                  <li>You have compliance/security requirements</li>
                  <li>You're using a cloud load balancer</li>
                </ul>
              </div>
            </div>
          </section>

          {/* Nginx Configuration Section */}
          <NginxConfigSection agentId={selectedAgent} />
        </div>
      )}

      {!selectedAgent && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 py-12 text-center text-gray-500">
          <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Select an agent to configure settings</p>
          {activeAgents.length === 0 && (
            <p className="text-sm mt-1">
              No active agents available. Register an agent first.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
