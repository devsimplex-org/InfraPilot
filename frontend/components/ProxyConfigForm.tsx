"use client";

import { useState, useEffect, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Lock,
  Shield,
  Code,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
  Loader2,
  Check,
  AlertTriangle,
  Copy,
  FlaskConical,
  Save,
  User,
} from "lucide-react";
import { api, ProxyHost, SecurityHeaders, AuthUser, ConfigPreviewRequest } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ProxyConfigFormProps {
  proxy: ProxyHost;
  agentId: string;
  securityHeaders: SecurityHeaders;
  onSave: (proxyData: Partial<ProxyHost>, headerData: Omit<SecurityHeaders, "id" | "proxy_host_id">) => Promise<void>;
  onRefresh?: () => void;
}

interface FormSection {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  defaultOpen?: boolean;
}

export function ProxyConfigForm({
  proxy,
  agentId,
  securityHeaders: initialHeaders,
  onSave,
  onRefresh,
}: ProxyConfigFormProps) {
  const queryClient = useQueryClient();

  // Form state
  const [formData, setFormData] = useState({
    domain: proxy.domain,
    upstream_target: proxy.upstream_target,
    ssl_enabled: proxy.ssl_enabled,
    force_ssl: proxy.force_ssl,
    http2_enabled: proxy.http2_enabled,
    include_www: proxy.include_www,
    basic_auth_enabled: proxy.basic_auth_enabled || false,
    basic_auth_realm: proxy.basic_auth_realm || "Restricted",
    basic_auth_excluded_paths: proxy.basic_auth_excluded_paths || [],
  });

  const [headers, setHeaders] = useState({
    hsts_enabled: initialHeaders.hsts_enabled,
    hsts_max_age: initialHeaders.hsts_max_age || 31536000,
    x_frame_options: initialHeaders.x_frame_options || "SAMEORIGIN",
    x_content_type_options: initialHeaders.x_content_type_options,
    x_xss_protection: initialHeaders.x_xss_protection,
    content_security_policy: initialHeaders.content_security_policy || "",
  });

  // Config preview state
  const [configPreview, setConfigPreview] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);

  // Test result state
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);

  // Save state
  const [saving, setSaving] = useState(false);

  // Section collapse state
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    basic: true,
    auth: false,
    security: false,
    preview: false,
  });

  // New auth user form state
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [addingUser, setAddingUser] = useState(false);

  // Fetch auth users
  const { data: authUsers = [], refetch: refetchAuthUsers } = useQuery({
    queryKey: ["authUsers", agentId, proxy.id],
    queryFn: () => api.listAuthUsers(agentId, proxy.id),
    enabled: formData.basic_auth_enabled,
  });

  // Update form when proxy changes
  useEffect(() => {
    setFormData({
      domain: proxy.domain,
      upstream_target: proxy.upstream_target,
      ssl_enabled: proxy.ssl_enabled,
      force_ssl: proxy.force_ssl,
      http2_enabled: proxy.http2_enabled,
      include_www: proxy.include_www,
      basic_auth_enabled: proxy.basic_auth_enabled || false,
      basic_auth_realm: proxy.basic_auth_realm || "Restricted",
      basic_auth_excluded_paths: proxy.basic_auth_excluded_paths || [],
    });
  }, [proxy]);

  // Update headers when initialHeaders change
  useEffect(() => {
    setHeaders({
      hsts_enabled: initialHeaders.hsts_enabled,
      hsts_max_age: initialHeaders.hsts_max_age || 31536000,
      x_frame_options: initialHeaders.x_frame_options || "SAMEORIGIN",
      x_content_type_options: initialHeaders.x_content_type_options,
      x_xss_protection: initialHeaders.x_xss_protection,
      content_security_policy: initialHeaders.content_security_policy || "",
    });
  }, [initialHeaders]);

  // Generate config preview with debounce
  const generatePreview = useCallback(async () => {
    setPreviewLoading(true);
    try {
      const previewRequest: ConfigPreviewRequest = {
        domain: formData.domain,
        upstream_target: formData.upstream_target,
        ssl_enabled: formData.ssl_enabled,
        force_ssl: formData.force_ssl,
        http2_enabled: formData.http2_enabled,
        include_www: formData.include_www,
        basic_auth_enabled: formData.basic_auth_enabled,
        basic_auth_realm: formData.basic_auth_realm,
        hsts_enabled: headers.hsts_enabled,
        hsts_max_age: headers.hsts_max_age,
        x_frame_options: headers.x_frame_options,
        x_content_type_options: headers.x_content_type_options,
        x_xss_protection: headers.x_xss_protection,
        content_security_policy: headers.content_security_policy || undefined,
      };
      const response = await api.previewProxyConfig(agentId, proxy.id, previewRequest);
      setConfigPreview(response.config);
    } catch {
      setConfigPreview("# Error generating config preview");
    } finally {
      setPreviewLoading(false);
    }
  }, [formData, headers, agentId, proxy.id]);

  // Debounced preview generation
  useEffect(() => {
    const timer = setTimeout(() => {
      if (openSections.preview) {
        generatePreview();
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [formData, headers, openSections.preview, generatePreview]);

  // Handle test config
  const handleTestConfig = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testProxyConfig(agentId, proxy.id);
      setTestResult({ success: result.valid, message: result.message });
    } catch {
      setTestResult({ success: false, message: "Failed to test configuration" });
    } finally {
      setTesting(false);
    }
  };

  // Handle save
  const handleSave = async () => {
    setSaving(true);
    try {
      const proxyData: Partial<ProxyHost> = {
        domain: formData.domain,
        upstream_target: formData.upstream_target,
        force_ssl: formData.force_ssl,
        http2_enabled: formData.http2_enabled,
        include_www: formData.include_www,
        basic_auth_enabled: formData.basic_auth_enabled,
        basic_auth_realm: formData.basic_auth_realm,
      };

      const headerData = {
        hsts_enabled: headers.hsts_enabled,
        hsts_max_age: headers.hsts_max_age,
        x_frame_options: headers.x_frame_options,
        x_content_type_options: headers.x_content_type_options,
        x_xss_protection: headers.x_xss_protection,
        content_security_policy: headers.content_security_policy || undefined,
      };

      await onSave(proxyData, headerData);
      setTestResult({ success: true, message: "Configuration saved successfully" });
    } catch {
      setTestResult({ success: false, message: "Failed to save configuration" });
    } finally {
      setSaving(false);
    }
  };

  // Handle add auth user
  const handleAddAuthUser = async () => {
    if (!newUsername || !newPassword) return;
    setAddingUser(true);
    try {
      await api.createAuthUser(agentId, proxy.id, {
        username: newUsername,
        password: newPassword,
      });
      setNewUsername("");
      setNewPassword("");
      refetchAuthUsers();
    } catch {
      // Handle error
    } finally {
      setAddingUser(false);
    }
  };

  // Handle delete auth user
  const handleDeleteAuthUser = async (userId: string) => {
    try {
      await api.deleteAuthUser(agentId, proxy.id, userId);
      refetchAuthUsers();
    } catch {
      // Handle error
    }
  };

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const toggleSection = (sectionId: string) => {
    setOpenSections((prev) => ({
      ...prev,
      [sectionId]: !prev[sectionId],
    }));
  };

  const sections: FormSection[] = [
    { id: "basic", title: "Basic Settings", icon: Globe, defaultOpen: true },
    { id: "auth", title: "Basic Authentication", icon: Lock },
    { id: "security", title: "Security Headers", icon: Shield },
    { id: "preview", title: "Configuration Preview", icon: Code },
  ];

  return (
    <div className="space-y-4">
      {/* Basic Settings Section */}
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <button
          onClick={() => toggleSection("basic")}
          className="w-full flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-blue-500" />
            <span className="font-medium">Basic Settings</span>
          </div>
          {openSections.basic ? (
            <ChevronUp className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          )}
        </button>
        {openSections.basic && (
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Domain
                </label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  placeholder="example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Upstream Target
                </label>
                <input
                  type="text"
                  value={formData.upstream_target}
                  onChange={(e) => setFormData({ ...formData, upstream_target: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  placeholder="http://backend:3000"
                />
              </div>
            </div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.force_ssl}
                  onChange={(e) => setFormData({ ...formData, force_ssl: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">Force HTTPS</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.http2_enabled}
                  onChange={(e) => setFormData({ ...formData, http2_enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">HTTP/2</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.include_www}
                  onChange={(e) => setFormData({ ...formData, include_www: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">Include www subdomain</span>
              </label>
            </div>
          </div>
        )}
      </div>

      {/* Basic Authentication Section */}
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <button
          onClick={() => toggleSection("auth")}
          className="w-full flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          <div className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-yellow-500" />
            <span className="font-medium">Basic Authentication</span>
            {formData.basic_auth_enabled && (
              <span className="px-2 py-0.5 text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400 rounded">
                Enabled
              </span>
            )}
          </div>
          {openSections.auth ? (
            <ChevronUp className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          )}
        </button>
        {openSections.auth && (
          <div className="p-4 space-y-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.basic_auth_enabled}
                onChange={(e) => {
                  setFormData({ ...formData, basic_auth_enabled: e.target.checked });
                  if (e.target.checked) {
                    refetchAuthUsers();
                  }
                }}
                className="w-4 h-4 rounded text-blue-600"
              />
              <span className="text-sm">Enable Basic Authentication</span>
            </label>
            <p className="text-xs text-gray-500">
              Require username/password to access this proxy
            </p>

            {formData.basic_auth_enabled && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Auth Realm
                  </label>
                  <input
                    type="text"
                    value={formData.basic_auth_realm}
                    onChange={(e) => setFormData({ ...formData, basic_auth_realm: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    placeholder="Restricted Area"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    The message shown in the browser&apos;s login dialog
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Excluded Paths
                  </label>
                  <input
                    type="text"
                    value={formData.basic_auth_excluded_paths.join(", ")}
                    onChange={(e) => {
                      const paths = e.target.value
                        .split(",")
                        .map((p) => p.trim())
                        .filter((p) => p.length > 0);
                      setFormData({ ...formData, basic_auth_excluded_paths: paths });
                    }}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    placeholder="/api/, /health, /public/"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Comma-separated paths that bypass basic auth (e.g., /api/, /health)
                  </p>
                </div>

                {/* Auth Users List */}
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Authorized Users
                  </h4>
                  {authUsers.length === 0 ? (
                    <p className="text-sm text-gray-500">No users configured</p>
                  ) : (
                    <div className="space-y-2">
                      {authUsers.map((user) => (
                        <div
                          key={user.id}
                          className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-800 rounded-lg"
                        >
                          <div className="flex items-center gap-2">
                            <User className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium">{user.username}</span>
                          </div>
                          <button
                            onClick={() => handleDeleteAuthUser(user.id)}
                            className="p-1 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/20 rounded"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Add User Form */}
                  <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={newUsername}
                        onChange={(e) => setNewUsername(e.target.value)}
                        placeholder="Username"
                        className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                      />
                      <div className="relative flex-1">
                        <input
                          type={showPassword ? "text" : "password"}
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          placeholder="Password"
                          className="w-full px-3 py-2 pr-10 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                        >
                          {showPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                      <button
                        onClick={handleAddAuthUser}
                        disabled={!newUsername || !newPassword || addingUser}
                        className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1"
                      >
                        {addingUser ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Plus className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                      Password must be at least 6 characters
                    </p>
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Security Headers Section */}
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <button
          onClick={() => toggleSection("security")}
          className="w-full flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-green-500" />
            <span className="font-medium">Security Headers</span>
          </div>
          {openSections.security ? (
            <ChevronUp className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          )}
        </button>
        {openSections.security && (
          <div className="p-4 space-y-4">
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={headers.hsts_enabled}
                  onChange={(e) => setHeaders({ ...headers, hsts_enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">HSTS</span>
              </label>
              {headers.hsts_enabled && (
                <div className="flex items-center gap-2">
                  <label className="text-sm text-gray-600 dark:text-gray-400">Max Age:</label>
                  <input
                    type="number"
                    value={headers.hsts_max_age}
                    onChange={(e) => setHeaders({ ...headers, hsts_max_age: parseInt(e.target.value) || 0 })}
                    className="w-32 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  />
                  <span className="text-xs text-gray-500">seconds</span>
                </div>
              )}
            </div>

            <div className="flex items-center gap-4">
              <label className="text-sm text-gray-600 dark:text-gray-400">X-Frame-Options:</label>
              <select
                value={headers.x_frame_options}
                onChange={(e) => setHeaders({ ...headers, x_frame_options: e.target.value })}
                className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
              >
                <option value="DENY">DENY</option>
                <option value="SAMEORIGIN">SAMEORIGIN</option>
                <option value="">Disabled</option>
              </select>
            </div>

            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={headers.x_content_type_options}
                  onChange={(e) => setHeaders({ ...headers, x_content_type_options: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">X-Content-Type-Options (nosniff)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={headers.x_xss_protection}
                  onChange={(e) => setHeaders({ ...headers, x_xss_protection: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600"
                />
                <span className="text-sm">X-XSS-Protection</span>
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Content-Security-Policy
              </label>
              <textarea
                value={headers.content_security_policy}
                onChange={(e) => setHeaders({ ...headers, content_security_policy: e.target.value })}
                rows={2}
                className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 font-mono"
                placeholder="default-src 'self'; script-src 'self' 'unsafe-inline';"
              />
            </div>
          </div>
        )}
      </div>

      {/* Configuration Preview Section */}
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <button
          onClick={() => toggleSection("preview")}
          className="w-full flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          <div className="flex items-center gap-2">
            <Code className="h-5 w-5 text-purple-500" />
            <span className="font-medium">Nginx Configuration Preview</span>
          </div>
          {openSections.preview ? (
            <ChevronUp className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          )}
        </button>
        {openSections.preview && (
          <div className="p-4">
            <div className="relative">
              {previewLoading && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-900/50 rounded-lg">
                  <Loader2 className="h-6 w-6 text-white animate-spin" />
                </div>
              )}
              <div className="bg-gray-900 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
                  <span className="text-xs text-gray-400 font-mono">{formData.domain}.conf</span>
                  <button
                    onClick={() => copyToClipboard(configPreview)}
                    className="p-1 text-gray-400 hover:text-white rounded"
                    title="Copy to clipboard"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
                <pre className="p-4 text-xs text-green-400 font-mono whitespace-pre-wrap overflow-auto max-h-80">
                  {configPreview || "# Loading preview..."}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Actions Bar */}
      <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <button
            onClick={handleTestConfig}
            disabled={testing}
            className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-2 disabled:opacity-50"
          >
            {testing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FlaskConical className="h-4 w-4" />
            )}
            Test Configuration
          </button>
          {testResult && (
            <div
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm",
                testResult.success
                  ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                  : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
              )}
            >
              {testResult.success ? (
                <Check className="h-4 w-4" />
              ) : (
                <AlertTriangle className="h-4 w-4" />
              )}
              {testResult.message}
            </div>
          )}
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2 disabled:opacity-50"
        >
          {saving ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Save className="h-4 w-4" />
          )}
          Save Changes
        </button>
      </div>
    </div>
  );
}
