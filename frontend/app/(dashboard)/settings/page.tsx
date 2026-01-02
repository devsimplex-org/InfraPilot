"use client";

import { useState } from "react";
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
} from "lucide-react";
import { api, Agent, User, MFASetupResponse } from "@/lib/api";
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
