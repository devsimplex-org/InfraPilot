"use client";

import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import {
  Shield,
  Zap,
  Bot,
  MapPin,
  Lock,
  Globe,
  Settings,
  Plus,
  Trash2,
  CheckCircle,
  AlertTriangle,
  ArrowLeft,
  Info,
} from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/page-layout";
import { api, CreateTrafficPolicyRequest, TrafficPolicyType } from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { Badge } from "@/components/ui/Badge";

// Policy type configuration
const POLICY_TYPES: {
  id: TrafficPolicyType;
  label: string;
  description: string;
  icon: React.ElementType;
  color: string;
}[] = [
  {
    id: "rate_limit",
    label: "Rate Limit",
    description: "Limit request rate per IP, user, or custom key",
    icon: Zap,
    color: "text-blue-600 dark:text-blue-400",
  },
  {
    id: "bot_protection",
    label: "Bot Protection",
    description: "Detect and block malicious bot traffic",
    icon: Bot,
    color: "text-purple-600 dark:text-purple-400",
  },
  {
    id: "geo_blocking",
    label: "Geo Blocking",
    description: "Allow or block traffic by country",
    icon: MapPin,
    color: "text-yellow-600 dark:text-yellow-400",
  },
  {
    id: "ip_filtering",
    label: "IP Filtering",
    description: "Allow or block specific IP addresses/ranges",
    icon: Shield,
    color: "text-red-600 dark:text-red-400",
  },
  {
    id: "cors",
    label: "CORS",
    description: "Configure Cross-Origin Resource Sharing",
    icon: Globe,
    color: "text-blue-600 dark:text-blue-400",
  },
  {
    id: "authentication",
    label: "Authentication",
    description: "Require authentication for access",
    icon: Lock,
    color: "text-green-600 dark:text-green-400",
  },
  {
    id: "header_transform",
    label: "Header Transform",
    description: "Modify request/response headers",
    icon: Settings,
    color: "text-gray-600 dark:text-gray-400",
  },
];

// Country list for geo blocking
const COUNTRIES = [
  { code: "US", name: "United States" },
  { code: "GB", name: "United Kingdom" },
  { code: "CA", name: "Canada" },
  { code: "AU", name: "Australia" },
  { code: "DE", name: "Germany" },
  { code: "FR", name: "France" },
  { code: "JP", name: "Japan" },
  { code: "CN", name: "China" },
  { code: "RU", name: "Russia" },
  { code: "BR", name: "Brazil" },
  { code: "IN", name: "India" },
  { code: "KR", name: "South Korea" },
  { code: "IT", name: "Italy" },
  { code: "ES", name: "Spain" },
  { code: "NL", name: "Netherlands" },
  { code: "SE", name: "Sweden" },
  { code: "NO", name: "Norway" },
  { code: "DK", name: "Denmark" },
  { code: "FI", name: "Finland" },
  { code: "SG", name: "Singapore" },
];

export default function CreateTrafficPolicyPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [policyType, setPolicyType] = useState<TrafficPolicyType | null>(null);
  const [isGlobal, setIsGlobal] = useState(false);
  const [priority, setPriority] = useState(100);
  const [enabled, setEnabled] = useState(true);

  // Type-specific config state
  // Rate Limit
  const [rateLimit, setRateLimit] = useState({
    requests_per_second: 10,
    burst: 20,
    key: "ip" as "ip" | "user" | "header",
    key_header: "",
    action: "reject" as "reject" | "throttle" | "log",
  });

  // Geo Blocking
  const [geoBlocking, setGeoBlocking] = useState({
    mode: "block" as "allow" | "block",
    countries: [] as string[],
  });

  // IP Filtering
  const [ipFiltering, setIpFiltering] = useState({
    rules: [{ cidr: "", action: "allow" as "allow" | "block" }],
    default_action: "allow" as "allow" | "block",
  });

  // Bot Protection
  const [botProtection, setBotProtection] = useState({
    mode: "detect" as "detect" | "challenge" | "block",
    challenge_type: "js" as "js" | "captcha",
    threshold: 0.5,
    allow_verified_bots: true,
  });

  // CORS
  const [cors, setCors] = useState({
    allowed_origins: ["*"],
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowed_headers: ["*"],
    exposed_headers: [] as string[],
    max_age: 86400,
    allow_credentials: false,
  });

  // Authentication
  const [authentication, setAuthentication] = useState({
    type: "basic" as "basic" | "jwt" | "api_key",
    realm: "Protected Area",
    jwt_issuer: "",
    jwt_audience: "",
    api_key_header: "X-API-Key",
  });

  // Header Transform
  const [headerTransform, setHeaderTransform] = useState({
    request_add: [] as { header: string; value: string }[],
    request_remove: [] as string[],
    response_add: [] as { header: string; value: string }[],
    response_remove: [] as string[],
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: CreateTrafficPolicyRequest) => api.createTrafficPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["traffic-policies"] });
      router.push("/traffic/policies");
    },
  });

  // Build config based on policy type
  const buildConfig = (): Record<string, unknown> => {
    switch (policyType) {
      case "rate_limit":
        return {
          requests_per_second: rateLimit.requests_per_second,
          burst: rateLimit.burst,
          key: rateLimit.key,
          key_header: rateLimit.key === "header" ? rateLimit.key_header : undefined,
          action: rateLimit.action,
        };
      case "geo_blocking":
        return {
          mode: geoBlocking.mode,
          countries: geoBlocking.countries,
        };
      case "ip_filtering":
        return {
          rules: ipFiltering.rules.filter((r) => r.cidr.trim() !== ""),
          default_action: ipFiltering.default_action,
        };
      case "bot_protection":
        return {
          mode: botProtection.mode,
          challenge_type: botProtection.challenge_type,
          threshold: botProtection.threshold,
          allow_verified_bots: botProtection.allow_verified_bots,
        };
      case "cors":
        return {
          allowed_origins: cors.allowed_origins.filter((o) => o.trim() !== ""),
          allowed_methods: cors.allowed_methods,
          allowed_headers: cors.allowed_headers.filter((h) => h.trim() !== ""),
          exposed_headers: cors.exposed_headers.filter((h) => h.trim() !== ""),
          max_age: cors.max_age,
          allow_credentials: cors.allow_credentials,
        };
      case "authentication":
        return {
          type: authentication.type,
          realm: authentication.realm,
          jwt_issuer: authentication.type === "jwt" ? authentication.jwt_issuer : undefined,
          jwt_audience: authentication.type === "jwt" ? authentication.jwt_audience : undefined,
          api_key_header: authentication.type === "api_key" ? authentication.api_key_header : undefined,
        };
      case "header_transform":
        return {
          request_add: headerTransform.request_add.filter((h) => h.header.trim() !== ""),
          request_remove: headerTransform.request_remove.filter((h) => h.trim() !== ""),
          response_add: headerTransform.response_add.filter((h) => h.header.trim() !== ""),
          response_remove: headerTransform.response_remove.filter((h) => h.trim() !== ""),
        };
      default:
        return {};
    }
  };

  // Handle create
  const handleCreate = () => {
    if (!policyType || !name.trim()) return;

    createMutation.mutate({
      name: name.trim(),
      description: description.trim() || undefined,
      policy_type: policyType,
      config: buildConfig(),
      is_global: isGlobal,
      priority,
      enabled,
    });
  };

  // Validation
  const isValid = (): boolean => {
    if (!name.trim() || !policyType) return false;

    switch (policyType) {
      case "rate_limit":
        return rateLimit.requests_per_second > 0;
      case "geo_blocking":
        return geoBlocking.countries.length > 0;
      case "ip_filtering":
        return ipFiltering.rules.some((r) => r.cidr.trim() !== "");
      case "cors":
        return cors.allowed_origins.some((o) => o.trim() !== "");
      default:
        return true;
    }
  };

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Traffic", href: "/traffic" },
        { label: "Policies", href: "/traffic/policies" },
        { label: "Create Policy", current: true },
      ]}
    />
  );

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Create Traffic Policy"
        description="Configure a new traffic policy for rate limiting, security, or routing"
        breadcrumbs={breadcrumbs}
      />

      <div className="grid grid-cols-3 gap-6">
        {/* Main Form */}
        <div className="col-span-2 space-y-6">
          {/* Basic Info */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Basic Information
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Policy Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., api-rate-limit"
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Optional description..."
                  rows={2}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>
            </div>
          </div>

          {/* Policy Type Selection */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Policy Type <span className="text-red-500">*</span>
            </h3>

            <div className="grid grid-cols-2 gap-3">
              {POLICY_TYPES.map((type) => {
                const Icon = type.icon;
                return (
                  <label
                    key={type.id}
                    className={cn(
                      "flex items-start gap-3 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                      policyType === type.id
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <input
                      type="radio"
                      name="policyType"
                      value={type.id}
                      checked={policyType === type.id}
                      onChange={() => setPolicyType(type.id)}
                      className="sr-only"
                    />
                    <div className={cn("p-2 rounded-lg bg-gray-100 dark:bg-gray-800", type.color)}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="flex-1">
                      <div className="font-medium text-gray-900 dark:text-white">{type.label}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">{type.description}</div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Type-Specific Configuration */}
          {policyType && (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Configuration
              </h3>

              {/* Rate Limit Config */}
              {policyType === "rate_limit" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Requests per Second
                      </label>
                      <input
                        type="number"
                        min="1"
                        value={rateLimit.requests_per_second}
                        onChange={(e) => setRateLimit({ ...rateLimit, requests_per_second: parseInt(e.target.value) || 1 })}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Burst Limit
                      </label>
                      <input
                        type="number"
                        min="1"
                        value={rateLimit.burst}
                        onChange={(e) => setRateLimit({ ...rateLimit, burst: parseInt(e.target.value) || 1 })}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Rate Limit Key
                    </label>
                    <select
                      value={rateLimit.key}
                      onChange={(e) => setRateLimit({ ...rateLimit, key: e.target.value as "ip" | "user" | "header" })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="ip">Client IP Address</option>
                      <option value="user">Authenticated User</option>
                      <option value="header">Custom Header</option>
                    </select>
                  </div>
                  {rateLimit.key === "header" && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Header Name
                      </label>
                      <input
                        type="text"
                        value={rateLimit.key_header}
                        onChange={(e) => setRateLimit({ ...rateLimit, key_header: e.target.value })}
                        placeholder="X-API-Key"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      />
                    </div>
                  )}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Action on Limit
                    </label>
                    <select
                      value={rateLimit.action}
                      onChange={(e) => setRateLimit({ ...rateLimit, action: e.target.value as "reject" | "throttle" | "log" })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="reject">Reject (429 Too Many Requests)</option>
                      <option value="throttle">Throttle (Delay requests)</option>
                      <option value="log">Log Only (No blocking)</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Geo Blocking Config */}
              {policyType === "geo_blocking" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Mode
                    </label>
                    <div className="flex gap-4">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          value="block"
                          checked={geoBlocking.mode === "block"}
                          onChange={() => setGeoBlocking({ ...geoBlocking, mode: "block" })}
                          className="text-primary-600"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">Block selected countries</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          value="allow"
                          checked={geoBlocking.mode === "allow"}
                          onChange={() => setGeoBlocking({ ...geoBlocking, mode: "allow" })}
                          className="text-primary-600"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">Allow only selected countries</span>
                      </label>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Countries
                    </label>
                    <div className="grid grid-cols-3 gap-2 max-h-64 overflow-y-auto p-2 border border-gray-200 dark:border-gray-700 rounded-lg">
                      {COUNTRIES.map((country) => (
                        <label key={country.code} className="flex items-center gap-2 cursor-pointer text-sm">
                          <input
                            type="checkbox"
                            checked={geoBlocking.countries.includes(country.code)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setGeoBlocking({ ...geoBlocking, countries: [...geoBlocking.countries, country.code] });
                              } else {
                                setGeoBlocking({ ...geoBlocking, countries: geoBlocking.countries.filter((c) => c !== country.code) });
                              }
                            }}
                            className="text-primary-600 rounded"
                          />
                          <span className="text-gray-700 dark:text-gray-300">{country.name}</span>
                        </label>
                      ))}
                    </div>
                    {geoBlocking.countries.length > 0 && (
                      <p className="mt-2 text-sm text-gray-500">
                        {geoBlocking.countries.length} countries selected
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* IP Filtering Config */}
              {policyType === "ip_filtering" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      IP Rules
                    </label>
                    <div className="space-y-2">
                      {ipFiltering.rules.map((rule, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={rule.cidr}
                            onChange={(e) => {
                              const updated = [...ipFiltering.rules];
                              updated[idx] = { ...updated[idx], cidr: e.target.value };
                              setIpFiltering({ ...ipFiltering, rules: updated });
                            }}
                            placeholder="10.0.0.0/8 or 192.168.1.1"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm font-mono"
                          />
                          <select
                            value={rule.action}
                            onChange={(e) => {
                              const updated = [...ipFiltering.rules];
                              updated[idx] = { ...updated[idx], action: e.target.value as "allow" | "block" };
                              setIpFiltering({ ...ipFiltering, rules: updated });
                            }}
                            className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          >
                            <option value="allow">Allow</option>
                            <option value="block">Block</option>
                          </select>
                          {ipFiltering.rules.length > 1 && (
                            <button
                              type="button"
                              onClick={() => setIpFiltering({ ...ipFiltering, rules: ipFiltering.rules.filter((_, i) => i !== idx) })}
                              className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => setIpFiltering({ ...ipFiltering, rules: [...ipFiltering.rules, { cidr: "", action: "allow" }] })}
                      className="mt-2 flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg"
                    >
                      <Plus className="h-4 w-4" />
                      Add Rule
                    </button>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Default Action (for unmatched IPs)
                    </label>
                    <select
                      value={ipFiltering.default_action}
                      onChange={(e) => setIpFiltering({ ...ipFiltering, default_action: e.target.value as "allow" | "block" })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="allow">Allow</option>
                      <option value="block">Block</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Bot Protection Config */}
              {policyType === "bot_protection" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Protection Mode
                    </label>
                    <select
                      value={botProtection.mode}
                      onChange={(e) => setBotProtection({ ...botProtection, mode: e.target.value as "detect" | "challenge" | "block" })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="detect">Detect (Log only)</option>
                      <option value="challenge">Challenge (CAPTCHA/JS)</option>
                      <option value="block">Block (Immediate rejection)</option>
                    </select>
                  </div>
                  {botProtection.mode === "challenge" && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Challenge Type
                      </label>
                      <select
                        value={botProtection.challenge_type}
                        onChange={(e) => setBotProtection({ ...botProtection, challenge_type: e.target.value as "js" | "captcha" })}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      >
                        <option value="js">JavaScript Challenge</option>
                        <option value="captcha">CAPTCHA</option>
                      </select>
                    </div>
                  )}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Detection Threshold (0-1)
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="1"
                      step="0.1"
                      value={botProtection.threshold}
                      onChange={(e) => setBotProtection({ ...botProtection, threshold: parseFloat(e.target.value) || 0.5 })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    />
                    <p className="mt-1 text-xs text-gray-500">Lower values are more strict (more blocking)</p>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={botProtection.allow_verified_bots}
                      onChange={(e) => setBotProtection({ ...botProtection, allow_verified_bots: e.target.checked })}
                      className="text-primary-600 rounded"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Allow verified bots (Googlebot, Bingbot, etc.)</span>
                  </label>
                </div>
              )}

              {/* CORS Config */}
              {policyType === "cors" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Allowed Origins
                    </label>
                    <div className="space-y-2">
                      {cors.allowed_origins.map((origin, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={origin}
                            onChange={(e) => {
                              const updated = [...cors.allowed_origins];
                              updated[idx] = e.target.value;
                              setCors({ ...cors, allowed_origins: updated });
                            }}
                            placeholder="https://example.com or *"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          {cors.allowed_origins.length > 1 && (
                            <button
                              type="button"
                              onClick={() => setCors({ ...cors, allowed_origins: cors.allowed_origins.filter((_, i) => i !== idx) })}
                              className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => setCors({ ...cors, allowed_origins: [...cors.allowed_origins, ""] })}
                      className="mt-2 flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg"
                    >
                      <Plus className="h-4 w-4" />
                      Add Origin
                    </button>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Allowed Methods
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((method) => (
                        <label key={method} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={cors.allowed_methods.includes(method)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setCors({ ...cors, allowed_methods: [...cors.allowed_methods, method] });
                              } else {
                                setCors({ ...cors, allowed_methods: cors.allowed_methods.filter((m) => m !== method) });
                              }
                            }}
                            className="text-primary-600 rounded"
                          />
                          <span className="text-sm text-gray-700 dark:text-gray-300">{method}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Max Age (seconds)
                    </label>
                    <input
                      type="number"
                      min="0"
                      value={cors.max_age}
                      onChange={(e) => setCors({ ...cors, max_age: parseInt(e.target.value) || 0 })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    />
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={cors.allow_credentials}
                      onChange={(e) => setCors({ ...cors, allow_credentials: e.target.checked })}
                      className="text-primary-600 rounded"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Allow Credentials</span>
                  </label>
                </div>
              )}

              {/* Authentication Config */}
              {policyType === "authentication" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Authentication Type
                    </label>
                    <select
                      value={authentication.type}
                      onChange={(e) => setAuthentication({ ...authentication, type: e.target.value as "basic" | "jwt" | "api_key" })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                    >
                      <option value="basic">Basic Authentication</option>
                      <option value="jwt">JWT Token</option>
                      <option value="api_key">API Key</option>
                    </select>
                  </div>
                  {authentication.type === "basic" && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Realm
                      </label>
                      <input
                        type="text"
                        value={authentication.realm}
                        onChange={(e) => setAuthentication({ ...authentication, realm: e.target.value })}
                        placeholder="Protected Area"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      />
                    </div>
                  )}
                  {authentication.type === "jwt" && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          JWT Issuer
                        </label>
                        <input
                          type="text"
                          value={authentication.jwt_issuer}
                          onChange={(e) => setAuthentication({ ...authentication, jwt_issuer: e.target.value })}
                          placeholder="https://auth.example.com"
                          className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          JWT Audience
                        </label>
                        <input
                          type="text"
                          value={authentication.jwt_audience}
                          onChange={(e) => setAuthentication({ ...authentication, jwt_audience: e.target.value })}
                          placeholder="api.example.com"
                          className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                        />
                      </div>
                    </>
                  )}
                  {authentication.type === "api_key" && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        API Key Header Name
                      </label>
                      <input
                        type="text"
                        value={authentication.api_key_header}
                        onChange={(e) => setAuthentication({ ...authentication, api_key_header: e.target.value })}
                        placeholder="X-API-Key"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                      />
                    </div>
                  )}
                </div>
              )}

              {/* Header Transform Config */}
              {policyType === "header_transform" && (
                <div className="space-y-6">
                  {/* Request Headers Add */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Add Request Headers
                    </label>
                    <div className="space-y-2">
                      {headerTransform.request_add.map((header, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={header.header}
                            onChange={(e) => {
                              const updated = [...headerTransform.request_add];
                              updated[idx] = { ...updated[idx], header: e.target.value };
                              setHeaderTransform({ ...headerTransform, request_add: updated });
                            }}
                            placeholder="Header-Name"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          <span className="text-gray-400">:</span>
                          <input
                            type="text"
                            value={header.value}
                            onChange={(e) => {
                              const updated = [...headerTransform.request_add];
                              updated[idx] = { ...updated[idx], value: e.target.value };
                              setHeaderTransform({ ...headerTransform, request_add: updated });
                            }}
                            placeholder="value"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          <button
                            type="button"
                            onClick={() => setHeaderTransform({ ...headerTransform, request_add: headerTransform.request_add.filter((_, i) => i !== idx) })}
                            className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => setHeaderTransform({ ...headerTransform, request_add: [...headerTransform.request_add, { header: "", value: "" }] })}
                      className="mt-2 flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg"
                    >
                      <Plus className="h-4 w-4" />
                      Add Header
                    </button>
                  </div>

                  {/* Request Headers Remove */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Remove Request Headers
                    </label>
                    <div className="space-y-2">
                      {headerTransform.request_remove.map((header, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={header}
                            onChange={(e) => {
                              const updated = [...headerTransform.request_remove];
                              updated[idx] = e.target.value;
                              setHeaderTransform({ ...headerTransform, request_remove: updated });
                            }}
                            placeholder="Header-Name"
                            className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                          />
                          <button
                            type="button"
                            onClick={() => setHeaderTransform({ ...headerTransform, request_remove: headerTransform.request_remove.filter((_, i) => i !== idx) })}
                            className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => setHeaderTransform({ ...headerTransform, request_remove: [...headerTransform.request_remove, ""] })}
                      className="mt-2 flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg"
                    >
                      <Plus className="h-4 w-4" />
                      Add Header to Remove
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Settings */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Settings
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Priority
                </label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={priority}
                  onChange={(e) => setPriority(parseInt(e.target.value) || 100)}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg"
                />
                <p className="mt-1 text-xs text-gray-500">Higher values take precedence</p>
              </div>

              <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                <label className="flex items-center justify-between cursor-pointer">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Global Policy</span>
                  <input
                    type="checkbox"
                    checked={isGlobal}
                    onChange={(e) => setIsGlobal(e.target.checked)}
                    className="text-primary-600 rounded"
                  />
                </label>
                <p className="mt-1 text-xs text-gray-500">
                  Global policies apply to all resources automatically
                </p>
              </div>

              <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                <label className="flex items-center justify-between cursor-pointer">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Enabled</span>
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => setEnabled(e.target.checked)}
                    className="text-primary-600 rounded"
                  />
                </label>
              </div>
            </div>
          </div>

          {/* Info */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
            <div className="flex gap-2">
              <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-700 dark:text-blue-300">
                <p className="font-medium">Policy Tips</p>
                <ul className="mt-1 space-y-1 text-blue-600 dark:text-blue-400">
                  <li>Policies can be assigned to specific resources or applied globally</li>
                  <li>Higher priority policies are evaluated first</li>
                  <li>Disabled policies have no effect</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-3">
            <Button
              variant="primary"
              className="w-full justify-center"
              onClick={handleCreate}
              disabled={!isValid() || createMutation.isPending}
            >
              {createMutation.isPending ? (
                <>Creating...</>
              ) : (
                <>
                  <CheckCircle className="h-4 w-4 mr-1" />
                  Create Policy
                </>
              )}
            </Button>
            <Link
              href="/traffic/policies"
              className="w-full px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-center"
            >
              Cancel
            </Link>
          </div>

          {/* Error Display */}
          {createMutation.isError && (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                <span className="text-sm text-red-700 dark:text-red-300">
                  {createMutation.error?.message || "Failed to create policy"}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
