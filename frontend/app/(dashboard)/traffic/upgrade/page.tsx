"use client";

import {
  Zap,
  Shield,
  Network,
  Activity,
  Settings,
  Globe,
  BarChart3,
  Lock,
  GitMerge,
  Layers,
  ExternalLink,
  CheckCircle2,
} from "lucide-react";

const PRO_FEATURES = [
  {
    icon: Network,
    label: "Traffic Resources & Load Balancing",
    desc: "Define upstream services with health checks, weighted load balancing, and circuit breaking.",
  },
  {
    icon: Shield,
    label: "Traffic Policies",
    desc: "Apply security and routing policies across resources — rate limiting, auth, header manipulation.",
  },
  {
    icon: Activity,
    label: "Exposure Management",
    desc: "Map and audit all exposed endpoints across your infrastructure with risk scoring.",
  },
  {
    icon: Settings,
    label: "Rate Limit Profiles",
    desc: "Create reusable rate limit profiles and attach them to any exposed endpoint.",
  },
  {
    icon: Globe,
    label: "TLS Posture",
    desc: "Continuous TLS certificate scanning with expiry alerts and cipher-suite auditing.",
  },
  {
    icon: Lock,
    label: "mTLS & Zero-Trust Policies",
    desc: "Enforce mutual TLS and workload identity between services at the gateway level.",
  },
];

const ENTERPRISE_FEATURES = [
  {
    icon: GitMerge,
    label: "Multi-environment Promotion",
    desc: "Promote traffic configurations dev → staging → production with approval gates.",
  },
  {
    icon: Layers,
    label: "Canary / Blue-Green Traffic Splits",
    desc: "Progressive rollouts with precise traffic splitting and automatic rollback triggers.",
  },
  {
    icon: BarChart3,
    label: "Advanced Traffic Analytics",
    desc: "30-day retention, per-resource latency percentiles, error budgets, and SLO tracking.",
  },
];

export default function TrafficUpgradePage() {
  return (
    <div className="space-y-8 max-w-5xl">
      {/* Hero */}
      <div className="rounded-xl border border-purple-200 dark:border-purple-800 bg-gradient-to-br from-purple-50 to-indigo-50/40 dark:from-purple-900/20 dark:to-indigo-900/10 p-8">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/40 rounded-xl flex-shrink-0">
            <Zap className="h-6 w-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
              Unlock Traffic Governance
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 max-w-2xl mb-6">
              The Community Edition includes Reverse Proxy management and Nginx analytics.
              Upgrade to <span className="font-semibold text-purple-600 dark:text-purple-400">Professional</span> or{" "}
              <span className="font-semibold text-purple-600 dark:text-purple-400">Enterprise</span> to manage
              traffic resources, policies, exposure, rate limits, and TLS posture — all from one place.
            </p>
            <div className="flex flex-wrap gap-3">
              <a
                href="https://infrapilot.org/enterprise"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-sm font-semibold rounded-lg transition-all shadow-sm"
              >
                <Zap className="h-4 w-4" />
                Upgrade to Pro / Enterprise
              </a>
              <a
                href="https://infrapilot.org/docs/traffic"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 text-sm font-semibold rounded-lg transition-all"
              >
                <ExternalLink className="h-4 w-4" />
                View Docs
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Pro Features */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-0.5 bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 text-xs font-bold rounded-full uppercase tracking-wider">
            Professional
          </span>
          <h3 className="text-base font-semibold text-gray-900 dark:text-white">Traffic Governance Features</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {PRO_FEATURES.map(({ icon: Icon, label, desc }) => (
            <div
              key={label}
              className="flex items-start gap-3 p-4 bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800"
            >
              <div className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg flex-shrink-0">
                <Icon className="h-4 w-4 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-gray-900 dark:text-white mb-1">{label}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Enterprise Features */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-0.5 bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700 dark:text-indigo-300 text-xs font-bold rounded-full uppercase tracking-wider">
            Enterprise
          </span>
          <h3 className="text-base font-semibold text-gray-900 dark:text-white">Advanced Traffic Features</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {ENTERPRISE_FEATURES.map(({ icon: Icon, label, desc }) => (
            <div
              key={label}
              className="flex items-start gap-3 p-4 bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800"
            >
              <div className="p-2 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg flex-shrink-0">
                <Icon className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-gray-900 dark:text-white mb-1">{label}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* What's included in CE */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
          Already included in Community Edition
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: "Reverse Proxy Hosts", desc: "Domain → upstream mapping with SSL termination" },
            { label: "Nginx Analytics", desc: "Request rates, status codes, and top endpoints" },
            { label: "Nginx Log Viewer", desc: "Real-time log streaming with search and filtering" },
          ].map(({ label, desc }) => (
            <div key={label} className="flex items-start gap-3">
              <CheckCircle2 className="h-4 w-4 text-green-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">{label}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom CTA */}
      <div className="flex items-center justify-between p-5 rounded-xl border border-purple-200 dark:border-purple-800 bg-purple-50/50 dark:bg-purple-900/10">
        <div>
          <p className="text-sm font-semibold text-gray-900 dark:text-white">Ready to upgrade?</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Contact us or visit infrapilot.org to get started.</p>
        </div>
        <a
          href="https://infrapilot.org/enterprise"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-sm font-semibold rounded-lg transition-all shadow-sm flex-shrink-0"
        >
          <Zap className="h-4 w-4" />
          Get Started
        </a>
      </div>
    </div>
  );
}
