import Link from "next/link";
import { Lock, Sparkles, ArrowRight } from "lucide-react";

interface UpgradePromptProps {
  feature: string;
  tier: "professional" | "enterprise";
  title?: string;
  description?: string;
}

const TIER_CONFIG = {
  professional: {
    label: "Professional",
    color: "blue",
    badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    btnClass: "bg-blue-600 hover:bg-blue-500",
    borderClass: "border-blue-500/20",
    bgClass: "bg-blue-500/5",
  },
  enterprise: {
    label: "Enterprise",
    color: "purple",
    badgeClass: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    btnClass: "bg-purple-600 hover:bg-purple-500",
    borderClass: "border-purple-500/20",
    bgClass: "bg-purple-500/5",
  },
};

export function UpgradePrompt({ feature, tier, title, description }: UpgradePromptProps) {
  const cfg = TIER_CONFIG[tier];
  const tierLabel = cfg.label;

  return (
    <div className={`flex flex-col items-center justify-center min-h-[400px] p-8 rounded-2xl border ${cfg.borderClass} ${cfg.bgClass}`}>
      <div className="p-4 rounded-2xl bg-gray-100 dark:bg-gray-800 mb-6">
        <Lock className="h-8 w-8 text-gray-400" />
      </div>

      <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${cfg.badgeClass} mb-4`}>
        <Sparkles className="h-3 w-3" />
        {tierLabel} Feature
      </span>

      <h2 className="text-xl font-bold text-gray-900 dark:text-white text-center mb-2">
        {title ?? `${feature} requires ${tierLabel}`}
      </h2>
      <p className="text-gray-500 dark:text-gray-400 text-center max-w-md mb-8">
        {description ?? `Upgrade to ${tierLabel} to unlock this feature and more advanced capabilities for your infrastructure.`}
      </p>

      <div className="flex items-center gap-3">
        <Link
          href="/settings"
          className={`inline-flex items-center gap-2 px-5 py-2.5 ${cfg.btnClass} text-white rounded-xl font-semibold text-sm transition-colors`}
        >
          <Sparkles className="h-4 w-4" />
          Manage License
          <ArrowRight className="h-4 w-4" />
        </Link>
        <a
          href="https://infrapilot.sh/billing"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-xl font-semibold text-sm transition-colors"
        >
          View Plans
        </a>
      </div>
    </div>
  );
}
