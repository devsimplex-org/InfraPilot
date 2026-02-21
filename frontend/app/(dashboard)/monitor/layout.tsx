"use client";

import { ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Activity, BarChart3, Globe } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { cn } from "@/lib/utils";

const tabs = [
  { id: "jobs", label: "Background Jobs", href: "/monitor", icon: Activity },
  { id: "metrics", label: "Metrics & Reports", href: "/monitor/metrics", icon: BarChart3 },
  { id: "dependencies", label: "Dependencies", href: "/monitor/dependencies", icon: Globe },
];

const tabDescriptions: Record<string, string> = {
  jobs: "Monitor background jobs, scheduled tasks, and worker processes",
  metrics: "Manage metric definitions, dashboards, and scheduled reports",
  dependencies: "Track and monitor external services, APIs, and third-party dependencies",
};

export default function MonitorLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();

  const getActiveTab = () => {
    if (pathname === "/monitor" || pathname === "/monitor/") return "jobs";
    const segment = pathname.split("/")[2];
    return segment || "jobs";
  };

  const activeTab = getActiveTab();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Monitor"
        description={tabDescriptions[activeTab] ?? "Monitor system health, jobs, and dependencies"}
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform" },
              { label: "Monitor" },
            ]}
          />
        }
      />

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => router.push(tab.href)}
                className={cn(
                  "inline-flex items-center gap-2 whitespace-nowrap border-b-2 py-3 px-1 text-sm font-medium transition-colors",
                  activeTab === tab.id
                    ? "border-primary-500 text-primary-600 dark:text-primary-400"
                    : "border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      {children}
    </div>
  );
}
