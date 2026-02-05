"use client";

import { ReactNode, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  RefreshCw,
  Server,
  Plus,
  Globe,
  Shield,
  Network,
  FileText,
  Activity,
  Settings,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

const tabs = [
  { id: "overview", label: "Overview", href: "/traffic" },
  { id: "resources", label: "Resources", href: "/traffic/resources" },
  { id: "policies", label: "Policies", href: "/traffic/policies" },
  { id: "proxies", label: "Proxies", href: "/proxies" },
  { id: "logs", label: "Nginx Logs", href: "/traffic/logs" },
];

export default function TrafficLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();

  // Fetch agents for agent selector
  const { data: agents, isLoading: isLoadingAgents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  // Set default agent
  const activeAgents = agents?.filter((a) => a.status === "active") || [];
  const effectiveAgent = selectedAgent || activeAgents[0]?.id;

  // Check if we're on a detail page (e.g., /traffic/resources/[id])
  const pathParts = pathname.split("/").filter(Boolean);
  const isDetailPage = pathParts.length > 2 && pathParts[2] !== "resources" && pathParts[2] !== "policies" && pathParts[2] !== "proxies" && pathParts[2] !== "logs";

  // Determine active tab from pathname
  const getActiveTab = () => {
    if (pathname === "/traffic") return "overview";
    if (pathname === "/proxies" || pathname.startsWith("/proxies/")) return "proxies";
    const segment = pathname.split("/")[2];
    return segment || "overview";
  };

  const activeTab = getActiveTab();

  // Get action button based on active tab
  const getActionButton = () => {
    switch (activeTab) {
      case "resources":
        return (
          <button
            onClick={() => router.push("/traffic/resources/create")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            New Resource
          </button>
        );
      case "policies":
        return (
          <button
            onClick={() => router.push("/traffic/policies/create")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            New Policy
          </button>
        );
      case "proxies":
        return (
          <button
            onClick={() => router.push("/traffic/proxies/create")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Add Proxy
          </button>
        );
      default:
        return null;
    }
  };

  if (isLoadingAgents) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Traffic"
          description="Manage traffic routing, policies, and nginx configuration"
          breadcrumbs={<Breadcrumb items={[{ label: "Run" }, { label: "Traffic" }]} />}
        />
        <Spinner.LogoPage label="Loading..." />
      </div>
    );
  }

  // For detail pages, just render children without the layout wrapper
  if (isDetailPage) {
    return <>{children}</>;
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Traffic"
        description="Manage traffic routing, policies, and nginx configuration"
        breadcrumbs={<Breadcrumb items={[{ label: "Run" }, { label: "Traffic" }]} />}
        action={
          <div className="flex items-center gap-3">
            {activeAgents.length > 1 && (
              <select
                value={effectiveAgent || ""}
                onChange={(e) => setSelectedAgent(e.target.value)}
                className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-4 py-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                {activeAgents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} ({agent.hostname || "unknown host"})
                  </option>
                ))}
              </select>
            )}
            {getActionButton()}
            <button
              onClick={() => queryClient.invalidateQueries()}
              className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
        }
      />

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => router.push(tab.href)}
              className={cn(
                "whitespace-nowrap border-b-2 py-3 px-1 text-sm font-medium transition-colors",
                activeTab === tab.id
                  ? "border-primary-500 text-primary-600 dark:text-primary-400"
                  : "border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
              )}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Page Content */}
      {children}
    </div>
  );
}
