"use client";

import { ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { cn } from "@/lib/utils";

const tabs = [
  { id: "overview",  label: "Overview",              href: "/runtime-security" },
  { id: "drift",     label: "Drift Events",          href: "/runtime-security/drift" },
  { id: "anomalies", label: "Behavioral Anomalies",  href: "/runtime-security/anomalies" },
];

export default function RuntimeSecurityLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();

  const getActiveTab = () => {
    if (pathname === "/runtime-security") return "overview";
    const segment = pathname.split("/")[2];
    return segment || "overview";
  };
  const activeTab = getActiveTab();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Runtime Security"
        description="Monitor runtime drift detection and behavioral anomalies"
        breadcrumbs={<Breadcrumb items={[{ label: "Security" }, { label: "Runtime Security" }]} />}
        action={
          <button
            onClick={() => queryClient.invalidateQueries()}
            className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        }
      />

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

      {children}
    </div>
  );
}
