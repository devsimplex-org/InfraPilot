"use client";

import { ReactNode } from "react";
import { RefreshCw } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";

export default function SecurityPostureLayout({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Posture"
        description="Real-time DevSecOps metrics and security insights"
        breadcrumbs={<Breadcrumb items={[{ label: "Overview" }, { label: "Security Posture" }]} />}
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
      {children}
    </div>
  );
}
