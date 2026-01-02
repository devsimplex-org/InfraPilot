"use client";

import { useQuery } from "@tanstack/react-query";
import { Server, Container, Globe, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";

function StatCard({
  title,
  value,
  icon: Icon,
  color,
}: {
  title: string;
  value: number | string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
      <div className="flex items-center gap-4">
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
        <div>
          <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active").length || 0;
  const totalAgents = agents?.length || 0;

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-8">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Active Agents"
          value={`${activeAgents}/${totalAgents}`}
          icon={Server}
          color="bg-green-600"
        />
        <StatCard
          title="Running Containers"
          value="—"
          icon={Container}
          color="bg-blue-600"
        />
        <StatCard
          title="Proxy Hosts"
          value="—"
          icon={Globe}
          color="bg-purple-600"
        />
        <StatCard
          title="Active Alerts"
          value="0"
          icon={AlertTriangle}
          color="bg-yellow-600"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Recent Activity
          </h2>
          <p className="text-gray-500">No recent activity</p>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            System Health
          </h2>
          <p className="text-gray-500">All systems operational</p>
        </div>
      </div>
    </div>
  );
}
