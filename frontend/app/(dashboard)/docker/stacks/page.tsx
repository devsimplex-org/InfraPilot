"use client";

import { useState, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Layers,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Eye,
  ChevronDown,
  ChevronRight,
  Server,
  StopCircle,
  Box,
} from "lucide-react";
import { api, Stack, Container } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";

type StackStatus = "running" | "partial" | "stopped";
type StatusFilter = "all" | StackStatus;

const statusConfig: Record<StackStatus, { color: string; icon: React.ElementType; label: string }> = {
  running: { color: "green", icon: CheckCircle, label: "Running" },
  partial: { color: "yellow", icon: AlertTriangle, label: "Partial" },
  stopped: { color: "gray", icon: StopCircle, label: "Stopped" },
};

export default function DockerStacksPage() {
  const queryClient = useQueryClient();
  const { selectedAgent, openContainerPanel } = useDocker();

  // Local state
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [searchFilter, setSearchFilter] = useState("");
  const [expandedStacks, setExpandedStacks] = useState<Set<string>>(new Set());

  // Fetch discovered stacks from Docker
  const { data: stacks, isLoading } = useQuery({
    queryKey: ["stacks", selectedAgent],
    queryFn: () => selectedAgent ? api.getStacks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 5000,
  });

  // Filtered stacks
  const filteredStacks = useMemo(() => {
    if (!stacks) return [];
    return stacks.filter((s) => {
      const matchesStatus = statusFilter === "all" || s.status === statusFilter;
      const matchesSearch = !searchFilter ||
        s.name.toLowerCase().includes(searchFilter.toLowerCase());
      return matchesStatus && matchesSearch;
    });
  }, [stacks, statusFilter, searchFilter]);

  // Metrics
  const metrics = {
    total: stacks?.length || 0,
    running: stacks?.filter((s) => s.status === "running").length || 0,
    partial: stacks?.filter((s) => s.status === "partial").length || 0,
    stopped: stacks?.filter((s) => s.status === "stopped").length || 0,
    totalContainers: stacks?.reduce((sum, s) => sum + s.container_count, 0) || 0,
    runningContainers: stacks?.reduce((sum, s) => sum + s.running_count, 0) || 0,
  };

  // Toggle stack expansion
  const toggleExpanded = (stackName: string) => {
    setExpandedStacks((prev) => {
      const next = new Set(prev);
      if (next.has(stackName)) {
        next.delete(stackName);
      } else {
        next.add(stackName);
      }
      return next;
    });
  };

  // Render status badge
  const renderStatusBadge = (status: StackStatus) => {
    const config = statusConfig[status];
    const Icon = config.icon;
    return (
      <Badge variant={config.color as "gray" | "green" | "yellow"}>
        <Icon className="h-3 w-3 mr-1" />
        {config.label}
      </Badge>
    );
  };

  if (isLoading) {
    return <Spinner.LogoPage label="Loading stacks..." />;
  }

  return (
    <div className="space-y-6">
      {/* Metrics */}
      <MetricsGrid>
        <StatCard
          title="Total Stacks"
          value={metrics.total}
          icon={Layers}
          color="indigo"
        />
        <StatCard
          title="Running"
          value={metrics.running}
          icon={CheckCircle}
          color="green"
          subtitle={`${metrics.runningContainers} containers`}
        />
        <StatCard
          title="Partial"
          value={metrics.partial}
          icon={AlertTriangle}
          color="yellow"
        />
        <StatCard
          title="Stopped"
          value={metrics.stopped}
          icon={StopCircle}
          color="gray"
        />
      </MetricsGrid>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <Input
          placeholder="Search stacks..."
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
          className="w-64"
        />
        <div className="flex gap-2">
          {(["all", "running", "partial", "stopped"] as StatusFilter[]).map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={cn(
                "px-3 py-1.5 text-sm rounded-lg transition-colors",
                statusFilter === status
                  ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300"
                  : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
              )}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
              {status !== "all" && stacks && (
                <span className="ml-1 text-xs opacity-60">
                  ({stacks.filter((s) => s.status === status).length})
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Stacks List */}
      {filteredStacks.length === 0 ? (
        <EmptyState
          icon={Layers}
          title="No stacks found"
          description={
            stacks?.length === 0
              ? "Deploy your first stack using the Deploy Stack button above. Stacks are groups of containers deployed via docker-compose."
              : "No stacks match your current filters"
          }
        />
      ) : (
        <div className="space-y-4">
          {filteredStacks.map((stack) => (
            <StackCard
              key={stack.name}
              stack={stack}
              isExpanded={expandedStacks.has(stack.name)}
              onToggleExpand={() => toggleExpanded(stack.name)}
              onOpenContainer={openContainerPanel}
              renderStatusBadge={renderStatusBadge}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Stack Card Component
interface StackCardProps {
  stack: Stack;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onOpenContainer: (containerId: string) => void;
  renderStatusBadge: (status: StackStatus) => React.ReactNode;
}

function StackCard({
  stack,
  isExpanded,
  onToggleExpand,
  onOpenContainer,
  renderStatusBadge,
}: StackCardProps) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
      {/* Stack Header */}
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
        onClick={onToggleExpand}
      >
        <div className="flex items-center gap-4">
          <button className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
            {isExpanded ? (
              <ChevronDown className="h-5 w-5" />
            ) : (
              <ChevronRight className="h-5 w-5" />
            )}
          </button>
          <div className="p-2 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg">
            <Layers className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-gray-900 dark:text-white">{stack.name}</h3>
              {renderStatusBadge(stack.status)}
            </div>
            <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400 mt-1">
              <span className="flex items-center gap-1">
                <Box className="h-3.5 w-3.5" />
                {stack.running_count}/{stack.container_count} containers running
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Expanded Content - Containers Table */}
      {isExpanded && (
        <div className="border-t border-gray-200 dark:border-gray-800">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-800/50">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Container
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Image
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Networks
                  </th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                {stack.containers.map((container) => (
                  <ContainerRow
                    key={container.container_id}
                    container={container}
                    onOpenContainer={onOpenContainer}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// Container Row Component
interface ContainerRowProps {
  container: Container;
  onOpenContainer: (containerId: string) => void;
}

function ContainerRow({ container, onOpenContainer }: ContainerRowProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case "running":
        return "green";
      case "exited":
      case "stopped":
        return "gray";
      case "paused":
        return "yellow";
      default:
        return "gray";
    }
  };

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/30">
      <td className="px-4 py-3">
        <span className="font-medium text-gray-900 dark:text-white">
          {container.name}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-gray-600 dark:text-gray-400 font-mono truncate block max-w-xs">
          {container.image}
        </span>
      </td>
      <td className="px-4 py-3">
        <Badge variant={getStatusColor(container.status) as "green" | "gray" | "yellow"}>
          {container.status}
        </Badge>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {container.networks?.slice(0, 2).map((network) => (
            <span
              key={network}
              className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 rounded text-gray-600 dark:text-gray-400"
            >
              {network}
            </span>
          ))}
          {container.networks && container.networks.length > 2 && (
            <span className="text-xs text-gray-500">+{container.networks.length - 2}</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3 text-right">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onOpenContainer(container.container_id)}
        >
          <Eye className="h-4 w-4" />
        </Button>
      </td>
    </tr>
  );
}
