"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  RefreshCw,
  AlertCircle,
  AlertTriangle,
  Info,
  Bug,
  Server,
  Globe,
  Pause,
  Play,
  Download,
  Container,
  Clock,
  Activity,
  XCircle,
} from "lucide-react";
import { api, LogEntry } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SlideOver } from "@/components/ui/SlideOver";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Button } from "@/components/ui/page-layout";

type LogLevel = "all" | "error" | "warn" | "info" | "debug";

export default function LogsPage() {
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LogLevel>("all");
  const [selectedContainer, setSelectedContainer] = useState<string>("all");
  const [tail, setTail] = useState(500);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Fetch agents
  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Set default agent when agents load
  useEffect(() => {
    if (agents && agents.length > 0 && !selectedAgentId) {
      setSelectedAgentId(agents[0].id);
    }
  }, [agents, selectedAgentId]);

  // Fetch unified logs
  const {
    data: unifiedLogs,
    isLoading: isLoading,
    refetch,
  } = useQuery({
    queryKey: ["unifiedLogs", selectedAgentId, search, level, tail],
    queryFn: () =>
      api.getUnifiedLogs(selectedAgentId, {
        search: search || undefined,
        levels: level !== "all" ? [level] : undefined,
        tail,
      }),
    enabled: !!selectedAgentId,
    refetchInterval: autoRefresh ? 5000 : false,
  });

  // Extract unique containers from logs
  const containers = useMemo(() => {
    if (!unifiedLogs?.logs) return [];
    const containerSet = new Set<string>();
    unifiedLogs.logs.forEach((log) => {
      if (log.container_name) {
        containerSet.add(log.container_name);
      }
    });
    return Array.from(containerSet).sort();
  }, [unifiedLogs?.logs]);

  // Filter logs by selected container
  const filteredLogs = useMemo(() => {
    if (!unifiedLogs?.logs) return [];
    if (selectedContainer === "all") return unifiedLogs.logs;
    return unifiedLogs.logs.filter((log) => log.container_name === selectedContainer);
  }, [unifiedLogs?.logs, selectedContainer]);

  // Calculate metrics
  const metrics = useMemo(() => {
    const logs = filteredLogs || [];
    return {
      total: logs.length,
      errors: logs.filter((l) => l.level === "error").length,
      warnings: logs.filter((l) => l.level === "warn").length,
      info: logs.filter((l) => l.level === "info").length,
      debug: logs.filter((l) => l.level === "debug").length,
      containers: containers.length,
    };
  }, [filteredLogs, containers]);

  const handleRefresh = useCallback(() => {
    refetch();
  }, [refetch]);

  const getLevelIcon = (logLevel: string) => {
    switch (logLevel) {
      case "error":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "warn":
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case "debug":
        return <Bug className="h-4 w-4 text-purple-500" />;
      default:
        return <Info className="h-4 w-4 text-blue-500" />;
    }
  };

  const getLevelBadgeColor = (logLevel: string) => {
    switch (logLevel) {
      case "error":
        return "red" as const;
      case "warn":
        return "yellow" as const;
      case "debug":
        return "gray" as const;
      default:
        return "blue" as const;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        fractionalSecondDigits: 3,
      });
    } catch {
      return timestamp;
    }
  };

  const formatFullTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch {
      return timestamp;
    }
  };

  const exportLogs = () => {
    if (!filteredLogs || filteredLogs.length === 0) return;

    const content = filteredLogs
      .map(
        (log) =>
          `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.container_name ? `[${log.container_name}] ` : ""}${log.message}`
      )
      .join("\n");

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logs-${selectedContainer !== "all" ? selectedContainer + "-" : ""}${new Date().toISOString().split("T")[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Filter configuration
  const filterGroups = [
    {
      id: "container",
      label: "Container",
      type: "radio" as const,
      value: selectedContainer,
      onChange: (value: string | string[]) => setSelectedContainer(value as string),
      options: [
        { label: "All Containers", value: "all", count: metrics.total },
        ...containers.map((c) => ({
          label: c,
          value: c,
          count: unifiedLogs?.logs?.filter((l) => l.container_name === c).length || 0,
        })),
      ],
    },
    {
      id: "level",
      label: "Log Level",
      type: "radio" as const,
      value: level,
      onChange: (value: string | string[]) => setLevel(value as LogLevel),
      options: [
        { label: "All Levels", value: "all" },
        { label: "Error", value: "error", count: metrics.errors },
        { label: "Warning", value: "warn", count: metrics.warnings },
        { label: "Info", value: "info", count: metrics.info },
        { label: "Debug", value: "debug", count: metrics.debug },
      ],
    },
    {
      id: "search",
      label: "Search",
      type: "search" as const,
      value: search,
      onChange: (value: string | string[]) => setSearch(value as string),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Log Explorer"
        description="Real-time log aggregation and analysis across all containers"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Run", href: "/" },
              { label: "Logs" },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-3">
            {/* Agent Selector */}
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-gray-400" />
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                disabled={agentsLoading || !agents?.length}
              >
                {agentsLoading ? (
                  <option>Loading...</option>
                ) : agents && agents.length > 0 ? (
                  agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name}
                    </option>
                  ))
                ) : (
                  <option>No agents</option>
                )}
              </select>
            </div>

            {/* Lines selector */}
            <select
              value={tail}
              onChange={(e) => setTail(parseInt(e.target.value))}
              className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
            >
              <option value={100}>100 lines</option>
              <option value={200}>200 lines</option>
              <option value={500}>500 lines</option>
              <option value={1000}>1000 lines</option>
              <option value={2000}>2000 lines</option>
            </select>

            <div className="h-6 w-px bg-gray-300 dark:bg-gray-700" />

            <Button
              variant={autoRefresh ? "primary" : "secondary"}
              size="sm"
              icon={autoRefresh ? Pause : Play}
              onClick={() => setAutoRefresh(!autoRefresh)}
            >
              {autoRefresh ? "Pause" : "Live"}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              onClick={handleRefresh}
            >
              Refresh
            </Button>
            <Button
              variant="secondary"
              size="sm"
              icon={Download}
              onClick={exportLogs}
              disabled={!filteredLogs || filteredLogs.length === 0}
            >
              Export
            </Button>
          </div>
        }
      />

      {/* Metrics Overview */}
      <MetricsGrid columns={6}>
        <StatCard
          label="Total Logs"
          value={metrics.total}
          icon={FileText}
          iconColor="text-gray-600"
        />
        <StatCard
          label="Errors"
          value={metrics.errors}
          icon={XCircle}
          iconColor="text-red-600"
          valueColor={metrics.errors > 0 ? "text-red-600 dark:text-red-400" : undefined}
        />
        <StatCard
          label="Warnings"
          value={metrics.warnings}
          icon={AlertTriangle}
          iconColor="text-amber-600"
          valueColor={metrics.warnings > 0 ? "text-amber-600 dark:text-amber-400" : undefined}
        />
        <StatCard
          label="Info"
          value={metrics.info}
          icon={Info}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Debug"
          value={metrics.debug}
          icon={Bug}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Containers"
          value={metrics.containers}
          icon={Container}
          iconColor="text-cyan-600"
        />
      </MetricsGrid>

      {/* Main Content */}
      <div className="flex gap-6">
        {/* Filters Sidebar */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filterGroups}
            onReset={() => {
              setSearch("");
              setLevel("all");
              setSelectedContainer("all");
            }}
          />
        </div>

        {/* Logs Panel */}
        <div className="flex-1 min-w-0">
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
            {/* Log Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
              <div className="flex items-center gap-3">
                <Activity className="h-4 w-4 text-gray-500" />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {filteredLogs?.length || 0} log entries
                </span>
                {autoRefresh && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs font-medium rounded-full">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                    Live
                  </span>
                )}
              </div>
              {selectedContainer !== "all" && (
                <Badge>
                  <Container className="h-3 w-3 mr-1" />
                  {selectedContainer}
                </Badge>
              )}
            </div>

            {/* Log Entries */}
            <div className="h-[calc(100vh-420px)] min-h-[400px] overflow-auto">
              {isLoading ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" label="Loading logs..." />
                </div>
              ) : !selectedAgentId ? (
                <div className="py-16">
                  <EmptyState
                    icon={Server}
                    title="No agent selected"
                    description="Select an agent to view logs"
                  />
                </div>
              ) : filteredLogs && filteredLogs.length > 0 ? (
                <div className="divide-y divide-gray-100 dark:divide-gray-800">
                  {filteredLogs.map((log, index) => (
                    <div
                      key={`${log.timestamp}-${index}`}
                      onClick={() => setSelectedLog(log)}
                      className={cn(
                        "group flex items-start gap-4 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors cursor-pointer",
                        log.level === "error" && "bg-red-50/50 dark:bg-red-900/10",
                        log.level === "warn" && "bg-amber-50/50 dark:bg-amber-900/10"
                      )}
                    >
                      {/* Level Icon */}
                      <div className="flex-shrink-0 pt-0.5">
                        {getLevelIcon(log.level)}
                      </div>

                      {/* Timestamp */}
                      <div className="flex-shrink-0 w-24 text-right">
                        <div className="text-xs font-mono text-gray-500 dark:text-gray-400">
                          {formatTimestamp(log.timestamp)}
                        </div>
                      </div>

                      {/* Level Badge */}
                      <div className="flex-shrink-0 w-16">
                        <Badge color={getLevelBadgeColor(log.level)} size="sm">
                          {log.level.toUpperCase()}
                        </Badge>
                      </div>

                      {/* Container */}
                      <div className="flex-shrink-0 w-32">
                        {log.container_name ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 text-xs font-medium rounded truncate max-w-full">
                            <Container className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{log.container_name}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400">-</span>
                        )}
                      </div>

                      {/* Message */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-900 dark:text-gray-100 font-mono break-all line-clamp-2 group-hover:line-clamp-none transition-all">
                          {log.message}
                        </p>
                      </div>
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              ) : (
                <div className="py-16">
                  <EmptyState
                    icon={FileText}
                    title="No logs found"
                    description={
                      search || selectedContainer !== "all"
                        ? "Try adjusting your filters"
                        : "No log entries available"
                    }
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Log Details SlideOver */}
      <SlideOver isOpen={!!selectedLog} onClose={() => setSelectedLog(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedLog(null)}>
          <div className="flex items-center gap-3">
            {selectedLog && getLevelIcon(selectedLog.level)}
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Log Entry Details
              </h2>
              {selectedLog && (
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                  {formatFullTimestamp(selectedLog.timestamp)}
                </p>
              )}
            </div>
          </div>
        </SlideOver.Header>
        <SlideOver.Body>
          {selectedLog && (
            <div className="space-y-6">
              {/* Metadata Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                    Log Level
                  </p>
                  <Badge color={getLevelBadgeColor(selectedLog.level)} size="md">
                    {selectedLog.level.toUpperCase()}
                  </Badge>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                    Container
                  </p>
                  {selectedLog.container_name ? (
                    <div className="flex items-center gap-2">
                      <Container className="h-4 w-4 text-gray-500" />
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {selectedLog.container_name}
                      </span>
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">N/A</span>
                  )}
                </div>
              </div>

              {/* Timestamp */}
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                  Timestamp
                </p>
                <div className="flex items-center gap-2 text-sm text-gray-900 dark:text-white">
                  <Clock className="h-4 w-4 text-gray-400" />
                  {formatFullTimestamp(selectedLog.timestamp)}
                </div>
              </div>

              {/* Message */}
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                  Message
                </p>
                <div className="bg-gray-900 dark:bg-black rounded-lg p-4 overflow-x-auto">
                  <pre className="text-sm text-gray-100 font-mono whitespace-pre-wrap break-all">
                    {selectedLog.message}
                  </pre>
                </div>
              </div>

              {/* Copy Button */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-800">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    const content = `[${selectedLog.timestamp}] [${selectedLog.level.toUpperCase()}] ${selectedLog.container_name ? `[${selectedLog.container_name}] ` : ""}${selectedLog.message}`;
                    navigator.clipboard.writeText(content);
                  }}
                >
                  Copy Log Entry
                </Button>
              </div>
            </div>
          )}
        </SlideOver.Body>
      </SlideOver>
    </div>
  );
}
