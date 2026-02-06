"use client";

import { useState, useRef, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  AlertTriangle,
  Info,
  Bug,
  Container,
  Clock,
  Activity,
  XCircle,
} from "lucide-react";
import { api, LogEntry } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useDocker } from "@/lib/docker-context";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SlideOver } from "@/components/ui/SlideOver";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Button } from "@/components/ui/page-layout";
import { FilterToolbar, ToggleOption, SelectOption } from "@/components/ui/FilterToolbar";

// Log level filter options
const LOG_LEVEL_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All Levels" },
  { value: "error", label: "Errors", color: "red" },
  { value: "warn", label: "Warnings", color: "yellow" },
  { value: "info", label: "Info", color: "blue" },
  { value: "debug", label: "Debug", color: "gray" },
];

// Lines selector options
const LINES_OPTIONS: SelectOption[] = [
  { value: "100", label: "100 lines" },
  { value: "200", label: "200 lines" },
  { value: "500", label: "500 lines" },
  { value: "1000", label: "1000 lines" },
  { value: "2000", label: "2000 lines" },
];

type LogLevel = "all" | "error" | "warn" | "info" | "debug";

export default function DockerLogsPage() {
  const { selectedAgent } = useDocker();
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LogLevel>("all");
  const [selectedContainer, setSelectedContainer] = useState<string>("all");
  const [tail, setTail] = useState(500);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Fetch unified logs
  const {
    data: unifiedLogs,
    isLoading: isLoading,
    refetch,
  } = useQuery({
    queryKey: ["unifiedLogs", selectedAgent, search, level, tail],
    queryFn: () =>
      api.getUnifiedLogs(selectedAgent!, {
        search: search || undefined,
        levels: level !== "all" ? [level] : undefined,
        tail,
      }),
    enabled: !!selectedAgent,
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

  // Build container options for dropdown
  const containerOptions: SelectOption[] = useMemo(() => [
    { value: "all", label: "All Containers" },
    ...containers.map((c) => ({ value: c, label: c })),
  ], [containers]);

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-4">
      {/* Filter Toolbar */}
      <FilterToolbar
        primaryToggle={{
          options: LOG_LEVEL_OPTIONS,
          value: level,
          onChange: (v) => setLevel(v as LogLevel),
        }}
        dropdownSelector={{
          options: containerOptions,
          value: selectedContainer,
          onChange: setSelectedContainer,
          label: "Container",
        }}
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search logs..."
        showSearch={true}
        showAutoRefresh={true}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        autoRefreshInterval={5000}
        showRefresh={true}
        onRefresh={handleRefresh}
        showExport={true}
        onExport={exportLogs}
        singleRow={true}
        customActions={
          <select
            value={tail}
            onChange={(e) => setTail(parseInt(e.target.value))}
            className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
          >
            {LINES_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
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

      {/* Logs Panel */}
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
            <div className="h-[calc(100vh-480px)] min-h-[400px] overflow-auto">
              {isLoading ? (
                <div className="flex items-center justify-center h-64">
                  <Spinner size="lg" label="Loading logs..." />
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
