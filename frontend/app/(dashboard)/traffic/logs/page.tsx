"use client";

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  AlertTriangle,
  RefreshCw,
  Download,
  Search,
  Filter,
  Clock,
  Globe,
  AlertCircle,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { api } from "@/lib/api";

// Component library imports
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input, Button } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";

type LogType = "access" | "error";

interface NginxLogEntry {
  timestamp: string;
  message: string;
  source: string;
  container_name: string;
  level?: string;
  // Parsed access log fields
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  bytes?: number;
  referer?: string;
  user_agent?: string;
}

export default function NginxLogsPage() {
  const [logType, setLogType] = useState<LogType>("access");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lines, setLines] = useState(100);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgentId = agents?.filter((a) => a.status === "active")[0]?.id;

  // Fetch nginx logs
  const { data: logsData, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["nginx-logs", defaultAgentId, logType, lines],
    queryFn: async () => {
      if (!defaultAgentId) return { logs: [] };
      const response = await fetch(
        `/api/v1/agents/${defaultAgentId}/logs/nginx?type=${logType}&lines=${lines}`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      if (!response.ok) throw new Error("Failed to fetch logs");
      return response.json();
    },
    enabled: !!defaultAgentId,
    refetchInterval: autoRefresh ? 5000 : false,
  });

  const logs: NginxLogEntry[] = logsData?.logs || [];

  // Parse nginx access log line
  const parseAccessLog = (message: string): Partial<NginxLogEntry> => {
    // Common nginx log format: IP - - [timestamp] "METHOD PATH PROTOCOL" STATUS BYTES "REFERER" "USER_AGENT"
    const match = message.match(
      /^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/
    );
    if (match) {
      return {
        ip: match[1],
        method: match[3],
        path: match[4],
        status: parseInt(match[5]),
        bytes: parseInt(match[6]),
        referer: match[7] === "-" ? undefined : match[7],
        user_agent: match[8],
      };
    }
    return {};
  };

  // Parse nginx error log line
  const parseErrorLog = (message: string): { level: string } => {
    if (message.includes("[emerg]")) return { level: "critical" };
    if (message.includes("[error]")) return { level: "error" };
    if (message.includes("[warn]")) return { level: "warning" };
    if (message.includes("[notice]")) return { level: "info" };
    return { level: "info" };
  };

  // Filter logs
  const filteredLogs = logs.filter((log) => {
    if (!searchQuery) return true;
    const searchLower = searchQuery.toLowerCase();
    return (
      log.message.toLowerCase().includes(searchLower) ||
      log.ip?.toLowerCase().includes(searchLower) ||
      log.path?.toLowerCase().includes(searchLower)
    );
  });

  // Calculate metrics
  const metrics = {
    total: logs.length,
    errors: logs.filter((l) => {
      if (logType === "error") return true;
      const parsed = parseAccessLog(l.message);
      return parsed.status && parsed.status >= 400;
    }).length,
    success: logs.filter((l) => {
      if (logType === "error") return false;
      const parsed = parseAccessLog(l.message);
      return parsed.status && parsed.status >= 200 && parsed.status < 400;
    }).length,
  };

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoRefresh && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoRefresh]);

  // Get status color
  const getStatusColor = (status: number | undefined): string => {
    if (!status) return "gray";
    if (status >= 500) return "red";
    if (status >= 400) return "yellow";
    if (status >= 300) return "blue";
    if (status >= 200) return "green";
    return "gray";
  };

  // Download logs
  const downloadLogs = () => {
    const content = logs.map((l) => l.message).join("\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nginx-${logType}-${new Date().toISOString().split("T")[0]}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return <Spinner.LogoPage label="Loading nginx logs..." />;
  }

  return (
    <div className="space-y-6">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Log Entries"
          value={metrics.total}
          icon={FileText}
          iconColor="text-blue-600"
        />
        <StatCard
          label={logType === "access" ? "Successful" : "Notices"}
          value={metrics.success}
          icon={CheckCircle}
          iconColor="text-green-600"
        />
        <StatCard
          label={logType === "access" ? "Errors (4xx/5xx)" : "Errors/Warnings"}
          value={metrics.errors}
          icon={AlertCircle}
          iconColor="text-red-600"
        />
        <StatCard
          label="Last Refresh"
          value={new Date().toLocaleTimeString()}
          icon={Clock}
          iconColor="text-gray-600"
        />
      </MetricsGrid>

      {/* Controls */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-4">
          {/* Log Type Toggle */}
          <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setLogType("access")}
              className={cn(
                "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                logType === "access"
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
                  : "text-gray-600 dark:text-gray-400"
              )}
            >
              Access Logs
            </button>
            <button
              onClick={() => setLogType("error")}
              className={cn(
                "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                logType === "error"
                  ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
                  : "text-gray-600 dark:text-gray-400"
              )}
            >
              Error Logs
            </button>
          </div>

          {/* Lines selector */}
          <select
            value={lines}
            onChange={(e) => setLines(parseInt(e.target.value))}
            className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
          >
            <option value={50}>Last 50 lines</option>
            <option value={100}>Last 100 lines</option>
            <option value={500}>Last 500 lines</option>
            <option value={1000}>Last 1000 lines</option>
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 w-64"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={cn(
              "inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
              autoRefresh
                ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
            )}
          >
            <RefreshCw className={cn("h-4 w-4", autoRefresh && "animate-spin")} />
            {autoRefresh ? "Auto-refresh ON" : "Auto-refresh"}
          </button>

          {/* Manual refresh */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors"
          >
            <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
            Refresh
          </button>

          {/* Download */}
          <button
            onClick={downloadLogs}
            className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors"
          >
            <Download className="h-4 w-4" />
            Download
          </button>
        </div>
      </div>

      {/* Logs */}
      {filteredLogs.length > 0 ? (
        <div
          ref={logContainerRef}
          className="bg-gray-900 rounded-lg border border-gray-700 p-4 font-mono text-sm overflow-auto max-h-[600px]"
        >
          {filteredLogs.map((log, index) => {
            if (logType === "access") {
              const parsed = parseAccessLog(log.message);
              return (
                <div
                  key={index}
                  className="py-1 px-2 rounded hover:bg-gray-800 transition-colors"
                >
                  {parsed.status ? (
                    <div className="flex items-center gap-3">
                      <Badge
                        color={getStatusColor(parsed.status) as "green" | "yellow" | "red" | "blue" | "gray"}
                        className="font-mono text-xs"
                      >
                        {parsed.status}
                      </Badge>
                      <span className="text-gray-400">{parsed.method}</span>
                      <span className="text-white flex-1 truncate">{parsed.path}</span>
                      <span className="text-gray-500 text-xs">{parsed.ip}</span>
                    </div>
                  ) : (
                    <span className="text-gray-300">{log.message}</span>
                  )}
                </div>
              );
            } else {
              const parsed = parseErrorLog(log.message);
              return (
                <div
                  key={index}
                  className={cn(
                    "py-1 px-2 rounded hover:bg-gray-800 transition-colors",
                    parsed.level === "critical" && "bg-red-900/20",
                    parsed.level === "error" && "bg-red-900/10"
                  )}
                >
                  <span
                    className={cn(
                      "text-gray-300",
                      log.message.includes("[error]") && "text-red-400",
                      log.message.includes("[warn]") && "text-yellow-400",
                      log.message.includes("[emerg]") && "text-red-500 font-bold"
                    )}
                  >
                    {log.message}
                  </span>
                </div>
              );
            }
          })}
        </div>
      ) : (
        <EmptyState
          icon={FileText}
          title={searchQuery ? "No logs match your search" : "No logs available"}
          description={
            searchQuery
              ? "Try adjusting your search terms"
              : "Nginx logs will appear here when traffic is received"
          }
        />
      )}
    </div>
  );
}
