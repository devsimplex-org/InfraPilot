"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  X,
  Copy,
  Check,
  Terminal,
  ArrowDown,
  FileJson,
  FileSpreadsheet,
} from "lucide-react";
import { api } from "@/lib/api";
import { useTraffic } from "@/lib/traffic-context";

// Component library imports
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { SlideOver } from "@/components/ui/SlideOver";
import { cn } from "@/lib/utils";
import {
  FilterToolbar,
  SelectOption,
  ToggleOption,
  DEFAULT_LINE_OPTIONS,
} from "@/components/ui/FilterToolbar";

type LogType = "access" | "error";
type LogLevel = "all" | "info" | "warn" | "error";

// Toggle options for log type
const LOG_TYPE_OPTIONS: ToggleOption[] = [
  { value: "access", label: "Access Logs" },
  { value: "error", label: "Error Logs" },
];

// Status filter options for access logs
const ACCESS_STATUS_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "info", label: "2xx/3xx", color: "green" },
  { value: "warn", label: "4xx", color: "yellow" },
  { value: "error", label: "5xx", color: "red" },
];

// Method filter options
const METHOD_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "GET", label: "GET", color: "green" },
  { value: "POST", label: "POST", color: "blue" },
  { value: "PUT", label: "PUT", color: "yellow" },
  { value: "DELETE", label: "DELETE", color: "red" },
];

// Status filter options for error logs
const ERROR_STATUS_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "info", label: "Info", color: "green" },
  { value: "warn", label: "Warn", color: "yellow" },
  { value: "error", label: "Error", color: "red" },
];

// Custom export options for logs
const LOG_EXPORT_OPTIONS = [
  { format: "txt", label: "Plain Text (.log)", icon: <Terminal className="h-4 w-4" /> },
  { format: "json", label: "JSON (.json)", icon: <FileJson className="h-4 w-4" /> },
  { format: "csv", label: "CSV (.csv)", icon: <FileSpreadsheet className="h-4 w-4" /> },
];

interface NginxLogEntry {
  timestamp: string;
  message: string;
  source: string;
  container_name: string;
  level?: string;
  // Structured fields from database (backend)
  status_code?: number;
  method?: string;
  path?: string;
  response_bytes?: number;
  response_time?: number;
  client_ip?: string;
  host?: string;
  // Legacy parsed access log fields (file-based)
  ip?: string;
  status?: number;
  bytes?: number;
  referer?: string;
  user_agent?: string;
  // Parsed error log fields
  error_level?: string;
  error_message?: string;
}

interface ParsedAccessLog {
  ip: string;
  timestamp: string;
  method: string;
  path: string;
  protocol: string;
  status: number;
  bytes: number;
  referer: string;
  userAgent: string;
}

// Log entry component for better organization
function LogEntryRow({
  log,
  index,
  logType,
  isSelected,
  onClick,
  searchQuery,
}: {
  log: NginxLogEntry;
  index: number;
  logType: LogType;
  isSelected: boolean;
  onClick: () => void;
  searchQuery: string;
}) {
  // Use structured fields if available, otherwise parse from message
  const parsedFromMessage = logType === "access" ? parseAccessLog(log.message) : null;
  const parsed = logType === "access" ? (log.status_code ? {
    ip: log.client_ip || log.ip || "-",
    method: log.method || "GET",
    path: log.path || "/",
    status: log.status_code,
    bytes: log.response_bytes || log.bytes || 0,
    referer: "",
    userAgent: "",
    timestamp: "",
    protocol: "",
  } : parsedFromMessage) : null;
  const errorLevel = logType === "error" ? parseErrorLevel(log.message) : null;

  const getStatusColor = (status: number | undefined): "green" | "yellow" | "red" | "blue" | "gray" => {
    if (!status) return "gray";
    if (status >= 500) return "red";
    if (status >= 400) return "yellow";
    if (status >= 300) return "blue";
    if (status >= 200) return "green";
    return "gray";
  };

  const highlightText = (text: string, query: string) => {
    if (!query) return text;
    const parts = text.split(new RegExp(`(${query})`, "gi"));
    return parts.map((part, i) =>
      part.toLowerCase() === query.toLowerCase() ? (
        <mark key={i} className="bg-yellow-300 dark:bg-yellow-600 text-black dark:text-white rounded px-0.5">
          {part}
        </mark>
      ) : (
        part
      )
    );
  };

  // Format timestamp for display
  const formatTimestamp = (ts: string) => {
    if (!ts) return "-";
    try {
      const date = new Date(ts);
      return date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      });
    } catch {
      return "-";
    }
  };

  if (logType === "access" && parsed) {
    return (
      <div
        onClick={onClick}
        className={cn(
          "group flex items-center gap-2 py-2 px-3 rounded-md cursor-pointer transition-colors",
          isSelected
            ? "bg-primary-500/20 border border-primary-500/50"
            : "hover:bg-gray-800/50"
        )}
      >
        <span className="text-gray-600 text-xs font-mono w-6 text-right shrink-0">
          {index + 1}
        </span>
        <span className="text-gray-500 text-xs font-mono shrink-0 w-[70px]">
          {formatTimestamp(log.timestamp)}
        </span>
        <Badge
          color={getStatusColor(parsed.status)}
          className="font-mono text-xs shrink-0"
        >
          {parsed.status}
        </Badge>
        <span className={cn(
          "text-xs font-medium w-10 shrink-0",
          parsed.method === "GET" && "text-green-400",
          parsed.method === "POST" && "text-blue-400",
          parsed.method === "PUT" && "text-yellow-400",
          parsed.method === "DELETE" && "text-red-400",
          parsed.method === "PATCH" && "text-purple-400"
        )}>
          {parsed.method}
        </span>
        {log.host && (
          <span className="text-cyan-400 text-xs font-mono shrink-0 max-w-[120px] truncate" title={log.host}>
            {log.host}
          </span>
        )}
        <span className="text-white flex-1 truncate font-mono text-sm">
          {highlightText(parsed.path, searchQuery)}
        </span>
        <span className="text-gray-500 text-xs shrink-0 hidden lg:block">
          {parsed.bytes > 0 ? `${(parsed.bytes / 1024).toFixed(1)}KB` : "-"}
        </span>
        <span className="text-gray-500 text-xs font-mono shrink-0 hidden md:block">
          {highlightText(parsed.ip, searchQuery)}
        </span>
      </div>
    );
  }

  // Error log display
  return (
    <div
      onClick={onClick}
      className={cn(
        "group py-2 px-3 rounded-md cursor-pointer transition-colors",
        isSelected
          ? "bg-primary-500/20 border border-primary-500/50"
          : "hover:bg-gray-800/50",
        errorLevel === "emerg" && "bg-red-900/30",
        errorLevel === "error" && "bg-red-900/20",
        errorLevel === "warn" && "bg-yellow-900/20"
      )}
    >
      <div className="flex items-start gap-2">
        <span className="text-gray-600 text-xs font-mono w-6 text-right shrink-0 pt-0.5">
          {index + 1}
        </span>
        <span className="text-gray-500 text-xs font-mono shrink-0 w-[70px] pt-0.5">
          {formatTimestamp(log.timestamp)}
        </span>
        {errorLevel && (
          <Badge
            color={
              errorLevel === "emerg" || errorLevel === "error"
                ? "red"
                : errorLevel === "warn"
                ? "yellow"
                : "gray"
            }
            className="font-mono text-xs shrink-0"
          >
            {errorLevel.toUpperCase()}
          </Badge>
        )}
        <span
          className={cn(
            "font-mono text-sm break-all",
            errorLevel === "emerg" && "text-red-400 font-bold",
            errorLevel === "error" && "text-red-400",
            errorLevel === "warn" && "text-yellow-400",
            !errorLevel && "text-gray-300"
          )}
        >
          {highlightText(log.message, searchQuery)}
        </span>
      </div>
    </div>
  );
}

// Parse nginx access log
function parseAccessLog(message: string): ParsedAccessLog | null {
  const match = message.match(
    /^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/
  );
  if (match) {
    return {
      ip: match[1],
      timestamp: match[2],
      method: match[3],
      path: match[4],
      protocol: match[5],
      status: parseInt(match[6]),
      bytes: parseInt(match[7]),
      referer: match[8] === "-" ? "" : match[8],
      userAgent: match[9],
    };
  }
  return null;
}

// Parse error level
function parseErrorLevel(message: string): string | null {
  if (message.includes("[emerg]")) return "emerg";
  if (message.includes("[error]")) return "error";
  if (message.includes("[warn]")) return "warn";
  if (message.includes("[notice]")) return "notice";
  if (message.includes("[info]")) return "info";
  return null;
}

export default function TrafficLogsPage() {
  const { selectedAgent, setSelectedAgent } = useTraffic();
  const [logType, setLogType] = useState<LogType>("access");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lines, setLines] = useState("100");
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [levelFilter, setLevelFilter] = useState<LogLevel>("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [ipFilter, setIpFilter] = useState<string>("");
  const [selectedLog, setSelectedLog] = useState<NginxLogEntry | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Build agent options for FilterToolbar
  const agentOptions: SelectOption[] = agents
    ? agents.map((a) => ({
        value: a.id,
        label: a.name,
        disabled: a.status !== "active",
      }))
    : [];

  // Auto-select first active agent
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent, setSelectedAgent]);

  // Fetch proxies for domain list
  const { data: proxies } = useQuery({
    queryKey: ["proxies", selectedAgent],
    queryFn: () => (selectedAgent ? api.getProxyHosts(selectedAgent) : Promise.resolve([])),
    enabled: !!selectedAgent,
  });

  // Get unique domains from proxies
  const domains = useMemo(() => {
    if (!proxies) return [];
    return [...new Set(proxies.map((p) => p.domain))].sort();
  }, [proxies]);

  // Fetch nginx logs
  const {
    data: logsData,
    isLoading,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["nginx-logs", selectedAgent, logType, lines, selectedDomain],
    queryFn: async () => {
      if (!selectedAgent) return { logs: [] };
      const params = new URLSearchParams({
        type: logType,
        lines: lines,
      });
      if (selectedDomain) {
        params.append("domain", selectedDomain);
      }
      const response = await fetch(
        `/api/v1/agents/${selectedAgent}/logs/nginx?${params}`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        }
      );
      if (!response.ok) throw new Error("Failed to fetch logs");
      return response.json();
    },
    enabled: !!selectedAgent,
    refetchInterval: autoRefresh ? 5000 : false,
  });

  const logs: NginxLogEntry[] = logsData?.logs || [];

  // Filter logs by search and level
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // Search filter
      if (searchQuery) {
        const searchLower = searchQuery.toLowerCase();
        const matchesSearch =
          log.message.toLowerCase().includes(searchLower) ||
          log.ip?.toLowerCase().includes(searchLower) ||
          log.path?.toLowerCase().includes(searchLower);
        if (!matchesSearch) return false;
      }

      // Level filter for error logs
      if (logType === "error" && levelFilter !== "all") {
        const level = parseErrorLevel(log.message);
        if (levelFilter === "error" && level !== "error" && level !== "emerg") return false;
        if (levelFilter === "warn" && level !== "warn") return false;
        if (levelFilter === "info" && level !== "info" && level !== "notice") return false;
      }

      // Level filter for access logs (by status code)
      if (logType === "access" && levelFilter !== "all") {
        // Use structured status_code if available, otherwise parse from message
        let status = log.status_code;
        if (!status) {
          const parsed = parseAccessLog(log.message);
          status = parsed?.status;
        }
        if (status) {
          if (levelFilter === "error" && status < 500) return false;
          if (levelFilter === "warn" && (status < 400 || status >= 500)) return false;
          if (levelFilter === "info" && status >= 400) return false;
        }
      }

      // Method filter for access logs
      if (logType === "access" && methodFilter !== "all") {
        const method = log.method || parseAccessLog(log.message)?.method;
        if (method !== methodFilter) return false;
      }

      // IP filter
      if (ipFilter) {
        const clientIp = log.client_ip || log.ip || "";
        if (!clientIp.includes(ipFilter)) return false;
      }

      return true;
    });
  }, [logs, searchQuery, levelFilter, logType, methodFilter, ipFilter]);

  // Calculate metrics
  const metrics = useMemo(() => {
    const total = logs.length;
    let errors = 0;
    let warnings = 0;
    let success = 0;

    logs.forEach((log) => {
      if (logType === "access") {
        // Use structured status_code if available, otherwise parse from message
        let status = log.status_code;
        if (!status) {
          const parsed = parseAccessLog(log.message);
          status = parsed?.status;
        }
        if (status) {
          if (status >= 500) errors++;
          else if (status >= 400) warnings++;
          else if (status >= 200 && status < 400) success++;
        }
      } else {
        const level = parseErrorLevel(log.message);
        if (level === "error" || level === "emerg") errors++;
        else if (level === "warn") warnings++;
        else success++;
      }
    });

    return { total, errors, warnings, success };
  }, [logs, logType]);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoRefresh && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoRefresh]);

  // Export function
  const exportLogs = (format: string) => {
    let content: string;
    let mimeType: string;
    let extension: string;

    const logsToExport = filteredLogs;

    switch (format) {
      case "json":
        content = JSON.stringify(
          logsToExport.map((l) => ({
            ...l,
            ...(logType === "access" ? parseAccessLog(l.message) : {}),
          })),
          null,
          2
        );
        mimeType = "application/json";
        extension = "json";
        break;
      case "csv":
        if (logType === "access") {
          const headers = "timestamp,ip,method,path,status,bytes,referer,user_agent\n";
          const rows = logsToExport
            .map((l) => {
              const p = parseAccessLog(l.message);
              return p
                ? `"${p.timestamp}","${p.ip}","${p.method}","${p.path}",${p.status},${p.bytes},"${p.referer}","${p.userAgent}"`
                : "";
            })
            .filter(Boolean)
            .join("\n");
          content = headers + rows;
        } else {
          const headers = "level,message\n";
          const rows = logsToExport
            .map((l) => `"${parseErrorLevel(l.message) || "info"}","${l.message.replace(/"/g, '""')}"`)
            .join("\n");
          content = headers + rows;
        }
        mimeType = "text/csv";
        extension = "csv";
        break;
      default:
        content = logsToExport.map((l) => l.message).join("\n");
        mimeType = "text/plain";
        extension = "log";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const dateStr = new Date().toISOString().split("T")[0];
    const domainStr = selectedDomain ? `_${selectedDomain.replace(/\./g, "_")}` : "";
    a.download = `nginx-${logType}${domainStr}_${dateStr}.${extension}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Copy log to clipboard
  const copyToClipboard = async (text: string, index: number) => {
    await navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Scroll to bottom
  const scrollToBottom = () => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  };

  // Show loading only when we have an agent selected and are actually loading
  if (selectedAgent && isLoading && !logs.length) {
    return <Spinner.LogoPage label="Loading logs..." />;
  }

  return (
    <div className="space-y-6">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Total Entries"
          value={metrics.total}
          icon={FileText}
          iconColor="text-blue-600"
        />
        <StatCard
          label={logType === "access" ? "Successful (2xx/3xx)" : "Info/Notice"}
          value={metrics.success}
          icon={CheckCircle}
          iconColor="text-green-600"
        />
        <StatCard
          label={logType === "access" ? "Client Errors (4xx)" : "Warnings"}
          value={metrics.warnings}
          icon={AlertTriangle}
          iconColor="text-yellow-600"
        />
        <StatCard
          label={logType === "access" ? "Server Errors (5xx)" : "Errors"}
          value={metrics.errors}
          icon={AlertCircle}
          iconColor="text-red-600"
        />
      </MetricsGrid>

      {/* Filter Toolbar */}
      <FilterToolbar
        // Agent selector
        agents={agentOptions}
        selectedAgent={selectedAgent}
        onAgentChange={setSelectedAgent}
        showAgentFilter={true}
        // Domain selector
        domains={domains}
        selectedDomain={selectedDomain}
        onDomainChange={setSelectedDomain}
        showDomainFilter={true}
        // Log type toggle
        primaryToggle={{
          options: LOG_TYPE_OPTIONS,
          value: logType,
          onChange: (v) => setLogType(v as LogType),
        }}
        // Lines dropdown
        dropdownSelector={{
          options: DEFAULT_LINE_OPTIONS,
          value: lines,
          onChange: setLines,
        }}
        // Search
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search logs..."
        showSearch={true}
        // Status filter - changes based on log type
        statusFilter={{
          options: logType === "access" ? ACCESS_STATUS_OPTIONS : ERROR_STATUS_OPTIONS,
          value: levelFilter,
          onChange: (v) => setLevelFilter(v as LogLevel),
        }}
        // Auto-refresh
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        showAutoRefresh={true}
        autoRefreshLabel={{ active: "Live", inactive: "Paused" }}
        // Refresh
        onRefresh={() => refetch()}
        isRefreshing={isFetching}
        showRefresh={true}
        // Export
        exportOptions={LOG_EXPORT_OPTIONS}
        onExport={exportLogs}
        showExport={true}
      />

      {/* Secondary Filters: Method and IP */}
      {logType === "access" && (
        <div className="flex flex-wrap items-center gap-4 px-4 py-2 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
          {/* Method Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 font-medium">Method:</span>
            <div className="flex gap-1">
              {METHOD_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setMethodFilter(opt.value)}
                  className={cn(
                    "px-2 py-1 text-xs font-medium rounded transition-colors",
                    methodFilter === opt.value
                      ? opt.value === "GET" ? "bg-green-500 text-white" :
                        opt.value === "POST" ? "bg-blue-500 text-white" :
                        opt.value === "PUT" ? "bg-yellow-500 text-white" :
                        opt.value === "DELETE" ? "bg-red-500 text-white" :
                        "bg-gray-600 text-white"
                      : "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
                  )}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          {/* IP Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 font-medium">IP:</span>
            <input
              type="text"
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              placeholder="Filter by IP..."
              className="px-2 py-1 text-xs bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded w-32 focus:outline-none focus:ring-1 focus:ring-primary-500"
            />
            {ipFilter && (
              <button
                onClick={() => setIpFilter("")}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>
      )}

      {/* Active filters display */}
      {(searchQuery || selectedDomain || levelFilter !== "all" || methodFilter !== "all" || ipFilter) && (
        <div className="flex items-center gap-2 px-4 py-2 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
          <span className="text-xs text-gray-500">Active filters:</span>
          {selectedDomain && (
            <Badge color="blue" size="sm" className="gap-1">
              {selectedDomain}
              <button onClick={() => setSelectedDomain("")}>
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {searchQuery && (
            <Badge color="purple" size="sm" className="gap-1">
              &quot;{searchQuery}&quot;
              <button onClick={() => setSearchQuery("")}>
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {methodFilter !== "all" && (
            <Badge
              color={methodFilter === "GET" ? "green" : methodFilter === "POST" ? "blue" : methodFilter === "DELETE" ? "red" : "yellow"}
              size="sm"
              className="gap-1"
            >
              {methodFilter}
              <button onClick={() => setMethodFilter("all")}>
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {ipFilter && (
            <Badge color="cyan" size="sm" className="gap-1">
              IP: {ipFilter}
              <button onClick={() => setIpFilter("")}>
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {levelFilter !== "all" && (
            <Badge
              color={levelFilter === "error" ? "red" : levelFilter === "warn" ? "yellow" : "green"}
              size="sm"
              className="gap-1"
            >
              {levelFilter}
              <button onClick={() => setLevelFilter("all")}>
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          <span className="text-xs text-gray-500 ml-2">
            Showing {filteredLogs.length} of {logs.length} entries
          </span>
        </div>
      )}

      {/* Logs Display */}
      {!selectedAgent ? (
        <EmptyState
          icon={Terminal}
          title="Select an agent"
          description="Choose an agent to view its nginx logs"
        />
      ) : filteredLogs.length > 0 ? (
        <Card>
          <CardHeader
            action={
              <button
                onClick={scrollToBottom}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
              >
                <ArrowDown className="h-3 w-3" />
                Scroll to bottom
              </button>
            }
          >
            <div className="flex items-center gap-3">
              <Terminal className="h-5 w-5 text-gray-400" />
              <span className="font-medium text-gray-900 dark:text-white">
                {logType === "access" ? "Access" : "Error"} Logs
              </span>
              {selectedDomain && (
                <Badge color="blue" size="sm">
                  {selectedDomain}
                </Badge>
              )}
              <span className="text-sm text-gray-500">
                {filteredLogs.length} entries
              </span>
              {isFetching && (
                <Spinner size="sm" className="ml-2" />
              )}
            </div>
          </CardHeader>
          <CardBody noPadding>
            <div
              ref={logContainerRef}
              className="bg-gray-950 font-mono text-sm overflow-auto max-h-[600px] p-2 space-y-0.5"
            >
              {filteredLogs.map((log, index) => (
                <LogEntryRow
                  key={index}
                  log={log}
                  index={index}
                  logType={logType}
                  isSelected={selectedLog === log}
                  onClick={() => setSelectedLog(log)}
                  searchQuery={searchQuery}
                />
              ))}
            </div>
          </CardBody>
        </Card>
      ) : (
        <EmptyState
          icon={FileText}
          title={searchQuery ? "No logs match your search" : "No logs available"}
          description={
            searchQuery
              ? "Try adjusting your search terms or filters"
              : selectedDomain
              ? `No ${logType} logs found for ${selectedDomain}`
              : "Nginx logs will appear here when traffic is received"
          }
        />
      )}

      {/* Log Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title="Log Entry Details"
        size="md"
      >
        {selectedLog && (
          <div className="space-y-6">
            {/* Raw message */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Raw Log
              </label>
              <div className="relative">
                <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-xs overflow-auto max-h-48 whitespace-pre-wrap break-all">
                  {selectedLog.message}
                </pre>
                <button
                  onClick={() => copyToClipboard(selectedLog.message, -1)}
                  className="absolute top-2 right-2 p-1.5 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
                >
                  {copiedIndex === -1 ? (
                    <Check className="h-4 w-4 text-green-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Parsed fields for access logs */}
            {logType === "access" && (() => {
              const parsed = parseAccessLog(selectedLog.message);
              if (!parsed) return null;
              return (
                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Parsed Fields
                  </h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Status</label>
                      <Badge
                        color={
                          parsed.status >= 500
                            ? "red"
                            : parsed.status >= 400
                            ? "yellow"
                            : parsed.status >= 300
                            ? "blue"
                            : "green"
                        }
                      >
                        {parsed.status}
                      </Badge>
                    </div>
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Method</label>
                      <span className="font-medium">{parsed.method}</span>
                    </div>
                    <div className="col-span-2">
                      <label className="block text-xs text-gray-500 mb-1">Path</label>
                      <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded break-all">
                        {parsed.path}
                      </code>
                    </div>
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">IP Address</label>
                      <code className="text-sm">{parsed.ip}</code>
                    </div>
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Bytes</label>
                      <span>{parsed.bytes > 0 ? `${(parsed.bytes / 1024).toFixed(2)} KB` : "-"}</span>
                    </div>
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Timestamp</label>
                      <span className="text-sm">{parsed.timestamp}</span>
                    </div>
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Protocol</label>
                      <span className="text-sm">{parsed.protocol}</span>
                    </div>
                    {parsed.referer && (
                      <div className="col-span-2">
                        <label className="block text-xs text-gray-500 mb-1">Referer</label>
                        <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded break-all">
                          {parsed.referer}
                        </code>
                      </div>
                    )}
                    <div className="col-span-2">
                      <label className="block text-xs text-gray-500 mb-1">User Agent</label>
                      <code className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded break-all block">
                        {parsed.userAgent}
                      </code>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Error log details */}
            {logType === "error" && (
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Error Details
                </h4>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Level</label>
                  <Badge
                    color={
                      parseErrorLevel(selectedLog.message) === "error" ||
                      parseErrorLevel(selectedLog.message) === "emerg"
                        ? "red"
                        : parseErrorLevel(selectedLog.message) === "warn"
                        ? "yellow"
                        : "gray"
                    }
                  >
                    {(parseErrorLevel(selectedLog.message) || "info").toUpperCase()}
                  </Badge>
                </div>
              </div>
            )}
          </div>
        )}
      </SlideOver>
    </div>
  );
}
