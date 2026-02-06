"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  AlertTriangle,
  RefreshCw,
  Download,
  Search,
  Clock,
  Globe,
  AlertCircle,
  CheckCircle,
  Filter,
  ChevronDown,
  X,
  Copy,
  Check,
  Play,
  Pause,
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
import { Input, Button } from "@/components/ui/page-layout";
import { SlideOver } from "@/components/ui/SlideOver";
import { cn } from "@/lib/utils";

type LogType = "access" | "error";
type LogLevel = "all" | "info" | "warn" | "error";
type ExportFormat = "txt" | "json" | "csv";

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
  const parsed = logType === "access" ? parseAccessLog(log.message) : null;
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

  if (logType === "access" && parsed) {
    return (
      <div
        onClick={onClick}
        className={cn(
          "group flex items-center gap-3 py-2 px-3 rounded-md cursor-pointer transition-colors",
          isSelected
            ? "bg-primary-500/20 border border-primary-500/50"
            : "hover:bg-gray-800/50"
        )}
      >
        <span className="text-gray-600 text-xs font-mono w-8 text-right shrink-0">
          {index + 1}
        </span>
        <Badge
          color={getStatusColor(parsed.status)}
          className="font-mono text-xs shrink-0"
        >
          {parsed.status}
        </Badge>
        <span className={cn(
          "text-xs font-medium w-12 shrink-0",
          parsed.method === "GET" && "text-green-400",
          parsed.method === "POST" && "text-blue-400",
          parsed.method === "PUT" && "text-yellow-400",
          parsed.method === "DELETE" && "text-red-400",
          parsed.method === "PATCH" && "text-purple-400"
        )}>
          {parsed.method}
        </span>
        <span className="text-white flex-1 truncate font-mono text-sm">
          {highlightText(parsed.path, searchQuery)}
        </span>
        <span className="text-gray-500 text-xs shrink-0 hidden md:block">
          {parsed.bytes > 0 ? `${(parsed.bytes / 1024).toFixed(1)}KB` : "-"}
        </span>
        <span className="text-gray-500 text-xs font-mono shrink-0">
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
      <div className="flex items-start gap-3">
        <span className="text-gray-600 text-xs font-mono w-8 text-right shrink-0 pt-0.5">
          {index + 1}
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
  const [lines, setLines] = useState(100);
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [levelFilter, setLevelFilter] = useState<LogLevel>("all");
  const [selectedLog, setSelectedLog] = useState<NginxLogEntry | null>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

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
        lines: lines.toString(),
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
        const parsed = parseAccessLog(log.message);
        if (parsed) {
          if (levelFilter === "error" && parsed.status < 500) return false;
          if (levelFilter === "warn" && (parsed.status < 400 || parsed.status >= 500)) return false;
          if (levelFilter === "info" && parsed.status >= 400) return false;
        }
      }

      return true;
    });
  }, [logs, searchQuery, levelFilter, logType]);

  // Calculate metrics
  const metrics = useMemo(() => {
    const total = logs.length;
    let errors = 0;
    let warnings = 0;
    let success = 0;

    logs.forEach((log) => {
      if (logType === "access") {
        const parsed = parseAccessLog(log.message);
        if (parsed) {
          if (parsed.status >= 500) errors++;
          else if (parsed.status >= 400) warnings++;
          else if (parsed.status >= 200 && parsed.status < 400) success++;
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

  // Close export menu on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Export functions
  const exportLogs = (format: ExportFormat) => {
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
    setShowExportMenu(false);
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

      {/* Controls Card */}
      <Card>
        <CardBody className="space-y-4">
          {/* Top row: Agent, Domain, Log Type */}
          <div className="flex flex-wrap items-center gap-4">
            {/* Agent Selector */}
            <div className="flex items-center gap-2">
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
                Agent
              </label>
              <select
                value={selectedAgent || ""}
                onChange={(e) => setSelectedAgent(e.target.value || null)}
                className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              >
                <option value="">Select agent...</option>
                {agents?.map((agent) => (
                  <option key={agent.id} value={agent.id} disabled={agent.status !== "active"}>
                    {agent.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Domain Selector */}
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-gray-400" />
              <select
                value={selectedDomain}
                onChange={(e) => setSelectedDomain(e.target.value)}
                className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              >
                <option value="">All Domains</option>
                {domains.map((domain) => (
                  <option key={domain} value={domain}>
                    {domain}
                  </option>
                ))}
              </select>
            </div>

            {/* Log Type Toggle */}
            <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
              <button
                onClick={() => setLogType("access")}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                  logType === "access"
                    ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
                    : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
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
                    : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                )}
              >
                Error Logs
              </button>
            </div>

            {/* Lines selector */}
            <select
              value={lines}
              onChange={(e) => setLines(parseInt(e.target.value))}
              className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
            >
              <option value={50}>Last 50</option>
              <option value={100}>Last 100</option>
              <option value={250}>Last 250</option>
              <option value={500}>Last 500</option>
            </select>
          </div>

          {/* Bottom row: Search, Level Filter, Actions */}
          <div className="flex flex-wrap items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search logs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 w-full"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>

            {/* Level Filter */}
            <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
              <button
                onClick={() => setLevelFilter("all")}
                className={cn(
                  "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                  levelFilter === "all"
                    ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
                    : "text-gray-600 dark:text-gray-400"
                )}
              >
                All
              </button>
              <button
                onClick={() => setLevelFilter("info")}
                className={cn(
                  "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                  levelFilter === "info"
                    ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                    : "text-gray-600 dark:text-gray-400"
                )}
              >
                {logType === "access" ? "2xx/3xx" : "Info"}
              </button>
              <button
                onClick={() => setLevelFilter("warn")}
                className={cn(
                  "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                  levelFilter === "warn"
                    ? "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300"
                    : "text-gray-600 dark:text-gray-400"
                )}
              >
                {logType === "access" ? "4xx" : "Warn"}
              </button>
              <button
                onClick={() => setLevelFilter("error")}
                className={cn(
                  "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                  levelFilter === "error"
                    ? "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300"
                    : "text-gray-600 dark:text-gray-400"
                )}
              >
                {logType === "access" ? "5xx" : "Error"}
              </button>
            </div>

            <div className="flex items-center gap-2 ml-auto">
              {/* Auto-refresh toggle */}
              <button
                onClick={() => setAutoRefresh(!autoRefresh)}
                className={cn(
                  "inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                  autoRefresh
                    ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 border border-green-300 dark:border-green-800"
                    : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
                )}
              >
                {autoRefresh ? (
                  <Pause className="h-4 w-4" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                {autoRefresh ? "Live" : "Paused"}
              </button>

              {/* Manual refresh */}
              <button
                onClick={() => refetch()}
                disabled={isFetching}
                className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
                Refresh
              </button>

              {/* Export dropdown */}
              <div className="relative" ref={exportMenuRef}>
                <button
                  onClick={() => setShowExportMenu(!showExportMenu)}
                  className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors"
                >
                  <Download className="h-4 w-4" />
                  Export
                  <ChevronDown className="h-3 w-3" />
                </button>
                {showExportMenu && (
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-10">
                    <button
                      onClick={() => exportLogs("txt")}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 first:rounded-t-lg"
                    >
                      <Terminal className="h-4 w-4" />
                      Plain Text (.log)
                    </button>
                    <button
                      onClick={() => exportLogs("json")}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
                    >
                      <FileJson className="h-4 w-4" />
                      JSON (.json)
                    </button>
                    <button
                      onClick={() => exportLogs("csv")}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 last:rounded-b-lg"
                    >
                      <FileSpreadsheet className="h-4 w-4" />
                      CSV (.csv)
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Active filters display */}
          {(searchQuery || selectedDomain || levelFilter !== "all") && (
            <div className="flex items-center gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
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
                  "{searchQuery}"
                  <button onClick={() => setSearchQuery("")}>
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
        </CardBody>
      </Card>

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
