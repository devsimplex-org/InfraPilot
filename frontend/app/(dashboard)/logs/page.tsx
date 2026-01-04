"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  Search,
  RefreshCw,
  Filter,
  ChevronDown,
  AlertCircle,
  AlertTriangle,
  Info,
  Bug,
  Server,
  Globe,
  Pause,
  Play,
  Download,
} from "lucide-react";
import { api, LogEntry, Agent } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  PageLayout,
  Button,
  Tabs,
  Input,
  EmptyState,
} from "@/components/ui/page-layout";

type Tab = "unified" | "nginx";
type LogLevel = "all" | "error" | "warn" | "info" | "debug";

export default function LogsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("unified");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LogLevel>("all");
  const [tail, setTail] = useState(200);
  const [nginxType, setNginxType] = useState<"access" | "error">("access");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
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
    isLoading: unifiedLoading,
    refetch: refetchUnified,
  } = useQuery({
    queryKey: ["unifiedLogs", selectedAgentId, search, level, tail],
    queryFn: () =>
      api.getUnifiedLogs(selectedAgentId, {
        search: search || undefined,
        levels: level !== "all" ? [level] : undefined,
        tail,
      }),
    enabled: !!selectedAgentId && activeTab === "unified",
    refetchInterval: autoRefresh ? 5000 : false,
  });

  // Fetch nginx logs
  const {
    data: nginxLogs,
    isLoading: nginxLoading,
    refetch: refetchNginx,
  } = useQuery({
    queryKey: ["nginxLogs", selectedAgentId, nginxType, tail],
    queryFn: () => api.getNginxLogs(selectedAgentId, nginxType, tail),
    enabled: !!selectedAgentId && activeTab === "nginx",
    refetchInterval: autoRefresh ? 5000 : false,
  });

  const handleRefresh = useCallback(() => {
    if (activeTab === "unified") {
      refetchUnified();
    } else {
      refetchNginx();
    }
  }, [activeTab, refetchUnified, refetchNginx]);

  const getLevelIcon = (logLevel: string) => {
    switch (logLevel) {
      case "error":
        return <AlertCircle className="h-3.5 w-3.5 text-red-500" />;
      case "warn":
        return <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />;
      case "debug":
        return <Bug className="h-3.5 w-3.5 text-purple-500" />;
      default:
        return <Info className="h-3.5 w-3.5 text-blue-500" />;
    }
  };

  const getLevelColor = (logLevel: string) => {
    switch (logLevel) {
      case "error":
        return "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800";
      case "warn":
        return "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800";
      case "debug":
        return "bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800";
      default:
        return "bg-gray-50 dark:bg-gray-800/50 border-gray-200 dark:border-gray-700";
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
      });
    } catch {
      return timestamp;
    }
  };

  const formatDate = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });
    } catch {
      return "";
    }
  };

  const exportLogs = () => {
    const logs = activeTab === "unified" ? unifiedLogs?.logs : nginxLogs?.logs;
    if (!logs || logs.length === 0) return;

    const content = logs
      .map(
        (log) =>
          `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.container_name ? `[${log.container_name}] ` : ""}${log.message}`
      )
      .join("\n");

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logs-${activeTab}-${new Date().toISOString().split("T")[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const tabs = [
    { id: "unified", label: "All Logs" },
    { id: "nginx", label: "Nginx" },
  ];

  const currentLogs = activeTab === "unified" ? unifiedLogs?.logs : nginxLogs?.logs;
  const isLoading = activeTab === "unified" ? unifiedLoading : nginxLoading;

  return (
    <PageLayout
      title="Logs"
      description="Consolidated logs from all containers and services"
      actions={
        <div className="flex items-center gap-2">
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
            disabled={!currentLogs || currentLogs.length === 0}
          >
            Export
          </Button>
        </div>
      }
    >
      {/* Agent selector and tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-4">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-gray-500" />
          <select
            value={selectedAgentId}
            onChange={(e) => setSelectedAgentId(e.target.value)}
            className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
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

        <Tabs
          tabs={tabs}
          activeTab={activeTab}
          onChange={(id) => setActiveTab(id as Tab)}
        />

        <div className="flex-1" />

        {/* Filters toggle */}
        <Button
          variant="ghost"
          size="sm"
          icon={Filter}
          onClick={() => setShowFilters(!showFilters)}
          className={showFilters ? "bg-gray-100 dark:bg-gray-800" : ""}
        >
          Filters
          <ChevronDown
            className={cn(
              "h-4 w-4 ml-1 transition-transform",
              showFilters && "rotate-180"
            )}
          />
        </Button>
      </div>

      {/* Filters panel */}
      {showFilters && (
        <div className="mb-4 p-4 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <div className="flex flex-wrap items-center gap-4">
            {/* Search */}
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search logs..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white placeholder-gray-500 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>
            </div>

            {/* Level filter */}
            {activeTab === "unified" && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">Level:</span>
                <div className="flex items-center gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg">
                  {(["all", "error", "warn", "info", "debug"] as LogLevel[]).map(
                    (l) => (
                      <button
                        key={l}
                        onClick={() => setLevel(l)}
                        className={cn(
                          "px-2.5 py-1 text-xs font-medium rounded-md transition-colors capitalize",
                          level === l
                            ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                            : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                        )}
                      >
                        {l}
                      </button>
                    )
                  )}
                </div>
              </div>
            )}

            {/* Nginx log type */}
            {activeTab === "nginx" && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">Type:</span>
                <div className="flex items-center gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg">
                  {(["access", "error"] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setNginxType(t)}
                      className={cn(
                        "px-2.5 py-1 text-xs font-medium rounded-md transition-colors capitalize",
                        nginxType === t
                          ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                          : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                      )}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Tail limit */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">Lines:</span>
              <select
                value={tail}
                onChange={(e) => setTail(parseInt(e.target.value))}
                className="px-2.5 py-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              >
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Logs display */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <FileText className="h-4 w-4" />
            <span>
              {currentLogs?.length || 0} log entries
              {autoRefresh && (
                <span className="ml-2 inline-flex items-center gap-1 text-green-600 dark:text-green-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                  Live
                </span>
              )}
            </span>
          </div>
          {activeTab === "nginx" && (
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <Globe className="h-3.5 w-3.5" />
              {nginxType === "access" ? "Access Log" : "Error Log"}
            </div>
          )}
        </div>

        {/* Log entries */}
        <div className="h-[calc(100vh-380px)] min-h-[400px] overflow-auto font-mono text-xs">
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
            </div>
          ) : !selectedAgentId ? (
            <div className="py-12">
              <EmptyState
                icon={Server}
                title="No agent selected"
                description="Select an agent to view logs"
              />
            </div>
          ) : currentLogs && currentLogs.length > 0 ? (
            <div className="divide-y divide-gray-100 dark:divide-gray-800">
              {currentLogs.map((log, index) => (
                <div
                  key={`${log.timestamp}-${index}`}
                  className={cn(
                    "flex items-start gap-3 px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-800/30 transition-colors",
                    getLevelColor(log.level)
                  )}
                >
                  <div className="flex-shrink-0 pt-0.5">
                    {getLevelIcon(log.level)}
                  </div>
                  <div className="flex-shrink-0 text-gray-400 dark:text-gray-500 w-16 text-right">
                    <div>{formatTimestamp(log.timestamp)}</div>
                    <div className="text-[10px]">{formatDate(log.timestamp)}</div>
                  </div>
                  {log.container_name && (
                    <div className="flex-shrink-0 px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-300 max-w-[120px] truncate">
                      {log.container_name}
                    </div>
                  )}
                  <div className="flex-1 text-gray-900 dark:text-gray-100 break-all whitespace-pre-wrap">
                    {log.message}
                  </div>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          ) : (
            <div className="py-12">
              <EmptyState
                icon={FileText}
                title="No logs found"
                description={
                  search
                    ? "Try adjusting your search or filters"
                    : "No log entries available"
                }
              />
            </div>
          )}
        </div>
      </div>
    </PageLayout>
  );
}
