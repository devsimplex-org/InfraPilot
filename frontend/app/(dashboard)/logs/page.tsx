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
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { FilterPanel, type FilterGroup } from "@/components/ui/FilterPanel";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SlideOver } from "@/components/ui/SlideOver";
import {
  Button,
  Tabs,
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

  // Filter configuration
  const filters: FilterGroup[] = [
    {
      id: "search",
      label: "Search",
      type: "search",
      value: search,
      onChange: (value: string | string[]) => setSearch(value as string),
    },
  ];

  if (activeTab === "unified") {
    filters.push({
      id: "level",
      label: "Log Level",
      type: "radio",
      value: level,
      onChange: (value: string | string[]) => setLevel(value as LogLevel),
      options: [
        { label: "All", value: "all" },
        { label: "Error", value: "error" },
        { label: "Warning", value: "warn" },
        { label: "Info", value: "info" },
        { label: "Debug", value: "debug" },
      ],
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Logs"
        description="Consolidated logs from all containers and services"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Run", href: "/" },
              { label: "Logs", current: true },
            ]}
          />
        }
        action={
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
      />

      {/* Agent selector and tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
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
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-1">
            <FilterPanel
              filters={filters}
              onReset={() => {
                setSearch("");
                setLevel("all");
              }}
            />
          </div>

          <div className="md:col-span-3 space-y-4">
            {/* Additional filters */}
            <div className="flex flex-wrap items-center gap-4 p-4 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
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
        </div>
      )}

      {/* Logs display */}
      <Card>
        {/* Header */}
        <Card.Header>
          <div className="flex items-center justify-between">
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
        </Card.Header>

        {/* Log entries */}
        <Card.Body noPadding>
          <div className="h-[calc(100vh-380px)] min-h-[400px] overflow-auto font-mono text-xs">
            {isLoading ? (
              <div className="flex items-center justify-center h-32">
                <Spinner />
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
                    onClick={() => setSelectedLog(log)}
                    className={cn(
                      "flex items-start gap-3 px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-800/30 transition-colors cursor-pointer",
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
                      <Badge size="sm" className="flex-shrink-0 max-w-[120px] truncate">
                        {log.container_name}
                      </Badge>
                    )}
                    <div className="flex-1 text-gray-900 dark:text-gray-100 break-all whitespace-pre-wrap line-clamp-2">
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
        </Card.Body>
      </Card>

      {/* Log Details SlideOver */}
      <SlideOver isOpen={!!selectedLog} onClose={() => setSelectedLog(null)} size="lg">
        <SlideOver.Header onClose={() => setSelectedLog(null)}>
          <div className="flex items-center gap-2">
            {selectedLog && getLevelIcon(selectedLog.level)}
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Log Entry Details
            </h2>
          </div>
        </SlideOver.Header>
        <SlideOver.Body>
          {selectedLog && (
            <div className="space-y-6">
              {/* Metadata */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Metadata</h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-xs text-gray-500 mb-1">Timestamp</p>
                    <p className="text-sm text-gray-900 dark:text-white">{new Date(selectedLog.timestamp).toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 mb-1">Level</p>
                    <Badge>{selectedLog.level.toUpperCase()}</Badge>
                  </div>
                  {selectedLog.container_name && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Container</p>
                      <Badge>{selectedLog.container_name}</Badge>
                    </div>
                  )}
                </div>
              </div>

              {/* Message */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Message</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded-lg p-4">
                  <pre className="text-sm text-gray-900 dark:text-white font-mono whitespace-pre-wrap break-all">
                    {selectedLog.message}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </SlideOver.Body>
      </SlideOver>
    </div>
  );
}
