"use client";

import { useState, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Clock,
  Globe,
  Users,
  Zap,
} from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { FilterToolbar, DEFAULT_TIME_RANGES, DEFAULT_EXPORT_OPTIONS, SelectOption, TimeRangeOption, ToggleOption } from "@/components/ui/FilterToolbar";
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

// =============================================================================
// Filter Options
// =============================================================================

const ANALYTICS_STATUS_OPTIONS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "success", label: "2xx/3xx", color: "green" },
  { value: "errors", label: "4xx/5xx", color: "red" },
];

// =============================================================================
// Types
// =============================================================================

interface NginxAnalyticsDataPoint {
  bucket: string;
  total_requests: number;
  count_2xx: number;
  count_3xx: number;
  count_4xx: number;
  count_5xx: number;
  total_bytes: number;
  avg_response_time: number;
  p95_response_time: number;
  p99_response_time: number;
  max_response_time: number;
  min_response_time: number;
  unique_visitors: number;
}

interface NginxAnalyticsResponse {
  interval: string;
  start_time: string;
  end_time: string;
  data_points: NginxAnalyticsDataPoint[];
}

interface NginxAnalyticsSummary {
  total_requests: number;
  total_bytes: number;
  unique_visitors: number;
  avg_response_time: number;
  p95_response_time: number;
  p99_response_time: number;
  error_rate: number;
  count_2xx: number;
  count_3xx: number;
  count_4xx: number;
  count_5xx: number;
  requests_per_second: number;
  bytes_per_second: number;
}

interface NginxTopPath {
  path: string;
  request_count: number;
  total_bytes: number;
  avg_response_time: number;
  p95_response_time: number;
  count_4xx: number;
  count_5xx: number;
  error_rate: number;
  unique_visitors: number;
}

interface StatusCodeDistribution {
  status_codes: Array<{
    status_code: number;
    count: number;
    percentage: number;
  }>;
  categories: {
    "2xx": number;
    "3xx": number;
    "4xx": number;
    "5xx": number;
  };
  total: number;
}

// =============================================================================
// Constants
// =============================================================================

const STATUS_COLORS = {
  "2xx": "#22c55e", // green
  "3xx": "#3b82f6", // blue
  "4xx": "#f59e0b", // amber
  "5xx": "#ef4444", // red
};

const PIE_COLORS = ["#22c55e", "#3b82f6", "#f59e0b", "#ef4444"];

// =============================================================================
// Helper Functions
// =============================================================================

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatResponseTime(ms: number): string {
  if (ms < 0.001) return "< 1ms";
  if (ms < 1) return `${(ms * 1000).toFixed(0)}ms`;
  return `${ms.toFixed(2)}s`;
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// =============================================================================
// Main Component
// =============================================================================

export default function TrafficAnalyticsPage() {
  const queryClient = useQueryClient();

  // State
  const [selectedRange, setSelectedRange] = useState<TimeRangeOption>(DEFAULT_TIME_RANGES[2]); // Default 30m
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

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

  // Helper to build time params based on unit (minutes or hours)
  const getTimeParams = (): Record<string, string> => {
    if (selectedRange.unit === "minutes") {
      return { minutes: selectedRange.value.toString() };
    }
    return { hours: selectedRange.value.toString() };
  };

  // Fetch analytics data
  const { data: analytics, isLoading: isLoadingAnalytics, isFetching: isFetchingAnalytics } = useQuery({
    queryKey: ["traffic-analytics", selectedRange.value, selectedRange.unit, selectedRange.interval, selectedAgent, selectedDomain],
    queryFn: async () => {
      const params = new URLSearchParams({
        ...getTimeParams(),
        interval: selectedRange.interval || "1m",
      });
      if (selectedAgent) {
        params.append("agent_id", selectedAgent);
      }
      if (selectedDomain) {
        params.append("domain", selectedDomain);
      }
      return api.fetchAPI<NginxAnalyticsResponse>(`/traffic/analytics?${params}`);
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  // Fetch summary
  const { data: summary, isLoading: isLoadingSummary } = useQuery({
    queryKey: ["traffic-analytics-summary", selectedRange.value, selectedRange.unit, selectedAgent, selectedDomain],
    queryFn: async () => {
      const params = new URLSearchParams(getTimeParams());
      if (selectedAgent) {
        params.append("agent_id", selectedAgent);
      }
      if (selectedDomain) {
        params.append("domain", selectedDomain);
      }
      return api.fetchAPI<NginxAnalyticsSummary>(`/traffic/analytics/summary?${params}`);
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  // Fetch top paths
  const { data: topPathsResponse, isLoading: isLoadingTopPaths } = useQuery({
    queryKey: ["traffic-top-paths", selectedRange.value, selectedRange.unit, selectedAgent, selectedDomain],
    queryFn: async () => {
      const params = new URLSearchParams({
        ...getTimeParams(),
        limit: "15",
      });
      if (selectedAgent) {
        params.append("agent_id", selectedAgent);
      }
      if (selectedDomain) {
        params.append("domain", selectedDomain);
      }
      return api.fetchAPI<{ paths: NginxTopPath[] }>(`/traffic/analytics/top-paths?${params}`);
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  // Fetch status codes
  const { data: statusCodes, isLoading: isLoadingStatusCodes } = useQuery({
    queryKey: ["traffic-status-codes", selectedRange.value, selectedRange.unit, selectedAgent, selectedDomain],
    queryFn: async () => {
      const params = new URLSearchParams(getTimeParams());
      if (selectedAgent) {
        params.append("agent_id", selectedAgent);
      }
      if (selectedDomain) {
        params.append("domain", selectedDomain);
      }
      return api.fetchAPI<StatusCodeDistribution>(`/traffic/analytics/status-codes?${params}`);
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  // Prepare chart data
  const chartData = useMemo(() => {
    if (!analytics?.data_points) return [];
    return analytics.data_points.map((dp) => ({
      time: formatTime(dp.bucket),
      requests: dp.total_requests,
      "2xx": dp.count_2xx,
      "3xx": dp.count_3xx,
      "4xx": dp.count_4xx,
      "5xx": dp.count_5xx,
      avgLatency: dp.avg_response_time * 1000, // Convert to ms
      p95Latency: dp.p95_response_time * 1000,
      visitors: dp.unique_visitors,
      bytes: dp.total_bytes,
    }));
  }, [analytics]);

  // Prepare pie chart data
  const pieData = useMemo(() => {
    if (!statusCodes?.categories) return [];
    return [
      { name: "2xx Success", value: statusCodes.categories["2xx"], color: STATUS_COLORS["2xx"] },
      { name: "3xx Redirect", value: statusCodes.categories["3xx"], color: STATUS_COLORS["3xx"] },
      { name: "4xx Client Error", value: statusCodes.categories["4xx"], color: STATUS_COLORS["4xx"] },
      { name: "5xx Server Error", value: statusCodes.categories["5xx"], color: STATUS_COLORS["5xx"] },
    ].filter((d) => d.value > 0);
  }, [statusCodes]);

  // Top paths table columns
  const topPathsColumns = [
    {
      key: "path",
      header: "Path",
      render: (value: string) => (
        <span className="font-mono text-sm text-gray-900 dark:text-white truncate max-w-xs block">
          {value}
        </span>
      ),
    },
    {
      key: "request_count",
      header: "Requests",
      width: "100px",
      align: "right" as const,
      render: (value: number) => (
        <span className="font-medium text-gray-900 dark:text-white">{formatNumber(value)}</span>
      ),
    },
    {
      key: "avg_response_time",
      header: "Avg Latency",
      width: "100px",
      align: "right" as const,
      render: (value: number) => (
        <span className="text-gray-600 dark:text-gray-400">{formatResponseTime(value)}</span>
      ),
    },
    {
      key: "p95_response_time",
      header: "P95",
      width: "100px",
      align: "right" as const,
      render: (value: number) => (
        <span className="text-gray-600 dark:text-gray-400">{formatResponseTime(value)}</span>
      ),
    },
    {
      key: "total_bytes",
      header: "Bandwidth",
      width: "100px",
      align: "right" as const,
      render: (value: number) => (
        <span className="text-gray-600 dark:text-gray-400">{formatBytes(value)}</span>
      ),
    },
    {
      key: "error_rate",
      header: "Errors",
      width: "100px",
      align: "right" as const,
      render: (value: number, row: NginxTopPath) => {
        const hasErrors = row.count_4xx + row.count_5xx > 0;
        return (
          <span className={hasErrors ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}>
            {value.toFixed(1)}%
          </span>
        );
      },
    },
  ];

  const isLoading = isLoadingAnalytics || isLoadingSummary;

  // Loading state
  if (isLoading && !summary) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Traffic Analytics"
          description="Real-time nginx access log analytics and insights"
          breadcrumbs={
            <Breadcrumb
              items={[
                { label: "Overview", href: "/" },
                { label: "Traffic", href: "/traffic" },
                { label: "Analytics", current: true },
              ]}
            />
          }
        />
        <Spinner.Page label="Loading analytics..." />
      </div>
    );
  }

  // Build agent options for FilterToolbar
  const agentOptions: SelectOption[] = agents
    ? agents
        .filter((a) => a.status === "active")
        .map((a) => ({ value: a.id, label: a.name }))
    : [];

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["traffic-analytics"] });
    queryClient.invalidateQueries({ queryKey: ["traffic-analytics-summary"] });
    queryClient.invalidateQueries({ queryKey: ["traffic-top-paths"] });
    queryClient.invalidateQueries({ queryKey: ["traffic-status-codes"] });
  };

  const handleExport = (format: string) => {
    if (!summary || !topPathsResponse?.paths) return;

    const exportData = {
      timeRange: selectedRange.label,
      summary: summary,
      topPaths: topPathsResponse.paths,
      statusCodes: statusCodes,
      chartData: chartData,
    };

    let content: string;
    let mimeType: string;
    let extension: string;

    switch (format) {
      case "json":
        content = JSON.stringify(exportData, null, 2);
        mimeType = "application/json";
        extension = "json";
        break;
      case "csv":
        // Export top paths as CSV
        const headers = "path,requests,avg_latency,p95_latency,bandwidth,error_rate\n";
        const rows = topPathsResponse.paths
          .map((p) => `"${p.path}",${p.request_count},${p.avg_response_time},${p.p95_response_time},${p.total_bytes},${p.error_rate}`)
          .join("\n");
        content = headers + rows;
        mimeType = "text/csv";
        extension = "csv";
        break;
      default:
        // Plain text summary
        content = `Traffic Analytics Report - ${selectedRange.label}\n`;
        content += `Generated: ${new Date().toISOString()}\n\n`;
        content += `Summary:\n`;
        content += `  Total Requests: ${summary.total_requests}\n`;
        content += `  Error Rate: ${summary.error_rate.toFixed(2)}%\n`;
        content += `  Avg Latency: ${(summary.avg_response_time * 1000).toFixed(1)}ms\n`;
        content += `  P95 Latency: ${(summary.p95_response_time * 1000).toFixed(1)}ms\n`;
        content += `  Unique Visitors: ${summary.unique_visitors}\n\n`;
        content += `Top Paths:\n`;
        topPathsResponse.paths.forEach((p, i) => {
          content += `  ${i + 1}. ${p.path} - ${p.request_count} requests\n`;
        });
        mimeType = "text/plain";
        extension = "txt";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const dateStr = new Date().toISOString().split("T")[0];
    a.download = `traffic-analytics_${selectedRange.label}_${dateStr}.${extension}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // No data state
  if (!isLoading && (!summary || summary.total_requests === 0)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Traffic Analytics"
          description="Real-time nginx access log analytics and insights"
          breadcrumbs={
            <Breadcrumb
              items={[
                { label: "Overview", href: "/" },
                { label: "Traffic", href: "/traffic" },
                { label: "Analytics", current: true },
              ]}
            />
          }
        />
        <FilterToolbar
          agents={agentOptions}
          selectedAgent={selectedAgent}
          onAgentChange={setSelectedAgent}
          showAgentFilter={agentOptions.length > 1}
          domains={domains}
          selectedDomain={selectedDomain}
          onDomainChange={setSelectedDomain}
          showDomainFilter={true}
          timeRange={{
            options: DEFAULT_TIME_RANGES,
            value: selectedRange,
            onChange: setSelectedRange,
          }}
          statusFilter={{
            options: ANALYTICS_STATUS_OPTIONS,
            value: statusFilter,
            onChange: setStatusFilter,
          }}
          showSearch={false}
          showAutoRefresh={true}
          autoRefresh={autoRefresh}
          onAutoRefreshChange={setAutoRefresh}
          autoRefreshLabel={{ active: "Live", inactive: "Auto" }}
          showRefresh={true}
          onRefresh={handleRefresh}
          isRefreshing={isFetchingAnalytics}
          exportOptions={DEFAULT_EXPORT_OPTIONS}
          onExport={handleExport}
          showExport={true}
        />
        <EmptyState
          icon={Activity}
          title="No traffic data available"
          description="Traffic analytics will appear here once nginx access logs start flowing from your agents."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Traffic Analytics"
        description="Real-time nginx access log analytics and insights"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Overview", href: "/" },
              { label: "Traffic", href: "/traffic" },
              { label: "Analytics", current: true },
            ]}
          />
        }
      />

      {/* Filter Toolbar */}
      <FilterToolbar
        agents={agentOptions}
        selectedAgent={selectedAgent}
        onAgentChange={setSelectedAgent}
        showAgentFilter={agentOptions.length > 1}
        domains={domains}
        selectedDomain={selectedDomain}
        onDomainChange={setSelectedDomain}
        showDomainFilter={true}
        timeRange={{
          options: DEFAULT_TIME_RANGES,
          value: selectedRange,
          onChange: setSelectedRange,
        }}
        statusFilter={{
          options: ANALYTICS_STATUS_OPTIONS,
          value: statusFilter,
          onChange: setStatusFilter,
        }}
        showSearch={false}
        showAutoRefresh={true}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        autoRefreshLabel={{ active: "Live", inactive: "Auto" }}
        showRefresh={true}
        onRefresh={handleRefresh}
        isRefreshing={isFetchingAnalytics}
        exportOptions={DEFAULT_EXPORT_OPTIONS}
        onExport={handleExport}
        showExport={true}
      />

      {/* Summary Stats */}
      {summary && (
        <MetricsGrid columns={5}>
          <StatCard
            label="Total Requests"
            value={formatNumber(summary.total_requests)}
            description={`${summary.requests_per_second.toFixed(1)} req/s`}
            icon={Activity}
            iconColor="text-blue-600 dark:text-blue-400"
          />
          <StatCard
            label="Error Rate"
            value={`${summary.error_rate.toFixed(2)}%`}
            description={`${formatNumber(summary.count_4xx + summary.count_5xx)} errors`}
            icon={AlertTriangle}
            iconColor={
              summary.error_rate > 5
                ? "text-red-600 dark:text-red-400"
                : summary.error_rate > 1
                ? "text-yellow-600 dark:text-yellow-400"
                : "text-green-600 dark:text-green-400"
            }
            valueColor={
              summary.error_rate > 5
                ? "text-red-600 dark:text-red-400"
                : summary.error_rate > 1
                ? "text-yellow-600 dark:text-yellow-400"
                : "text-green-600 dark:text-green-400"
            }
          />
          <StatCard
            label="Avg Latency"
            value={formatResponseTime(summary.avg_response_time)}
            description={`P95: ${formatResponseTime(summary.p95_response_time)}`}
            icon={Clock}
            iconColor="text-purple-600 dark:text-purple-400"
          />
          <StatCard
            label="P99 Latency"
            value={formatResponseTime(summary.p99_response_time)}
            description="99th percentile"
            icon={Zap}
            iconColor="text-orange-600 dark:text-orange-400"
          />
          <StatCard
            label="Unique Visitors"
            value={formatNumber(summary.unique_visitors)}
            description={formatBytes(summary.total_bytes) + " transferred"}
            icon={Users}
            iconColor="text-indigo-600 dark:text-indigo-400"
          />
        </MetricsGrid>
      )}

      {/* Charts Row 1: Request Rate */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request Rate Chart */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Request Rate
            </h3>
          </Card.Header>
          <Card.Body>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" fontSize={12} />
                <YAxis stroke="#9CA3AF" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1F2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="2xx"
                  stackId="1"
                  stroke={STATUS_COLORS["2xx"]}
                  fill={STATUS_COLORS["2xx"]}
                  fillOpacity={0.6}
                  name="2xx"
                />
                <Area
                  type="monotone"
                  dataKey="3xx"
                  stackId="1"
                  stroke={STATUS_COLORS["3xx"]}
                  fill={STATUS_COLORS["3xx"]}
                  fillOpacity={0.6}
                  name="3xx"
                />
                <Area
                  type="monotone"
                  dataKey="4xx"
                  stackId="1"
                  stroke={STATUS_COLORS["4xx"]}
                  fill={STATUS_COLORS["4xx"]}
                  fillOpacity={0.6}
                  name="4xx"
                />
                <Area
                  type="monotone"
                  dataKey="5xx"
                  stackId="1"
                  stroke={STATUS_COLORS["5xx"]}
                  fill={STATUS_COLORS["5xx"]}
                  fillOpacity={0.6}
                  name="5xx"
                />
              </AreaChart>
            </ResponsiveContainer>
          </Card.Body>
        </Card>

        {/* Response Time Chart */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Response Time
            </h3>
          </Card.Header>
          <Card.Body>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" fontSize={12} />
                <YAxis stroke="#9CA3AF" fontSize={12} unit="ms" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1F2937",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                  }}
                  formatter={(value: number) => [`${value.toFixed(1)}ms`]}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="avgLatency"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={false}
                  name="Avg"
                />
                <Line
                  type="monotone"
                  dataKey="p95Latency"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  dot={false}
                  name="P95"
                />
              </LineChart>
            </ResponsiveContainer>
          </Card.Body>
        </Card>
      </div>

      {/* Charts Row 2: Status Codes + Bandwidth */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Status Code Distribution */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Status Codes
            </h3>
          </Card.Header>
          <Card.Body>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) =>
                      percent > 0.05 ? `${(percent * 100).toFixed(0)}%` : ""
                    }
                    labelLine={false}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1F2937",
                      border: "1px solid #374151",
                      borderRadius: "8px",
                    }}
                    formatter={(value: number) => [formatNumber(value), "Requests"]}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[250px] text-gray-500">
                No data available
              </div>
            )}
          </Card.Body>
        </Card>

        {/* Status Code Breakdown */}
        <Card className="lg:col-span-2">
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Status Code Breakdown
            </h3>
          </Card.Header>
          <Card.Body>
            {statusCodes?.status_codes && statusCodes.status_codes.length > 0 ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {statusCodes.status_codes.slice(0, 8).map((sc) => (
                  <div
                    key={sc.status_code}
                    className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <Badge
                        color={
                          sc.status_code >= 500
                            ? "red"
                            : sc.status_code >= 400
                            ? "yellow"
                            : sc.status_code >= 300
                            ? "blue"
                            : "green"
                        }
                        size="sm"
                      >
                        {sc.status_code}
                      </Badge>
                      <span className="text-xs text-gray-500">{sc.percentage.toFixed(1)}%</span>
                    </div>
                    <div className="text-lg font-semibold text-gray-900 dark:text-white">
                      {formatNumber(sc.count)}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center justify-center h-[200px] text-gray-500">
                No status code data available
              </div>
            )}
          </Card.Body>
        </Card>
      </div>

      {/* Top Paths Table */}
      <Card>
        <Card.Header>
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Top Endpoints
            </h3>
            <Badge color="gray" size="sm">
              {topPathsResponse?.paths?.length || 0} paths
            </Badge>
          </div>
        </Card.Header>
        <Card.Body className="p-0">
          <Table
            columns={topPathsColumns}
            data={topPathsResponse?.paths || []}
            keyExtractor={(row) => row.path}
            hoverable
            emptyState={
              <EmptyState
                icon={Globe}
                title="No endpoint data"
                description="Top endpoints will appear once traffic is recorded"
                size="sm"
              />
            }
          />
        </Card.Body>
      </Card>
    </div>
  );
}
