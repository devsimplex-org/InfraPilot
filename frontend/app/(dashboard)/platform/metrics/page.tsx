"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  MetricDefinition,
  MetricSummary,
  Dashboard,
  Report,
  ReportExecution,
  TelemetrySettings,
} from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard } from "@/components/ui/StatCard";
import { Table, Column } from "@/components/ui/Table";
import { SlideOver, SlideOverHeader, SlideOverBody } from "@/components/ui/SlideOver";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";
import {
  Activity,
  BarChart3,
  FileText,
  LayoutDashboard,
  Settings,
  Play,
  Eye,
  Trash2,
  CheckCircle,
  Clock,
  AlertTriangle,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";

const categoryColors: Record<string, string> = {
  security: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  performance: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  compliance: "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400",
  usage: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  cost: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  health: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-400",
};

const statusColors: Record<string, string> = {
  pending: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  completed: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
};

const visibilityLabels: Record<string, string> = {
  private: "Private",
  team: "Team",
  org: "Organization",
  public: "Public",
};

// Simple Tabs component
interface TabItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
}

function Tabs({
  tabs,
  activeTab,
  onChange,
}: {
  tabs: TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="border-b border-gray-200 dark:border-gray-700">
      <nav className="-mb-px flex space-x-6 overflow-x-auto" aria-label="Tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={cn(
              "whitespace-nowrap py-3 px-1 border-b-2 text-sm font-medium flex items-center gap-2",
              activeTab === tab.id
                ? "border-primary-500 text-primary-600 dark:text-primary-400"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  );
}

export default function MetricsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedMetric, setSelectedMetric] = useState<MetricDefinition | null>(null);
  const [selectedDashboard, setSelectedDashboard] = useState<Dashboard | null>(null);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<ReportExecution | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [reportTypeFilter, setReportTypeFilter] = useState<string>("");
  const [executionStatusFilter, setExecutionStatusFilter] = useState<string>("");

  // Queries
  const { data: metricsData, isLoading: loadingMetrics } = useQuery({
    queryKey: ["metrics", categoryFilter],
    queryFn: () => api.listMetricDefinitions({ category: categoryFilter || undefined }),
  });

  const { data: summaryData, isLoading: loadingSummary } = useQuery({
    queryKey: ["metricsSummary"],
    queryFn: () => api.getMetricSummary(),
  });

  const { data: dashboardsData, isLoading: loadingDashboards } = useQuery({
    queryKey: ["dashboards"],
    queryFn: () => api.listDashboards(),
  });

  const { data: reportsData, isLoading: loadingReports } = useQuery({
    queryKey: ["reports", reportTypeFilter],
    queryFn: () => api.listReports({ report_type: reportTypeFilter || undefined }),
  });

  const { data: executionsData, isLoading: loadingExecutions } = useQuery({
    queryKey: ["reportExecutions", executionStatusFilter],
    queryFn: () => api.listReportExecutions({ status: executionStatusFilter || undefined, limit: 50 }),
  });

  const { data: telemetrySettings } = useQuery({
    queryKey: ["telemetrySettings"],
    queryFn: () => api.getTelemetrySettings(),
  });

  // Mutations
  const runReportMutation = useMutation({
    mutationFn: (reportId: string) => api.runReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reportExecutions"] });
    },
  });

  const deleteMetricMutation = useMutation({
    mutationFn: (metricId: string) => api.deleteMetricDefinition(metricId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
      queryClient.invalidateQueries({ queryKey: ["metricsSummary"] });
      setSelectedMetric(null);
    },
  });

  const deleteDashboardMutation = useMutation({
    mutationFn: (dashboardId: string) => api.deleteDashboard(dashboardId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
      setSelectedDashboard(null);
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (reportId: string) => api.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      setSelectedReport(null);
    },
  });

  const updateTelemetryMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.updateTelemetrySettings>[0]) =>
      api.updateTelemetrySettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["telemetrySettings"] });
    },
  });

  const metrics = metricsData?.metrics || [];
  const summary = summaryData?.summaries || [];
  const dashboards = dashboardsData?.dashboards || [];
  const reports = reportsData?.reports || [];
  const executions = executionsData?.executions || [];

  // Calculate stats
  const totalMetrics = metrics.length;
  const enabledMetrics = metrics.filter((m) => m.enabled).length;
  const totalDashboards = dashboards.length;
  const totalReports = reports.length;
  const scheduledReports = reports.filter((r) => r.schedule_enabled).length;
  const recentExecutions = executions.slice(0, 10);

  // Columns
  const metricColumns: Column<MetricDefinition>[] = [
    {
      key: "name",
      header: "Metric",
      render: (_, metric) => (
        <div>
          <p className="font-medium text-gray-900 dark:text-white">
            {metric.display_name || metric.name}
          </p>
          {metric.description && (
            <p className="text-xs text-gray-500 truncate max-w-xs">{metric.description}</p>
          )}
        </div>
      ),
    },
    {
      key: "category",
      header: "Category",
      render: (_, metric) => (
        <Badge className={categoryColors[metric.category] || "bg-gray-100 text-gray-800"}>
          {metric.category}
        </Badge>
      ),
    },
    {
      key: "metric_type",
      header: "Type",
      render: (_, metric) => (
        <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
          {metric.metric_type}
        </span>
      ),
    },
    {
      key: "collection_method",
      header: "Collection",
      render: (_, metric) => (
        <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
          {metric.collection_method}
        </span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (_, metric) =>
        metric.enabled ? (
          <Badge className="bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
            Enabled
          </Badge>
        ) : (
          <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">
            Disabled
          </Badge>
        ),
    },
    {
      key: "actions",
      header: "",
      render: (_, metric) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setSelectedMetric(metric);
          }}
          className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
        >
          <Eye className="h-4 w-4" />
        </button>
      ),
    },
  ];

  const dashboardColumns: Column<Dashboard>[] = [
    {
      key: "name",
      header: "Dashboard",
      render: (_, dashboard) => (
        <div>
          <p className="font-medium text-gray-900 dark:text-white">{dashboard.name}</p>
          {dashboard.description && (
            <p className="text-xs text-gray-500 truncate max-w-xs">{dashboard.description}</p>
          )}
        </div>
      ),
    },
    {
      key: "visibility",
      header: "Visibility",
      render: (_, dashboard) => (
        <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
          {visibilityLabels[dashboard.visibility] || dashboard.visibility}
        </span>
      ),
    },
    {
      key: "widget_count",
      header: "Widgets",
      render: (_, dashboard) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {dashboard.widget_count || 0}
        </span>
      ),
    },
    {
      key: "is_default",
      header: "Default",
      render: (_, dashboard) =>
        dashboard.is_default ? (
          <CheckCircle className="h-4 w-4 text-green-500" />
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "updated_at",
      header: "Updated",
      render: (_, dashboard) => (
        <span className="text-sm text-gray-500">
          {formatDistanceToNow(new Date(dashboard.updated_at), { addSuffix: true })}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (_, dashboard) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setSelectedDashboard(dashboard);
          }}
          className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
        >
          <Eye className="h-4 w-4" />
        </button>
      ),
    },
  ];

  const reportColumns: Column<Report>[] = [
    {
      key: "name",
      header: "Report",
      render: (_, report) => (
        <div>
          <p className="font-medium text-gray-900 dark:text-white">{report.name}</p>
          {report.description && (
            <p className="text-xs text-gray-500 truncate max-w-xs">{report.description}</p>
          )}
        </div>
      ),
    },
    {
      key: "report_type",
      header: "Type",
      render: (_, report) => (
        <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
          {report.report_type.replace(/_/g, " ")}
        </Badge>
      ),
    },
    {
      key: "schedule_enabled",
      header: "Scheduled",
      render: (_, report) =>
        report.schedule_enabled ? (
          <div className="flex items-center gap-1">
            <Clock className="h-4 w-4 text-blue-500" />
            <span className="text-xs text-gray-500">{report.schedule_cron}</span>
          </div>
        ) : (
          <span className="text-gray-400">Manual</span>
        ),
    },
    {
      key: "last_run_at",
      header: "Last Run",
      render: (_, report) =>
        report.last_run_at ? (
          <span className="text-sm text-gray-500">
            {formatDistanceToNow(new Date(report.last_run_at), { addSuffix: true })}
          </span>
        ) : (
          <span className="text-gray-400">Never</span>
        ),
    },
    {
      key: "actions",
      header: "",
      render: (_, report) => (
        <div className="flex items-center gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              runReportMutation.mutate(report.id);
            }}
            className="text-blue-500 hover:text-blue-700"
            title="Run Report"
          >
            <Play className="h-4 w-4" />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSelectedReport(report);
            }}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
          >
            <Eye className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ];

  const executionColumns: Column<ReportExecution>[] = [
    {
      key: "report_name",
      header: "Report",
      render: (_, exec) => (
        <p className="font-medium text-gray-900 dark:text-white">
          {exec.report_name || "Unknown"}
        </p>
      ),
    },
    {
      key: "triggered_by",
      header: "Trigger",
      render: (_, exec) => (
        <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
          {exec.triggered_by}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (_, exec) => (
        <Badge className={statusColors[exec.status] || "bg-gray-100 text-gray-800"}>
          {exec.status}
        </Badge>
      ),
    },
    {
      key: "duration_seconds",
      header: "Duration",
      render: (_, exec) =>
        exec.duration_seconds ? (
          <span className="text-sm text-gray-500">{exec.duration_seconds}s</span>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "created_at",
      header: "Started",
      render: (_, exec) => (
        <span className="text-sm text-gray-500">
          {formatDistanceToNow(new Date(exec.created_at), { addSuffix: true })}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (_, exec) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setSelectedExecution(exec);
          }}
          className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
        >
          <Eye className="h-4 w-4" />
        </button>
      ),
    },
  ];

  const tabs: TabItem[] = [
    { id: "overview", label: "Overview", icon: <Activity className="h-4 w-4" /> },
    { id: "metrics", label: "Metrics", icon: <BarChart3 className="h-4 w-4" /> },
    { id: "dashboards", label: "Dashboards", icon: <LayoutDashboard className="h-4 w-4" /> },
    { id: "reports", label: "Reports", icon: <FileText className="h-4 w-4" /> },
    { id: "executions", label: "Executions", icon: <Play className="h-4 w-4" /> },
    { id: "telemetry", label: "Telemetry", icon: <Settings className="h-4 w-4" /> },
  ];

  return (
    <div className="space-y-6">
      <Breadcrumb
        items={[
          { label: "Platform", href: "/platform/jobs" },
          { label: "Metrics & Reports" },
        ]}
      />

      <PageHeader
        title="Metrics & Reports"
        description="Manage metric definitions, dashboards, and scheduled reports"
        action={
          <button
            onClick={() => setActiveTab("telemetry")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            <Settings className="h-4 w-4" />
            Telemetry Settings
          </button>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          label="Total Metrics"
          value={totalMetrics}
          icon={BarChart3}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Enabled Metrics"
          value={enabledMetrics}
          icon={CheckCircle}
          iconColor="text-green-600"
        />
        <StatCard
          label="Dashboards"
          value={totalDashboards}
          icon={LayoutDashboard}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Total Reports"
          value={totalReports}
          icon={FileText}
          iconColor="text-cyan-600"
        />
        <StatCard
          label="Scheduled Reports"
          value={scheduledReports}
          icon={Clock}
          iconColor="text-yellow-600"
        />
      </div>

      <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Metric Summary by Category */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Metrics by Category
            </h3>
            {loadingSummary ? (
              <div className="animate-pulse space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
                ))}
              </div>
            ) : summary.length === 0 ? (
              <p className="text-gray-500">No metrics defined yet</p>
            ) : (
              <div className="space-y-3">
                {summary.map((cat) => (
                  <div
                    key={cat.category}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <Badge className={categoryColors[cat.category] || "bg-gray-100 text-gray-800"}>
                        {cat.category}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <span className="text-gray-500">
                        {cat.enabled_metrics} / {cat.total_metrics} enabled
                      </span>
                      <span className="text-gray-500">
                        {cat.metrics_with_data} with data
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent Executions */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Recent Report Executions
            </h3>
            {loadingExecutions ? (
              <div className="animate-pulse space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
                ))}
              </div>
            ) : recentExecutions.length === 0 ? (
              <p className="text-gray-500">No report executions yet</p>
            ) : (
              <div className="space-y-2">
                {recentExecutions.map((exec) => (
                  <div
                    key={exec.id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white text-sm">
                        {exec.report_name || "Unknown Report"}
                      </p>
                      <p className="text-xs text-gray-500">
                        {formatDistanceToNow(new Date(exec.created_at), { addSuffix: true })}
                      </p>
                    </div>
                    <Badge className={statusColors[exec.status] || "bg-gray-100 text-gray-800"}>
                      {exec.status}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Metrics Tab */}
      {activeTab === "metrics" && (
        <div className="space-y-4">
          {/* Category Filter */}
          <div className="flex items-center gap-4">
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Category:
            </label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm"
            >
              <option value="">All Categories</option>
              <option value="security">Security</option>
              <option value="performance">Performance</option>
              <option value="compliance">Compliance</option>
              <option value="usage">Usage</option>
              <option value="cost">Cost</option>
              <option value="health">Health</option>
            </select>
          </div>

          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              data={metrics}
              columns={metricColumns}
              keyExtractor={(row) => row.id}
              loading={loadingMetrics}
              emptyState={<p className="text-gray-500 py-8 text-center">No metrics defined</p>}
            />
          </div>
        </div>
      )}

      {/* Dashboards Tab */}
      {activeTab === "dashboards" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={dashboards}
            columns={dashboardColumns}
            keyExtractor={(row) => row.id}
            loading={loadingDashboards}
            emptyState={<p className="text-gray-500 py-8 text-center">No dashboards created</p>}
          />
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === "reports" && (
        <div className="space-y-4">
          {/* Report Type Filter */}
          <div className="flex items-center gap-4">
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Type:
            </label>
            <select
              value={reportTypeFilter}
              onChange={(e) => setReportTypeFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm"
            >
              <option value="">All Types</option>
              <option value="security_summary">Security Summary</option>
              <option value="compliance">Compliance</option>
              <option value="executive">Executive</option>
              <option value="custom">Custom</option>
            </select>
          </div>

          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              data={reports}
              columns={reportColumns}
              keyExtractor={(row) => row.id}
              loading={loadingReports}
              emptyState={<p className="text-gray-500 py-8 text-center">No reports configured</p>}
            />
          </div>
        </div>
      )}

      {/* Executions Tab */}
      {activeTab === "executions" && (
        <div className="space-y-4">
          {/* Status Filter */}
          <div className="flex items-center gap-4">
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Status:
            </label>
            <select
              value={executionStatusFilter}
              onChange={(e) => setExecutionStatusFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm"
            >
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              data={executions}
              columns={executionColumns}
              keyExtractor={(row) => row.id}
              loading={loadingExecutions}
              emptyState={<p className="text-gray-500 py-8 text-center">No report executions</p>}
            />
          </div>
        </div>
      )}

      {/* Telemetry Tab */}
      {activeTab === "telemetry" && telemetrySettings && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
            Telemetry & Data Collection Settings
          </h3>

          <div className="space-y-6">
            {/* Data Collection */}
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Data Collection
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.collect_usage_metrics}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({ collect_usage_metrics: e.target.checked })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Usage Metrics
                    </p>
                    <p className="text-xs text-gray-500">Collect feature usage data</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.collect_performance_metrics}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({
                        collect_performance_metrics: e.target.checked,
                      })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Performance Metrics
                    </p>
                    <p className="text-xs text-gray-500">Collect performance data</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.collect_security_metrics}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({
                        collect_security_metrics: e.target.checked,
                      })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Security Metrics
                    </p>
                    <p className="text-xs text-gray-500">Collect security posture data</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.collect_error_reports}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({ collect_error_reports: e.target.checked })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Error Reports
                    </p>
                    <p className="text-xs text-gray-500">Collect error and crash data</p>
                  </div>
                </label>
              </div>
            </div>

            {/* Research Participation */}
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Research Participation
              </h4>
              <label className="flex items-center gap-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                <input
                  type="checkbox"
                  checked={telemetrySettings.research_participation}
                  onChange={(e) =>
                    updateTelemetryMutation.mutate({
                      research_participation: e.target.checked,
                      research_consent_version: e.target.checked ? "1.0" : undefined,
                    })
                  }
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <div>
                  <p className="font-medium text-gray-900 dark:text-white text-sm">
                    Participate in Research
                  </p>
                  <p className="text-xs text-gray-500">
                    Allow anonymized data to be used for security research
                  </p>
                </div>
              </label>
              {telemetrySettings.research_consent_date && (
                <p className="text-xs text-gray-500 mt-2">
                  Consent given on{" "}
                  {new Date(telemetrySettings.research_consent_date).toLocaleDateString()}
                </p>
              )}
            </div>

            {/* Privacy Settings */}
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Privacy Settings
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.anonymize_data}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({ anonymize_data: e.target.checked })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Anonymize Data
                    </p>
                    <p className="text-xs text-gray-500">Remove identifying information</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={telemetrySettings.allow_data_export}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({ allow_data_export: e.target.checked })
                    }
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white text-sm">
                      Allow Data Export
                    </p>
                    <p className="text-xs text-gray-500">Enable data export functionality</p>
                  </div>
                </label>

                <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">
                    Data Retention (days)
                  </label>
                  <input
                    type="number"
                    value={telemetrySettings.data_retention_days}
                    onChange={(e) =>
                      updateTelemetryMutation.mutate({
                        data_retention_days: parseInt(e.target.value) || 90,
                      })
                    }
                    min={7}
                    max={365}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Metric Details SlideOver */}
      <SlideOver
        isOpen={!!selectedMetric}
        onClose={() => setSelectedMetric(null)}
      >
        <SlideOverHeader onClose={() => setSelectedMetric(null)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Metric Details
          </h2>
        </SlideOverHeader>
        <SlideOverBody>
          {selectedMetric && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedMetric.display_name || selectedMetric.name}
                </h3>
                {selectedMetric.description && (
                  <p className="text-sm text-gray-500 mt-1">{selectedMetric.description}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Category</p>
                  <Badge
                    className={categoryColors[selectedMetric.category] || "bg-gray-100 text-gray-800"}
                  >
                    {selectedMetric.category}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Type</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedMetric.metric_type}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Unit</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedMetric.unit || "-"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Value Type</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedMetric.value_type}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Collection Method</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedMetric.collection_method}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Collection Interval</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedMetric.collection_interval_seconds}s
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Source</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedMetric.source || "-"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Status</p>
                  {selectedMetric.enabled ? (
                    <Badge className="bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      Enabled
                    </Badge>
                  ) : (
                    <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">
                      Disabled
                    </Badge>
                  )}
                </div>
              </div>

              {/* Thresholds */}
              {(selectedMetric.warning_threshold || selectedMetric.critical_threshold) && (
                <div>
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Thresholds
                  </h4>
                  <div className="grid grid-cols-2 gap-4">
                    {selectedMetric.warning_threshold && (
                      <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                        <p className="text-xs text-yellow-600 dark:text-yellow-400">Warning</p>
                        <p className="text-sm font-medium text-yellow-800 dark:text-yellow-300">
                          {selectedMetric.threshold_direction === "above" ? ">" : "<"}{" "}
                          {selectedMetric.warning_threshold}
                        </p>
                      </div>
                    )}
                    {selectedMetric.critical_threshold && (
                      <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                        <p className="text-xs text-red-600 dark:text-red-400">Critical</p>
                        <p className="text-sm font-medium text-red-800 dark:text-red-300">
                          {selectedMetric.threshold_direction === "above" ? ">" : "<"}{" "}
                          {selectedMetric.critical_threshold}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => deleteMetricMutation.mutate(selectedMetric.id)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                >
                  <Trash2 className="h-4 w-4" />
                  Delete Metric
                </button>
              </div>
            </div>
          )}
        </SlideOverBody>
      </SlideOver>

      {/* Dashboard Details SlideOver */}
      <SlideOver
        isOpen={!!selectedDashboard}
        onClose={() => setSelectedDashboard(null)}
      >
        <SlideOverHeader onClose={() => setSelectedDashboard(null)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Dashboard Details
          </h2>
        </SlideOverHeader>
        <SlideOverBody>
          {selectedDashboard && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedDashboard.name}
                </h3>
                {selectedDashboard.description && (
                  <p className="text-sm text-gray-500 mt-1">{selectedDashboard.description}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Visibility</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedDashboard.visibility}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Widgets</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedDashboard.widget_count || 0}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Default</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedDashboard.is_default ? "Yes" : "No"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Shared</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedDashboard.is_shared ? "Yes" : "No"}
                  </p>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => deleteDashboardMutation.mutate(selectedDashboard.id)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                >
                  <Trash2 className="h-4 w-4" />
                  Delete Dashboard
                </button>
              </div>
            </div>
          )}
        </SlideOverBody>
      </SlideOver>

      {/* Report Details SlideOver */}
      <SlideOver
        isOpen={!!selectedReport}
        onClose={() => setSelectedReport(null)}
      >
        <SlideOverHeader onClose={() => setSelectedReport(null)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Report Details
          </h2>
        </SlideOverHeader>
        <SlideOverBody>
          {selectedReport && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedReport.name}
                </h3>
                {selectedReport.description && (
                  <p className="text-sm text-gray-500 mt-1">{selectedReport.description}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Type</p>
                  <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
                    {selectedReport.report_type.replace(/_/g, " ")}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Visibility</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedReport.visibility}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Scheduled</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedReport.schedule_enabled ? "Yes" : "No"}
                  </p>
                </div>
                {selectedReport.schedule_enabled && (
                  <>
                    <div>
                      <p className="text-xs text-gray-500">Schedule</p>
                      <p className="text-sm text-gray-900 dark:text-white font-mono">
                        {selectedReport.schedule_cron}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">Timezone</p>
                      <p className="text-sm text-gray-900 dark:text-white">
                        {selectedReport.schedule_timezone}
                      </p>
                    </div>
                  </>
                )}
                {selectedReport.delivery_method && (
                  <div>
                    <p className="text-xs text-gray-500">Delivery</p>
                    <p className="text-sm text-gray-900 dark:text-white capitalize">
                      {selectedReport.delivery_method}
                    </p>
                  </div>
                )}
              </div>

              {selectedReport.recipients && selectedReport.recipients.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">Recipients</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedReport.recipients.map((r, i) => (
                      <Badge key={i} className="bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                        {r}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => {
                    runReportMutation.mutate(selectedReport.id);
                    setSelectedReport(null);
                  }}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  <Play className="h-4 w-4" />
                  Run Now
                </button>
                <button
                  onClick={() => deleteReportMutation.mutate(selectedReport.id)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                >
                  <Trash2 className="h-4 w-4" />
                  Delete
                </button>
              </div>
            </div>
          )}
        </SlideOverBody>
      </SlideOver>

      {/* Execution Details SlideOver */}
      <SlideOver
        isOpen={!!selectedExecution}
        onClose={() => setSelectedExecution(null)}
      >
        <SlideOverHeader onClose={() => setSelectedExecution(null)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Execution Details
          </h2>
        </SlideOverHeader>
        <SlideOverBody>
          {selectedExecution && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedExecution.report_name || "Report Execution"}
                </h3>
                <Badge className={statusColors[selectedExecution.status] || "bg-gray-100 text-gray-800"}>
                  {selectedExecution.status}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Triggered By</p>
                  <p className="text-sm text-gray-900 dark:text-white capitalize">
                    {selectedExecution.triggered_by}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Started</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedExecution.started_at
                      ? new Date(selectedExecution.started_at).toLocaleString()
                      : "-"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Completed</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedExecution.completed_at
                      ? new Date(selectedExecution.completed_at).toLocaleString()
                      : "-"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Duration</p>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedExecution.duration_seconds
                      ? `${selectedExecution.duration_seconds}s`
                      : "-"}
                  </p>
                </div>
                {selectedExecution.output_format && (
                  <div>
                    <p className="text-xs text-gray-500">Output Format</p>
                    <p className="text-sm text-gray-900 dark:text-white uppercase">
                      {selectedExecution.output_format}
                    </p>
                  </div>
                )}
                {selectedExecution.output_size_bytes && (
                  <div>
                    <p className="text-xs text-gray-500">Output Size</p>
                    <p className="text-sm text-gray-900 dark:text-white">
                      {(selectedExecution.output_size_bytes / 1024).toFixed(1)} KB
                    </p>
                  </div>
                )}
              </div>

              {selectedExecution.error_message && (
                <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-red-800 dark:text-red-300">Error</p>
                      <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                        {selectedExecution.error_message}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </SlideOverBody>
      </SlideOver>
    </div>
  );
}
