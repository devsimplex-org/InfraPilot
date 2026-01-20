"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Server,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Play,
  Pause,
  RefreshCw,
  Plus,
  Calendar,
  Cpu,
  MemoryStick,
  Cog,
  ListChecks,
  Timer,
  Ban,
} from "lucide-react";
import {
  api,
  BackgroundJob,
  JobSchedule,
  Worker,
  JobLog,
  JobStatistics,
  WorkerSummary,
} from "@/lib/api";
import { Breadcrumb, BreadcrumbItem } from "@/components/ui/Breadcrumb";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Tabs } from "@/components/ui/page-layout";
import { Table, Column } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { cn, formatDuration, formatRelativeTime } from "@/lib/utils";

const jobStatusColors: Record<string, string> = {
  pending: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  queued: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  running: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200",
  completed: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  failed: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  cancelled: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  timeout: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  retrying: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
};

const workerStatusColors: Record<string, string> = {
  starting: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  idle: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  busy: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200",
  stopping: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  stopped: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  unhealthy: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
};

const categoryColors: Record<string, string> = {
  system: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  security: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  maintenance: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  user_triggered: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
};

const logLevelColors: Record<string, string> = {
  debug: "text-gray-500",
  info: "text-blue-600 dark:text-blue-400",
  warn: "text-yellow-600 dark:text-yellow-400",
  error: "text-red-600 dark:text-red-400",
};

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "jobs", label: "Jobs" },
  { id: "schedules", label: "Schedules" },
  { id: "workers", label: "Workers" },
  { id: "statistics", label: "Statistics" },
];

export default function JobsPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedJob, setSelectedJob] = useState<BackgroundJob | null>(null);
  const [selectedSchedule, setSelectedSchedule] = useState<JobSchedule | null>(null);
  const [selectedWorker, setSelectedWorker] = useState<Worker | null>(null);
  const queryClient = useQueryClient();

  // Queries
  const { data: jobs, isLoading: loadingJobs } = useQuery({
    queryKey: ["background-jobs"],
    queryFn: () => api.listJobs({ limit: 100 }),
    enabled: activeTab === "jobs" || activeTab === "overview",
  });

  const { data: schedules, isLoading: loadingSchedules } = useQuery({
    queryKey: ["job-schedules"],
    queryFn: () => api.listSchedules(),
    enabled: activeTab === "schedules" || activeTab === "overview",
  });

  const { data: workers, isLoading: loadingWorkers } = useQuery({
    queryKey: ["workers"],
    queryFn: () => api.listWorkers(),
    enabled: activeTab === "workers" || activeTab === "overview",
  });

  const { data: workerSummary, isLoading: loadingSummary } = useQuery({
    queryKey: ["worker-summary"],
    queryFn: () => api.getWorkerSummary(),
    enabled: activeTab === "overview" || activeTab === "workers",
  });

  const { data: statistics, isLoading: loadingStats } = useQuery({
    queryKey: ["job-statistics"],
    queryFn: () => api.getJobStatistics(),
    enabled: activeTab === "statistics" || activeTab === "overview",
  });

  const { data: jobLogs, isLoading: loadingLogs } = useQuery({
    queryKey: ["job-logs", selectedJob?.id],
    queryFn: () => api.getJobLogs(selectedJob!.id, { limit: 100 }),
    enabled: !!selectedJob,
  });

  // Mutations
  const cancelJob = useMutation({
    mutationFn: (jobId: string) => api.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["background-jobs"] });
      setSelectedJob(null);
    },
  });

  const retryJob = useMutation({
    mutationFn: (jobId: string) => api.retryJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["background-jobs"] });
      setSelectedJob(null);
    },
  });

  const toggleSchedule = useMutation({
    mutationFn: ({ scheduleId, enabled }: { scheduleId: string; enabled: boolean }) =>
      api.toggleSchedule(scheduleId, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["job-schedules"] }),
  });

  const deleteSchedule = useMutation({
    mutationFn: (scheduleId: string) => api.deleteSchedule(scheduleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-schedules"] });
      setSelectedSchedule(null);
    },
  });

  // Compute summary stats
  const runningJobs = jobs?.filter((j) => j.status === "running").length || 0;
  const pendingJobs = jobs?.filter((j) => j.status === "pending" || j.status === "queued").length || 0;
  const failedJobs = jobs?.filter((j) => j.status === "failed").length || 0;
  const completedToday = jobs?.filter(
    (j) => j.status === "completed" && j.completed_at && new Date(j.completed_at).toDateString() === new Date().toDateString()
  ).length || 0;

  const activeWorkers = workers?.filter((w) => w.status === "idle" || w.status === "busy").length || 0;
  const busyWorkers = workers?.filter((w) => w.status === "busy").length || 0;
  const unhealthyWorkers = workers?.filter((w) => w.status === "unhealthy").length || 0;

  const enabledSchedules = schedules?.filter((s) => s.enabled).length || 0;
  const failingSchedules = schedules?.filter((s) => s.consecutive_failures > 0).length || 0;

  // Job columns
  const jobColumns: Column<BackgroundJob>[] = [
    {
      key: "job_name",
      header: "Job",
      render: (job) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{job.job_name}</div>
          <div className="text-xs text-gray-500">{job.job_type}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (job) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", jobStatusColors[job.status])}>
          {job.status}
        </span>
      ),
    },
    {
      key: "job_category",
      header: "Category",
      render: (job) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", categoryColors[job.job_category])}>
          {job.job_category}
        </span>
      ),
    },
    {
      key: "progress",
      header: "Progress",
      render: (job) =>
        job.status === "running" ? (
          <div className="flex items-center gap-2">
            <div className="w-20 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-primary-600 h-2 rounded-full transition-all"
                style={{ width: `${job.progress_percent}%` }}
              />
            </div>
            <span className="text-xs text-gray-500">{job.progress_percent}%</span>
          </div>
        ) : job.steps_total > 0 ? (
          <span className="text-sm text-gray-500">
            {job.steps_completed}/{job.steps_total} steps
          </span>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "triggered_by",
      header: "Triggered By",
      render: (job) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {job.triggered_by_email || job.triggered_by || "System"}
        </span>
      ),
    },
    {
      key: "started_at",
      header: "Started",
      render: (job) => (job.started_at ? formatRelativeTime(job.started_at) : "-"),
    },
    {
      key: "worker",
      header: "Worker",
      render: (job) => (
        <span className="text-sm text-gray-500">{job.worker_hostname || "-"}</span>
      ),
    },
  ];

  // Schedule columns
  const scheduleColumns: Column<JobSchedule>[] = [
    {
      key: "name",
      header: "Schedule",
      render: (schedule) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{schedule.name}</div>
          <div className="text-xs text-gray-500">{schedule.job_type}</div>
        </div>
      ),
    },
    {
      key: "cron_expression",
      header: "Cron",
      render: (schedule) => (
        <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
          {schedule.cron_expression}
        </code>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (schedule) => (
        <span
          className={cn(
            "px-2 py-1 text-xs font-medium rounded-full",
            schedule.enabled
              ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
              : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
          )}
        >
          {schedule.enabled ? "Enabled" : "Disabled"}
        </span>
      ),
    },
    {
      key: "last_run_status",
      header: "Last Run",
      render: (schedule) =>
        schedule.last_run_status ? (
          <span className={cn("px-2 py-1 text-xs font-medium rounded-full", jobStatusColors[schedule.last_run_status])}>
            {schedule.last_run_status}
          </span>
        ) : (
          <span className="text-gray-400">Never</span>
        ),
    },
    {
      key: "next_run_at",
      header: "Next Run",
      render: (schedule) =>
        schedule.next_run_at && schedule.enabled ? formatRelativeTime(schedule.next_run_at) : "-",
    },
    {
      key: "run_count",
      header: "Runs",
      render: (schedule) => (
        <div className="text-sm">
          <span className="text-gray-900 dark:text-white">{schedule.run_count}</span>
          {schedule.failure_count > 0 && (
            <span className="text-red-500 ml-1">({schedule.failure_count} failed)</span>
          )}
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (schedule) => (
        <div className="flex gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              toggleSchedule.mutate({ scheduleId: schedule.id, enabled: !schedule.enabled });
            }}
            className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-800"
            title={schedule.enabled ? "Disable" : "Enable"}
          >
            {schedule.enabled ? (
              <Pause className="h-4 w-4 text-gray-500" />
            ) : (
              <Play className="h-4 w-4 text-green-500" />
            )}
          </button>
        </div>
      ),
    },
  ];

  // Worker columns
  const workerColumns: Column<Worker>[] = [
    {
      key: "hostname",
      header: "Worker",
      render: (worker) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{worker.hostname}</div>
          <div className="text-xs text-gray-500">ID: {worker.id.slice(0, 8)}...</div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (worker) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", workerStatusColors[worker.status])}>
          {worker.status}
        </span>
      ),
    },
    {
      key: "worker_type",
      header: "Type",
      render: (worker) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{worker.worker_type}</span>
      ),
    },
    {
      key: "current_jobs",
      header: "Jobs",
      render: (worker) => (
        <span className="text-sm">
          {worker.current_jobs}/{worker.max_concurrent_jobs}
        </span>
      ),
    },
    {
      key: "jobs_processed",
      header: "Processed",
      render: (worker) => (
        <div className="text-sm">
          <span className="text-green-600">{worker.jobs_processed}</span>
          {worker.jobs_failed > 0 && <span className="text-red-500 ml-1">({worker.jobs_failed} failed)</span>}
        </div>
      ),
    },
    {
      key: "resources",
      header: "Resources",
      render: (worker) => (
        <div className="text-sm text-gray-500">
          {worker.cpu_percent != null && (
            <span className="mr-2">CPU: {worker.cpu_percent.toFixed(1)}%</span>
          )}
          {worker.memory_percent != null && <span>Mem: {worker.memory_percent.toFixed(1)}%</span>}
        </div>
      ),
    },
    {
      key: "last_heartbeat_at",
      header: "Last Heartbeat",
      render: (worker) => formatRelativeTime(worker.last_heartbeat_at),
    },
  ];

  // Statistics columns
  const statsColumns: Column<JobStatistics>[] = [
    {
      key: "job_type",
      header: "Job Type",
      render: (stat) => <span className="font-medium text-gray-900 dark:text-white">{stat.job_type}</span>,
    },
    {
      key: "total_jobs",
      header: "Total",
      render: (stat) => <span>{stat.total_jobs}</span>,
    },
    {
      key: "completed_jobs",
      header: "Completed",
      render: (stat) => <span className="text-green-600">{stat.completed_jobs}</span>,
    },
    {
      key: "failed_jobs",
      header: "Failed",
      render: (stat) => <span className="text-red-600">{stat.failed_jobs}</span>,
    },
    {
      key: "running_jobs",
      header: "Running",
      render: (stat) => <span className="text-blue-600">{stat.running_jobs}</span>,
    },
    {
      key: "pending_jobs",
      header: "Pending",
      render: (stat) => <span className="text-gray-600">{stat.pending_jobs}</span>,
    },
    {
      key: "jobs_last_24h",
      header: "Last 24h",
      render: (stat) => <span>{stat.jobs_last_24h}</span>,
    },
    {
      key: "avg_duration_seconds",
      header: "Avg Duration",
      render: (stat) => (stat.avg_duration_seconds ? formatDuration(stat.avg_duration_seconds) : "-"),
    },
  ];

  return (
    <div className="space-y-6">
      <Breadcrumb>
        <BreadcrumbItem href="/dashboard">Home</BreadcrumbItem>
        <BreadcrumbItem href="/platform/jobs">Background Jobs</BreadcrumbItem>
      </Breadcrumb>

      <PageHeader
        title="Background Jobs"
        description="Monitor background jobs, scheduled tasks, and worker processes"
        icon={Activity}
      />

      <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <MetricsGrid columns={4}>
            <StatCard
              title="Running Jobs"
              value={runningJobs}
              icon={Activity}
              trend={pendingJobs > 0 ? { direction: "neutral", label: `${pendingJobs} pending` } : undefined}
            />
            <StatCard
              title="Completed Today"
              value={completedToday}
              icon={CheckCircle}
              variant="success"
            />
            <StatCard
              title="Failed Jobs"
              value={failedJobs}
              icon={XCircle}
              variant={failedJobs > 0 ? "danger" : "default"}
            />
            <StatCard
              title="Active Workers"
              value={activeWorkers}
              icon={Server}
              trend={unhealthyWorkers > 0 ? { direction: "down", label: `${unhealthyWorkers} unhealthy` } : undefined}
            />
          </MetricsGrid>

          <div className="grid grid-cols-2 gap-6">
            {/* Recent Jobs */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Jobs</h3>
              {loadingJobs ? (
                <div className="animate-pulse space-y-2">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="h-8 bg-gray-200 dark:bg-gray-700 rounded" />
                  ))}
                </div>
              ) : (
                <div className="space-y-2">
                  {jobs?.slice(0, 5).map((job) => (
                    <div
                      key={job.id}
                      className="flex items-center justify-between p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                      onClick={() => setSelectedJob(job)}
                    >
                      <div>
                        <span className="font-medium text-gray-900 dark:text-white">{job.job_name}</span>
                        <span className="text-xs text-gray-500 ml-2">{job.job_type}</span>
                      </div>
                      <span className={cn("px-2 py-1 text-xs font-medium rounded-full", jobStatusColors[job.status])}>
                        {job.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Worker Status */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Worker Status</h3>
              {loadingSummary ? (
                <div className="animate-pulse space-y-4">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-6 bg-gray-200 dark:bg-gray-700 rounded" />
                  ))}
                </div>
              ) : workerSummary ? (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Total Workers</span>
                    <span className="font-semibold text-gray-900 dark:text-white">{workerSummary.total_workers}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Idle</span>
                    <span className="font-semibold text-green-600">{workerSummary.idle_workers}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Busy</span>
                    <span className="font-semibold text-blue-600">{workerSummary.busy_workers}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-400">Unhealthy</span>
                    <span className={cn("font-semibold", workerSummary.unhealthy_workers > 0 ? "text-red-600" : "text-gray-500")}>
                      {workerSummary.unhealthy_workers}
                    </span>
                  </div>
                  <div className="border-t border-gray-200 dark:border-gray-700 pt-4 mt-4">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600 dark:text-gray-400">Jobs Processed</span>
                      <span className="font-semibold text-gray-900 dark:text-white">{workerSummary.total_jobs_processed}</span>
                    </div>
                    <div className="flex justify-between items-center mt-2">
                      <span className="text-gray-600 dark:text-gray-400">Jobs Failed</span>
                      <span className={cn("font-semibold", workerSummary.total_jobs_failed > 0 ? "text-red-600" : "text-gray-500")}>
                        {workerSummary.total_jobs_failed}
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-gray-500">No worker data available</p>
              )}
            </div>
          </div>

          {/* Schedules Overview */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Active Schedules ({enabledSchedules})
              {failingSchedules > 0 && (
                <span className="ml-2 text-sm text-red-500">({failingSchedules} with failures)</span>
              )}
            </h3>
            {loadingSchedules ? (
              <div className="animate-pulse space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-8 bg-gray-200 dark:bg-gray-700 rounded" />
                ))}
              </div>
            ) : (
              <div className="space-y-2">
                {schedules
                  ?.filter((s) => s.enabled)
                  .slice(0, 5)
                  .map((schedule) => (
                    <div
                      key={schedule.id}
                      className="flex items-center justify-between p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                      onClick={() => setSelectedSchedule(schedule)}
                    >
                      <div>
                        <span className="font-medium text-gray-900 dark:text-white">{schedule.name}</span>
                        <code className="text-xs text-gray-500 ml-2 bg-gray-100 dark:bg-gray-800 px-1 rounded">
                          {schedule.cron_expression}
                        </code>
                      </div>
                      <div className="flex items-center gap-2">
                        {schedule.consecutive_failures > 0 && (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        )}
                        {schedule.next_run_at && (
                          <span className="text-xs text-gray-500">
                            Next: {formatRelativeTime(schedule.next_run_at)}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Jobs Tab */}
      {activeTab === "jobs" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={jobs || []}
            columns={jobColumns}
            isLoading={loadingJobs}
            onRowClick={setSelectedJob}
            emptyMessage="No background jobs found"
          />
        </div>
      )}

      {/* Schedules Tab */}
      {activeTab === "schedules" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={schedules || []}
            columns={scheduleColumns}
            isLoading={loadingSchedules}
            onRowClick={setSelectedSchedule}
            emptyMessage="No job schedules configured"
          />
        </div>
      )}

      {/* Workers Tab */}
      {activeTab === "workers" && (
        <div className="space-y-6">
          {workerSummary && (
            <MetricsGrid columns={4}>
              <StatCard title="Total Workers" value={workerSummary.total_workers} icon={Server} />
              <StatCard title="Idle Workers" value={workerSummary.idle_workers} icon={CheckCircle} variant="success" />
              <StatCard title="Busy Workers" value={workerSummary.busy_workers} icon={Activity} variant="warning" />
              <StatCard
                title="Unhealthy Workers"
                value={workerSummary.unhealthy_workers}
                icon={AlertTriangle}
                variant={workerSummary.unhealthy_workers > 0 ? "danger" : "default"}
              />
            </MetricsGrid>
          )}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              data={workers || []}
              columns={workerColumns}
              isLoading={loadingWorkers}
              onRowClick={setSelectedWorker}
              emptyMessage="No workers registered"
            />
          </div>
        </div>
      )}

      {/* Statistics Tab */}
      {activeTab === "statistics" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={statistics || []}
            columns={statsColumns}
            isLoading={loadingStats}
            emptyMessage="No job statistics available"
          />
        </div>
      )}

      {/* Job Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedJob}
        onClose={() => setSelectedJob(null)}
        title={selectedJob?.job_name || "Job Details"}
      >
        {selectedJob && (
          <div className="space-y-6">
            <div className="flex items-center gap-2">
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", jobStatusColors[selectedJob.status])}>
                {selectedJob.status}
              </span>
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", categoryColors[selectedJob.job_category])}>
                {selectedJob.job_category}
              </span>
            </div>

            {/* Progress */}
            {selectedJob.status === "running" && (
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Progress</span>
                  <span className="text-sm font-medium">{selectedJob.progress_percent}%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className="bg-primary-600 h-2 rounded-full transition-all"
                    style={{ width: `${selectedJob.progress_percent}%` }}
                  />
                </div>
                {selectedJob.current_step && (
                  <p className="text-sm text-gray-500 mt-1">{selectedJob.current_step}</p>
                )}
              </div>
            )}

            {/* Details */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Job Type</label>
                <p className="font-medium">{selectedJob.job_type}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Priority</label>
                <p className="font-medium">{selectedJob.priority}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Triggered By</label>
                <p className="font-medium">{selectedJob.triggered_by_email || selectedJob.triggered_by || "System"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Worker</label>
                <p className="font-medium">{selectedJob.worker_hostname || "Unassigned"}</p>
              </div>
              {selectedJob.target_name && (
                <div>
                  <label className="text-sm text-gray-500">Target</label>
                  <p className="font-medium">{selectedJob.target_name}</p>
                </div>
              )}
              <div>
                <label className="text-sm text-gray-500">Retries</label>
                <p className="font-medium">
                  {selectedJob.retry_count}/{selectedJob.max_retries}
                </p>
              </div>
            </div>

            {/* Timing */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Timing</h4>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Created</span>
                  <span>{formatRelativeTime(selectedJob.created_at)}</span>
                </div>
                {selectedJob.scheduled_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Scheduled</span>
                    <span>{formatRelativeTime(selectedJob.scheduled_at)}</span>
                  </div>
                )}
                {selectedJob.started_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Started</span>
                    <span>{formatRelativeTime(selectedJob.started_at)}</span>
                  </div>
                )}
                {selectedJob.completed_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Completed</span>
                    <span>{formatRelativeTime(selectedJob.completed_at)}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Error Message */}
            {selectedJob.error_message && (
              <div>
                <h4 className="font-medium text-red-600 mb-2">Error</h4>
                <pre className="text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 p-3 rounded overflow-auto">
                  {selectedJob.error_message}
                </pre>
              </div>
            )}

            {/* Logs */}
            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">Logs</h4>
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 max-h-64 overflow-auto">
                {loadingLogs ? (
                  <p className="text-gray-500">Loading logs...</p>
                ) : jobLogs && jobLogs.length > 0 ? (
                  <div className="space-y-1 font-mono text-xs">
                    {jobLogs.map((log) => (
                      <div key={log.id} className="flex gap-2">
                        <span className="text-gray-400">{new Date(log.logged_at).toLocaleTimeString()}</span>
                        <span className={logLevelColors[log.log_level]}>[{log.log_level}]</span>
                        <span className="text-gray-700 dark:text-gray-300">{log.message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500">No logs available</p>
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
              {(selectedJob.status === "pending" || selectedJob.status === "queued" || selectedJob.status === "running") && (
                <button
                  onClick={() => cancelJob.mutate(selectedJob.id)}
                  disabled={cancelJob.isPending}
                  className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
                >
                  <Ban className="h-4 w-4" />
                  {cancelJob.isPending ? "Cancelling..." : "Cancel Job"}
                </button>
              )}
              {(selectedJob.status === "failed" || selectedJob.status === "cancelled") && (
                <button
                  onClick={() => retryJob.mutate(selectedJob.id)}
                  disabled={retryJob.isPending}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
                >
                  <RefreshCw className="h-4 w-4" />
                  {retryJob.isPending ? "Retrying..." : "Retry Job"}
                </button>
              )}
            </div>
          </div>
        )}
      </SlideOver>

      {/* Schedule Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedSchedule}
        onClose={() => setSelectedSchedule(null)}
        title={selectedSchedule?.name || "Schedule Details"}
      >
        {selectedSchedule && (
          <div className="space-y-6">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "px-3 py-1 text-sm font-medium rounded-full",
                  selectedSchedule.enabled
                    ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                    : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                )}
              >
                {selectedSchedule.enabled ? "Enabled" : "Disabled"}
              </span>
              {selectedSchedule.consecutive_failures > 0 && (
                <span className="px-3 py-1 text-sm font-medium rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                  {selectedSchedule.consecutive_failures} consecutive failures
                </span>
              )}
            </div>

            {selectedSchedule.description && (
              <p className="text-gray-600 dark:text-gray-400">{selectedSchedule.description}</p>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Job Type</label>
                <p className="font-medium">{selectedSchedule.job_type}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Job Name</label>
                <p className="font-medium">{selectedSchedule.job_name}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Cron Expression</label>
                <code className="font-medium bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                  {selectedSchedule.cron_expression}
                </code>
              </div>
              <div>
                <label className="text-sm text-gray-500">Timezone</label>
                <p className="font-medium">{selectedSchedule.timezone}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Priority</label>
                <p className="font-medium">{selectedSchedule.priority}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Timeout</label>
                <p className="font-medium">{formatDuration(selectedSchedule.timeout_seconds)}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Max Retries</label>
                <p className="font-medium">{selectedSchedule.max_retries}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Total Runs</label>
                <p className="font-medium">{selectedSchedule.run_count}</p>
              </div>
            </div>

            {/* Execution History */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Execution</h4>
              <div className="text-sm space-y-1">
                {selectedSchedule.last_run_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Last Run</span>
                    <span>{formatRelativeTime(selectedSchedule.last_run_at)}</span>
                  </div>
                )}
                {selectedSchedule.last_run_status && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Last Status</span>
                    <span className={cn("px-2 py-0.5 text-xs rounded-full", jobStatusColors[selectedSchedule.last_run_status])}>
                      {selectedSchedule.last_run_status}
                    </span>
                  </div>
                )}
                {selectedSchedule.last_run_duration_seconds && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Last Duration</span>
                    <span>{formatDuration(selectedSchedule.last_run_duration_seconds)}</span>
                  </div>
                )}
                {selectedSchedule.next_run_at && selectedSchedule.enabled && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Next Run</span>
                    <span>{formatRelativeTime(selectedSchedule.next_run_at)}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Alerting */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Alerting</h4>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Alert on Failure</span>
                  <span>{selectedSchedule.alert_on_failure ? "Yes" : "No"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Alert After Failures</span>
                  <span>{selectedSchedule.alert_after_consecutive_failures}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Pause After Failures</span>
                  <span>{selectedSchedule.pause_after_failures}</span>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => toggleSchedule.mutate({ scheduleId: selectedSchedule.id, enabled: !selectedSchedule.enabled })}
                disabled={toggleSchedule.isPending}
                className={cn(
                  "flex items-center gap-2 px-4 py-2 rounded-lg disabled:opacity-50",
                  selectedSchedule.enabled
                    ? "bg-yellow-600 text-white hover:bg-yellow-700"
                    : "bg-green-600 text-white hover:bg-green-700"
                )}
              >
                {selectedSchedule.enabled ? (
                  <>
                    <Pause className="h-4 w-4" />
                    Disable
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Enable
                  </>
                )}
              </button>
              <button
                onClick={() => deleteSchedule.mutate(selectedSchedule.id)}
                disabled={deleteSchedule.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                <XCircle className="h-4 w-4" />
                {deleteSchedule.isPending ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        )}
      </SlideOver>

      {/* Worker Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedWorker}
        onClose={() => setSelectedWorker(null)}
        title={selectedWorker?.hostname || "Worker Details"}
      >
        {selectedWorker && (
          <div className="space-y-6">
            <div className="flex items-center gap-2">
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", workerStatusColors[selectedWorker.status])}>
                {selectedWorker.status}
              </span>
              <span className="px-3 py-1 text-sm font-medium rounded-full bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200">
                {selectedWorker.worker_type}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Worker ID</label>
                <p className="font-medium font-mono text-sm">{selectedWorker.id}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Version</label>
                <p className="font-medium">{selectedWorker.version || "Unknown"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">PID</label>
                <p className="font-medium">{selectedWorker.pid || "-"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Current Jobs</label>
                <p className="font-medium">
                  {selectedWorker.current_jobs}/{selectedWorker.max_concurrent_jobs}
                </p>
              </div>
            </div>

            {/* Performance */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Performance</h4>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-500">Jobs Processed</label>
                  <p className="font-medium text-green-600">{selectedWorker.jobs_processed}</p>
                </div>
                <div>
                  <label className="text-sm text-gray-500">Jobs Failed</label>
                  <p className={cn("font-medium", selectedWorker.jobs_failed > 0 ? "text-red-600" : "text-gray-500")}>
                    {selectedWorker.jobs_failed}
                  </p>
                </div>
              </div>
            </div>

            {/* Resources */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Resources</h4>
              <div className="space-y-3">
                {selectedWorker.cpu_percent != null && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-sm text-gray-500">CPU Usage</span>
                      <span className="text-sm font-medium">{selectedWorker.cpu_percent.toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className={cn(
                          "h-2 rounded-full transition-all",
                          selectedWorker.cpu_percent > 80 ? "bg-red-500" : selectedWorker.cpu_percent > 50 ? "bg-yellow-500" : "bg-green-500"
                        )}
                        style={{ width: `${selectedWorker.cpu_percent}%` }}
                      />
                    </div>
                  </div>
                )}
                {selectedWorker.memory_percent != null && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-sm text-gray-500">Memory Usage</span>
                      <span className="text-sm font-medium">
                        {selectedWorker.memory_percent.toFixed(1)}%
                        {selectedWorker.memory_mb && ` (${selectedWorker.memory_mb} MB)`}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className={cn(
                          "h-2 rounded-full transition-all",
                          selectedWorker.memory_percent > 80 ? "bg-red-500" : selectedWorker.memory_percent > 50 ? "bg-yellow-500" : "bg-green-500"
                        )}
                        style={{ width: `${selectedWorker.memory_percent}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Timing */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Timing</h4>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Started</span>
                  <span>{formatRelativeTime(selectedWorker.started_at)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Heartbeat</span>
                  <span>{formatRelativeTime(selectedWorker.last_heartbeat_at)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Health Check Failures</span>
                  <span className={cn(selectedWorker.health_check_failures > 0 ? "text-red-600" : "")}>
                    {selectedWorker.health_check_failures}
                  </span>
                </div>
              </div>
            </div>

            {/* Capabilities */}
            {selectedWorker.capabilities && selectedWorker.capabilities.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium text-gray-900 dark:text-white">Capabilities</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedWorker.capabilities.map((cap) => (
                    <span
                      key={cap}
                      className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </SlideOver>
    </div>
  );
}
