"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Link2,
  Cloud,
  Database,
  Shield,
  TrendingUp,
  Plus,
  ExternalLink,
  AlertCircle,
} from "lucide-react";
import {
  api,
  ExternalService,
  ServiceDependency,
  ExternalServiceIncident,
  DependencyRisk,
  ExternalHealthOverview,
} from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Tabs } from "@/components/ui/page-layout";
import { Table, Column } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { cn, formatRelativeTime } from "@/lib/utils";

const healthStatusColors: Record<string, string> = {
  healthy: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  degraded: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  unhealthy: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  unknown: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
};

const criticalityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  low: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
};

const riskLevelColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  low: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
};

const incidentStatusColors: Record<string, string> = {
  active: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  investigating: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  identified: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  monitoring: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  resolved: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
};

const serviceTypeIcons: Record<string, typeof Globe> = {
  api: Globe,
  database: Database,
  storage: Server,
  messaging: Link2,
  cdn: Cloud,
  auth: Shield,
  monitoring: TrendingUp,
  other: Server,
};

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "services", label: "External Services" },
  { id: "dependencies", label: "Dependencies" },
  { id: "risks", label: "Risk Assessment" },
  { id: "incidents", label: "Incidents" },
];

export default function DependenciesPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedService, setSelectedService] = useState<ExternalService | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<ExternalServiceIncident | null>(null);
  const queryClient = useQueryClient();

  // Queries
  const { data: overview, isLoading: loadingOverview } = useQuery({
    queryKey: ["external-health-overview"],
    queryFn: () => api.getExternalHealthOverview(),
  });

  const { data: servicesData, isLoading: loadingServices } = useQuery({
    queryKey: ["external-services"],
    queryFn: () => api.listExternalServices({ limit: 100 }),
    enabled: activeTab === "services" || activeTab === "overview",
  });

  const { data: dependenciesData, isLoading: loadingDependencies } = useQuery({
    queryKey: ["service-dependencies"],
    queryFn: () => api.listServiceDependencies(),
    enabled: activeTab === "dependencies" || activeTab === "overview",
  });

  const { data: risksData, isLoading: loadingRisks } = useQuery({
    queryKey: ["dependency-risks"],
    queryFn: () => api.getDependencyRisks(),
    enabled: activeTab === "risks" || activeTab === "overview",
  });

  const { data: incidentsData, isLoading: loadingIncidents } = useQuery({
    queryKey: ["external-incidents"],
    queryFn: () => api.listExternalIncidents(),
    enabled: activeTab === "incidents" || activeTab === "overview",
  });

  // Mutations
  const updateIncidentStatus = useMutation({
    mutationFn: ({ incidentId, status, notes }: { incidentId: string; status: string; notes?: string }) =>
      api.updateExternalIncidentStatus(incidentId, { status, resolution_notes: notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["external-incidents"] });
      setSelectedIncident(null);
    },
  });

  const services = servicesData?.services || [];
  const dependencies = dependenciesData?.dependencies || [];
  const risks = risksData?.risks || [];
  const incidents = incidentsData?.incidents || [];

  const activeIncidents = incidents.filter((i) => i.status === "active").length;
  const criticalRisks = risks.filter((r) => r.risk_level === "critical").length;
  const highRisks = risks.filter((r) => r.risk_level === "high").length;

  // Service columns
  const serviceColumns: Column<ExternalService>[] = [
    {
      key: "name",
      header: "Service",
      render: (service) => {
        const Icon = serviceTypeIcons[service.service_type] || Server;
        return (
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
              <Icon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
            </div>
            <div>
              <div className="font-medium text-gray-900 dark:text-white">{service.name}</div>
              <div className="text-xs text-gray-500">{service.provider || service.service_type}</div>
            </div>
          </div>
        );
      },
    },
    {
      key: "health_status",
      header: "Health",
      render: (service) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", healthStatusColors[service.health_status])}>
          {service.health_status}
        </span>
      ),
    },
    {
      key: "criticality",
      header: "Criticality",
      render: (service) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", criticalityColors[service.criticality])}>
          {service.criticality}
        </span>
      ),
    },
    {
      key: "environment",
      header: "Environment",
      render: (service) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{service.environment}</span>
      ),
    },
    {
      key: "endpoint_url",
      header: "Endpoint",
      render: (service) => (
        <span className="text-sm text-gray-500 font-mono truncate max-w-xs block">
          {service.endpoint_url || service.base_domain || "-"}
        </span>
      ),
    },
    {
      key: "last_health_check",
      header: "Last Check",
      render: (service) =>
        service.last_health_check ? formatRelativeTime(service.last_health_check) : "Never",
    },
  ];

  // Dependency columns
  const dependencyColumns: Column<ServiceDependency>[] = [
    {
      key: "source_name",
      header: "Internal Service",
      render: (dep) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{dep.source_name}</div>
          <div className="text-xs text-gray-500">{dep.source_type}</div>
        </div>
      ),
    },
    {
      key: "external_service_name",
      header: "External Service",
      render: (dep) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{dep.external_service_name}</div>
          <div className="text-xs text-gray-500">{dep.provider || dep.external_service_type}</div>
        </div>
      ),
    },
    {
      key: "dependency_type",
      header: "Type",
      render: (dep) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{dep.dependency_type}</span>
      ),
    },
    {
      key: "is_critical",
      header: "Critical",
      render: (dep) =>
        dep.is_critical ? (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
            Yes
          </span>
        ) : (
          <span className="text-gray-400">No</span>
        ),
    },
    {
      key: "fallback_available",
      header: "Fallback",
      render: (dep) =>
        dep.fallback_available ? (
          <CheckCircle className="h-4 w-4 text-green-500" />
        ) : (
          <XCircle className="h-4 w-4 text-gray-400" />
        ),
    },
    {
      key: "failure_impact",
      header: "Failure Impact",
      render: (dep) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{dep.failure_impact || "-"}</span>
      ),
    },
  ];

  // Risk columns
  const riskColumns: Column<DependencyRisk>[] = [
    {
      key: "source_name",
      header: "Service",
      render: (risk) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{risk.source_name}</div>
          <div className="text-xs text-gray-500">{risk.source_type}</div>
        </div>
      ),
    },
    {
      key: "external_service_name",
      header: "Depends On",
      render: (risk) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{risk.external_service_name}</div>
          <div className="text-xs text-gray-500">{risk.provider || risk.service_type}</div>
        </div>
      ),
    },
    {
      key: "risk_level",
      header: "Risk Level",
      render: (risk) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", riskLevelColors[risk.risk_level])}>
          {risk.risk_level}
        </span>
      ),
    },
    {
      key: "health_status",
      header: "Health",
      render: (risk) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", healthStatusColors[risk.health_status])}>
          {risk.health_status}
        </span>
      ),
    },
    {
      key: "dependency_critical",
      header: "Critical Dep",
      render: (risk) =>
        risk.dependency_critical ? (
          <AlertTriangle className="h-4 w-4 text-red-500" />
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "fallback_available",
      header: "Fallback",
      render: (risk) =>
        risk.fallback_available ? (
          <CheckCircle className="h-4 w-4 text-green-500" />
        ) : (
          <XCircle className="h-4 w-4 text-red-400" />
        ),
    },
  ];

  // Incident columns
  const incidentColumns: Column<ExternalServiceIncident>[] = [
    {
      key: "title",
      header: "Incident",
      render: (incident) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{incident.title}</div>
          <div className="text-xs text-gray-500">{incident.service_name}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (incident) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", incidentStatusColors[incident.status])}>
          {incident.status}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (incident) => (
        <span className={cn("px-2 py-1 text-xs font-medium rounded-full", criticalityColors[incident.severity])}>
          {incident.severity}
        </span>
      ),
    },
    {
      key: "started_at",
      header: "Started",
      render: (incident) => formatRelativeTime(incident.started_at),
    },
    {
      key: "resolved_at",
      header: "Resolved",
      render: (incident) =>
        incident.resolved_at ? formatRelativeTime(incident.resolved_at) : "-",
    },
    {
      key: "user_impact",
      header: "Impact",
      render: (incident) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{incident.user_impact || "-"}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">

      <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <MetricsGrid columns={4}>
            <StatCard
              title="Total Services"
              value={overview?.total_services || 0}
              icon={Server}
            />
            <StatCard
              title="Healthy"
              value={overview?.healthy_services || 0}
              icon={CheckCircle}
              variant="success"
            />
            <StatCard
              title="Unhealthy"
              value={(overview?.unhealthy_services || 0) + (overview?.degraded_services || 0)}
              icon={AlertTriangle}
              variant={(overview?.unhealthy_services || 0) > 0 ? "danger" : "default"}
            />
            <StatCard
              title="Active Incidents"
              value={activeIncidents}
              icon={AlertCircle}
              variant={activeIncidents > 0 ? "danger" : "default"}
            />
          </MetricsGrid>

          {/* Risk Summary */}
          {(criticalRisks > 0 || highRisks > 0) && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-600" />
                <h3 className="font-semibold text-red-800 dark:text-red-200">Risk Alert</h3>
              </div>
              <p className="text-sm text-red-700 dark:text-red-300">
                {criticalRisks > 0 && `${criticalRisks} critical risk${criticalRisks > 1 ? "s" : ""}`}
                {criticalRisks > 0 && highRisks > 0 && " and "}
                {highRisks > 0 && `${highRisks} high risk${highRisks > 1 ? "s" : ""}`}
                {" identified. Review the Risk Assessment tab for details."}
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-6">
            {/* Services by Health */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Services by Health</h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                    <span className="text-gray-600 dark:text-gray-400">Healthy</span>
                  </div>
                  <span className="font-semibold text-gray-900 dark:text-white">{overview?.healthy_services || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <span className="text-gray-600 dark:text-gray-400">Degraded</span>
                  </div>
                  <span className="font-semibold text-gray-900 dark:text-white">{overview?.degraded_services || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <span className="text-gray-600 dark:text-gray-400">Unhealthy</span>
                  </div>
                  <span className="font-semibold text-gray-900 dark:text-white">{overview?.unhealthy_services || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-gray-500" />
                    <span className="text-gray-600 dark:text-gray-400">Unknown</span>
                  </div>
                  <span className="font-semibold text-gray-900 dark:text-white">{overview?.unknown_services || 0}</span>
                </div>
              </div>
            </div>

            {/* Critical Services */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Critical Services</h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">Total Critical</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{overview?.critical_services || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">Critical & Unhealthy</span>
                  <span className={cn("font-semibold", (overview?.critical_unhealthy || 0) > 0 ? "text-red-600" : "text-gray-900 dark:text-white")}>
                    {overview?.critical_unhealthy || 0}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">Dependencies Tracked</span>
                  <span className="font-semibold text-gray-900 dark:text-white">{dependencies.length}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Incidents */}
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Incidents</h3>
            {loadingIncidents ? (
              <div className="animate-pulse space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-12 bg-gray-200 dark:bg-gray-700 rounded" />
                ))}
              </div>
            ) : incidents.length > 0 ? (
              <div className="space-y-2">
                {incidents.slice(0, 5).map((incident) => (
                  <div
                    key={incident.id}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                    onClick={() => setSelectedIncident(incident)}
                  >
                    <div className="flex items-center gap-3">
                      <AlertCircle className={cn(
                        "h-5 w-5",
                        incident.status === "active" ? "text-red-500" : incident.status === "resolved" ? "text-green-500" : "text-yellow-500"
                      )} />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">{incident.title}</div>
                        <div className="text-xs text-gray-500">{incident.service_name}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={cn("px-2 py-1 text-xs font-medium rounded-full", incidentStatusColors[incident.status])}>
                        {incident.status}
                      </span>
                      <span className="text-xs text-gray-500">{formatRelativeTime(incident.started_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-center py-4">No recent incidents</p>
            )}
          </div>
        </div>
      )}

      {/* Services Tab */}
      {activeTab === "services" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={services}
            columns={serviceColumns}
            keyExtractor={(row) => row.id}
            loading={loadingServices}
            onRowClick={setSelectedService}
            emptyState="No external services configured"
          />
        </div>
      )}

      {/* Dependencies Tab */}
      {activeTab === "dependencies" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={dependencies}
            columns={dependencyColumns}
            keyExtractor={(row) => row.id}
            loading={loadingDependencies}
            emptyState="No dependencies mapped"
          />
        </div>
      )}

      {/* Risks Tab */}
      {activeTab === "risks" && (
        <div className="space-y-4">
          <MetricsGrid columns={4}>
            <StatCard
              title="Critical Risks"
              value={criticalRisks}
              icon={AlertTriangle}
              variant={criticalRisks > 0 ? "danger" : "default"}
            />
            <StatCard
              title="High Risks"
              value={highRisks}
              icon={AlertCircle}
              variant={highRisks > 0 ? "warning" : "default"}
            />
            <StatCard
              title="Medium Risks"
              value={risks.filter((r) => r.risk_level === "medium").length}
              icon={Clock}
            />
            <StatCard
              title="Low Risks"
              value={risks.filter((r) => r.risk_level === "low").length}
              icon={CheckCircle}
              variant="success"
            />
          </MetricsGrid>
          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
            <Table
              data={risks}
              columns={riskColumns}
              keyExtractor={(row, index) => `${row.source_name}-${row.external_service_name}-${index}`}
              loading={loadingRisks}
              emptyState="No dependency risks identified"
            />
          </div>
        </div>
      )}

      {/* Incidents Tab */}
      {activeTab === "incidents" && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
          <Table
            data={incidents}
            columns={incidentColumns}
            keyExtractor={(row) => row.id}
            loading={loadingIncidents}
            onRowClick={setSelectedIncident}
            emptyState="No incidents recorded"
          />
        </div>
      )}

      {/* Service Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedService}
        onClose={() => setSelectedService(null)}
        title={selectedService?.name || "Service Details"}
      >
        {selectedService && (
          <div className="space-y-6">
            <div className="flex items-center gap-2">
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", healthStatusColors[selectedService.health_status])}>
                {selectedService.health_status}
              </span>
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", criticalityColors[selectedService.criticality])}>
                {selectedService.criticality}
              </span>
            </div>

            {selectedService.description && (
              <p className="text-gray-600 dark:text-gray-400">{selectedService.description}</p>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Service Type</label>
                <p className="font-medium">{selectedService.service_type}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Provider</label>
                <p className="font-medium">{selectedService.provider || "-"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Environment</label>
                <p className="font-medium">{selectedService.environment}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Protocol</label>
                <p className="font-medium">{selectedService.protocol}</p>
              </div>
            </div>

            {selectedService.endpoint_url && (
              <div>
                <label className="text-sm text-gray-500">Endpoint</label>
                <a
                  href={selectedService.endpoint_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm text-primary-600 hover:underline flex items-center gap-1"
                >
                  {selectedService.endpoint_url}
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            )}

            {/* Health Check */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Health Monitoring</h4>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Check</span>
                  <span>{selectedService.last_health_check ? formatRelativeTime(selectedService.last_health_check) : "Never"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Check Interval</span>
                  <span>{selectedService.health_check_interval_seconds}s</span>
                </div>
                {selectedService.expected_uptime_percent && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Expected Uptime</span>
                    <span>{selectedService.expected_uptime_percent}%</span>
                  </div>
                )}
              </div>
            </div>

            {/* Ownership */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Ownership</h4>
              <div className="text-sm space-y-1">
                {selectedService.owner_team && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Team</span>
                    <span>{selectedService.owner_team}</span>
                  </div>
                )}
                {selectedService.owner_contact && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Contact</span>
                    <span>{selectedService.owner_contact}</span>
                  </div>
                )}
                {selectedService.vendor_contact && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Vendor Contact</span>
                    <span>{selectedService.vendor_contact}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Compliance */}
            {selectedService.compliance_requirements && selectedService.compliance_requirements.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium text-gray-900 dark:text-white">Compliance</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedService.compliance_requirements.map((req) => (
                    <span
                      key={req}
                      className="px-2 py-1 text-xs font-medium rounded-full bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
                    >
                      {req.toUpperCase()}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Tags */}
            {selectedService.tags && selectedService.tags.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium text-gray-900 dark:text-white">Tags</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedService.tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </SlideOver>

      {/* Incident Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        title={selectedIncident?.title || "Incident Details"}
      >
        {selectedIncident && (
          <div className="space-y-6">
            <div className="flex items-center gap-2">
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", incidentStatusColors[selectedIncident.status])}>
                {selectedIncident.status}
              </span>
              <span className={cn("px-3 py-1 text-sm font-medium rounded-full", criticalityColors[selectedIncident.severity])}>
                {selectedIncident.severity}
              </span>
            </div>

            {selectedIncident.description && (
              <p className="text-gray-600 dark:text-gray-400">{selectedIncident.description}</p>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Service</label>
                <p className="font-medium">{selectedIncident.service_name}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Type</label>
                <p className="font-medium">{selectedIncident.incident_type || "-"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">User Impact</label>
                <p className="font-medium">{selectedIncident.user_impact || "-"}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Reported By</label>
                <p className="font-medium">{selectedIncident.reported_by || "-"}</p>
              </div>
            </div>

            {/* Timeline */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 dark:text-white">Timeline</h4>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Started</span>
                  <span>{formatRelativeTime(selectedIncident.started_at)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Detected</span>
                  <span>{formatRelativeTime(selectedIncident.detected_at)}</span>
                </div>
                {selectedIncident.acknowledged_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Acknowledged</span>
                    <span>{formatRelativeTime(selectedIncident.acknowledged_at)}</span>
                  </div>
                )}
                {selectedIncident.resolved_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Resolved</span>
                    <span>{formatRelativeTime(selectedIncident.resolved_at)}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Impact */}
            {selectedIncident.impact_description && (
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Impact Description</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">{selectedIncident.impact_description}</p>
              </div>
            )}

            {/* Affected Services */}
            {selectedIncident.affected_services && selectedIncident.affected_services.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium text-gray-900 dark:text-white">Affected Services</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedIncident.affected_services.map((service) => (
                    <span
                      key={service}
                      className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                    >
                      {service}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Resolution */}
            {selectedIncident.resolution_notes && (
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Resolution Notes</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">{selectedIncident.resolution_notes}</p>
              </div>
            )}

            {selectedIncident.root_cause && (
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Root Cause</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">{selectedIncident.root_cause}</p>
              </div>
            )}

            {/* Vendor Link */}
            {selectedIncident.vendor_incident_url && (
              <a
                href={selectedIncident.vendor_incident_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-primary-600 hover:underline flex items-center gap-1"
              >
                View Vendor Status Page
                <ExternalLink className="h-3 w-3" />
              </a>
            )}

            {/* Actions */}
            {selectedIncident.status !== "resolved" && (
              <div className="flex gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
                {selectedIncident.status === "active" && (
                  <button
                    onClick={() => updateIncidentStatus.mutate({ incidentId: selectedIncident.id, status: "investigating" })}
                    disabled={updateIncidentStatus.isPending}
                    className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                  >
                    Mark Investigating
                  </button>
                )}
                <button
                  onClick={() => updateIncidentStatus.mutate({ incidentId: selectedIncident.id, status: "resolved" })}
                  disabled={updateIncidentStatus.isPending}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
                >
                  Mark Resolved
                </button>
              </div>
            )}
          </div>
        )}
      </SlideOver>
    </div>
  );
}
