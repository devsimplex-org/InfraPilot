"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Search,
  Package,
  Server,
  Ban,
  Eye,
  TrendingUp,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  PageLayout,
  ListCard,
  EmptyState,
  Button,
  Tabs,
} from "@/components/ui/page-layout";
import {
  DetailPanel,
  DetailSection,
  DetailRow,
} from "@/components/ui/detail-panel";

// ==================== Types ====================

interface CVESummary {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  affected_packages: string[];
  running_count: number;
  blocked_count: number;
  first_seen: string;
  last_seen: string;
}

interface CVEDetail {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  published_date: string | null;
  last_modified_date: string | null;
  references: string[];
  affected_packages: AffectedPackageInfo[];
  running_deployments: DeploymentCVEInfo[];
  blocked_deployments: DeploymentCVEInfo[];
  first_detected: string;
  last_detected: string;
  total_occurrences: number;
}

interface AffectedPackageInfo {
  package_name: string;
  package_version: string;
  fixed_version: string;
}

interface DeploymentCVEInfo {
  deployment_id: string;
  service_name: string;
  environment: string;
  image_repository: string;
  image_tag: string;
  status: string;
  created_at: string;
  package_name: string;
  package_version: string;
  policy_blocked: boolean;
  policy_reason: string | null;
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

// ==================== Component ====================

export default function VulnerabilitiesPage() {
  const [selectedCVE, setSelectedCVE] = useState<CVESummary | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [searchTerm, setSearchTerm] = useState("");

  // Fetch default agent
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.fetchAPI<any[]>("/agents"),
  });

  const defaultAgent = agents?.[0];

  // Fetch CVE summaries
  const { data: cveData, isLoading } = useQuery({
    queryKey: ["cves", defaultAgent?.id, severityFilter],
    queryFn: () =>
      api.fetchAPI<{ cves: CVESummary[]; count: number }>(
        `/agents/${defaultAgent?.id}/cves?severity=${severityFilter}`
      ),
    enabled: !!defaultAgent?.id,
    refetchInterval: 30000,
  });

  // Fetch selected CVE details
  const { data: cveDetail } = useQuery({
    queryKey: ["cve-detail", defaultAgent?.id, selectedCVE?.cve_id],
    queryFn: () =>
      api.fetchAPI<CVEDetail>(
        `/agents/${defaultAgent?.id}/cves/${selectedCVE?.cve_id}`
      ),
    enabled: !!defaultAgent?.id && !!selectedCVE,
  });

  const allCVEs = cveData?.cves || [];

  // Apply search filter
  const filteredCVEs = allCVEs.filter(
    (cve) =>
      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.affected_packages.some((pkg) =>
        pkg.toLowerCase().includes(searchTerm.toLowerCase())
      )
  );

  // Calculate stats
  const stats = {
    total: allCVEs.length,
    critical: allCVEs.filter((c) => c.severity === "critical").length,
    high: allCVEs.filter((c) => c.severity === "high").length,
    medium: allCVEs.filter((c) => c.severity === "medium").length,
    low: allCVEs.filter((c) => c.severity === "low").length,
    running: allCVEs.reduce((sum, cve) => sum + cve.running_count, 0),
    blocked: allCVEs.reduce((sum, cve) => sum + cve.blocked_count, 0),
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "high":
        return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
      case "medium":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "low":
        return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
      case "high":
        return AlertCircle;
      case "medium":
        return AlertTriangle;
      default:
        return Shield;
    }
  };

  return (
    <PageLayout
      title="CVE-Centric View"
      description="Track vulnerabilities and their impact across deployments"
      panel={
        selectedCVE && cveDetail && (
          <DetailPanel
            open={!!selectedCVE}
            onClose={() => setSelectedCVE(null)}
            title={cveDetail.cve_id}
            subtitle={`${cveDetail.severity.toUpperCase()} severity`}
          >
            {/* CVE Details */}
            <DetailSection title="Vulnerability Information">
              <DetailRow
                label="Severity"
                value={
                  <span className={cn("px-2 py-1 text-xs font-medium rounded-full capitalize", getSeverityColor(cveDetail.severity))}>
                    {cveDetail.severity}
                  </span>
                }
              />
              {cveDetail.cvss_v3_score && (
                <DetailRow
                  label="CVSS v3 Score"
                  value={<span className="font-semibold">{cveDetail.cvss_v3_score}</span>}
                />
              )}
              <DetailRow
                label="First Detected"
                value={new Date(cveDetail.first_detected).toLocaleDateString()}
              />
              <DetailRow
                label="Total Occurrences"
                value={cveDetail.total_occurrences}
              />
            </DetailSection>

            <DetailSection title="Description">
              <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {cveDetail.description}
              </p>
            </DetailSection>

            {/* Affected Packages */}
            {cveDetail.affected_packages.length > 0 && (
              <DetailSection title={`Affected Packages (${cveDetail.affected_packages.length})`}>
                <div className="space-y-2">
                  {cveDetail.affected_packages.map((pkg, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="font-mono font-medium text-sm text-gray-900 dark:text-white">
                            {pkg.package_name}
                          </span>
                          <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                            {pkg.package_version}
                          </span>
                        </div>
                        {pkg.fixed_version && (
                          <div className="text-xs">
                            <span className="text-gray-500 dark:text-gray-400">Fixed: </span>
                            <span className="font-medium text-green-600 dark:text-green-400">
                              {pkg.fixed_version}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </DetailSection>
            )}

            {/* Running Deployments */}
            <DetailSection title={`Running Deployments (${cveDetail.running_deployments.length})`}>
              {cveDetail.running_deployments.length === 0 ? (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  No running deployments affected
                </p>
              ) : (
                <div className="space-y-2">
                  {cveDetail.running_deployments.map((dep) => (
                    <div
                      key={dep.deployment_id}
                      className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <div className="font-medium text-sm text-gray-900 dark:text-white">
                          {dep.service_name}
                        </div>
                        <span className="px-2 py-0.5 text-xs font-medium bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400 rounded">
                          {dep.status}
                        </span>
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">
                        <div>{dep.environment}</div>
                        <div className="font-mono">
                          {dep.image_repository}:{dep.image_tag}
                        </div>
                        <div className="mt-1">
                          {dep.package_name} {dep.package_version}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </DetailSection>

            {/* Blocked Deployments */}
            <DetailSection title={`Blocked Deployments (${cveDetail.blocked_deployments.length})`}>
              {cveDetail.blocked_deployments.length === 0 ? (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  No deployments blocked by policy
                </p>
              ) : (
                <div className="space-y-2">
                  {cveDetail.blocked_deployments.map((dep) => (
                    <div
                      key={dep.deployment_id}
                      className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <div className="font-medium text-sm text-gray-900 dark:text-white">
                          {dep.service_name}
                        </div>
                        <span className="px-2 py-0.5 text-xs font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400 rounded">
                          BLOCKED
                        </span>
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">
                        <div>{dep.environment}</div>
                        <div className="font-mono">
                          {dep.image_repository}:{dep.image_tag}
                        </div>
                        {dep.policy_reason && (
                          <div className="mt-2 p-2 bg-white dark:bg-gray-900 border border-green-300 dark:border-green-700 rounded text-green-700 dark:text-green-400">
                            <strong>Policy: </strong>
                            {dep.policy_reason}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </DetailSection>
          </DetailPanel>
        )
      }
      panelOpen={!!selectedCVE}
    >
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total CVEs</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.total}
              </p>
            </div>
            <Shield className="w-8 h-8 text-primary-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Critical + High</p>
              <p className="text-2xl font-semibold text-red-600 dark:text-red-400 mt-1">
                {stats.critical + stats.high}
              </p>
            </div>
            <AlertCircle className="w-8 h-8 text-red-500" />
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            {stats.critical} critical, {stats.high} high
          </p>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Running</p>
              <p className="text-2xl font-semibold text-orange-600 dark:text-orange-400 mt-1">
                {stats.running}
              </p>
            </div>
            <Server className="w-8 h-8 text-orange-500" />
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            Affected deployments
          </p>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Blocked</p>
              <p className="text-2xl font-semibold text-green-600 dark:text-green-400 mt-1">
                {stats.blocked}
              </p>
            </div>
            <Ban className="w-8 h-8 text-green-500" />
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            By policy
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-6 relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
        <input
          type="text"
          placeholder="Search by CVE ID, description, or package name..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-800 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
        />
      </div>

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "all", label: "All", count: allCVEs.length },
          { id: "critical", label: "Critical", count: stats.critical },
          { id: "high", label: "High", count: stats.high },
          { id: "medium", label: "Medium", count: stats.medium },
          { id: "low", label: "Low", count: stats.low },
        ]}
        activeTab={severityFilter}
        onChange={(id) => setSeverityFilter(id as SeverityFilter)}
      />

      {/* CVE List */}
      <div className="mt-6">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : filteredCVEs.length === 0 ? (
          <EmptyState
            icon={Shield}
            title={stats.total === 0 ? "No Vulnerabilities Found" : "No Matching CVEs"}
            description={
              stats.total === 0
                ? "All scanned images are secure. Start scanning deployments to track vulnerabilities."
                : searchTerm
                ? "Try adjusting your search term."
                : "No CVEs match the selected severity level."
            }
          />
        ) : (
          <div className="space-y-4">
            {filteredCVEs.map((cve) => {
              const SeverityIcon = getSeverityIcon(cve.severity);
              return (
                <ListCard
                  key={cve.cve_id}
                  selected={selectedCVE?.cve_id === cve.cve_id}
                  onClick={() => setSelectedCVE(cve)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <SeverityIcon
                        className={cn(
                          "w-5 h-5 flex-shrink-0",
                          cve.severity === "critical" && "text-red-500",
                          cve.severity === "high" && "text-orange-500",
                          cve.severity === "medium" && "text-yellow-500",
                          cve.severity === "low" && "text-blue-500"
                        )}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="text-sm font-mono font-medium text-gray-900 dark:text-white">
                            {cve.cve_id}
                          </h3>
                          <span
                            className={cn(
                              "px-2 py-0.5 text-xs font-medium rounded-full capitalize",
                              getSeverityColor(cve.severity)
                            )}
                          >
                            {cve.severity}
                          </span>
                          {cve.cvss_v3_score && (
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              CVSS: {cve.cvss_v3_score}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-1">
                          {cve.description}
                        </p>
                        <div className="flex items-center gap-3 mt-1 text-xs text-gray-500 dark:text-gray-400">
                          <span className="flex items-center gap-1">
                            <Package className="w-3 h-3" />
                            {cve.affected_packages.length} package
                            {cve.affected_packages.length !== 1 ? "s" : ""}
                          </span>
                          {cve.running_count > 0 && (
                            <span className="flex items-center gap-1 text-orange-600 dark:text-orange-400">
                              <Server className="w-3 h-3" />
                              {cve.running_count} running
                            </span>
                          )}
                          {cve.blocked_count > 0 && (
                            <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
                              <Ban className="w-3 h-3" />
                              {cve.blocked_count} blocked
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <Eye className="w-4 h-4 text-gray-400" />
                  </div>
                </ListCard>
              );
            })}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
