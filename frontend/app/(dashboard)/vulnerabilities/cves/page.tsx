"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import {
  Shield,
  AlertCircle,
  Package,
  Server,
  Ban,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SeverityBadge } from "@/components/ui/Badge";

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

export default function CVEsPage() {
  const [selectedCVE, setSelectedCVE] = useState<CVESummary | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [packageFilter, setPackageFilter] = useState<string[]>([]);

  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.fetchAPI<any[]>("/agents"),
  });

  const defaultAgent = agents?.[0];

  const { data: cveData, isLoading } = useQuery({
    queryKey: ["cves", defaultAgent?.id, severityFilter],
    queryFn: () =>
      api.fetchAPI<{ cves: CVESummary[]; count: number }>(
        `/agents/${defaultAgent?.id}/cves?severity=${severityFilter}`
      ),
    enabled: !!defaultAgent?.id,
    refetchInterval: 30000,
  });

  const { data: cveDetail, isLoading: isLoadingDetail } = useQuery({
    queryKey: ["cve-detail", defaultAgent?.id, selectedCVE?.cve_id],
    queryFn: () =>
      api.fetchAPI<CVEDetail>(
        `/agents/${defaultAgent?.id}/cves/${selectedCVE?.cve_id}`
      ),
    enabled: !!defaultAgent?.id && !!selectedCVE,
  });

  const allCVEs = cveData?.cves || [];

  const filteredCVEs = allCVEs.filter((cve) => {
    const matchesSearch =
      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.affected_packages.some((pkg) =>
        pkg.toLowerCase().includes(searchTerm.toLowerCase())
      );
    const matchesPackage =
      packageFilter.length === 0 ||
      cve.affected_packages.some((pkg) => packageFilter.includes(pkg));
    return matchesSearch && matchesPackage;
  });

  const stats = {
    total:    allCVEs.length,
    critical: allCVEs.filter((c) => c.severity === "critical").length,
    high:     allCVEs.filter((c) => c.severity === "high").length,
    medium:   allCVEs.filter((c) => c.severity === "medium").length,
    low:      allCVEs.filter((c) => c.severity === "low").length,
    running:  allCVEs.reduce((sum, cve) => sum + cve.running_count, 0),
    blocked:  allCVEs.reduce((sum, cve) => sum + cve.blocked_count, 0),
  };

  const uniquePackages = Array.from(
    new Set(allCVEs.flatMap((cve) => cve.affected_packages))
  ).sort();

  const filters = [
    {
      id: "severity",
      label: "Severity",
      type: "radio" as const,
      value: severityFilter,
      onChange: (value: string | string[]) => setSeverityFilter(value as SeverityFilter),
      options: [
        { label: "All",      value: "all",      count: stats.total },
        { label: "Critical", value: "critical", count: stats.critical },
        { label: "High",     value: "high",     count: stats.high },
        { label: "Medium",   value: "medium",   count: stats.medium },
        { label: "Low",      value: "low",      count: stats.low },
      ],
    },
    {
      id: "package",
      label: "Affected Package",
      type: "checkbox" as const,
      value: packageFilter,
      onChange: (value: string | string[]) => setPackageFilter(value as string[]),
      options: uniquePackages.slice(0, 10).map((pkg) => ({ label: pkg, value: pkg })),
    },
    {
      id: "search",
      label: "Search",
      type: "search" as const,
      value: searchTerm,
      onChange: (value: string | string[]) => setSearchTerm(value as string),
    },
  ];

  const columns = [
    {
      key: "cve_id",
      header: "CVE ID",
      sortable: true,
      width: "200px",
      render: (value: string) => (
        <span className="font-mono font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      sortable: true,
      width: "120px",
      render: (value: string, row: CVESummary) => (
        <div className="flex items-center gap-2">
          <SeverityBadge severity={value as "critical" | "high" | "medium" | "low"} size="sm" />
          {row.cvss_v3_score && (
            <span className="text-xs text-gray-500 dark:text-gray-400">{row.cvss_v3_score}</span>
          )}
        </div>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (value: string) => (
        <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">{value}</p>
      ),
    },
    {
      key: "affected_packages",
      header: "Packages",
      width: "100px",
      align: "center" as const,
      render: (value: string[]) => (
        <div className="flex items-center justify-center gap-1 text-sm text-gray-600 dark:text-gray-400">
          <Package className="w-4 h-4" />
          <span>{value.length}</span>
        </div>
      ),
    },
    {
      key: "running_count",
      header: "Running",
      width: "100px",
      align: "center" as const,
      sortable: true,
      render: (value: number) => (
        <div
          className={cn(
            "flex items-center justify-center gap-1 text-sm",
            value > 0
              ? "text-orange-600 dark:text-orange-400 font-medium"
              : "text-gray-500 dark:text-gray-400"
          )}
        >
          <Server className="w-4 h-4" />
          <span>{value}</span>
        </div>
      ),
    },
    {
      key: "blocked_count",
      header: "Blocked",
      width: "100px",
      align: "center" as const,
      sortable: true,
      render: (value: number) => (
        <div
          className={cn(
            "flex items-center justify-center gap-1 text-sm",
            value > 0
              ? "text-green-600 dark:text-green-400 font-medium"
              : "text-gray-500 dark:text-gray-400"
          )}
        >
          <Ban className="w-4 h-4" />
          <span>{value}</span>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard label="Total CVEs"          value={stats.total}                  icon={Shield}       iconColor="text-primary-600" />
        <StatCard label="Critical + High"      value={stats.critical + stats.high}  description={`${stats.critical} critical, ${stats.high} high`} icon={AlertCircle}  iconColor="text-red-600" valueColor="text-red-600 dark:text-red-400" />
        <StatCard label="Running Deployments"  value={stats.running}                description="Affected deployments"  icon={Server}       iconColor="text-orange-600" valueColor="text-orange-600 dark:text-orange-400" />
        <StatCard label="Blocked by Policy"    value={stats.blocked}                description="Prevented deployments" icon={Ban}          iconColor="text-green-600" valueColor="text-green-600 dark:text-green-400" />
      </MetricsGrid>

      {/* Filters + Table */}
      <div className="flex gap-6">
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filters}
            onReset={() => {
              setSeverityFilter("all");
              setPackageFilter([]);
              setSearchTerm("");
            }}
          />
        </div>

        <div className="flex-1 flex flex-col min-w-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
          {/* Search Bar */}
          <div className="p-4 border-b border-gray-200 dark:border-gray-800">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search by CVE ID, description, or package..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>
          </div>

          {/* Table */}
          <div className="flex-1 overflow-auto">
            {isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Spinner size="lg" label="Loading vulnerabilities..." />
              </div>
            ) : filteredCVEs.length === 0 ? (
              <EmptyState
                icon={Shield}
                title={stats.total === 0 ? "No Vulnerabilities Found" : "No Matching CVEs"}
                description={
                  stats.total === 0
                    ? "All scanned images are secure."
                    : "Try adjusting your search or filters."
                }
              />
            ) : (
              <Table
                columns={columns}
                data={filteredCVEs}
                keyExtractor={(row) => row.cve_id}
                onRowClick={(row) => setSelectedCVE(row)}
                hoverable
              />
            )}
          </div>
        </div>
      </div>

      {/* CVE Detail SlideOver */}
      <SlideOver isOpen={!!selectedCVE} onClose={() => setSelectedCVE(null)} size="lg">
        {selectedCVE && (
          <>
            <SlideOver.Header onClose={() => setSelectedCVE(null)}>
              <div>
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                  {selectedCVE.cve_id}
                </h2>
                <div className="mt-1">
                  <SeverityBadge
                    severity={selectedCVE.severity as "critical" | "high" | "medium" | "low"}
                  />
                </div>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {isLoadingDetail ? (
                <div className="flex items-center justify-center py-12">
                  <Spinner size="lg" label="Loading details..." />
                </div>
              ) : cveDetail ? (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Vulnerability Information
                    </h3>
                    <div className="space-y-2">
                      {cveDetail.cvss_v3_score && (
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-500 dark:text-gray-400">CVSS v3 Score</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {cveDetail.cvss_v3_score}
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500 dark:text-gray-400">First Detected</span>
                        <span className="text-gray-900 dark:text-white">
                          {new Date(cveDetail.first_detected).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500 dark:text-gray-400">Total Occurrences</span>
                        <span className="text-gray-900 dark:text-white">{cveDetail.total_occurrences}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Description</h3>
                    <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                      {cveDetail.description}
                    </p>
                  </div>

                  {cveDetail.affected_packages.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        Affected Packages ({cveDetail.affected_packages.length})
                      </h3>
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
                    </div>
                  )}

                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Running Deployments ({cveDetail.running_deployments.length})
                    </h3>
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
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                      Blocked Deployments ({cveDetail.blocked_deployments.length})
                    </h3>
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
                  </div>
                </div>
              ) : null}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>
    </div>
  );
}
