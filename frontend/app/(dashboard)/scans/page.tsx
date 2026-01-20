"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  Clock,
  Package,
  Search,
  Filter,
  ChevronRight,
  RefreshCw,
  ExternalLink,
  Image as ImageIcon,
  X,
} from "lucide-react";
import { api, ScanResult, Vulnerability, SBOM } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Tabs } from "@/components/ui/page-layout";
import { ScanModal } from "@/components/ui/ScanModal";

type TabType = "scans" | "sboms";

export default function ScansPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>("scans");
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [selectedSBOM, setSelectedSBOM] = useState<SBOM | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [showScanModal, setShowScanModal] = useState(false);
  const [newScanImage, setNewScanImage] = useState("");

  // Fetch scans
  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
  });

  // Fetch SBOMs
  const { data: sboms, isLoading: sbomsLoading } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => api.listSBOMs(),
  });

  // Fetch vulnerabilities for selected scan
  const { data: vulnerabilities, isLoading: vulnsLoading } = useQuery({
    queryKey: ["scan-vulnerabilities", selectedScan?.id],
    queryFn: () => api.getScanVulnerabilities(selectedScan!.id),
    enabled: !!selectedScan?.id,
  });

  // Filter scans
  const filteredScans = scans?.filter((scan) => {
    if (searchQuery && !scan.image_repository.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    if (severityFilter.length > 0) {
      const hasCritical = severityFilter.includes("critical") && scan.critical > 0;
      const hasHigh = severityFilter.includes("high") && scan.high > 0;
      const hasMedium = severityFilter.includes("medium") && scan.medium > 0;
      const hasLow = severityFilter.includes("low") && scan.low > 0;
      if (!hasCritical && !hasHigh && !hasMedium && !hasLow) {
        return false;
      }
    }
    return true;
  }) || [];

  // Filter SBOMs
  const filteredSBOMs = sboms?.filter((sbom) => {
    if (searchQuery && !sbom.image_repository.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    return true;
  }) || [];

  // Calculate metrics
  const totalScans = scans?.length || 0;
  const criticalIssues = scans?.reduce((sum, s) => sum + s.critical, 0) || 0;
  const highIssues = scans?.reduce((sum, s) => sum + s.high, 0) || 0;
  const uniqueImages = new Set(scans?.map((s) => s.image_repository) || []).size;
  const lastScan = scans && scans.length > 0
    ? scans.reduce((latest, scan) =>
        new Date(scan.scanned_at) > new Date(latest.scanned_at) ? scan : latest
      )
    : null;

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter((prev) =>
      prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
    );
  };

  const handleNewScan = () => {
    if (newScanImage.trim()) {
      setShowScanModal(true);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "high":
        return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
      case "medium":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "low":
        return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400";
    }
  };

  // Scans table columns
  const scanColumns = [
    {
      key: "image_repository",
      header: "Image",
      sortable: true,
      render: (_: any, row: ScanResult) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <ImageIcon className="h-4 w-4 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white text-sm">
              {row.image_repository}
            </p>
            {row.image_tag && (
              <p className="text-xs text-gray-500">{row.image_tag}</p>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "critical",
      header: "Critical",
      align: "center" as const,
      sortable: true,
      render: (value: number) =>
        value > 0 ? (
          <Badge className="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 border-0 px-2 py-0.5">
            {value}
          </Badge>
        ) : (
          <span className="text-gray-400">0</span>
        ),
    },
    {
      key: "high",
      header: "High",
      align: "center" as const,
      sortable: true,
      render: (value: number) =>
        value > 0 ? (
          <Badge className="bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 border-0 px-2 py-0.5">
            {value}
          </Badge>
        ) : (
          <span className="text-gray-400">0</span>
        ),
    },
    {
      key: "medium",
      header: "Medium",
      align: "center" as const,
      sortable: true,
      render: (value: number) =>
        value > 0 ? (
          <Badge className="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 border-0 px-2 py-0.5">
            {value}
          </Badge>
        ) : (
          <span className="text-gray-400">0</span>
        ),
    },
    {
      key: "low",
      header: "Low",
      align: "center" as const,
      sortable: true,
      render: (value: number) =>
        value > 0 ? (
          <Badge className="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 border-0 px-2 py-0.5">
            {value}
          </Badge>
        ) : (
          <span className="text-gray-400">0</span>
        ),
    },
    {
      key: "total",
      header: "Total",
      align: "center" as const,
      sortable: true,
      render: (value: number) => (
        <span className="font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
    {
      key: "scanned_at",
      header: "Scanned",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-500">{formatRelativeTime(value)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      width: "120px",
      render: (_: any, row: ScanResult) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/scans/${row.id}`);
          }}
          className="px-3 py-1.5 text-sm font-medium text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg transition-colors"
        >
          View Report
        </button>
      ),
    },
  ];

  // SBOMs table columns
  const sbomColumns = [
    {
      key: "image_repository",
      header: "Image",
      sortable: true,
      render: (_: any, row: SBOM) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <Package className="h-4 w-4 text-gray-500" />
          </div>
          <p className="font-medium text-gray-900 dark:text-white text-sm">
            {row.image_repository}
          </p>
        </div>
      ),
    },
    {
      key: "format",
      header: "Format",
      render: (value: string) => (
        <Badge size="sm">
          {value}
        </Badge>
      ),
    },
    {
      key: "total_packages",
      header: "Packages",
      align: "center" as const,
      sortable: true,
      render: (value: number) => (
        <span className="font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
    {
      key: "os_packages",
      header: "OS",
      align: "center" as const,
      render: (value: number) => (
        <span className="text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "library_packages",
      header: "Libraries",
      align: "center" as const,
      render: (value: number) => (
        <span className="text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "created_at",
      header: "Generated",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-500">{formatRelativeTime(value)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      width: "100px",
      render: (_: any, row: SBOM) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            api.downloadSBOM(row.id);
          }}
          className="px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
        >
          Download
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Scans"
        description="View vulnerability scans and software bill of materials"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Deploy", href: "/" },
              { label: "Scans", current: true },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newScanImage}
                onChange={(e) => setNewScanImage(e.target.value)}
                placeholder="nginx:latest"
                className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 w-48"
                onKeyDown={(e) => e.key === "Enter" && handleNewScan()}
              />
              <Button
                variant="primary"
                size="sm"
                onClick={handleNewScan}
                disabled={!newScanImage.trim()}
              >
                <Shield className="h-4 w-4 mr-1" />
                New Scan
              </Button>
            </div>
          </div>
        }
      />

      {/* Metrics */}
      <MetricsGrid columns={4} className="mb-6">
        <StatCard
          label="Total Scans"
          value={totalScans}
          icon={Shield}
          iconColor="text-primary-600 dark:text-primary-400"
        />
        <StatCard
          label="Critical Issues"
          value={criticalIssues}
          icon={AlertTriangle}
          iconColor="text-red-600 dark:text-red-400"
        />
        <StatCard
          label="High Issues"
          value={highIssues}
          icon={AlertTriangle}
          iconColor="text-orange-600 dark:text-orange-400"
        />
        <StatCard
          label="Images Scanned"
          value={uniqueImages}
          icon={ImageIcon}
          iconColor="text-blue-600 dark:text-blue-400"
        />
      </MetricsGrid>

      {/* Tabs */}
      <div className="mb-4">
        <Tabs
          tabs={[
            { id: "scans", label: "Vulnerability Scans", count: scans?.length || 0 },
            { id: "sboms", label: "SBOMs", count: sboms?.length || 0 },
          ]}
          activeTab={activeTab}
          onChange={(id) => setActiveTab(id as TabType)}
        />
      </div>

      {/* Filters */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search images..."
              className="pl-9 pr-3 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 w-64"
            />
          </div>

          {activeTab === "scans" && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500 dark:text-gray-400">Severity:</span>
              {["critical", "high", "medium", "low"].map((severity) => (
                <button
                  key={severity}
                  onClick={() => toggleSeverityFilter(severity)}
                  className={cn(
                    "px-2.5 py-1 text-xs font-medium rounded-full transition-colors",
                    severityFilter.includes(severity)
                      ? getSeverityColor(severity)
                      : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
                  )}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </button>
              ))}
              {severityFilter.length > 0 && (
                <button
                  onClick={() => setSeverityFilter([])}
                  className="text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                >
                  Clear
                </button>
              )}
            </div>
          )}
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["scans"] })}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Scans Tab */}
      {activeTab === "scans" && (
        <>
          {scansLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" />
            </div>
          ) : filteredScans.length > 0 ? (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
              <Table
                columns={scanColumns}
                data={filteredScans}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => router.push(`/scans/${row.id}`)}
                hoverable
              />
            </div>
          ) : (
            <EmptyState
              icon={Shield}
              title="No scans found"
              description={searchQuery || severityFilter.length > 0
                ? "No scans match your filters"
                : "Scan an image to see vulnerability results"
              }
              action={
                <Button variant="primary" onClick={() => setShowScanModal(true)}>
                  <Shield className="h-4 w-4 mr-1" />
                  Start Scanning
                </Button>
              }
            />
          )}
        </>
      )}

      {/* SBOMs Tab */}
      {activeTab === "sboms" && (
        <>
          {sbomsLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" />
            </div>
          ) : filteredSBOMs.length > 0 ? (
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
              <Table
                columns={sbomColumns}
                data={filteredSBOMs}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedSBOM(row)}
                hoverable
              />
            </div>
          ) : (
            <EmptyState
              icon={Package}
              title="No SBOMs found"
              description="Generate an SBOM to see software packages"
              action={
                <Button variant="primary" onClick={() => setShowScanModal(true)}>
                  <Package className="h-4 w-4 mr-1" />
                  Generate SBOM
                </Button>
              }
            />
          )}
        </>
      )}

      {/* Scan Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedScan}
        onClose={() => setSelectedScan(null)}
        size="lg"
      >
        {selectedScan && (
          <>
            <SlideOver.Header onClose={() => setSelectedScan(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Scan Details
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                  {selectedScan.image_repository}
                  {selectedScan.image_tag && `:${selectedScan.image_tag}`}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Summary Cards */}
                <div className="grid grid-cols-5 gap-3">
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {selectedScan.critical}
                    </p>
                    <p className="text-xs text-red-600 dark:text-red-400">Critical</p>
                  </div>
                  <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                      {selectedScan.high}
                    </p>
                    <p className="text-xs text-orange-600 dark:text-orange-400">High</p>
                  </div>
                  <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {selectedScan.medium}
                    </p>
                    <p className="text-xs text-yellow-600 dark:text-yellow-400">Medium</p>
                  </div>
                  <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {selectedScan.low}
                    </p>
                    <p className="text-xs text-blue-600 dark:text-blue-400">Low</p>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg text-center">
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {selectedScan.total}
                    </p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">Total</p>
                  </div>
                </div>

                {/* Scan Info */}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                    Scan Information
                  </h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Scanner</p>
                      <p className="text-gray-900 dark:text-white">
                        {selectedScan.scanner_name}
                        {selectedScan.scanner_version && ` v${selectedScan.scanner_version}`}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Scanned</p>
                      <p className="text-gray-900 dark:text-white">
                        {new Date(selectedScan.scanned_at).toLocaleString()}
                      </p>
                    </div>
                    {selectedScan.scan_duration_ms && (
                      <div>
                        <p className="text-gray-500 dark:text-gray-400">Duration</p>
                        <p className="text-gray-900 dark:text-white">
                          {(selectedScan.scan_duration_ms / 1000).toFixed(1)}s
                        </p>
                      </div>
                    )}
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Fixable</p>
                      <p className="text-gray-900 dark:text-white">
                        {selectedScan.fixable} of {selectedScan.total}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities List */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Vulnerabilities
                  </h3>
                  {vulnsLoading ? (
                    <div className="flex items-center justify-center h-32">
                      <Spinner />
                    </div>
                  ) : vulnerabilities && vulnerabilities.length > 0 ? (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {vulnerabilities.map((vuln) => (
                        <div
                          key={vuln.id}
                          className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <Badge className={cn("border-0", getSeverityColor(vuln.severity))}>
                                  {vuln.severity.toUpperCase()}
                                </Badge>
                                <span className="font-mono text-sm text-gray-900 dark:text-white">
                                  {vuln.cve_id}
                                </span>
                              </div>
                              <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                                {vuln.package_name}
                                {vuln.package_version && ` @ ${vuln.package_version}`}
                              </p>
                              {vuln.title && (
                                <p className="text-xs text-gray-500 dark:text-gray-500 mt-1 line-clamp-2">
                                  {vuln.title}
                                </p>
                              )}
                            </div>
                            <div className="text-right flex-shrink-0">
                              {vuln.fix_available && vuln.fixed_version && (
                                <p className="text-xs text-green-600 dark:text-green-400">
                                  Fix: {vuln.fixed_version}
                                </p>
                              )}
                              {vuln.cvss_score && (
                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                  CVSS: {vuln.cvss_score}
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                      No vulnerabilities found
                    </div>
                  )}
                </div>
              </div>
            </SlideOver.Body>

            <SlideOver.Footer>
              <Button
                variant="secondary"
                onClick={() => {
                  // Re-scan functionality
                  setNewScanImage(
                    `${selectedScan.image_repository}${selectedScan.image_tag ? `:${selectedScan.image_tag}` : ""}`
                  );
                  setSelectedScan(null);
                  setShowScanModal(true);
                }}
              >
                <RefreshCw className="h-4 w-4 mr-1" />
                Re-scan
              </Button>
            </SlideOver.Footer>
          </>
        )}
      </SlideOver>

      {/* SBOM Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedSBOM}
        onClose={() => setSelectedSBOM(null)}
        size="md"
      >
        {selectedSBOM && (
          <>
            <SlideOver.Header onClose={() => setSelectedSBOM(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  SBOM Details
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                  {selectedSBOM.image_repository}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Package Stats */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {selectedSBOM.total_packages}
                    </p>
                    <p className="text-xs text-blue-600 dark:text-blue-400">Total Packages</p>
                  </div>
                  <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                      {selectedSBOM.os_packages}
                    </p>
                    <p className="text-xs text-green-600 dark:text-green-400">OS Packages</p>
                  </div>
                  <div className="p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg text-center">
                    <p className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {selectedSBOM.library_packages}
                    </p>
                    <p className="text-xs text-purple-600 dark:text-purple-400">Libraries</p>
                  </div>
                </div>

                {/* SBOM Info */}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                    SBOM Information
                  </h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Format</p>
                      <p className="text-gray-900 dark:text-white">{selectedSBOM.format}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Spec Version</p>
                      <p className="text-gray-900 dark:text-white">{selectedSBOM.spec_version}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Generator</p>
                      <p className="text-gray-900 dark:text-white">
                        {selectedSBOM.generator_name}
                        {selectedSBOM.generator_version && ` v${selectedSBOM.generator_version}`}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">Generated</p>
                      <p className="text-gray-900 dark:text-white">
                        {new Date(selectedSBOM.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </SlideOver.Body>

            <SlideOver.Footer>
              <Button
                variant="primary"
                onClick={() => api.downloadSBOM(selectedSBOM.id)}
              >
                <ExternalLink className="h-4 w-4 mr-1" />
                Download SBOM
              </Button>
            </SlideOver.Footer>
          </>
        )}
      </SlideOver>

      {/* Scan Modal */}
      <ScanModal
        isOpen={showScanModal}
        onClose={() => {
          setShowScanModal(false);
          setNewScanImage("");
        }}
        images={newScanImage ? [{ reference: newScanImage }] : []}
        onComplete={() => {
          queryClient.invalidateQueries({ queryKey: ["scans"] });
          queryClient.invalidateQueries({ queryKey: ["sboms"] });
        }}
        mode="both"
      />
    </div>
  );
}
