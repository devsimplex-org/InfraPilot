"use client";

import { useState, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  Package,
  Clock,
  ArrowLeft,
  Download,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  Copy,
  Check,
} from "lucide-react";
import { api, ScanResult, Vulnerability } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/page-layout";
import { EmptyState } from "@/components/ui/EmptyState";

type SortField = "severity" | "cve_id" | "package_name" | "cvss_score";
type SortOrder = "asc" | "desc";

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const [copiedCve, setCopiedCve] = useState<string | null>(null);

  // Fetch scan details
  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScanDetails(scanId),
  });

  // Fetch vulnerabilities
  const { data: vulnerabilities, isLoading: vulnsLoading } = useQuery({
    queryKey: ["scan-vulnerabilities", scanId],
    queryFn: () => api.getScanVulnerabilities(scanId),
    enabled: !!scanId,
  });

  // Filter and sort vulnerabilities
  const filteredVulns = useMemo(() => {
    if (!vulnerabilities) return [];

    let filtered = vulnerabilities.filter((vuln) => {
      if (severityFilter.length > 0 && !severityFilter.includes(vuln.severity)) {
        return false;
      }
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          vuln.cve_id.toLowerCase().includes(query) ||
          vuln.package_name.toLowerCase().includes(query) ||
          vuln.title?.toLowerCase().includes(query) ||
          vuln.description?.toLowerCase().includes(query)
        );
      }
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case "severity":
          comparison = severityOrder[a.severity] - severityOrder[b.severity];
          break;
        case "cve_id":
          comparison = a.cve_id.localeCompare(b.cve_id);
          break;
        case "package_name":
          comparison = a.package_name.localeCompare(b.package_name);
          break;
        case "cvss_score":
          comparison = (b.cvss_score || 0) - (a.cvss_score || 0);
          break;
      }
      return sortOrder === "asc" ? comparison : -comparison;
    });

    return filtered;
  }, [vulnerabilities, severityFilter, searchQuery, sortField, sortOrder]);

  // Group vulnerabilities by package
  const vulnsByPackage = useMemo(() => {
    const grouped = new Map<string, Vulnerability[]>();
    filteredVulns.forEach((vuln) => {
      const key = `${vuln.package_name}@${vuln.package_version || "unknown"}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(vuln);
    });
    return grouped;
  }, [filteredVulns]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  const toggleExpand = (vulnId: string) => {
    setExpandedVulns((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(vulnId)) {
        newSet.delete(vulnId);
      } else {
        newSet.add(vulnId);
      }
      return newSet;
    });
  };

  const copyCve = (cveId: string) => {
    navigator.clipboard.writeText(cveId);
    setCopiedCve(cveId);
    setTimeout(() => setCopiedCve(null), 2000);
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

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case "high":
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case "medium":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "low":
        return <Shield className="h-4 w-4 text-blue-500" />;
      default:
        return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const exportToCSV = () => {
    if (!vulnerabilities || !scan) return;

    const headers = ["CVE ID", "Severity", "Package", "Version", "Fixed Version", "CVSS Score", "Title"];
    const rows = vulnerabilities.map((v) => [
      v.cve_id,
      v.severity,
      v.package_name,
      v.package_version || "",
      v.fixed_version || "",
      v.cvss_score?.toString() || "",
      v.title || "",
    ]);

    const csv = [headers.join(","), ...rows.map((r) => r.map((c) => `"${c}"`).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${scan.image_repository.replace(/[/:]/g, "-")}-${scanId.slice(0, 8)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="space-y-6">
        <EmptyState
          icon={Shield}
          title="Scan not found"
          description="The scan you're looking for doesn't exist or has been deleted."
          action={
            <Button variant="primary" onClick={() => router.push("/scans")}>
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back to Scans
            </Button>
          }
        />
      </div>
    );
  }

  const imageRef = `${scan.image_repository}${scan.image_tag ? `:${scan.image_tag}` : ""}`;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan Report"
        description={imageRef}
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Deploy", href: "/" },
              { label: "Scans", href: "/scans" },
              { label: "Report", current: true },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => router.push("/scans")}>
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back
            </Button>
            <Button variant="secondary" size="sm" onClick={exportToCSV}>
              <Download className="h-4 w-4 mr-1" />
              Export CSV
            </Button>
          </div>
        }
      />

      {/* Severity Summary Cards */}
      <MetricsGrid columns={6} className="mb-6">
        <StatCard
          label="Critical"
          value={scan.critical}
          icon={AlertCircle}
          iconColor="text-red-600 dark:text-red-400"
          className={scan.critical > 0 ? "ring-2 ring-red-500/20" : ""}
        />
        <StatCard
          label="High"
          value={scan.high}
          icon={AlertTriangle}
          iconColor="text-orange-600 dark:text-orange-400"
          className={scan.high > 0 ? "ring-2 ring-orange-500/20" : ""}
        />
        <StatCard
          label="Medium"
          value={scan.medium}
          icon={AlertTriangle}
          iconColor="text-yellow-600 dark:text-yellow-400"
        />
        <StatCard
          label="Low"
          value={scan.low}
          icon={Shield}
          iconColor="text-blue-600 dark:text-blue-400"
        />
        <StatCard
          label="Total"
          value={scan.total}
          icon={Shield}
          iconColor="text-gray-600 dark:text-gray-400"
        />
        <StatCard
          label="Fixable"
          value={scan.fixable}
          icon={CheckCircle}
          iconColor="text-green-600 dark:text-green-400"
          description={`${scan.total > 0 ? Math.round((scan.fixable / scan.total) * 100) : 0}%`}
        />
      </MetricsGrid>

      {/* Scan Metadata */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4 mb-6">
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Scan Information</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-gray-500 dark:text-gray-400">Image</p>
            <p className="text-gray-900 dark:text-white font-mono text-xs break-all">{imageRef}</p>
          </div>
          {scan.image_digest && (
            <div>
              <p className="text-gray-500 dark:text-gray-400">Digest</p>
              <p className="text-gray-900 dark:text-white font-mono text-xs truncate" title={scan.image_digest}>
                {scan.image_digest.slice(0, 20)}...
              </p>
            </div>
          )}
          <div>
            <p className="text-gray-500 dark:text-gray-400">Scanner</p>
            <p className="text-gray-900 dark:text-white">
              {scan.scanner_name}
              {scan.scanner_version && ` v${scan.scanner_version}`}
            </p>
          </div>
          <div>
            <p className="text-gray-500 dark:text-gray-400">Scanned</p>
            <p className="text-gray-900 dark:text-white">{new Date(scan.scanned_at).toLocaleString()}</p>
          </div>
          {scan.scan_duration_ms && (
            <div>
              <p className="text-gray-500 dark:text-gray-400">Duration</p>
              <p className="text-gray-900 dark:text-white">{(scan.scan_duration_ms / 1000).toFixed(1)}s</p>
            </div>
          )}
        </div>
      </div>

      {/* Severity Distribution Bar */}
      {scan.total > 0 && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4 mb-6">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Severity Distribution</h3>
          <div className="h-4 rounded-full overflow-hidden flex bg-gray-100 dark:bg-gray-800">
            {scan.critical > 0 && (
              <div
                className="bg-red-500 h-full"
                style={{ width: `${(scan.critical / scan.total) * 100}%` }}
                title={`Critical: ${scan.critical}`}
              />
            )}
            {scan.high > 0 && (
              <div
                className="bg-orange-500 h-full"
                style={{ width: `${(scan.high / scan.total) * 100}%` }}
                title={`High: ${scan.high}`}
              />
            )}
            {scan.medium > 0 && (
              <div
                className="bg-yellow-500 h-full"
                style={{ width: `${(scan.medium / scan.total) * 100}%` }}
                title={`Medium: ${scan.medium}`}
              />
            )}
            {scan.low > 0 && (
              <div
                className="bg-blue-500 h-full"
                style={{ width: `${(scan.low / scan.total) * 100}%` }}
                title={`Low: ${scan.low}`}
              />
            )}
            {scan.unknown > 0 && (
              <div
                className="bg-gray-400 h-full"
                style={{ width: `${(scan.unknown / scan.total) * 100}%` }}
                title={`Unknown: ${scan.unknown}`}
              />
            )}
          </div>
          <div className="flex items-center gap-4 mt-2 text-xs">
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-red-500" />
              <span className="text-gray-600 dark:text-gray-400">Critical ({scan.critical})</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-orange-500" />
              <span className="text-gray-600 dark:text-gray-400">High ({scan.high})</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-yellow-500" />
              <span className="text-gray-600 dark:text-gray-400">Medium ({scan.medium})</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-blue-500" />
              <span className="text-gray-600 dark:text-gray-400">Low ({scan.low})</span>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerabilities Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
        <div className="p-4 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
              Vulnerabilities ({filteredVulns.length}
              {filteredVulns.length !== vulnerabilities?.length && ` of ${vulnerabilities?.length}`})
            </h3>
            <div className="flex items-center gap-3">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search CVE, package..."
                  className="pl-9 pr-3 py-1.5 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 w-48"
                />
              </div>

              {/* Severity Filter */}
              <div className="flex items-center gap-1">
                {["critical", "high", "medium", "low"].map((severity) => (
                  <button
                    key={severity}
                    onClick={() =>
                      setSeverityFilter((prev) =>
                        prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
                      )
                    }
                    className={cn(
                      "px-2 py-1 text-xs font-medium rounded transition-colors",
                      severityFilter.includes(severity)
                        ? getSeverityColor(severity)
                        : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
                    )}
                  >
                    {severity.charAt(0).toUpperCase()}
                  </button>
                ))}
                {severityFilter.length > 0 && (
                  <button
                    onClick={() => setSeverityFilter([])}
                    className="text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 ml-1"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Vulnerabilities List */}
        {vulnsLoading ? (
          <div className="flex items-center justify-center h-32">
            <Spinner />
          </div>
        ) : filteredVulns.length > 0 ? (
          <div className="divide-y divide-gray-200 dark:divide-gray-800 max-h-[600px] overflow-y-auto">
            {filteredVulns.map((vuln) => (
              <div key={vuln.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                {/* Main Row */}
                <div
                  className="p-4 cursor-pointer"
                  onClick={() => toggleExpand(vuln.id)}
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Icon */}
                    <div className="flex-shrink-0 mt-0.5">{getSeverityIcon(vuln.severity)}</div>

                    {/* Main Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge className={cn("border-0 text-xs", getSeverityColor(vuln.severity))}>
                          {vuln.severity.toUpperCase()}
                        </Badge>
                        <span className="font-mono text-sm font-medium text-gray-900 dark:text-white">
                          {vuln.cve_id}
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyCve(vuln.cve_id);
                          }}
                          className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                          title="Copy CVE ID"
                        >
                          {copiedCve === vuln.cve_id ? (
                            <Check className="h-3 w-3 text-green-500" />
                          ) : (
                            <Copy className="h-3 w-3 text-gray-400" />
                          )}
                        </button>
                        {vuln.cvss_score && (
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            CVSS {vuln.cvss_score.toFixed(1)}
                          </span>
                        )}
                      </div>

                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        <span className="font-medium">{vuln.package_name}</span>
                        {vuln.package_version && (
                          <span className="text-gray-500"> @ {vuln.package_version}</span>
                        )}
                        {vuln.package_type && (
                          <span className="text-gray-400 text-xs ml-2">({vuln.package_type})</span>
                        )}
                      </p>

                      {vuln.title && (
                        <p className="text-sm text-gray-500 dark:text-gray-500 mt-1 line-clamp-1">
                          {vuln.title}
                        </p>
                      )}
                    </div>

                    {/* Right Side */}
                    <div className="flex-shrink-0 text-right">
                      {vuln.fix_available && vuln.fixed_version && (
                        <div className="text-xs">
                          <span className="text-green-600 dark:text-green-400">Fix available</span>
                          <p className="text-gray-500 font-mono">{vuln.fixed_version}</p>
                        </div>
                      )}
                      <div className="mt-2">
                        {expandedVulns.has(vuln.id) ? (
                          <ChevronUp className="h-4 w-4 text-gray-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-gray-400" />
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expanded Details */}
                {expandedVulns.has(vuln.id) && (
                  <div className="px-4 pb-4 pl-12 bg-gray-50 dark:bg-gray-800/30">
                    {vuln.description && (
                      <div className="mb-3">
                        <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">
                          Description
                        </p>
                        <p className="text-sm text-gray-700 dark:text-gray-300">{vuln.description}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      {vuln.cvss_vector && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">
                            CVSS Vector
                          </p>
                          <p className="text-gray-900 dark:text-white font-mono text-xs break-all">
                            {vuln.cvss_vector}
                          </p>
                        </div>
                      )}
                      <div>
                        <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">
                          Package Type
                        </p>
                        <p className="text-gray-900 dark:text-white">{vuln.package_type || "Unknown"}</p>
                      </div>
                      {vuln.fixed_version && (
                        <div>
                          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">
                            Fixed In
                          </p>
                          <p className="text-green-600 dark:text-green-400 font-mono">{vuln.fixed_version}</p>
                        </div>
                      )}
                    </div>

                    <div className="mt-3 flex gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-primary-600 hover:text-primary-700 dark:text-primary-400"
                      >
                        View on NVD <ExternalLink className="h-3 w-3" />
                      </a>
                      <a
                        href={`https://www.cvedetails.com/cve/${vuln.cve_id}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-primary-600 hover:text-primary-700 dark:text-primary-400"
                      >
                        CVE Details <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center">
            {searchQuery || severityFilter.length > 0 ? (
              <div className="text-gray-500 dark:text-gray-400">
                <p>No vulnerabilities match your filters</p>
                <button
                  onClick={() => {
                    setSearchQuery("");
                    setSeverityFilter([]);
                  }}
                  className="text-primary-600 hover:text-primary-700 dark:text-primary-400 mt-2 text-sm"
                >
                  Clear filters
                </button>
              </div>
            ) : (
              <div className="text-gray-500 dark:text-gray-400">
                <CheckCircle className="h-12 w-12 mx-auto mb-3 text-green-500" />
                <p className="font-medium text-gray-900 dark:text-white">No vulnerabilities found</p>
                <p className="text-sm">This image has no known vulnerabilities.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
