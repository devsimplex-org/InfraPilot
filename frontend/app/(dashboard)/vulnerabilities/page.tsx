"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  Search,
  Filter,
  Package,
  ExternalLink,
  TrendingUp,
  Eye,
} from "lucide-react";
import { api } from "@/lib/api";
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

type VulnTab = "all" | "critical" | "high" | "medium" | "low";

interface Vulnerability {
  id: string;
  scan_result_id: string;
  cve_id: string;
  severity: string;
  package_name: string;
  package_version: string;
  package_type: string;
  fixed_version?: string;
  fix_available: boolean;
  title: string;
  description: string;
  cvss_v3_score?: number;
  cvss_v3_vector?: string;
  reference_urls?: string[];
  published_date?: string;
  last_modified_date?: string;
}

interface ScanWithVulns {
  scan_id: string;
  image_repository: string;
  image_tag: string;
  deployment_id: string;
  service_name: string;
  vulnerabilities: Vulnerability[];
}

export default function VulnerabilitiesPage() {
  const [activeTab, setActiveTab] = useState<VulnTab>("all");
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [fixableOnly, setFixableOnly] = useState(false);

  // Fetch all deployments to get scan IDs
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const agentId = agents?.[0]?.id;

  const { data: deployments } = useQuery({
    queryKey: ["deployments", agentId],
    queryFn: () => (agentId ? api.getDeployments(agentId) : Promise.resolve([])),
    enabled: !!agentId,
  });

  // Fetch all vulnerabilities from all scans
  const { data: allVulnerabilities, isLoading } = useQuery({
    queryKey: ["all-vulnerabilities", agentId],
    queryFn: async () => {
      if (!deployments || !agentId) return [];

      const scansWithVulns: ScanWithVulns[] = [];

      for (const deployment of deployments) {
        if (deployment.scan_result_id) {
          try {
            const vulns = await api.getScanVulnerabilities(deployment.scan_result_id, {});
            if (vulns && vulns.length > 0) {
              scansWithVulns.push({
                scan_id: deployment.scan_result_id,
                image_repository: deployment.image_repository,
                image_tag: deployment.image_tag || "latest",
                deployment_id: deployment.id,
                service_name: deployment.service_name,
                vulnerabilities: vulns,
              });
            }
          } catch (error) {
            console.error(`Failed to fetch vulnerabilities for scan ${deployment.scan_result_id}:`, error);
          }
        }
      }

      return scansWithVulns;
    },
    enabled: !!deployments && !!agentId,
  });

  // Flatten all vulnerabilities
  const allVulns = allVulnerabilities?.flatMap(scan =>
    scan.vulnerabilities.map(v => ({
      ...v,
      image_repository: scan.image_repository,
      image_tag: scan.image_tag,
      service_name: scan.service_name,
    }))
  ) || [];

  // Calculate statistics
  const stats = {
    total: allVulns.length,
    critical: allVulns.filter(v => v.severity === "critical").length,
    high: allVulns.filter(v => v.severity === "high").length,
    medium: allVulns.filter(v => v.severity === "medium").length,
    low: allVulns.filter(v => v.severity === "low").length,
    fixable: allVulns.filter(v => v.fix_available).length,
    uniqueCVEs: new Set(allVulns.map(v => v.cve_id)).size,
    affectedImages: allVulnerabilities?.length || 0,
  };

  // Filter vulnerabilities
  const filteredVulns = allVulns.filter(vuln => {
    // Severity filter
    if (activeTab !== "all" && vuln.severity !== activeTab) return false;

    // Search filter
    if (searchTerm && !vuln.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !vuln.package_name.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }

    // Fixable filter
    if (fixableOnly && !vuln.fix_available) return false;

    return true;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/30";
      case "high":
        return "text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-900/30";
      case "medium":
        return "text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/30";
      case "low":
        return "text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/30";
      default:
        return "text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-900/30";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return AlertCircle;
      case "high":
        return AlertTriangle;
      case "medium":
        return Info;
      case "low":
        return CheckCircle;
      default:
        return Shield;
    }
  };

  return (
    <PageLayout
      title="Vulnerability Management"
      description="Track and manage security vulnerabilities across all deployments"
      panel={
        selectedVuln && (
          <DetailPanel
            open={!!selectedVuln}
            onClose={() => setSelectedVuln(null)}
            title={selectedVuln.cve_id}
            subtitle={selectedVuln.package_name}
          >
            <DetailSection title="Vulnerability Details">
              <DetailRow
                label="Severity"
                value={
                  <span className={cn("px-2 py-1 text-xs font-medium rounded-full capitalize", getSeverityColor(selectedVuln.severity))}>
                    {selectedVuln.severity}
                  </span>
                }
              />
              <DetailRow
                label="CVSS v3 Score"
                value={selectedVuln.cvss_v3_score ? (
                  <span className="font-semibold">{selectedVuln.cvss_v3_score.toFixed(1)}</span>
                ) : "N/A"}
              />
              {selectedVuln.cvss_v3_vector && (
                <DetailRow label="CVSS Vector" value={selectedVuln.cvss_v3_vector} />
              )}
            </DetailSection>

            <DetailSection title="Affected Package">
              <DetailRow label="Package" value={selectedVuln.package_name} />
              <DetailRow label="Version" value={selectedVuln.package_version} />
              <DetailRow label="Type" value={selectedVuln.package_type} />
              <DetailRow
                label="Fix Available"
                value={
                  selectedVuln.fix_available ? (
                    <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
                      <CheckCircle className="w-4 h-4" />
                      Yes ({selectedVuln.fixed_version})
                    </span>
                  ) : (
                    <span className="text-gray-500">No fix available</span>
                  )
                }
              />
            </DetailSection>

            <DetailSection title="Description">
              <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {selectedVuln.description || selectedVuln.title}
              </p>
            </DetailSection>

            {selectedVuln.reference_urls && selectedVuln.reference_urls.length > 0 && (
              <DetailSection title="References">
                <div className="space-y-2">
                  {selectedVuln.reference_urls.map((url, idx) => (
                    <a
                      key={idx}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm text-primary-600 dark:text-primary-400 hover:underline"
                    >
                      <ExternalLink className="w-3 h-3" />
                      {url}
                    </a>
                  ))}
                </div>
              </DetailSection>
            )}

            <DetailSection title="Affected Service">
              <DetailRow label="Service" value={(selectedVuln as any).service_name} />
              <DetailRow label="Image" value={(selectedVuln as any).image_repository} />
              <DetailRow label="Tag" value={(selectedVuln as any).image_tag} />
            </DetailSection>
          </DetailPanel>
        )
      }
      panelOpen={!!selectedVuln}
    >
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Vulnerabilities</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.total}
              </p>
            </div>
            <Shield className="w-8 h-8 text-primary-500" />
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            {stats.uniqueCVEs} unique CVEs
          </p>
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
              <p className="text-sm text-gray-500 dark:text-gray-400">Fixable</p>
              <p className="text-2xl font-semibold text-green-600 dark:text-green-400 mt-1">
                {stats.fixable}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            {stats.total > 0 ? Math.round((stats.fixable / stats.total) * 100) : 0}% have fixes
          </p>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Affected Images</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.affectedImages}
              </p>
            </div>
            <Package className="w-8 h-8 text-purple-500" />
          </div>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="mb-6 flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Search by CVE ID or package name..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-800 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>
        <button
          onClick={() => setFixableOnly(!fixableOnly)}
          className={cn(
            "px-4 py-2 rounded-lg border transition-colors flex items-center gap-2",
            fixableOnly
              ? "bg-primary-600 text-white border-primary-600"
              : "bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800"
          )}
        >
          <Filter className="w-4 h-4" />
          Fixable Only
        </button>
      </div>

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "all", label: "All", count: allVulns.length },
          { id: "critical", label: "Critical", count: stats.critical },
          { id: "high", label: "High", count: stats.high },
          { id: "medium", label: "Medium", count: stats.medium },
          { id: "low", label: "Low", count: stats.low },
        ]}
        activeTab={activeTab}
        onChange={(id) => setActiveTab(id as VulnTab)}
      />

      <div className="mt-6">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : filteredVulns.length === 0 ? (
          <EmptyState
            icon={CheckCircle}
            title={stats.total === 0 ? "No Vulnerabilities Found" : "No Matching Vulnerabilities"}
            description={
              stats.total === 0
                ? "All scanned images are clean. Great job!"
                : searchTerm || fixableOnly
                ? "Try adjusting your filters."
                : "No vulnerabilities match the selected severity level."
            }
          />
        ) : (
          <div className="space-y-4">
            {filteredVulns.map((vuln, idx) => {
              const SeverityIcon = getSeverityIcon(vuln.severity);
              return (
                <ListCard
                  key={`${vuln.cve_id}-${idx}`}
                  selected={selectedVuln?.id === vuln.id}
                  onClick={() => setSelectedVuln(vuln)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <SeverityIcon className={cn("w-5 h-5 flex-shrink-0",
                        vuln.severity === "critical" && "text-red-500",
                        vuln.severity === "high" && "text-orange-500",
                        vuln.severity === "medium" && "text-yellow-500",
                        vuln.severity === "low" && "text-blue-500"
                      )} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                            {vuln.cve_id}
                          </h3>
                          <span className={cn("px-2 py-0.5 text-xs font-medium rounded-full capitalize", getSeverityColor(vuln.severity))}>
                            {vuln.severity}
                          </span>
                          {vuln.fix_available && (
                            <span className="px-2 py-0.5 text-xs bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-full">
                              Fixable
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-1">
                          {vuln.package_name}@{vuln.package_version} in {(vuln as any).service_name}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {vuln.cvss_v3_score && (
                        <div className="text-right">
                          <p className="text-sm font-semibold text-gray-900 dark:text-white">
                            {vuln.cvss_v3_score.toFixed(1)}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">CVSS</p>
                        </div>
                      )}
                      <Eye className="w-4 h-4 text-gray-400" />
                    </div>
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
