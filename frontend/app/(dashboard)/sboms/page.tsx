"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Package,
  Box,
  Layers,
  Download,
  Calendar,
  FileCode,
  TrendingUp,
  Shield,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// New Component Library Imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb, BreadcrumbItem } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table, Column } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel, FilterGroup } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

type SBOMTab = "all" | "images";

interface SBOM {
  id: string;
  image_repository: string;
  image_digest: string;
  format: string;
  spec_version: string;
  total_packages: number;
  os_packages: number;
  library_packages: number;
  generator_name: string;
  generator_version: string;
  created_at: string;
}

interface SBOMPackage {
  name: string;
  version: string;
  type: string;
  language?: string;
  purl?: string;
  cpe?: string;
  licenses?: string[];
  locations?: string[];
  vulnerabilities: number;
}

interface SBOMDetails extends SBOM {
  packages: SBOMPackage[];
  packages_by_type: Record<string, number>;
  packages_by_language: Record<string, number>;
}

export default function SBOMsPage() {
  // State management
  const [selectedSBOM, setSelectedSBOM] = useState<SBOM | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [packageSearchTerm, setPackageSearchTerm] = useState("");
  const [dateFilter, setDateFilter] = useState<string>("");
  const [formatFilter, setFormatFilter] = useState<string[]>([]);

  // Fetch all SBOMs
  const { data: sboms, isLoading } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => api.fetchAPI<SBOM[]>("/sboms"),
  });

  // Fetch SBOM details when one is selected
  const { data: sbomDetails, isLoading: isLoadingDetails } = useQuery({
    queryKey: ["sbom-details", selectedSBOM?.id],
    queryFn: () => api.fetchAPI<SBOMDetails>(`/sboms/${selectedSBOM?.id}`),
    enabled: !!selectedSBOM?.id,
  });

  // Calculate statistics
  const stats = sboms
    ? {
        total: sboms.length,
        totalPackages: sboms.reduce((sum, s) => sum + s.total_packages, 0),
        vulnerabilities: 0, // TODO: Calculate from actual vulnerability data
        coverage: sboms.length > 0 ? 100 : 0,
      }
    : { total: 0, totalPackages: 0, vulnerabilities: 0, coverage: 0 };

  // Filter SBOMs
  const filteredSBOMs = sboms
    ? sboms.filter((sbom) => {
        const matchesSearch = sbom.image_repository
          .toLowerCase()
          .includes(searchTerm.toLowerCase());
        const matchesFormat =
          formatFilter.length === 0 || formatFilter.includes(sbom.format);
        const matchesDate =
          !dateFilter ||
          new Date(sbom.created_at) >= new Date(dateFilter);
        return matchesSearch && matchesFormat && matchesDate;
      })
    : [];

  // Get unique formats for filter
  const uniqueFormats = sboms
    ? Array.from(new Set(sboms.map((s) => s.format)))
    : [];

  // Get unique deployments (image repositories)
  const uniqueDeployments = sboms
    ? Array.from(new Set(sboms.map((s) => s.image_repository)))
    : [];

  // Define filter groups
  const filterGroups: FilterGroup[] = [
    {
      id: "search",
      label: "Search",
      type: "search",
      value: searchTerm,
      onChange: (value) => setSearchTerm(value as string),
    },
    {
      id: "deployment",
      label: "Deployment",
      type: "checkbox",
      options: uniqueDeployments.map((dep) => ({
        label: dep,
        value: dep,
        count: sboms?.filter((s) => s.image_repository === dep).length || 0,
      })),
      value: [],
      onChange: (value) => {
        // Filter by selected deployments
        const selected = value as string[];
        if (selected.length === 0) {
          setSearchTerm("");
        } else {
          // This is a simplified approach - you might want to enhance this
          setSearchTerm(selected[0]);
        }
      },
    },
    {
      id: "format",
      label: "Format",
      type: "checkbox",
      options: uniqueFormats.map((format) => ({
        label: format,
        value: format,
        count: sboms?.filter((s) => s.format === format).length || 0,
      })),
      value: formatFilter,
      onChange: (value) => setFormatFilter(value as string[]),
    },
  ];

  // Table columns
  const columns: Column<SBOM>[] = [
    {
      key: "image_repository",
      header: "Image Repository",
      sortable: true,
      render: (value, row) => (
        <div className="flex items-center gap-3">
          <Layers className="w-5 h-5 text-gray-400 flex-shrink-0" />
          <div>
            <div className="text-sm font-medium text-gray-900 dark:text-white">
              {value}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">
              {row.format} {row.spec_version}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "total_packages",
      header: "Total Packages",
      sortable: true,
      align: "right",
      render: (value, row) => (
        <div className="text-right">
          <div className="text-sm font-medium text-gray-900 dark:text-white">
            {value}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {row.os_packages} OS, {row.library_packages} libs
          </div>
        </div>
      ),
    },
    {
      key: "created_at",
      header: "Generated",
      sortable: true,
      render: (value) => (
        <div className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
          <Calendar className="w-4 h-4 text-gray-400" />
          {new Date(value).toLocaleDateString()}
        </div>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "right",
      render: (_, row) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleDownloadSBOM(row.id, row.image_repository);
          }}
          className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          <Download className="w-4 h-4" />
        </button>
      ),
    },
  ];

  const handleDownloadSBOM = (sbomId: string, imageRepo: string) => {
    try {
      api.downloadSBOM(sbomId);
    } catch (error) {
      console.error("Failed to download SBOM:", error);
    }
  };

  const handleResetFilters = () => {
    setSearchTerm("");
    setFormatFilter([]);
    setDateFilter("");
  };

  // Breadcrumb items
  const breadcrumbItems: BreadcrumbItem[] = [
    { label: "Deploy", href: "/deploy" },
    { label: "SBOMs", current: true },
  ];

  return (
    <div className="h-full flex flex-col">
      {/* Section 1: Header with Breadcrumbs */}
      <PageHeader
        title="Software Bill of Materials"
        description="View and manage SBOMs for container images"
        breadcrumbs={<Breadcrumb items={breadcrumbItems} />}
      />

      {/* Section 2: Metrics Grid */}
      <MetricsGrid columns={4} className="mb-6">
        <StatCard
          label="Total SBOMs"
          value={stats.total}
          icon={FileCode}
          iconColor="text-primary-600"
        />
        <StatCard
          label="Packages Tracked"
          value={stats.totalPackages.toLocaleString()}
          icon={Package}
          iconColor="text-purple-600"
        />
        <StatCard
          label="Vulnerabilities Found"
          value={stats.vulnerabilities}
          icon={Shield}
          iconColor="text-red-600"
        />
        <StatCard
          label="Coverage"
          value={`${stats.coverage}%`}
          icon={TrendingUp}
          iconColor="text-green-600"
        />
      </MetricsGrid>

      {/* Section 3: Filter Panel & Table */}
      <div className="flex-1 flex gap-6 min-h-0">
        {/* Filter Panel */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filterGroups}
            onReset={handleResetFilters}
            collapsible={false}
          />
        </div>

        {/* Table Section */}
        <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden flex flex-col">
          {isLoading ? (
            <div className="flex-1 flex items-center justify-center">
              <Spinner size="lg" label="Loading SBOMs..." />
            </div>
          ) : filteredSBOMs.length === 0 ? (
            <EmptyState
              icon={Package}
              title={
                searchTerm || formatFilter.length > 0
                  ? "No SBOMs Found"
                  : "No SBOMs Generated Yet"
              }
              description={
                searchTerm || formatFilter.length > 0
                  ? "No SBOMs match your current filters. Try adjusting your search criteria."
                  : "Deploy a container image to generate your first SBOM and start tracking packages."
              }
            />
          ) : (
            <div className="flex-1 overflow-auto">
              <Table
                columns={columns}
                data={filteredSBOMs}
                keyExtractor={(row) => row.id}
                onRowClick={(row) => setSelectedSBOM(row)}
                hoverable
                selectedRows={
                  selectedSBOM ? new Set([selectedSBOM.id]) : new Set()
                }
              />
            </div>
          )}
        </div>
      </div>

      {/* Section 4: SlideOver for SBOM Details */}
      <SlideOver
        isOpen={!!selectedSBOM}
        onClose={() => setSelectedSBOM(null)}
        size="lg"
      >
        {selectedSBOM && (
          <>
            <SlideOver.Header onClose={() => setSelectedSBOM(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedSBOM.image_repository}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  SBOM {selectedSBOM.id.split("-")[0]}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {/* Image Information Section */}
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                  Image Information
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">
                      Repository
                    </span>
                    <span className="text-gray-900 dark:text-white font-medium">
                      {selectedSBOM.image_repository}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">
                      Digest
                    </span>
                    <span className="text-gray-900 dark:text-white font-mono text-xs">
                      {selectedSBOM.image_digest}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">
                      Generated
                    </span>
                    <span className="text-gray-900 dark:text-white">
                      {new Date(selectedSBOM.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* SBOM Details Section */}
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                  SBOM Details
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">
                      Format
                    </span>
                    <span className="text-gray-900 dark:text-white">
                      {selectedSBOM.format} {selectedSBOM.spec_version}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">
                      Generator
                    </span>
                    <span className="text-gray-900 dark:text-white">
                      {selectedSBOM.generator_name}{" "}
                      {selectedSBOM.generator_version}
                    </span>
                  </div>
                </div>
              </div>

              {/* Package Breakdown Section */}
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                  Package Breakdown
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 dark:text-gray-400">
                      Total Packages
                    </span>
                    <span className="text-lg font-semibold text-gray-900 dark:text-white">
                      {selectedSBOM.total_packages}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 dark:text-gray-400">
                      OS Packages
                    </span>
                    <span className="font-medium text-blue-600 dark:text-blue-400">
                      {selectedSBOM.os_packages}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 dark:text-gray-400">
                      Library Packages
                    </span>
                    <span className="font-medium text-purple-600 dark:text-purple-400">
                      {selectedSBOM.library_packages}
                    </span>
                  </div>

                  {/* Visual breakdown bar */}
                  <div className="mt-3">
                    <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
                      <span>OS</span>
                      <span className="flex-1"></span>
                      <span>Libraries</span>
                    </div>
                    <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden flex">
                      <div
                        className="bg-blue-500"
                        style={{
                          width: `${
                            (selectedSBOM.os_packages /
                              selectedSBOM.total_packages) *
                            100
                          }%`,
                        }}
                      />
                      <div
                        className="bg-purple-500"
                        style={{
                          width: `${
                            (selectedSBOM.library_packages /
                              selectedSBOM.total_packages) *
                            100
                          }%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Packages Section */}
              {sbomDetails && (
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                    Packages ({sbomDetails.packages.length})
                  </h3>

                  {/* Package search */}
                  <div className="mb-3">
                    <input
                      type="text"
                      placeholder="Search packages..."
                      value={packageSearchTerm}
                      onChange={(e) => setPackageSearchTerm(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>

                  {/* Package statistics */}
                  {sbomDetails.packages_by_language && (
                    <div className="mb-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg text-xs space-y-1">
                      {Object.entries(sbomDetails.packages_by_language).map(
                        ([lang, count]) => (
                          <div key={lang} className="flex justify-between">
                            <span className="text-gray-600 dark:text-gray-400">
                              {lang}
                            </span>
                            <span className="font-medium text-gray-900 dark:text-white">
                              {count} packages
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  )}

                  {/* Package list */}
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {isLoadingDetails ? (
                      <div className="flex justify-center py-4">
                        <Spinner size="md" />
                      </div>
                    ) : (
                      sbomDetails.packages
                        .filter(
                          (pkg) =>
                            packageSearchTerm === "" ||
                            pkg.name
                              .toLowerCase()
                              .includes(packageSearchTerm.toLowerCase())
                        )
                        .slice(0, 100)
                        .map((pkg, idx) => (
                          <div
                            key={idx}
                            className="p-3 bg-gray-50 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-750 transition-colors"
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {pkg.name}
                              </span>
                              {pkg.vulnerabilities > 0 && (
                                <span className="px-2 py-0.5 text-xs bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400 rounded-full flex-shrink-0">
                                  {pkg.vulnerabilities} vulns
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                              <span>{pkg.version}</span>
                              <span>•</span>
                              <span className="capitalize">{pkg.type}</span>
                              {pkg.language && (
                                <>
                                  <span>•</span>
                                  <span>{pkg.language}</span>
                                </>
                              )}
                            </div>
                            {pkg.licenses && pkg.licenses.length > 0 && (
                              <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                License: {pkg.licenses.join(", ")}
                              </div>
                            )}
                          </div>
                        ))
                    )}
                  </div>
                  {sbomDetails &&
                    sbomDetails.packages.filter(
                      (pkg) =>
                        packageSearchTerm === "" ||
                        pkg.name
                          .toLowerCase()
                          .includes(packageSearchTerm.toLowerCase())
                    ).length > 100 && (
                      <div className="mt-2 text-xs text-center text-gray-500 dark:text-gray-400">
                        Showing first 100 packages. Use search to filter.
                      </div>
                    )}
                </div>
              )}
            </SlideOver.Body>

            <SlideOver.Footer align="between">
              <button
                onClick={() => setSelectedSBOM(null)}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Close
              </button>
              <button
                onClick={() =>
                  handleDownloadSBOM(
                    selectedSBOM.id,
                    selectedSBOM.image_repository
                  )
                }
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download SBOM
              </button>
            </SlideOver.Footer>
          </>
        )}
      </SlideOver>
    </div>
  );
}
