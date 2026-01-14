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
  Search,
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
  const [activeTab, setActiveTab] = useState<SBOMTab>("all");
  const [selectedSBOM, setSelectedSBOM] = useState<SBOM | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [packageSearchTerm, setPackageSearchTerm] = useState("");

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
        avgPackages: Math.round(
          sboms.reduce((sum, s) => sum + s.total_packages, 0) / sboms.length
        ),
        uniqueImages: new Set(sboms.map((s) => s.image_repository)).size,
      }
    : { total: 0, totalPackages: 0, avgPackages: 0, uniqueImages: 0 };

  // Filter SBOMs by search term
  const filteredSBOMs = sboms
    ? sboms.filter((sbom) =>
        sbom.image_repository.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : [];

  // Group SBOMs by image for the images tab
  const groupedByImage = filteredSBOMs.reduce((acc, sbom) => {
    const key = sbom.image_repository;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(sbom);
    return acc;
  }, {} as Record<string, SBOM[]>);

  const handleDownloadSBOM = (sbomId: string, imageRepo: string) => {
    try {
      // Use the API method which opens download in new window
      api.downloadSBOM(sbomId);
    } catch (error) {
      console.error("Failed to download SBOM:", error);
    }
  };

  return (
    <PageLayout
      title="Software Bill of Materials"
      description="View and manage SBOMs for container images"
      panel={
        selectedSBOM && (
          <DetailPanel
            open={!!selectedSBOM}
            onClose={() => setSelectedSBOM(null)}
            title={selectedSBOM.image_repository}
            subtitle={`SBOM ${selectedSBOM.id.split("-")[0]}`}
          >
            <DetailSection title="Image Information">
              <DetailRow label="Repository" value={selectedSBOM.image_repository} />
              <DetailRow label="Digest" value={selectedSBOM.image_digest} />
              <DetailRow
                label="Generated"
                value={new Date(selectedSBOM.created_at).toLocaleString()}
              />
            </DetailSection>

            <DetailSection title="SBOM Details">
              <DetailRow
                label="Format"
                value={`${selectedSBOM.format} ${selectedSBOM.spec_version}`}
              />
              <DetailRow
                label="Generator"
                value={`${selectedSBOM.generator_name} ${selectedSBOM.generator_version}`}
              />
            </DetailSection>

            <DetailSection title="Package Breakdown">
              <DetailRow
                label="Total Packages"
                value={
                  <span className="text-lg font-semibold text-gray-900 dark:text-white">
                    {selectedSBOM.total_packages}
                  </span>
                }
              />
              <DetailRow
                label="OS Packages"
                value={
                  <span className="text-blue-600 dark:text-blue-400 font-medium">
                    {selectedSBOM.os_packages}
                  </span>
                }
              />
              <DetailRow
                label="Library Packages"
                value={
                  <span className="text-purple-600 dark:text-purple-400 font-medium">
                    {selectedSBOM.library_packages}
                  </span>
                }
              />
              <div className="mt-2">
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
                        (selectedSBOM.os_packages / selectedSBOM.total_packages) * 100
                      }%`,
                    }}
                  />
                  <div
                    className="bg-purple-500"
                    style={{
                      width: `${
                        (selectedSBOM.library_packages / selectedSBOM.total_packages) * 100
                      }%`,
                    }}
                  />
                </div>
              </div>
            </DetailSection>

            {/* Package Explorer */}
            {sbomDetails && (
              <DetailSection title={`Packages (${sbomDetails.packages.length})`}>
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
                <div className="mb-3 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg text-xs space-y-1">
                  {sbomDetails.packages_by_language && Object.entries(sbomDetails.packages_by_language).map(([lang, count]) => (
                    <div key={lang} className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">{lang}</span>
                      <span className="font-medium text-gray-900 dark:text-white">{count} packages</span>
                    </div>
                  ))}
                </div>

                {/* Package list */}
                <div className="max-h-96 overflow-y-auto space-y-2">
                  {isLoadingDetails ? (
                    <div className="flex justify-center py-4">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-600"></div>
                    </div>
                  ) : (
                    sbomDetails.packages
                      .filter((pkg) =>
                        packageSearchTerm === "" ||
                        pkg.name.toLowerCase().includes(packageSearchTerm.toLowerCase())
                      )
                      .slice(0, 100)
                      .map((pkg, idx) => (
                        <div
                          key={idx}
                          className="p-2 bg-gray-50 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-750 transition-colors"
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
                {sbomDetails && sbomDetails.packages.filter((pkg) =>
                  packageSearchTerm === "" ||
                  pkg.name.toLowerCase().includes(packageSearchTerm.toLowerCase())
                ).length > 100 && (
                  <div className="mt-2 text-xs text-center text-gray-500 dark:text-gray-400">
                    Showing first 100 packages. Use search to filter.
                  </div>
                )}
              </DetailSection>
            )}

            <DetailSection title="Actions">
              <Button
                onClick={() =>
                  handleDownloadSBOM(selectedSBOM.id, selectedSBOM.image_repository)
                }
                className="w-full"
              >
                <Download className="w-4 h-4 mr-2" />
                Download CycloneDX JSON
              </Button>
            </DetailSection>
          </DetailPanel>
        )
      }
      panelOpen={!!selectedSBOM}
    >
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total SBOMs</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.total}
              </p>
            </div>
            <FileCode className="w-8 h-8 text-primary-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Unique Images</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.uniqueImages}
              </p>
            </div>
            <Box className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Packages</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.totalPackages.toLocaleString()}
              </p>
            </div>
            <Package className="w-8 h-8 text-purple-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Avg per Image</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.avgPackages}
              </p>
            </div>
            <TrendingUp className="w-8 h-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Search by image repository..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-800 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>
      </div>

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "all", label: "All SBOMs", count: filteredSBOMs.length },
          { id: "images", label: "By Image", count: Object.keys(groupedByImage).length },
        ]}
        activeTab={activeTab}
        onChange={(id) => setActiveTab(id as SBOMTab)}
      />

      <div className="mt-6">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : filteredSBOMs.length === 0 ? (
          <EmptyState
            icon={Package}
            title={searchTerm ? "No SBOMs Found" : "No SBOMs Generated"}
            description={
              searchTerm
                ? "No SBOMs match your search criteria."
                : "Deploy an image to generate your first SBOM."
            }
          />
        ) : (
          <div className="space-y-4">
            {/* All SBOMs Tab */}
            {activeTab === "all" &&
              filteredSBOMs.map((sbom) => (
                <ListCard
                  key={sbom.id}
                  selected={selectedSBOM?.id === sbom.id}
                  onClick={() => setSelectedSBOM(sbom)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <Layers className="w-5 h-5 text-gray-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <h3 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {sbom.image_repository}
                        </h3>
                        <div className="flex items-center gap-4 mt-1">
                          <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
                            <Package className="w-3 h-3" />
                            {sbom.total_packages} packages
                          </div>
                          <div className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400">
                            <Box className="w-3 h-3" />
                            {sbom.os_packages} OS
                          </div>
                          <div className="flex items-center gap-1 text-xs text-purple-600 dark:text-purple-400">
                            <Layers className="w-3 h-3" />
                            {sbom.library_packages} libraries
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {new Date(sbom.created_at).toLocaleDateString()}
                        </p>
                        <p className="text-xs text-gray-400 dark:text-gray-500">
                          {sbom.format} {sbom.spec_version}
                        </p>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDownloadSBOM(sbom.id, sbom.image_repository);
                        }}
                        className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                      <Eye className="w-4 h-4 text-gray-400" />
                    </div>
                  </div>
                </ListCard>
              ))}

            {/* By Image Tab */}
            {activeTab === "images" &&
              Object.entries(groupedByImage).map(([imageRepo, imageSBOMs]) => (
                <div
                  key={imageRepo}
                  className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4"
                >
                  <div className="flex items-center gap-3 mb-3">
                    <Box className="w-5 h-5 text-primary-500" />
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      {imageRepo}
                    </h3>
                    <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded-full">
                      {imageSBOMs.length} {imageSBOMs.length === 1 ? "version" : "versions"}
                    </span>
                  </div>
                  <div className="space-y-2">
                    {imageSBOMs.map((sbom) => (
                      <div
                        key={sbom.id}
                        onClick={() => setSelectedSBOM(sbom)}
                        className={cn(
                          "flex items-center justify-between p-3 rounded-lg cursor-pointer transition-colors",
                          selectedSBOM?.id === sbom.id
                            ? "bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800"
                            : "hover:bg-gray-50 dark:hover:bg-gray-800 border border-transparent"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <Calendar className="w-4 h-4 text-gray-400" />
                          <div>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {new Date(sbom.created_at).toLocaleString()}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {sbom.total_packages} packages ({sbom.os_packages} OS,{" "}
                              {sbom.library_packages} libraries)
                            </p>
                          </div>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDownloadSBOM(sbom.id, sbom.image_repository);
                          }}
                          className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
