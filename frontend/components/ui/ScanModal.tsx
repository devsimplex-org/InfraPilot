"use client";

import React, { useState, useEffect, Fragment } from "react";
import { Dialog, Transition } from "@headlessui/react";
import {
  X,
  Shield,
  Package,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  ExternalLink,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/page-layout";

export interface ScanImage {
  reference: string;
  digest?: string;
  tag?: string;
}

export interface ScanResult {
  id: string;
  image: string;
  status: string;
  error?: string;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  total_count?: number;
}

export interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  images: ScanImage[];
  onComplete?: (results: ScanResult[]) => void;
  mode?: "scan" | "sbom" | "both";
}

type ScanStage = "preview" | "scanning" | "complete";

interface ImageScanState {
  image: string;
  status: "pending" | "scanning" | "success" | "error";
  scanResult?: ScanResult;
  sbomResult?: { id: string; total_packages: number };
  error?: string;
}

export function ScanModal({
  isOpen,
  onClose,
  images,
  onComplete,
  mode = "scan",
}: ScanModalProps) {
  const [stage, setStage] = useState<ScanStage>("preview");
  const [generateSBOM, setGenerateSBOM] = useState(mode === "sbom" || mode === "both");
  const [runScan, setRunScan] = useState(mode === "scan" || mode === "both");
  const [imageStates, setImageStates] = useState<Map<string, ImageScanState>>(new Map());
  const [currentImage, setCurrentImage] = useState<string>("");
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      setStage("preview");
      setImageStates(new Map());
      setCurrentImage("");
      setExpandedResults(new Set());

      // Initialize image states
      const initialStates = new Map<string, ImageScanState>();
      images.forEach((img) => {
        initialStates.set(img.reference, {
          image: img.reference,
          status: "pending",
        });
      });
      setImageStates(initialStates);
    }
  }, [isOpen, images]);

  const handleStartScan = async () => {
    if (!runScan && !generateSBOM) return;

    setStage("scanning");
    const results: ScanResult[] = [];

    for (let i = 0; i < images.length; i++) {
      const img = images[i];
      setCurrentImage(img.reference);

      // Update state to scanning
      setImageStates((prev) => {
        const newMap = new Map(prev);
        newMap.set(img.reference, { ...newMap.get(img.reference)!, status: "scanning" });
        return newMap;
      });

      let scanResult: ScanResult | undefined;
      let sbomResult: { id: string; total_packages: number } | undefined;
      let error: string | undefined;

      try {
        // Run vulnerability scan
        if (runScan) {
          const result = await api.triggerImageScan({
            image: img.reference,
            image_digest: img.digest,
            image_tag: img.tag,
          });

          // Fetch scan details to get vulnerability counts
          if (result.id) {
            const details = await api.getScanDetails(result.id);
            scanResult = {
              id: details.id,
              image: img.reference,
              status: "completed",
              critical_count: details.critical_count,
              high_count: details.high_count,
              medium_count: details.medium_count,
              low_count: details.low_count,
              total_count: details.total_count,
            };
            results.push(scanResult);
          }
        }

        // Generate SBOM
        if (generateSBOM) {
          const result = await api.generateSBOM({ image: img.reference });
          sbomResult = { id: result.id, total_packages: result.total_packages };
        }

        // Update state to success
        setImageStates((prev) => {
          const newMap = new Map(prev);
          newMap.set(img.reference, {
            ...newMap.get(img.reference)!,
            status: "success",
            scanResult,
            sbomResult,
          });
          return newMap;
        });
      } catch (err) {
        error = err instanceof Error ? err.message : "Scan failed";

        // Update state to error
        setImageStates((prev) => {
          const newMap = new Map(prev);
          newMap.set(img.reference, {
            ...newMap.get(img.reference)!,
            status: "error",
            error,
          });
          return newMap;
        });

        if (runScan) {
          results.push({
            id: "",
            image: img.reference,
            status: "failed",
            error,
          });
        }
      }
    }

    setCurrentImage("");
    setStage("complete");
    onComplete?.(results);
  };

  const handleClose = () => {
    if (stage === "scanning") return; // Prevent closing during scan
    onClose();
  };

  const toggleExpanded = (image: string) => {
    setExpandedResults((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(image)) {
        newSet.delete(image);
      } else {
        newSet.add(image);
      }
      return newSet;
    });
  };

  const completedCount = Array.from(imageStates.values()).filter(
    (s) => s.status === "success" || s.status === "error"
  ).length;

  const successCount = Array.from(imageStates.values()).filter(
    (s) => s.status === "success"
  ).length;

  const errorCount = Array.from(imageStates.values()).filter(
    (s) => s.status === "error"
  ).length;

  // Calculate totals for completed scans
  const totalVulnerabilities = Array.from(imageStates.values()).reduce((sum, state) => {
    return sum + (state.scanResult?.total_count || 0);
  }, 0);

  const criticalCount = Array.from(imageStates.values()).reduce((sum, state) => {
    return sum + (state.scanResult?.critical_count || 0);
  }, 0);

  const highCount = Array.from(imageStates.values()).reduce((sum, state) => {
    return sum + (state.scanResult?.high_count || 0);
  }, 0);

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={handleClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-900/50 dark:bg-gray-950/80 backdrop-blur-sm transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-xl bg-white dark:bg-gray-900 shadow-xl transition-all w-full max-w-2xl">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                      <Shield className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                    </div>
                    <div>
                      <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                        {stage === "preview" && "Scan Images"}
                        {stage === "scanning" && "Scanning in Progress"}
                        {stage === "complete" && "Scan Complete"}
                      </Dialog.Title>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {stage === "preview" && `${images.length} image${images.length !== 1 ? "s" : ""} selected`}
                        {stage === "scanning" && `Scanning ${completedCount + 1} of ${images.length}...`}
                        {stage === "complete" && `${successCount} successful, ${errorCount} failed`}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={handleClose}
                    disabled={stage === "scanning"}
                    className={cn(
                      "text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors",
                      stage === "scanning" && "opacity-50 cursor-not-allowed"
                    )}
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {/* Body */}
                <div className="px-6 py-4 max-h-[60vh] overflow-y-auto">
                  {/* Preview Stage */}
                  {stage === "preview" && (
                    <div className="space-y-4">
                      {/* Options */}
                      <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg space-y-3">
                        <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                          Scan Options
                        </p>
                        <label className="flex items-center gap-3 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={runScan}
                            onChange={(e) => setRunScan(e.target.checked)}
                            className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                          />
                          <div>
                            <span className="text-sm text-gray-900 dark:text-white">
                              Vulnerability Scan
                            </span>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              Scan for CVEs and security vulnerabilities using Trivy
                            </p>
                          </div>
                        </label>
                        <label className="flex items-center gap-3 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={generateSBOM}
                            onChange={(e) => setGenerateSBOM(e.target.checked)}
                            className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                          />
                          <div>
                            <span className="text-sm text-gray-900 dark:text-white">
                              Generate SBOM
                            </span>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              Create Software Bill of Materials using Syft
                            </p>
                          </div>
                        </label>
                      </div>

                      {/* Images List */}
                      <div>
                        <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Images to scan
                        </p>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {images.map((img) => (
                            <div
                              key={img.reference}
                              className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                            >
                              <Package className="h-4 w-4 text-gray-400" />
                              <span className="font-mono text-sm text-gray-900 dark:text-white truncate flex-1">
                                {img.reference}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Scanning Stage */}
                  {stage === "scanning" && (
                    <div className="space-y-4">
                      {/* Progress */}
                      <div>
                        <div className="flex justify-between text-sm mb-2">
                          <span className="text-gray-600 dark:text-gray-400">Progress</span>
                          <span className="text-gray-900 dark:text-white">
                            {completedCount} / {images.length}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-primary-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${(completedCount / images.length) * 100}%` }}
                          />
                        </div>
                      </div>

                      {/* Current Image */}
                      {currentImage && (
                        <div className="flex items-center gap-3 p-4 bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800 rounded-lg">
                          <Loader2 className="h-5 w-5 text-primary-600 dark:text-primary-400 animate-spin" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-primary-700 dark:text-primary-300">
                              Scanning...
                            </p>
                            <p className="text-xs text-primary-600 dark:text-primary-400 truncate font-mono">
                              {currentImage}
                            </p>
                          </div>
                        </div>
                      )}

                      {/* Completed Images */}
                      <div className="space-y-2">
                        {Array.from(imageStates.values())
                          .filter((s) => s.status === "success" || s.status === "error")
                          .map((state) => (
                            <div
                              key={state.image}
                              className={cn(
                                "flex items-center gap-3 p-3 rounded-lg",
                                state.status === "success"
                                  ? "bg-green-50 dark:bg-green-900/20"
                                  : "bg-red-50 dark:bg-red-900/20"
                              )}
                            >
                              {state.status === "success" ? (
                                <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
                              )}
                              <span className="font-mono text-sm truncate flex-1">
                                {state.image}
                              </span>
                              {state.scanResult && (
                                <span className="text-xs text-gray-500">
                                  {state.scanResult.total_count} vulnerabilities
                                </span>
                              )}
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Complete Stage */}
                  {stage === "complete" && (
                    <div className="space-y-4">
                      {/* Summary */}
                      {runScan && (
                        <div className="grid grid-cols-4 gap-3">
                          <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg text-center">
                            <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                              {criticalCount}
                            </p>
                            <p className="text-xs text-red-600 dark:text-red-400">Critical</p>
                          </div>
                          <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg text-center">
                            <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                              {highCount}
                            </p>
                            <p className="text-xs text-orange-600 dark:text-orange-400">High</p>
                          </div>
                          <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center">
                            <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                              {totalVulnerabilities}
                            </p>
                            <p className="text-xs text-blue-600 dark:text-blue-400">Total</p>
                          </div>
                          <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg text-center">
                            <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                              {successCount}
                            </p>
                            <p className="text-xs text-green-600 dark:text-green-400">Scanned</p>
                          </div>
                        </div>
                      )}

                      {/* Results List */}
                      <div className="space-y-2">
                        {Array.from(imageStates.values()).map((state) => (
                          <div
                            key={state.image}
                            className={cn(
                              "rounded-lg border",
                              state.status === "success"
                                ? "border-gray-200 dark:border-gray-700"
                                : "border-red-200 dark:border-red-800"
                            )}
                          >
                            <button
                              onClick={() => toggleExpanded(state.image)}
                              className="w-full flex items-center gap-3 p-3 text-left"
                            >
                              {state.status === "success" ? (
                                <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400 flex-shrink-0" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-600 dark:text-red-400 flex-shrink-0" />
                              )}
                              <span className="font-mono text-sm truncate flex-1 text-gray-900 dark:text-white">
                                {state.image}
                              </span>
                              {state.scanResult && (
                                <div className="flex items-center gap-2 flex-shrink-0">
                                  {state.scanResult.critical_count! > 0 && (
                                    <span className="px-2 py-0.5 text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded">
                                      {state.scanResult.critical_count} C
                                    </span>
                                  )}
                                  {state.scanResult.high_count! > 0 && (
                                    <span className="px-2 py-0.5 text-xs font-medium bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded">
                                      {state.scanResult.high_count} H
                                    </span>
                                  )}
                                </div>
                              )}
                              {expandedResults.has(state.image) ? (
                                <ChevronDown className="h-4 w-4 text-gray-400 flex-shrink-0" />
                              ) : (
                                <ChevronRight className="h-4 w-4 text-gray-400 flex-shrink-0" />
                              )}
                            </button>

                            {expandedResults.has(state.image) && (
                              <div className="px-3 pb-3 pt-0 space-y-2">
                                {state.error && (
                                  <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded text-sm text-red-600 dark:text-red-400">
                                    {state.error}
                                  </div>
                                )}
                                {state.scanResult && (
                                  <div className="grid grid-cols-5 gap-2 text-center text-xs">
                                    <div>
                                      <span className="block font-medium text-gray-900 dark:text-white">
                                        {state.scanResult.critical_count}
                                      </span>
                                      <span className="text-red-600 dark:text-red-400">Critical</span>
                                    </div>
                                    <div>
                                      <span className="block font-medium text-gray-900 dark:text-white">
                                        {state.scanResult.high_count}
                                      </span>
                                      <span className="text-orange-600 dark:text-orange-400">High</span>
                                    </div>
                                    <div>
                                      <span className="block font-medium text-gray-900 dark:text-white">
                                        {state.scanResult.medium_count}
                                      </span>
                                      <span className="text-yellow-600 dark:text-yellow-400">Medium</span>
                                    </div>
                                    <div>
                                      <span className="block font-medium text-gray-900 dark:text-white">
                                        {state.scanResult.low_count}
                                      </span>
                                      <span className="text-blue-600 dark:text-blue-400">Low</span>
                                    </div>
                                    <div>
                                      <span className="block font-medium text-gray-900 dark:text-white">
                                        {state.scanResult.total_count}
                                      </span>
                                      <span className="text-gray-600 dark:text-gray-400">Total</span>
                                    </div>
                                  </div>
                                )}
                                {state.sbomResult && (
                                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                                    <Package className="h-4 w-4" />
                                    SBOM: {state.sbomResult.total_packages} packages
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                  <div>
                    {stage === "complete" && (
                      <a
                        href="/scans"
                        className="inline-flex items-center gap-1 text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
                      >
                        View All Scans
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    {stage === "preview" && (
                      <>
                        <Button variant="secondary" onClick={handleClose}>
                          Cancel
                        </Button>
                        <Button
                          variant="primary"
                          onClick={handleStartScan}
                          disabled={!runScan && !generateSBOM}
                        >
                          <Shield className="h-4 w-4 mr-1" />
                          Start Scan
                        </Button>
                      </>
                    )}
                    {stage === "scanning" && (
                      <Button variant="secondary" disabled>
                        <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                        Scanning...
                      </Button>
                    )}
                    {stage === "complete" && (
                      <Button variant="primary" onClick={handleClose}>
                        Done
                      </Button>
                    )}
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
