"use client";

import { useState } from "react";
import { Dialog } from "@headlessui/react";
import {
  X,
  RotateCcw,
  Package,
  Tag,
  GitBranch,
  GitCommit,
  Globe,
  Download,
  AlertTriangle,
  Shield,
  ShieldOff,
} from "lucide-react";
import { Deployment } from "@/lib/api";
import { cn } from "@/lib/utils";

interface RedeployWizardProps {
  isOpen: boolean;
  deployment: Deployment | null;
  onClose: () => void;
  onConfirm: (pullLatest: boolean, skipScanning: boolean) => void;
  isLoading?: boolean;
}

export function RedeployWizard({
  isOpen,
  deployment,
  onClose,
  onConfirm,
  isLoading = false,
}: RedeployWizardProps) {
  const [pullLatest, setPullLatest] = useState(true);
  const [skipScanning, setSkipScanning] = useState(false);

  if (!deployment) return null;

  const handleConfirm = () => {
    onConfirm(pullLatest, skipScanning);
  };

  const getFullImageRef = () => {
    const parts = [];
    if (deployment.image_registry) {
      parts.push(deployment.image_registry);
    }
    parts.push(deployment.image_repository);
    if (deployment.image_tag) {
      return `${parts.join("/")}:${deployment.image_tag}`;
    }
    return parts.join("/");
  };

  return (
    <Dialog open={isOpen} onClose={onClose} className="relative z-50">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm" aria-hidden="true" />

      {/* Full-screen container */}
      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="mx-auto max-w-2xl w-full bg-zinc-900 rounded-xl border border-zinc-800 shadow-2xl">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-zinc-800">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-indigo-500/10 rounded-lg">
                <RotateCcw className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <Dialog.Title className="text-lg font-semibold text-white">
                  Redeploy {deployment.service_name}
                </Dialog.Title>
                <p className="text-sm text-zinc-400 mt-0.5">
                  Configure redeployment options
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              disabled={isLoading}
              className="p-2 hover:bg-zinc-800 rounded-lg transition-colors disabled:opacity-50"
            >
              <X className="h-5 w-5 text-zinc-400" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* Current Configuration */}
            <div>
              <h3 className="text-sm font-medium text-white mb-3">Current Configuration</h3>
              <div className="bg-zinc-800/50 rounded-lg border border-zinc-700 divide-y divide-zinc-700">
                {/* Environment */}
                <div className="p-3 flex items-center gap-3">
                  <Globe className="h-4 w-4 text-zinc-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-zinc-500">Environment</div>
                    <div className="text-sm text-white font-medium mt-0.5">
                      {deployment.environment}
                    </div>
                  </div>
                </div>

                {/* Image */}
                <div className="p-3 flex items-center gap-3">
                  <Package className="h-4 w-4 text-zinc-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-zinc-500">Container Image</div>
                    <div className="text-sm text-white font-mono mt-0.5 break-all">
                      {getFullImageRef()}
                    </div>
                  </div>
                </div>

                {/* Image Digest */}
                {deployment.image_digest && (
                  <div className="p-3 flex items-center gap-3">
                    <Tag className="h-4 w-4 text-zinc-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-zinc-500">Image Digest</div>
                      <div className="text-xs text-zinc-400 font-mono mt-0.5 break-all">
                        {deployment.image_digest}
                      </div>
                    </div>
                  </div>
                )}

                {/* Git Branch */}
                {deployment.git_branch && (
                  <div className="p-3 flex items-center gap-3">
                    <GitBranch className="h-4 w-4 text-zinc-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-zinc-500">Git Branch</div>
                      <div className="text-sm text-white mt-0.5">{deployment.git_branch}</div>
                    </div>
                  </div>
                )}

                {/* Git Commit */}
                {deployment.git_commit && (
                  <div className="p-3 flex items-center gap-3">
                    <GitCommit className="h-4 w-4 text-zinc-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-zinc-500">Git Commit</div>
                      <div className="text-sm text-zinc-400 font-mono mt-0.5">
                        {deployment.git_commit.substring(0, 8)}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Redeployment Options */}
            <div>
              <h3 className="text-sm font-medium text-white mb-3">Redeployment Options</h3>
              <div className="bg-zinc-800/50 rounded-lg border border-zinc-700 p-4 space-y-4">
                {/* Pull Latest Image */}
                <label className="flex items-start gap-3 cursor-pointer group">
                  <div className="relative flex items-center">
                    <input
                      type="checkbox"
                      checked={pullLatest}
                      onChange={(e) => setPullLatest(e.target.checked)}
                      disabled={isLoading}
                      className="w-5 h-5 rounded border-zinc-600 bg-zinc-800 text-indigo-500 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-0 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <div className="text-sm font-medium text-white group-hover:text-indigo-300 transition-colors">
                        Pull Latest Image
                      </div>
                      <span className="text-xs font-normal text-emerald-400">(Recommended)</span>
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">
                      {pullLatest ? (
                        <>
                          <Download className="h-3 w-3 inline mr-1" />
                          Will pull the latest version of the image from the registry before deployment
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="h-3 w-3 inline mr-1 text-amber-400" />
                          <span className="text-amber-400">
                            Will use the cached image if available (may not be the latest version)
                          </span>
                        </>
                      )}
                    </p>
                  </div>
                </label>

                {/* Security Scanning */}
                <label className="flex items-start gap-3 cursor-pointer group">
                  <div className="relative flex items-center">
                    <input
                      type="checkbox"
                      checked={!skipScanning}
                      onChange={(e) => setSkipScanning(!e.target.checked)}
                      disabled={isLoading}
                      className="w-5 h-5 rounded border-zinc-600 bg-zinc-800 text-indigo-500 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-0 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <div className="text-sm font-medium text-white group-hover:text-indigo-300 transition-colors">
                        Security Scanning
                      </div>
                      {deployment?.environment === "prod" && (
                        <span className="text-xs font-normal text-amber-400">(Recommended for Production)</span>
                      )}
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">
                      {!skipScanning ? (
                        <>
                          <Shield className="h-3 w-3 inline mr-1 text-emerald-400" />
                          <span className="text-emerald-400">
                            Will scan image for vulnerabilities before deployment
                          </span>
                        </>
                      ) : (
                        <>
                          <ShieldOff className="h-3 w-3 inline mr-1 text-amber-400" />
                          <span className="text-amber-400">
                            Security scanning disabled - image will deploy immediately
                          </span>
                          {deployment?.environment === "prod" && (
                            <span className="block mt-1 text-red-400 font-medium">
                              Warning: Deploying to production without scanning is not recommended
                            </span>
                          )}
                        </>
                      )}
                    </p>
                  </div>
                </label>
              </div>
            </div>

            {/* Info Notice */}
            <div className="bg-indigo-500/10 border border-indigo-500/30 rounded-lg p-4">
              <div className="flex gap-3">
                <RotateCcw className="h-5 w-5 text-indigo-400 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <div className="text-sm font-medium text-indigo-300">
                    What happens during redeployment?
                  </div>
                  <ul className="text-xs text-indigo-200/80 mt-2 space-y-1.5 list-disc list-inside">
                    <li>The existing container will be stopped gracefully (10s timeout)</li>
                    <li>The old container will be removed</li>
                    <li>
                      {pullLatest ? "Latest image will be pulled" : "Cached image will be used"}
                    </li>
                    <li>A new container will be created with the same configuration</li>
                    <li>
                      {skipScanning
                        ? "Container will deploy immediately (scanning skipped)"
                        : "Full deployment pipeline will run (scan, policy check, deploy)"}
                    </li>
                  </ul>
                  <p className="text-xs text-indigo-200/60 mt-2">
                    Expected downtime: 10-15 seconds
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 p-6 border-t border-zinc-800">
            <button
              onClick={onClose}
              disabled={isLoading}
              className="px-4 py-2 text-sm font-medium text-zinc-300 hover:text-white hover:bg-zinc-800 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirm}
              disabled={isLoading}
              className={cn(
                "px-5 py-2 text-sm font-medium rounded-lg transition-all",
                "bg-indigo-500 hover:bg-indigo-600 text-white",
                "disabled:opacity-50 disabled:cursor-not-allowed",
                "flex items-center gap-2"
              )}
            >
              {isLoading ? (
                <>
                  <svg
                    className="animate-spin h-4 w-4"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                  Redeploying...
                </>
              ) : (
                <>
                  <RotateCcw className="h-4 w-4" />
                  Confirm Redeploy
                </>
              )}
            </button>
          </div>
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}
