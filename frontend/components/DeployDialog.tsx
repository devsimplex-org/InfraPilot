"use client";

import React, { useState, Fragment } from "react";
import { Dialog, Transition } from "@headlessui/react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  X,
  Rocket,
  Package,
  Loader2,
  CheckCircle,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button, Input } from "@/components/ui/page-layout";
import { api, CreateDeploymentRequest } from "@/lib/api";

export interface DeployDialogProps {
  isOpen: boolean;
  onClose: () => void;
  // Pre-filled image info
  imageRepository: string;
  imageTag?: string;
  imageDigest?: string;
  registryId?: string; // For private registry auth (future use)
  // Callbacks
  onSuccess?: (deploymentId: string) => void;
}

type DeployStage = "form" | "deploying" | "success" | "error";

export function DeployDialog({
  isOpen,
  onClose,
  imageRepository,
  imageTag,
  imageDigest,
  registryId,
  onSuccess,
}: DeployDialogProps) {
  const [stage, setStage] = useState<DeployStage>("form");
  const [serviceName, setServiceName] = useState("");
  const [environment, setEnvironment] = useState("dev");
  const [tag, setTag] = useState(imageTag || "latest");
  const [deploymentId, setDeploymentId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Fetch agents to get the default agent
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];
  const defaultAgent = activeAgents[0];

  // Create deployment mutation
  const deployMutation = useMutation({
    mutationFn: (request: CreateDeploymentRequest) =>
      api.createDeployment(defaultAgent!.id, request),
    onSuccess: (deployment) => {
      setDeploymentId(deployment.id);
      setStage("success");
      onSuccess?.(deployment.id);
    },
    onError: (error: Error) => {
      setErrorMessage(error.message);
      setStage("error");
    },
  });

  const handleDeploy = () => {
    if (!serviceName.trim() || !defaultAgent) return;

    setStage("deploying");
    setErrorMessage(null);

    const request: CreateDeploymentRequest = {
      service_name: serviceName.trim(),
      environment,
      image_repository: imageRepository,
      image_tag: tag || undefined,
      image_digest: imageDigest || undefined,
    };

    deployMutation.mutate(request);
  };

  const handleClose = () => {
    if (stage === "deploying") return; // Prevent closing during deployment
    // Reset state
    setStage("form");
    setServiceName("");
    setEnvironment("dev");
    setTag(imageTag || "latest");
    setDeploymentId(null);
    setErrorMessage(null);
    onClose();
  };

  const handleRetry = () => {
    setStage("form");
    setErrorMessage(null);
  };

  // Generate a suggested service name from the image repository
  const getSuggestedServiceName = () => {
    const parts = imageRepository.split("/");
    const name = parts[parts.length - 1] || "service";
    return name.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
  };

  // Full image reference for display
  const fullImageRef = tag ? `${imageRepository}:${tag}` : imageRepository;

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
              <Dialog.Panel className="relative transform overflow-hidden rounded-xl bg-white dark:bg-gray-900 shadow-xl transition-all w-full max-w-md">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                      <Rocket className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                    </div>
                    <div>
                      <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                        {stage === "form" && "Deploy Image"}
                        {stage === "deploying" && "Deploying..."}
                        {stage === "success" && "Deployment Created"}
                        {stage === "error" && "Deployment Failed"}
                      </Dialog.Title>
                    </div>
                  </div>
                  <button
                    onClick={handleClose}
                    disabled={stage === "deploying"}
                    className={cn(
                      "text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors",
                      stage === "deploying" && "opacity-50 cursor-not-allowed"
                    )}
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {/* Body */}
                <div className="px-6 py-4">
                  {/* Image Info */}
                  <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="flex items-center gap-2 text-sm">
                      <Package className="h-4 w-4 text-gray-400" />
                      <span className="font-mono text-gray-900 dark:text-white truncate">
                        {fullImageRef}
                      </span>
                    </div>
                  </div>

                  {/* Form Stage */}
                  {stage === "form" && (
                    <div className="space-y-4">
                      {!defaultAgent && (
                        <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                          <div className="flex items-center gap-2 text-yellow-700 dark:text-yellow-400 text-sm">
                            <AlertTriangle className="h-4 w-4" />
                            <span>No active agents available. Please add an agent first.</span>
                          </div>
                        </div>
                      )}

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Service Name <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="text"
                          value={serviceName}
                          onChange={(e) => setServiceName(e.target.value)}
                          placeholder={getSuggestedServiceName()}
                          className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                          A unique name for this deployment
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Environment <span className="text-red-500">*</span>
                        </label>
                        <select
                          value={environment}
                          onChange={(e) => setEnvironment(e.target.value)}
                          className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                        >
                          <option value="dev">Development</option>
                          <option value="staging">Staging</option>
                          <option value="prod">Production</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Image Tag
                        </label>
                        <input
                          type="text"
                          value={tag}
                          onChange={(e) => setTag(e.target.value)}
                          placeholder="latest"
                          className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                        />
                      </div>
                    </div>
                  )}

                  {/* Deploying Stage */}
                  {stage === "deploying" && (
                    <div className="py-8 text-center">
                      <Loader2 className="h-12 w-12 text-primary-600 dark:text-primary-400 animate-spin mx-auto mb-4" />
                      <p className="text-gray-600 dark:text-gray-400">
                        Creating deployment and starting security scan...
                      </p>
                    </div>
                  )}

                  {/* Success Stage */}
                  {stage === "success" && (
                    <div className="py-6 text-center">
                      <div className="w-12 h-12 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mx-auto mb-4">
                        <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
                      </div>
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                        Deployment Created
                      </h3>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        Your deployment has been created and the security scan pipeline has started.
                      </p>
                      <a
                        href="/deployments"
                        className="inline-flex items-center gap-1 text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
                      >
                        View Deployments
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </div>
                  )}

                  {/* Error Stage */}
                  {stage === "error" && (
                    <div className="py-6">
                      <div className="w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center mx-auto mb-4">
                        <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
                      </div>
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white text-center mb-2">
                        Deployment Failed
                      </h3>
                      <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                        <p className="text-sm text-red-600 dark:text-red-400">
                          {errorMessage || "An unexpected error occurred"}
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                  {stage === "form" && (
                    <>
                      <Button variant="secondary" onClick={handleClose}>
                        Cancel
                      </Button>
                      <Button
                        variant="primary"
                        onClick={handleDeploy}
                        disabled={!serviceName.trim() || !defaultAgent}
                      >
                        <Rocket className="h-4 w-4 mr-1" />
                        Deploy
                      </Button>
                    </>
                  )}
                  {stage === "deploying" && (
                    <Button variant="secondary" disabled>
                      <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                      Deploying...
                    </Button>
                  )}
                  {stage === "success" && (
                    <Button variant="primary" onClick={handleClose}>
                      Done
                    </Button>
                  )}
                  {stage === "error" && (
                    <>
                      <Button variant="secondary" onClick={handleClose}>
                        Close
                      </Button>
                      <Button variant="primary" onClick={handleRetry}>
                        Try Again
                      </Button>
                    </>
                  )}
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
