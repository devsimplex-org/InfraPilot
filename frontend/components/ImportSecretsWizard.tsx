"use client";

import { useState, useEffect, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  X,
  ArrowRight,
  ArrowLeft,
  Check,
  AlertTriangle,
  Loader2,
  Upload,
  Lock,
  Settings,
  Shield,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  Trash2,
  Circle,
} from "lucide-react";
import { api, Container } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  useImportWebSocket,
  ImportProgress,
  ImportErrorMessage,
  ImportCompleteMessage,
} from "@/hooks/useImportWebSocket";

interface ImportSecretsWizardProps {
  isOpen: boolean;
  onClose: () => void;
  agentId: string;
  onSuccess?: () => void;
}

interface ParsedSecret {
  key: string;
  value: string;
  selected: boolean;
  masked: boolean;
}

type ImportMethod = "env_vars" | "docker_secrets";
type WizardStep = "source" | "method" | "target" | "review" | "execute";

interface ImportStep {
  id: string;
  label: string;
  status: "pending" | "in_progress" | "complete" | "error";
  message?: string;
}

const DOCKER_SECRETS_STEPS: ImportStep[] = [
  { id: "creating_secrets", label: "Creating secrets", status: "pending" },
  { id: "recreating_container", label: "Recreating container", status: "pending" },
  { id: "verifying", label: "Verifying", status: "pending" },
];

const ENV_VARS_STEPS: ImportStep[] = [
  { id: "preparing", label: "Preparing environment variables", status: "pending" },
  { id: "recreating_container", label: "Recreating container", status: "pending" },
  { id: "verifying", label: "Verifying", status: "pending" },
];

export function ImportSecretsWizard({
  isOpen,
  onClose,
  agentId,
  onSuccess,
}: ImportSecretsWizardProps) {
  const [step, setStep] = useState<WizardStep>("source");
  const [envContent, setEnvContent] = useState("");
  const [parsedSecrets, setParsedSecrets] = useState<ParsedSecret[]>([]);
  const [importMethod, setImportMethod] = useState<ImportMethod>("docker_secrets");
  const [selectedContainer, setSelectedContainer] = useState<string>("");
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionStatus, setExecutionStatus] = useState<"idle" | "running" | "success" | "error">("idle");
  const [executionMessage, setExecutionMessage] = useState("");
  const [importSteps, setImportSteps] = useState<ImportStep[]>([]);
  const [overallProgress, setOverallProgress] = useState(0);

  // WebSocket callbacks
  const handleProgress = useCallback((progress: ImportProgress) => {
    setOverallProgress(progress.progress);
    setImportSteps((prev) =>
      prev.map((s) =>
        s.id === progress.step
          ? { ...s, status: progress.status, message: progress.message }
          : s
      )
    );
    if (progress.message) {
      setExecutionMessage(progress.message);
    }

    // If progress is 100% and verifying is complete, treat as success
    // This handles cases where the complete message might be delayed
    if (progress.progress === 100 && progress.step === "verifying" && progress.status === "complete") {
      // Small delay to allow complete message to arrive first
      setTimeout(() => {
        setIsExecuting((executing) => {
          if (executing) {
            // Complete message hasn't arrived yet, trigger success
            setExecutionStatus("success");
            setExecutionMessage(progress.message || "Import completed successfully");
            return false;
          }
          return executing;
        });
      }, 500);
    }
  }, []);

  const handleError = useCallback((error: ImportErrorMessage) => {
    setIsExecuting(false);
    setExecutionStatus("error");
    setExecutionMessage(error.error);
    if (error.step) {
      setImportSteps((prev) =>
        prev.map((s) =>
          s.id === error.step ? { ...s, status: "error", message: error.error } : s
        )
      );
    }
  }, []);

  const handleComplete = useCallback((complete: ImportCompleteMessage) => {
    setIsExecuting(false);
    if (complete.success) {
      setExecutionStatus("success");
      setExecutionMessage(complete.message || "Import completed successfully");
      setOverallProgress(100);
    } else {
      setExecutionStatus("error");
      setExecutionMessage(complete.message || "Import failed");
    }
  }, []);

  const { startImport, disconnect } = useImportWebSocket({
    onProgress: handleProgress,
    onError: handleError,
    onComplete: handleComplete,
  });

  // Reset state when opening
  useEffect(() => {
    if (isOpen) {
      setStep("source");
      setEnvContent("");
      setParsedSecrets([]);
      setImportMethod("docker_secrets");
      setSelectedContainer("");
      setIsExecuting(false);
      setExecutionStatus("idle");
      setExecutionMessage("");
      setImportSteps([]);
      setOverallProgress(0);
    } else {
      // Disconnect WebSocket when closing
      disconnect();
    }
  }, [isOpen, disconnect]);

  // Fetch containers for the agent
  const { data: containers, isLoading: loadingContainers } = useQuery({
    queryKey: ["containers", agentId],
    queryFn: () => api.getContainers(agentId),
    enabled: isOpen && !!agentId,
  });

  // Parse .env content
  const parseEnvContent = (content: string) => {
    const lines = content.split("\n");
    const secrets: ParsedSecret[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith("#")) continue;

      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (match) {
        const [, key, rawValue] = match;
        // Remove surrounding quotes if present
        let value = rawValue.trim();
        if ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        secrets.push({
          key,
          value,
          selected: true,
          masked: true,
        });
      }
    }

    setParsedSecrets(secrets);
  };

  // Handle file upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setEnvContent(content);
        parseEnvContent(content);
      };
      reader.readAsText(file);
    }
  };

  // Toggle secret selection
  const toggleSecret = (index: number) => {
    setParsedSecrets((prev) =>
      prev.map((s, i) => (i === index ? { ...s, selected: !s.selected } : s))
    );
  };

  // Toggle secret visibility
  const toggleMask = (index: number) => {
    setParsedSecrets((prev) =>
      prev.map((s, i) => (i === index ? { ...s, masked: !s.masked } : s))
    );
  };

  // Remove a secret
  const removeSecret = (index: number) => {
    setParsedSecrets((prev) => prev.filter((_, i) => i !== index));
  };

  // Execute import using WebSocket
  const executeImport = () => {
    setIsExecuting(true);
    setExecutionStatus("running");
    setExecutionMessage("Connecting...");

    // Initialize steps based on method
    const steps = importMethod === "docker_secrets"
      ? [...DOCKER_SECRETS_STEPS]
      : [...ENV_VARS_STEPS];
    setImportSteps(steps);
    setOverallProgress(0);

    // Build secrets map
    const secretsMap: Record<string, string> = {};
    parsedSecrets
      .filter((s) => s.selected)
      .forEach((s) => {
        secretsMap[s.key] = s.value;
      });

    // Start import via WebSocket
    startImport({
      agent_id: agentId,
      container_id: selectedContainer,
      method: importMethod,
      secrets: secretsMap,
    });
  };

  const selectedCount = parsedSecrets.filter((s) => s.selected).length;
  const canProceedFromSource = parsedSecrets.length > 0 && selectedCount > 0;
  const canProceedFromTarget = !!selectedContainer;

  const handleClose = () => {
    if (executionStatus === "success") {
      onSuccess?.();
    }
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/50 transition-opacity"
          onClick={handleClose}
        />

        {/* Dialog */}
        <div className="relative w-full max-w-2xl bg-white dark:bg-gray-900 rounded-xl shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Import Secrets
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                {step === "source" && "Paste or upload .env file"}
                {step === "method" && "Choose how to attach secrets"}
                {step === "target" && "Select target container"}
                {step === "review" && "Review and confirm"}
                {step === "execute" && "Import in progress"}
              </p>
            </div>
            <button
              onClick={handleClose}
              className="p-2 text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Progress Steps */}
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <div className="flex items-center justify-between">
              {(["source", "method", "target", "review", "execute"] as WizardStep[]).map(
                (s, index) => (
                  <div key={s} className="flex items-center">
                    <div
                      className={cn(
                        "flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium",
                        step === s
                          ? "bg-primary-600 text-white"
                          : ["source", "method", "target", "review", "execute"].indexOf(step) > index
                          ? "bg-green-500 text-white"
                          : "bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400"
                      )}
                    >
                      {["source", "method", "target", "review", "execute"].indexOf(step) > index ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        index + 1
                      )}
                    </div>
                    {index < 4 && (
                      <div
                        className={cn(
                          "w-12 h-0.5 mx-1",
                          ["source", "method", "target", "review", "execute"].indexOf(step) > index
                            ? "bg-green-500"
                            : "bg-gray-200 dark:bg-gray-700"
                        )}
                      />
                    )}
                  </div>
                )
              )}
            </div>
          </div>

          {/* Content */}
          <div className="px-6 py-4 max-h-[60vh] overflow-y-auto">
            {/* Step 1: Source */}
            {step === "source" && (
              <div className="space-y-4">
                <div className="flex gap-4">
                  {/* File upload */}
                  <label className="flex-1 flex flex-col items-center justify-center p-6 border-2 border-dashed border-gray-300 dark:border-gray-700 rounded-lg cursor-pointer hover:border-primary-500 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                    <Upload className="h-8 w-8 text-gray-400 mb-2" />
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      Upload .env file
                    </span>
                    <span className="text-xs text-gray-500 mt-1">
                      Click to browse
                    </span>
                    <input
                      type="file"
                      accept=".env,.env.*"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </label>
                </div>

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300 dark:border-gray-700" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white dark:bg-gray-900 text-gray-500">
                      or paste content
                    </span>
                  </div>
                </div>

                <textarea
                  value={envContent}
                  onChange={(e) => {
                    setEnvContent(e.target.value);
                    parseEnvContent(e.target.value);
                  }}
                  placeholder="DATABASE_URL=postgresql://...&#10;API_KEY=sk-...&#10;JWT_SECRET=..."
                  className="w-full h-40 px-3 py-2 text-sm font-mono border border-gray-300 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />

                {parsedSecrets.length > 0 && (
                  <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Parsed secrets ({selectedCount}/{parsedSecrets.length} selected)
                      </span>
                      <button
                        onClick={() =>
                          setParsedSecrets((prev) =>
                            prev.map((s) => ({ ...s, selected: !prev.every((p) => p.selected) }))
                          )
                        }
                        className="text-xs text-primary-600 hover:text-primary-700"
                      >
                        {parsedSecrets.every((s) => s.selected) ? "Deselect all" : "Select all"}
                      </button>
                    </div>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {parsedSecrets.map((secret, index) => (
                        <div
                          key={index}
                          className="flex items-center gap-3 p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700"
                        >
                          <input
                            type="checkbox"
                            checked={secret.selected}
                            onChange={() => toggleSecret(index)}
                            className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                              {secret.key}
                            </div>
                            <div className="text-xs text-gray-500 font-mono truncate">
                              {secret.masked ? "••••••••" : secret.value}
                            </div>
                          </div>
                          <button
                            onClick={() => toggleMask(index)}
                            className="p-1 text-gray-400 hover:text-gray-600"
                          >
                            {secret.masked ? (
                              <Eye className="h-4 w-4" />
                            ) : (
                              <EyeOff className="h-4 w-4" />
                            )}
                          </button>
                          <button
                            onClick={() => removeSecret(index)}
                            className="p-1 text-gray-400 hover:text-red-600"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Step 2: Method */}
            {step === "method" && (
              <div className="space-y-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Choose how to attach secrets to the container.
                </p>

                <div className="grid gap-4">
                  {/* Docker Secrets option */}
                  <label
                    className={cn(
                      "flex items-start gap-4 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                      importMethod === "docker_secrets"
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <input
                      type="radio"
                      name="method"
                      value="docker_secrets"
                      checked={importMethod === "docker_secrets"}
                      onChange={() => setImportMethod("docker_secrets")}
                      className="mt-1 h-4 w-4 text-primary-600 focus:ring-primary-500"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-green-600" />
                        <span className="font-medium text-gray-900 dark:text-white">
                          Docker Secrets (Recommended)
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        Secrets are stored securely on the host and mounted as files at{" "}
                        <code className="bg-gray-100 dark:bg-gray-800 px-1 rounded">/run/secrets/</code>
                      </p>
                      <ul className="text-xs text-gray-500 mt-2 space-y-1">
                        <li>+ Not visible in docker inspect</li>
                        <li>+ Not logged or exposed in process list</li>
                        <li>+ Restricted file permissions (0400)</li>
                      </ul>
                    </div>
                  </label>

                  {/* Environment Variables option */}
                  <label
                    className={cn(
                      "flex items-start gap-4 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                      importMethod === "env_vars"
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <input
                      type="radio"
                      name="method"
                      value="env_vars"
                      checked={importMethod === "env_vars"}
                      onChange={() => setImportMethod("env_vars")}
                      className="mt-1 h-4 w-4 text-primary-600 focus:ring-primary-500"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Settings className="h-5 w-5 text-blue-600" />
                        <span className="font-medium text-gray-900 dark:text-white">
                          Environment Variables
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        Secrets are added as environment variables accessible via{" "}
                        <code className="bg-gray-100 dark:bg-gray-800 px-1 rounded">process.env</code>
                      </p>
                      <ul className="text-xs text-gray-500 mt-2 space-y-1">
                        <li>+ Compatible with all applications</li>
                        <li>- Visible in docker inspect</li>
                        <li>- May appear in logs</li>
                      </ul>
                    </div>
                  </label>
                </div>

                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                    <p className="text-sm text-yellow-800 dark:text-yellow-200">
                      The container will be stopped and recreated with the new configuration.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Step 3: Target */}
            {step === "target" && (
              <div className="space-y-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Select the container to attach secrets to.
                </p>

                {loadingContainers ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
                  </div>
                ) : containers && containers.length > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {containers.map((container: Container) => (
                      <label
                        key={container.id}
                        className={cn(
                          "flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors",
                          selectedContainer === container.id
                            ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                            : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                        )}
                      >
                        <input
                          type="radio"
                          name="container"
                          value={container.id}
                          checked={selectedContainer === container.id}
                          onChange={() => setSelectedContainer(container.id)}
                          className="h-4 w-4 text-primary-600 focus:ring-primary-500"
                        />
                        <div className="flex-1">
                          <div className="font-medium text-gray-900 dark:text-white">
                            {container.name}
                          </div>
                          <div className="text-xs text-gray-500">
                            {container.image} •{" "}
                            <span
                              className={cn(
                                container.state === "running"
                                  ? "text-green-600"
                                  : "text-gray-500"
                              )}
                            >
                              {container.state}
                            </span>
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    No containers found for this agent.
                  </div>
                )}
              </div>
            )}

            {/* Step 4: Review */}
            {step === "review" && (
              <div className="space-y-4">
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500">Container</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {containers?.find((c: Container) => c.id === selectedContainer)?.name}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500">Method</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {importMethod === "docker_secrets" ? "Docker Secrets" : "Environment Variables"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500">Secrets to import</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {selectedCount}
                    </span>
                  </div>
                </div>

                <div className="border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-200 dark:divide-gray-700">
                  {parsedSecrets
                    .filter((s) => s.selected)
                    .map((secret, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between px-4 py-2"
                      >
                        <div className="flex items-center gap-2">
                          <Lock className="h-4 w-4 text-gray-400" />
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {secret.key}
                          </span>
                        </div>
                        {importMethod === "docker_secrets" && (
                          <span className="text-xs text-gray-500 font-mono">
                            /run/secrets/{secret.key}
                          </span>
                        )}
                      </div>
                    ))}
                </div>

                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                    <div className="text-sm text-yellow-800 dark:text-yellow-200">
                      <p className="font-medium">Container will be recreated</p>
                      <p className="mt-1">
                        The container will be stopped, recreated with the new secrets, and started again.
                        This may cause brief downtime.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Step 5: Execute */}
            {step === "execute" && (
              <div className="py-4">
                {/* Progress bar */}
                {executionStatus === "running" && (
                  <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Progress
                      </span>
                      <span className="text-sm text-gray-500">{overallProgress}%</span>
                    </div>
                    <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary-600 transition-all duration-300 ease-out"
                        style={{ width: `${overallProgress}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Steps list - only show while running */}
                {importSteps.length > 0 && executionStatus === "running" && (
                  <div className="space-y-3 mb-6">
                    {importSteps.map((importStep, index) => (
                      <div
                        key={importStep.id}
                        className={cn(
                          "flex items-center gap-3 p-3 rounded-lg border transition-colors",
                          importStep.status === "in_progress"
                            ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                            : importStep.status === "complete"
                            ? "border-green-500 bg-green-50 dark:bg-green-900/20"
                            : importStep.status === "error"
                            ? "border-red-500 bg-red-50 dark:bg-red-900/20"
                            : "border-gray-200 dark:border-gray-700"
                        )}
                      >
                        <div className="flex-shrink-0">
                          {importStep.status === "in_progress" && (
                            <Loader2 className="h-5 w-5 text-primary-600 animate-spin" />
                          )}
                          {importStep.status === "complete" && (
                            <CheckCircle className="h-5 w-5 text-green-500" />
                          )}
                          {importStep.status === "error" && (
                            <XCircle className="h-5 w-5 text-red-500" />
                          )}
                          {importStep.status === "pending" && (
                            <Circle className="h-5 w-5 text-gray-400" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p
                            className={cn(
                              "text-sm font-medium",
                              importStep.status === "in_progress"
                                ? "text-primary-700 dark:text-primary-300"
                                : importStep.status === "complete"
                                ? "text-green-700 dark:text-green-300"
                                : importStep.status === "error"
                                ? "text-red-700 dark:text-red-300"
                                : "text-gray-600 dark:text-gray-400"
                            )}
                          >
                            {importStep.label}
                          </p>
                          {importStep.message && (
                            <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                              {importStep.message}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Status message */}
                <div className="flex flex-col items-center text-center">
                  {executionStatus === "running" && importSteps.length === 0 && (
                    <>
                      <Loader2 className="h-12 w-12 text-primary-600 animate-spin mb-4" />
                      <p className="text-gray-600 dark:text-gray-400">{executionMessage}</p>
                    </>
                  )}
                  {executionStatus === "success" && (
                    <>
                      <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                      <p className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                        Import Successful
                      </p>
                      <p className="text-gray-600 dark:text-gray-400 mb-4">{executionMessage}</p>
                      <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3 text-left max-w-md">
                        <p className="text-sm text-green-800 dark:text-green-200">
                          {importMethod === "docker_secrets"
                            ? "Secrets are now mounted at /run/secrets/ inside the container."
                            : "Environment variables are now available in the container."}
                        </p>
                      </div>
                    </>
                  )}
                  {executionStatus === "error" && (
                    <>
                      <XCircle className="h-12 w-12 text-red-500 mb-4" />
                      <p className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                        Import Failed
                      </p>
                      <p className="text-red-600 dark:text-red-400">{executionMessage}</p>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-800">
            <div>
              {step !== "source" && step !== "execute" && (
                <button
                  onClick={() => {
                    const steps: WizardStep[] = ["source", "method", "target", "review", "execute"];
                    const currentIndex = steps.indexOf(step);
                    if (currentIndex > 0) {
                      setStep(steps[currentIndex - 1]);
                    }
                  }}
                  className="flex items-center gap-2 px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Back
                </button>
              )}
            </div>
            <div className="flex gap-3">
              {executionStatus !== "running" && (
                <button
                  onClick={handleClose}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                >
                  {executionStatus === "success" || executionStatus === "error" ? "Close" : "Cancel"}
                </button>
              )}
              {step === "source" && (
                <button
                  onClick={() => setStep("method")}
                  disabled={!canProceedFromSource}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}
              {step === "method" && (
                <button
                  onClick={() => setStep("target")}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  Next
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}
              {step === "target" && (
                <button
                  onClick={() => setStep("review")}
                  disabled={!canProceedFromTarget}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}
              {step === "review" && (
                <button
                  onClick={() => {
                    setStep("execute");
                    executeImport();
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  Import Secrets
                  <Check className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
