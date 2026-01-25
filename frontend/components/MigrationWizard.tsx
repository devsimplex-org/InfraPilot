"use client";

import { useState, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  X,
  ArrowRight,
  ArrowLeft,
  Check,
  AlertTriangle,
  Loader2,
  FileCode,
  Lock,
  CheckCircle,
  XCircle,
  Shield,
} from "lucide-react";
import { api, SecretInventory, Container } from "@/lib/api";
import { cn } from "@/lib/utils";

interface MigrationWizardProps {
  isOpen: boolean;
  onClose: () => void;
  agentId: string;
  preselectedSecrets?: SecretInventory[];
  onSuccess?: () => void;
}

interface SecretValue {
  name: string;
  value: string;
  type?: string;
}

type WizardStep = "select" | "values" | "review" | "execute";

export function MigrationWizard({
  isOpen,
  onClose,
  agentId,
  preselectedSecrets = [],
  onSuccess,
}: MigrationWizardProps) {
  const [step, setStep] = useState<WizardStep>("select");
  const [selectedSecrets, setSelectedSecrets] = useState<SecretInventory[]>([]);
  const [secretValues, setSecretValues] = useState<SecretValue[]>([]);
  const [confirmRestart, setConfirmRestart] = useState(false);
  const [migrationId, setMigrationId] = useState<string | null>(null);

  // Reset state when opening
  useEffect(() => {
    if (isOpen) {
      setStep("select");
      setSelectedSecrets(preselectedSecrets);
      setSecretValues(
        preselectedSecrets.map((s) => ({
          name: s.name,
          value: "",
          type: s.secret_type,
        }))
      );
      setConfirmRestart(false);
      setMigrationId(null);
    }
  }, [isOpen, preselectedSecrets]);

  // Fetch containers for the agent
  const { data: containers } = useQuery({
    queryKey: ["containers", agentId],
    queryFn: () => api.getContainers(agentId),
    enabled: isOpen && !!agentId,
  });

  // Poll migration status during execution
  const { data: migrationStatus } = useQuery({
    queryKey: ["migration-status", agentId, migrationId],
    queryFn: () => api.getSecretMigration(agentId, migrationId!),
    enabled: step === "execute" && !!migrationId,
    refetchInterval: 2000,
  });

  // Create migration mutation
  const createMigration = useMutation({
    mutationFn: (data: {
      container_id: string;
      container_name: string;
      source_type: string;
      source_path?: string;
      secrets: SecretValue[];
    }) => api.createSecretMigration(agentId, data),
    onSuccess: (result) => {
      setMigrationId(result.id);
    },
  });

  // Get unique containers from selected secrets
  const containersFromSecrets = selectedSecrets.reduce((acc, secret) => {
    if (secret.container_id && !acc.find((c) => c.id === secret.container_id)) {
      acc.push({
        id: secret.container_id,
        name: secret.container_name || secret.container_id,
        location: secret.location,
      });
    }
    return acc;
  }, [] as { id: string; name: string; location?: string }[]);

  const handleSecretToggle = (secret: SecretInventory) => {
    setSelectedSecrets((prev) => {
      const exists = prev.find((s) => s.id === secret.id);
      if (exists) {
        const newSecrets = prev.filter((s) => s.id !== secret.id);
        setSecretValues((vals) => vals.filter((v) => v.name !== secret.name));
        return newSecrets;
      } else {
        setSecretValues((vals) => [
          ...vals,
          { name: secret.name, value: "", type: secret.secret_type },
        ]);
        return [...prev, secret];
      }
    });
  };

  const handleValueChange = (name: string, value: string) => {
    setSecretValues((prev) =>
      prev.map((v) => (v.name === name ? { ...v, value } : v))
    );
  };

  const canProceedToValues = selectedSecrets.length > 0;
  const canProceedToReview = secretValues.every((v) => v.value.trim() !== "");
  const canExecute = confirmRestart;

  const handleExecuteMigration = () => {
    if (containersFromSecrets.length === 0) return;

    const container = containersFromSecrets[0];
    const sourcePath = selectedSecrets[0]?.location?.includes(":")
      ? selectedSecrets[0].location.split(":")[1]
      : undefined;

    createMigration.mutate({
      container_id: container.id,
      container_name: container.name,
      source_type: "env_file",
      source_path: sourcePath,
      secrets: secretValues,
    });

    setStep("execute");
  };

  const isCompleted =
    migrationStatus?.migration?.status === "completed" ||
    migrationStatus?.migration?.status === "failed" ||
    migrationStatus?.migration?.status === "rolled_back";

  const handleClose = () => {
    if (isCompleted && migrationStatus?.migration?.status === "completed") {
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
                Migrate Secrets to Docker Secrets
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                {step === "select" && "Select secrets to migrate"}
                {step === "values" && "Enter secret values"}
                {step === "review" && "Review migration"}
                {step === "execute" && "Migration in progress"}
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
              {(["select", "values", "review", "execute"] as WizardStep[]).map(
                (s, index) => (
                  <div key={s} className="flex items-center">
                    <div
                      className={cn(
                        "flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium",
                        step === s
                          ? "bg-primary-600 text-white"
                          : (["select", "values", "review", "execute"].indexOf(
                              step
                            ) >
                            index
                            ? "bg-green-500 text-white"
                            : "bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400")
                      )}
                    >
                      {["select", "values", "review", "execute"].indexOf(step) >
                      index ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        index + 1
                      )}
                    </div>
                    {index < 3 && (
                      <div
                        className={cn(
                          "w-16 h-0.5 mx-2",
                          ["select", "values", "review", "execute"].indexOf(
                            step
                          ) > index
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
            {/* Step 1: Select Secrets */}
            {step === "select" && (
              <div className="space-y-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Select the secrets you want to migrate from .env files to
                  Docker Secrets.
                </p>

                {preselectedSecrets.length > 0 ? (
                  <div className="space-y-2">
                    {preselectedSecrets.map((secret) => (
                      <label
                        key={secret.id}
                        className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={selectedSecrets.some(
                            (s) => s.id === secret.id
                          )}
                          onChange={() => handleSecretToggle(secret)}
                          className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <Lock className="h-4 w-4 text-gray-400" />
                            <span className="font-medium text-gray-900 dark:text-white">
                              {secret.name}
                            </span>
                            <span className="px-2 py-0.5 text-xs rounded-full bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200">
                              {secret.secret_type?.replace(/_/g, " ")}
                            </span>
                          </div>
                          <div className="text-xs text-gray-500 mt-1">
                            Container: {secret.container_name || "Unknown"}
                            {secret.location?.includes(":") && (
                              <span className="ml-2">
                                • Path: {secret.location.split(":")[1]}
                              </span>
                            )}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <FileCode className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                    <p>No .env file secrets found for this agent.</p>
                    <p className="text-sm mt-1">
                      Run a secret scan first to discover secrets.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Step 2: Enter Values */}
            {step === "values" && (
              <div className="space-y-4">
                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
                    <p className="text-sm text-yellow-800 dark:text-yellow-200">
                      Enter the actual secret values. These will be securely
                      stored and mounted into your containers.
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  {secretValues.map((sv) => (
                    <div key={sv.name}>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        {sv.name}
                        <span className="ml-2 text-xs text-gray-500 font-normal">
                          ({sv.type?.replace(/_/g, " ")})
                        </span>
                      </label>
                      <input
                        type="password"
                        value={sv.value}
                        onChange={(e) =>
                          handleValueChange(sv.name, e.target.value)
                        }
                        placeholder="Enter secret value..."
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400"
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Step 3: Review */}
            {step === "review" && (
              <div className="space-y-4">
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <h4 className="font-medium text-gray-900 dark:text-white mb-3">
                    Migration Summary
                  </h4>

                  <dl className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <dt className="text-gray-500 dark:text-gray-400">
                        Container
                      </dt>
                      <dd className="font-medium text-gray-900 dark:text-white">
                        {containersFromSecrets[0]?.name || "Unknown"}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-gray-500 dark:text-gray-400">
                        Secrets to migrate
                      </dt>
                      <dd className="font-medium text-gray-900 dark:text-white">
                        {secretValues.length}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-gray-500 dark:text-gray-400">
                        New mount path
                      </dt>
                      <dd className="font-mono text-gray-900 dark:text-white">
                        /run/secrets/
                      </dd>
                    </div>
                  </dl>

                  <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Secrets:
                    </h5>
                    <ul className="space-y-1">
                      {secretValues.map((sv) => (
                        <li
                          key={sv.name}
                          className="flex items-center gap-2 text-sm"
                        >
                          <Lock className="h-3 w-3 text-gray-400" />
                          <span className="text-gray-900 dark:text-white">
                            {sv.name}
                          </span>
                          <span className="text-gray-500">→</span>
                          <span className="font-mono text-gray-600 dark:text-gray-400">
                            /run/secrets/{sv.name}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-red-900 dark:text-red-100">
                        Container will be restarted
                      </h4>
                      <p className="text-sm text-red-700 dark:text-red-300 mt-1">
                        The container will be stopped and recreated with the
                        secrets mounted. This may cause brief downtime.
                      </p>
                      <label className="flex items-center gap-2 mt-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={confirmRestart}
                          onChange={(e) => setConfirmRestart(e.target.checked)}
                          className="h-4 w-4 rounded border-red-300 text-red-600 focus:ring-red-500"
                        />
                        <span className="text-sm text-red-800 dark:text-red-200">
                          I understand the container will restart
                        </span>
                      </label>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Step 4: Execute */}
            {step === "execute" && (
              <div className="space-y-4">
                {!isCompleted ? (
                  <div className="text-center py-8">
                    <Loader2 className="h-12 w-12 animate-spin text-primary-600 mx-auto mb-4" />
                    <p className="text-lg font-medium text-gray-900 dark:text-white">
                      Migration in progress...
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      {migrationStatus?.migration?.status?.replace(/_/g, " ") ||
                        "Starting..."}
                    </p>
                  </div>
                ) : migrationStatus?.migration?.status === "completed" ? (
                  <div className="text-center py-8">
                    <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                    <p className="text-lg font-medium text-gray-900 dark:text-white">
                      Migration completed successfully!
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      Secrets are now mounted at /run/secrets/ in the container.
                    </p>
                    {migrationStatus?.migration?.new_container_id && (
                      <p className="text-sm text-gray-500 mt-2">
                        New container ID:{" "}
                        <code className="bg-gray-100 dark:bg-gray-800 px-1 rounded">
                          {migrationStatus.migration.new_container_id}
                        </code>
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <XCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
                    <p className="text-lg font-medium text-gray-900 dark:text-white">
                      Migration failed
                    </p>
                    <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                      {migrationStatus?.migration?.error_message ||
                        "An error occurred"}
                    </p>
                    <p className="text-sm text-gray-500 mt-2">
                      You can try rolling back from the Migrations tab.
                    </p>
                  </div>
                )}

                {/* Migration items progress */}
                {migrationStatus?.items && migrationStatus.items.length > 0 && (
                  <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 mt-4">
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                      Secret Status
                    </h4>
                    <ul className="space-y-2">
                      {migrationStatus.items.map((item) => (
                        <li
                          key={item.id}
                          className="flex items-center justify-between text-sm"
                        >
                          <span className="flex items-center gap-2">
                            <Lock className="h-3 w-3 text-gray-400" />
                            {item.secret_name}
                          </span>
                          <span
                            className={cn(
                              "px-2 py-0.5 text-xs rounded-full",
                              item.status === "completed"
                                ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                                : item.status === "failed"
                                ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                                : "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                            )}
                          >
                            {item.status}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-800">
            <div>
              {step !== "select" && step !== "execute" && (
                <button
                  onClick={() => {
                    if (step === "values") setStep("select");
                    if (step === "review") setStep("values");
                  }}
                  className="inline-flex items-center gap-2 px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Back
                </button>
              )}
            </div>

            <div className="flex items-center gap-3">
              {step !== "execute" && (
                <button
                  onClick={handleClose}
                  className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
                >
                  Cancel
                </button>
              )}

              {step === "select" && (
                <button
                  onClick={() => setStep("values")}
                  disabled={!canProceedToValues}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}

              {step === "values" && (
                <button
                  onClick={() => setStep("review")}
                  disabled={!canProceedToReview}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}

              {step === "review" && (
                <button
                  onClick={handleExecuteMigration}
                  disabled={!canExecute || createMigration.isPending}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createMigration.isPending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Starting...
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4" />
                      Start Migration
                    </>
                  )}
                </button>
              )}

              {step === "execute" && isCompleted && (
                <button
                  onClick={handleClose}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
                >
                  Done
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
