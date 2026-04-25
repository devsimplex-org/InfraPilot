"use client";

import React, { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import {
  Network,
  Server,
  Globe,
  ArrowRight,
  ArrowLeft,
  Plus,
  Trash2,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Info,
  Settings,
  Eye,
} from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/page-layout";
import {
  api,
  CreateTrafficResourceRequest,
  PathConfig,
  ApplyTrafficResponse,
} from "@/lib/api";

// Component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { Card, CardBody, CardFooter } from "@/components/ui/Card";

type WizardStep = "basics" | "domains" | "paths" | "agent" | "review";
type WizardStage = "wizard" | "validating" | "creating" | "success" | "error";

const WIZARD_STEPS: { id: WizardStep; label: string; icon: React.ElementType }[] = [
  { id: "basics", label: "Basic Info", icon: Info },
  { id: "domains", label: "Domains", icon: Globe },
  { id: "paths", label: "Paths", icon: Network },
  { id: "agent", label: "Agent", icon: Server },
  { id: "review", label: "Review", icon: Eye },
];

export default function CreateTrafficResourcePage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>("basics");
  const [stage, setStage] = useState<WizardStage>("wizard");
  const [validationResult, setValidationResult] = useState<ApplyTrafficResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [createdResourceId, setCreatedResourceId] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [gatewayType, setGatewayType] = useState<"system" | "application">("application");
  const [domains, setDomains] = useState<string[]>([""]);
  const [paths, setPaths] = useState<PathConfig[]>([{ path: "/", match: "prefix" }]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [labels, setLabels] = useState<{ key: string; value: string }[]>([]);

  // Fetch agents
  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Set default agent when agents load
  useEffect(() => {
    if (activeAgents.length > 0 && !selectedAgentId) {
      setSelectedAgentId(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgentId]);

  // Create resource mutation
  const createMutation = useMutation({
    mutationFn: (data: CreateTrafficResourceRequest) => api.createTrafficResource(data),
    onSuccess: (resource) => {
      setCreatedResourceId(resource.id);
      setStage("success");
      queryClient.invalidateQueries({ queryKey: ["traffic-resources"] });
      queryClient.invalidateQueries({ queryKey: ["traffic-summary"] });
    },
    onError: (error: Error) => {
      setErrorMessage(error.message);
      setStage("error");
    },
  });

  // Dry run mutation (for validation)
  const dryRunMutation = useMutation({
    mutationFn: (resourceId: string) => api.dryRunTrafficResource(resourceId),
    onSuccess: (result) => {
      setValidationResult(result);
      setStage("wizard");
    },
    onError: (error: Error) => {
      setValidationResult({
        success: false,
        resource_id: "",
        action: "dry_run",
        validation_passed: false,
        errors: [error.message],
        duration_ms: 0,
      });
      setStage("wizard");
    },
  });

  // Navigation helpers
  const stepIndex = WIZARD_STEPS.findIndex((s) => s.id === currentStep);

  const canGoNext = (): boolean => {
    switch (currentStep) {
      case "basics":
        return name.trim() !== "";
      case "domains":
        return domains.some((d) => d.trim() !== "");
      case "paths":
        return paths.some((p) => p.path.trim() !== "");
      case "agent":
        return selectedAgentId !== "";
      case "review":
        return true;
      default:
        return false;
    }
  };

  const goNext = () => {
    if (stepIndex < WIZARD_STEPS.length - 1) {
      setCurrentStep(WIZARD_STEPS[stepIndex + 1].id);
    }
  };

  const goBack = () => {
    if (stepIndex > 0) {
      setCurrentStep(WIZARD_STEPS[stepIndex - 1].id);
    }
  };

  // Domain management
  const addDomain = () => {
    setDomains([...domains, ""]);
  };

  const updateDomain = (index: number, value: string) => {
    const updated = [...domains];
    updated[index] = value;
    setDomains(updated);
  };

  const removeDomain = (index: number) => {
    if (domains.length > 1) {
      setDomains(domains.filter((_, i) => i !== index));
    }
  };

  // Path management
  const addPath = () => {
    setPaths([...paths, { path: "", match: "prefix" }]);
  };

  const updatePath = (index: number, field: keyof PathConfig, value: string) => {
    const updated = [...paths];
    updated[index] = { ...updated[index], [field]: value };
    setPaths(updated);
  };

  const removePath = (index: number) => {
    if (paths.length > 1) {
      setPaths(paths.filter((_, i) => i !== index));
    }
  };

  // Label management
  const addLabel = () => {
    setLabels([...labels, { key: "", value: "" }]);
  };

  const updateLabel = (index: number, field: "key" | "value", value: string) => {
    const updated = [...labels];
    updated[index] = { ...updated[index], [field]: value };
    setLabels(updated);
  };

  const removeLabel = (index: number) => {
    setLabels(labels.filter((_, i) => i !== index));
  };

  // Build request data
  const buildRequestData = (): CreateTrafficResourceRequest => {
    const labelsMap: Record<string, string> = {};
    labels.forEach((l) => {
      if (l.key.trim()) {
        labelsMap[l.key.trim()] = l.value;
      }
    });

    return {
      agent_id: selectedAgentId,
      name: name.trim(),
      description: description.trim() || undefined,
      domains: domains.filter((d) => d.trim() !== ""),
      paths: paths.filter((p) => p.path.trim() !== ""),
      gateway_type: gatewayType,
      labels: Object.keys(labelsMap).length > 0 ? labelsMap : undefined,
    };
  };

  // Handle create
  const handleCreate = () => {
    setStage("creating");
    setErrorMessage(null);
    createMutation.mutate(buildRequestData());
  };

  // Breadcrumbs
  const breadcrumbs = (
    <Breadcrumb
      items={[
        { label: "Traffic", href: "/traffic" },
        { label: "Resources", href: "/traffic/resources" },
        { label: "Create Resource", current: true },
      ]}
    />
  );

  if (agentsLoading) {
    return <Spinner.LogoPage label="Loading..." />;
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Create Traffic Resource"
        description="Configure a new traffic resource for routing and load balancing"
        breadcrumbs={breadcrumbs}
      />

      {/* Main Content */}
      <Card>
        {/* Wizard Steps Indicator */}
        {stage === "wizard" && (
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
            <div className="flex items-center justify-between">
              {WIZARD_STEPS.map((step, idx) => {
                const StepIcon = step.icon;
                const isActive = step.id === currentStep;
                const isPast = idx < stepIndex;
                return (
                  <div key={step.id} className="flex items-center">
                    <button
                      onClick={() => isPast && setCurrentStep(step.id)}
                      className={cn(
                        "flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors",
                        isActive && "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300",
                        isPast && "text-green-600 dark:text-green-400 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700",
                        !isActive && !isPast && "text-gray-400 cursor-not-allowed"
                      )}
                      disabled={!isPast && !isActive}
                    >
                      {isPast ? (
                        <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
                      ) : (
                        <StepIcon className="h-4 w-4" />
                      )}
                      <span className="text-sm font-medium hidden sm:inline">{step.label}</span>
                    </button>
                    {idx < WIZARD_STEPS.length - 1 && (
                      <ArrowRight className="h-4 w-4 mx-1 text-gray-300 dark:text-gray-600" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Wizard Body */}
        <div className="p-6 min-h-[400px]">
          {/* Step 1: Basic Info */}
          {stage === "wizard" && currentStep === "basics" && (
            <div className="space-y-6 max-w-xl">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Resource Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., my-api-gateway"
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  A unique identifier for this traffic resource
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Optional description of this resource..."
                  rows={3}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Gateway Type
                </label>
                <div className="flex gap-4">
                  <label
                    className={cn(
                      "flex-1 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                      gatewayType === "application"
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <input
                      type="radio"
                      name="gatewayType"
                      value="application"
                      checked={gatewayType === "application"}
                      onChange={() => setGatewayType("application")}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-3">
                      <Globe className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">Application</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          For application-level routing
                        </div>
                      </div>
                    </div>
                  </label>
                  <label
                    className={cn(
                      "flex-1 p-4 rounded-lg border-2 cursor-pointer transition-colors",
                      gatewayType === "system"
                        ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    )}
                  >
                    <input
                      type="radio"
                      name="gatewayType"
                      value="system"
                      checked={gatewayType === "system"}
                      onChange={() => setGatewayType("system")}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">System</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          For infrastructure services
                        </div>
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Optional Labels */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Labels (Optional)
                  </label>
                  <button
                    type="button"
                    onClick={addLabel}
                    className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 flex items-center gap-1"
                  >
                    <Plus className="h-3 w-3" />
                    Add Label
                  </button>
                </div>
                {labels.length > 0 && (
                  <div className="space-y-2">
                    {labels.map((label, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <input
                          type="text"
                          value={label.key}
                          onChange={(e) => updateLabel(idx, "key", e.target.value)}
                          placeholder="key"
                          className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                        />
                        <span className="text-gray-400">=</span>
                        <input
                          type="text"
                          value={label.value}
                          onChange={(e) => updateLabel(idx, "value", e.target.value)}
                          placeholder="value"
                          className="flex-1 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm"
                        />
                        <button
                          type="button"
                          onClick={() => removeLabel(idx)}
                          className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 2: Domains */}
          {stage === "wizard" && currentStep === "domains" && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Configure Domains
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Add the domains that will be routed through this traffic resource.
                  Wildcard domains (*.example.com) are supported.
                </p>
              </div>

              <div className="space-y-3">
                {domains.map((domain, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <div className="flex-1 relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <input
                        type="text"
                        value={domain}
                        onChange={(e) => updateDomain(idx, e.target.value)}
                        placeholder="example.com or *.example.com"
                        className="w-full pl-10 pr-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                      />
                    </div>
                    {domains.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeDomain(idx)}
                        className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <button
                type="button"
                onClick={addDomain}
                className="flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg transition-colors"
              >
                <Plus className="h-4 w-4" />
                Add Domain
              </button>

              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <div className="flex gap-2">
                  <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-blue-700 dark:text-blue-300">
                    <p className="font-medium">Domain Tips:</p>
                    <ul className="mt-1 space-y-1 text-blue-600 dark:text-blue-400">
                      <li>Use <code className="px-1 bg-blue-100 dark:bg-blue-800 rounded">*.example.com</code> for wildcard subdomains</li>
                      <li>Multiple domains can share the same upstream configuration</li>
                      <li>SSL certificates will be automatically provisioned</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Paths */}
          {stage === "wizard" && currentStep === "paths" && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Path Configuration
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Define the URL paths to route. Different match types determine how paths are matched.
                </p>
              </div>

              <div className="space-y-3">
                {paths.map((pathConfig, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <div className="flex-1 relative">
                      <Network className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <input
                        type="text"
                        value={pathConfig.path}
                        onChange={(e) => updatePath(idx, "path", e.target.value)}
                        placeholder="/api or /api/v1/.*"
                        className="w-full pl-10 pr-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 font-mono text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                      />
                    </div>
                    <select
                      value={pathConfig.match}
                      onChange={(e) => updatePath(idx, "match", e.target.value as PathConfig["match"])}
                      className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white text-sm"
                    >
                      <option value="prefix">Prefix</option>
                      <option value="exact">Exact</option>
                      <option value="regex">Regex</option>
                    </select>
                    {paths.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removePath(idx)}
                        className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <button
                type="button"
                onClick={addPath}
                className="flex items-center gap-2 px-3 py-2 text-sm text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg transition-colors"
              >
                <Plus className="h-4 w-4" />
                Add Path
              </button>

              <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Match Types</h4>
                <dl className="space-y-2 text-sm">
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-600 dark:text-gray-400 w-20">Prefix:</dt>
                    <dd className="text-gray-700 dark:text-gray-300">Matches paths starting with the pattern (e.g., /api matches /api/users)</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-600 dark:text-gray-400 w-20">Exact:</dt>
                    <dd className="text-gray-700 dark:text-gray-300">Matches only the exact path (e.g., /api only matches /api)</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-600 dark:text-gray-400 w-20">Regex:</dt>
                    <dd className="text-gray-700 dark:text-gray-300">Uses regular expression matching (e.g., /api/v[0-9]+/.*)</dd>
                  </div>
                </dl>
              </div>
            </div>
          )}

          {/* Step 4: Agent Selection */}
          {stage === "wizard" && currentStep === "agent" && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Select Target Agent
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Choose the agent where this traffic resource will be deployed.
                </p>
              </div>

              {activeAgents.length === 0 ? (
                <div className="p-6 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg text-center">
                  <AlertTriangle className="h-8 w-8 text-yellow-600 dark:text-yellow-400 mx-auto mb-2" />
                  <p className="text-yellow-700 dark:text-yellow-300 font-medium">No Active Agents</p>
                  <p className="text-sm text-yellow-600 dark:text-yellow-400 mt-1">
                    Please ensure at least one agent is active before creating a traffic resource.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {activeAgents.map((agent) => (
                    <label
                      key={agent.id}
                      className={cn(
                        "flex items-center justify-between p-4 rounded-lg border-2 cursor-pointer transition-colors",
                        selectedAgentId === agent.id
                          ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                          : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <input
                          type="radio"
                          name="agent"
                          value={agent.id}
                          checked={selectedAgentId === agent.id}
                          onChange={() => setSelectedAgentId(agent.id)}
                          className="text-primary-600"
                        />
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {agent.name}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {agent.hostname || "No hostname"}
                          </div>
                        </div>
                      </div>
                      <Badge color="green">Active</Badge>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Step 5: Review */}
          {stage === "wizard" && currentStep === "review" && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Review Configuration
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Review your traffic resource configuration before creating.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-6">
                {/* Basic Info */}
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                    <Info className="h-4 w-4" />
                    Basic Information
                  </h4>
                  <dl className="space-y-2 text-sm">
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Name</dt>
                      <dd className="font-medium text-gray-900 dark:text-white">{name}</dd>
                    </div>
                    {description && (
                      <div>
                        <dt className="text-gray-500 dark:text-gray-400">Description</dt>
                        <dd className="text-gray-700 dark:text-gray-300">{description}</dd>
                      </div>
                    )}
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Gateway Type</dt>
                      <dd>
                        <Badge color={gatewayType === "system" ? "purple" : "blue"}>
                          {gatewayType === "system" ? "System" : "Application"}
                        </Badge>
                      </dd>
                    </div>
                  </dl>
                </div>

                {/* Agent */}
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                    <Server className="h-4 w-4" />
                    Target Agent
                  </h4>
                  {selectedAgentId && (
                    <div className="text-sm">
                      <div className="font-medium text-gray-900 dark:text-white">
                        {activeAgents.find((a) => a.id === selectedAgentId)?.name}
                      </div>
                      <div className="text-gray-500 dark:text-gray-400">
                        {activeAgents.find((a) => a.id === selectedAgentId)?.hostname || "No hostname"}
                      </div>
                    </div>
                  )}
                </div>

                {/* Domains */}
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                    <Globe className="h-4 w-4" />
                    Domains ({domains.filter((d) => d.trim()).length})
                  </h4>
                  <div className="space-y-1">
                    {domains.filter((d) => d.trim()).map((domain, idx) => (
                      <div key={idx} className="text-sm text-gray-700 dark:text-gray-300 font-mono">
                        {domain}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Paths */}
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                    <Network className="h-4 w-4" />
                    Paths ({paths.filter((p) => p.path.trim()).length})
                  </h4>
                  <div className="space-y-1">
                    {paths.filter((p) => p.path.trim()).map((pathConfig, idx) => (
                      <div key={idx} className="flex items-center justify-between text-sm">
                        <span className="text-gray-700 dark:text-gray-300 font-mono">{pathConfig.path}</span>
                        <Badge color="gray">{pathConfig.match}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Labels */}
              {labels.filter((l) => l.key.trim()).length > 0 && (
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Labels</h4>
                  <div className="flex flex-wrap gap-2">
                    {labels.filter((l) => l.key.trim()).map((label, idx) => (
                      <Badge key={idx} color="gray">
                        {label.key}: {label.value}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Validation Result */}
              {validationResult && (
                <div
                  className={cn(
                    "p-4 rounded-lg border",
                    validationResult.validation_passed
                      ? "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800"
                      : "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800"
                  )}
                >
                  <div className="flex items-center gap-2">
                    {validationResult.validation_passed ? (
                      <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
                    )}
                    <span
                      className={cn(
                        "font-medium",
                        validationResult.validation_passed
                          ? "text-green-700 dark:text-green-300"
                          : "text-red-700 dark:text-red-300"
                      )}
                    >
                      {validationResult.validation_passed ? "Validation Passed" : "Validation Failed"}
                    </span>
                  </div>
                  {validationResult.errors && validationResult.errors.length > 0 && (
                    <ul className="mt-2 space-y-1 text-sm text-red-600 dark:text-red-400">
                      {validationResult.errors.map((error, idx) => (
                        <li key={idx}>{error}</li>
                      ))}
                    </ul>
                  )}
                  {validationResult.warnings && validationResult.warnings.length > 0 && (
                    <ul className="mt-2 space-y-1 text-sm text-yellow-600 dark:text-yellow-400">
                      {validationResult.warnings.map((warning, idx) => (
                        <li key={idx}>{warning}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Validating Stage */}
          {stage === "validating" && (
            <div className="py-12 text-center">
              <Loader2 className="h-12 w-12 text-primary-600 dark:text-primary-400 animate-spin mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400">Validating configuration...</p>
            </div>
          )}

          {/* Creating Stage */}
          {stage === "creating" && (
            <div className="py-12 text-center">
              <Loader2 className="h-12 w-12 text-primary-600 dark:text-primary-400 animate-spin mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400">Creating traffic resource...</p>
            </div>
          )}

          {/* Success Stage */}
          {stage === "success" && (
            <div className="py-12 text-center">
              <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Resource Created Successfully
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                Your traffic resource has been created and is ready to configure.
              </p>
              <div className="flex justify-center gap-3">
                <Link
                  href="/traffic/resources"
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  View All Resources
                </Link>
                {createdResourceId && (
                  <Link
                    href={`/traffic/resources/${createdResourceId}`}
                    className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
                  >
                    Configure Resource
                  </Link>
                )}
              </div>
            </div>
          )}

          {/* Error Stage */}
          {stage === "error" && (
            <div className="py-12 text-center">
              <div className="w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center mx-auto mb-4">
                <AlertTriangle className="h-8 w-8 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Failed to Create Resource
              </h3>
              <div className="max-w-md mx-auto p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg mb-6">
                <p className="text-sm text-red-600 dark:text-red-400">
                  {errorMessage || "An unexpected error occurred"}
                </p>
              </div>
              <div className="flex justify-center gap-3">
                <Link
                  href="/traffic/resources"
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </Link>
                <button
                  onClick={() => {
                    setStage("wizard");
                    setCurrentStep("review");
                    setErrorMessage(null);
                  }}
                  className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
                >
                  Try Again
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        {stage === "wizard" && (
          <CardFooter className="flex items-center justify-between gap-3">
            <div>
              {stepIndex > 0 && (
                <Button variant="secondary" onClick={goBack}>
                  <ArrowLeft className="h-4 w-4 mr-1" />
                  Back
                </Button>
              )}
            </div>
            <div className="flex gap-3">
              <Link
                href="/traffic/resources"
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </Link>
              {currentStep === "review" ? (
                <Button variant="primary" onClick={handleCreate} disabled={!canGoNext()}>
                  <CheckCircle className="h-4 w-4 mr-1" />
                  Create Resource
                </Button>
              ) : (
                <Button variant="primary" onClick={goNext} disabled={!canGoNext()}>
                  Next
                  <ArrowRight className="h-4 w-4 ml-1" />
                </Button>
              )}
            </div>
          </CardFooter>
        )}
      </Card>
    </div>
  );
}
