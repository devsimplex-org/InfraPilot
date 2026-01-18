"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  GitBranch,
  Package,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Container,
  Activity,
  ExternalLink,
  ArrowRight,
  FileCode,
} from "lucide-react";
import { api } from "@/lib/api";
import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Timeline } from "@/components/ui/Timeline";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

interface DeploymentSpine {
  deployment: {
    id: string;
    service_name: string;
    environment: string;
    status: string;
    status_message?: string;
    deployed_by?: string;
    deployed_at?: string;
    created_at: string;
    updated_at: string;
  };
  source?: {
    type: string;
    git_repo?: string;
    git_branch?: string;
    git_commit?: string;
    ci_provider?: string;
    ci_pipeline_id?: string;
    ci_build_url?: string;
    webhook_event?: {
      id: string;
      webhook_id: string;
      webhook_name: string;
      provider: string;
      event_type: string;
      verified: boolean;
      created_at: string;
    };
  };
  image: {
    registry?: string;
    repository: string;
    tag?: string;
    digest?: string;
    full_image: string;
  };
  security_scan?: {
    id: string;
    total_vulns: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    fixable_count: number;
    scanned_at: string;
    scanner: string;
    scanner_version: string;
    top_vulnerabilities?: Array<{
      id: string;
      cve: string;
      severity: string;
      package_name: string;
      fixed_version?: string;
      score?: number;
    }>;
  };
  sbom?: {
    id: string;
    format: string;
    total_packages: number;
    os_packages: number;
    library_packages: number;
  };
  policy_eval?: {
    decision: string;
    reason?: string;
    errors?: string[];
    warnings?: string[];
    evaluated_at: string;
    policy_version: string;
  };
  runtime?: {
    container_id?: string;
    container_name?: string;
    container_status: string;
    started_at?: string;
    proxy_configured: boolean;
    proxy_url?: string;
  };
  timeline: Array<{
    timestamp: string;
    type: string;
    title: string;
    description: string;
    status: string;
    details?: Record<string, any>;
  }>;
  related_deployments?: Array<{
    id: string;
    service_name: string;
    environment: string;
    status: string;
    image_tag?: string;
    deployed_at?: string;
    relationship: string;
  }>;
}

export default function DeploymentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const deploymentId = resolvedParams.id;

  // Fetch default agent
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const defaultAgent = agents?.[0];

  // Fetch deployment spine
  const { data: spine, isLoading } = useQuery({
    queryKey: ["deployment-spine", deploymentId],
    queryFn: () =>
      api.fetchAPI<DeploymentSpine>(`/agents/${defaultAgent?.id}/deployments/${deploymentId}/spine`),
    enabled: !!defaultAgent?.id,
  });

  const getDeploymentStatus = (status: string): "healthy" | "warning" | "degraded" | "critical" => {
    switch (status) {
      case "running":
        return "healthy";
      case "failed":
        return "critical";
      case "pending":
      case "scanning":
      case "policy_check":
        return "warning";
      default:
        return "degraded";
    }
  };

  const getPolicyDecisionStatus = (decision: string): "healthy" | "warning" | "degraded" | "critical" => {
    switch (decision) {
      case "allow":
        return "healthy";
      case "warn":
        return "warning";
      case "deny":
        return "critical";
      default:
        return "degraded";
    }
  };

  const getTimelineIconAndColor = (type: string, status: string) => {
    if (status === "error") return { icon: XCircle, color: "text-red-600 dark:text-red-400" };
    if (status === "warning") return { icon: AlertTriangle, color: "text-yellow-600 dark:text-yellow-400" };

    switch (type) {
      case "webhook":
      case "created":
        return { icon: GitBranch, color: "text-blue-600 dark:text-blue-400" };
      case "scanned":
        return { icon: Shield, color: "text-purple-600 dark:text-purple-400" };
      case "sbom_generated":
        return { icon: Package, color: "text-indigo-600 dark:text-indigo-400" };
      case "policy_evaluated":
        return { icon: FileCode, color: "text-orange-600 dark:text-orange-400" };
      case "deployed":
        return { icon: CheckCircle, color: "text-green-600 dark:text-green-400" };
      default:
        return { icon: Activity, color: "text-gray-600 dark:text-gray-400" };
    }
  };

  if (isLoading) {
    return <Spinner.Page label="Loading deployment..." />;
  }

  if (!spine) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title={spine.deployment.service_name}
        description={`${spine.deployment.environment} environment • Deployment ${spine.deployment.id.substring(0, 8)}`}
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Deploy", href: "/deploy" },
              { label: "Deployments", href: "/deployments" },
              { label: spine.deployment.service_name },
            ]}
          />
        }
        action={
          <StatusIndicator
            status={getDeploymentStatus(spine.deployment.status)}
            label={spine.deployment.status}
            pulse={spine.deployment.status === "running"}
          />
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Column - Timeline & Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Source Information */}
          {spine.source && (
            <Card>
              <Card.Header>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <GitBranch className="w-5 h-5" />
                  Source
                </h2>
              </Card.Header>
              <Card.Body className="space-y-4">
                {spine.source.webhook_event && (
                  <div className="flex items-center gap-3 p-3 bg-blue-50 dark:bg-blue-900/10 rounded-lg">
                    <CheckCircle className="w-5 h-5 text-blue-600 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        Triggered by {spine.source.ci_provider} webhook
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {spine.source.webhook_event.webhook_name}
                        {spine.source.webhook_event.verified && " • Verified"}
                      </p>
                    </div>
                  </div>
                )}

                {spine.source.git_commit && (
                  <div className="grid grid-cols-2 gap-4">
                    {spine.source.git_branch && (
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Branch</p>
                        <p className="text-sm font-mono text-gray-900 dark:text-white">
                          {spine.source.git_branch}
                        </p>
                      </div>
                    )}
                    <div>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Commit</p>
                      <p className="text-sm font-mono text-gray-900 dark:text-white">
                        {spine.source.git_commit?.substring(0, 8)}
                      </p>
                    </div>
                  </div>
                )}

                {spine.source.ci_build_url && (
                  <a
                    href={spine.source.ci_build_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
                  >
                    View CI Build
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </Card.Body>
            </Card>
          )}

          {/* Deployment Timeline */}
          <Card>
            <Card.Header>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <Clock className="w-5 h-5" />
                Deployment Timeline
              </h2>
            </Card.Header>
            <Card.Body>
              <Timeline>
                {spine.timeline.map((event, idx) => {
                  const { icon, color } = getTimelineIconAndColor(event.type, event.status);
                  return (
                    <Timeline.Item
                      key={idx}
                      icon={icon}
                      iconColor={color}
                      title={event.title}
                      description={event.description}
                      timestamp={new Date(event.timestamp).toLocaleTimeString()}
                      isLast={idx === spine.timeline.length - 1}
                    >
                      {event.details && Object.keys(event.details).length > 0 && (
                        <div className="mt-2 p-3 bg-gray-50 dark:bg-gray-800 rounded text-xs font-mono overflow-auto">
                          <pre>{JSON.stringify(event.details, null, 2)}</pre>
                        </div>
                      )}
                    </Timeline.Item>
                  );
                })}
              </Timeline>
            </Card.Body>
          </Card>

          {/* Security Scan Results */}
          {spine.security_scan && (
            <Card>
              <Card.Header>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Security Scan
                </h2>
              </Card.Header>
              <Card.Body className="space-y-4">
                {/* Vulnerability Counts */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-red-50 dark:bg-red-900/10 rounded-lg">
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {spine.security_scan.critical_count}
                    </p>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">Critical</p>
                  </div>
                  <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/10 rounded-lg">
                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                      {spine.security_scan.high_count}
                    </p>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">High</p>
                  </div>
                  <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-900/10 rounded-lg">
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {spine.security_scan.medium_count}
                    </p>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">Medium</p>
                  </div>
                  <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/10 rounded-lg">
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {spine.security_scan.low_count}
                    </p>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">Low</p>
                  </div>
                </div>

                {/* Top Vulnerabilities */}
                {spine.security_scan.top_vulnerabilities && spine.security_scan.top_vulnerabilities.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
                      Top Vulnerabilities
                    </h3>
                    <div className="space-y-2">
                      {spine.security_scan.top_vulnerabilities.map((vuln) => (
                        <div
                          key={vuln.id}
                          className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                        >
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <p className="text-sm font-mono font-semibold text-gray-900 dark:text-white">
                                {vuln.cve}
                              </p>
                              <SeverityBadge
                                severity={vuln.severity.toLowerCase() as "critical" | "high" | "medium" | "low"}
                                size="sm"
                              />
                            </div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {vuln.package_name}
                              {vuln.fixed_version && ` → ${vuln.fixed_version}`}
                            </p>
                          </div>
                          {vuln.score && (
                            <span className="text-xs font-semibold text-gray-600 dark:text-gray-400 ml-3">
                              {vuln.score.toFixed(1)}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card.Body>
            </Card>
          )}
        </div>

        {/* Sidebar - Quick Info */}
        <div className="space-y-6">
          {/* Image Information */}
          <Card>
            <Card.Header>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <Container className="w-5 h-5" />
                Image
              </h2>
            </Card.Header>
            <Card.Body className="space-y-3">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Repository</p>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {spine.image.repository}
                </p>
              </div>
              {spine.image.tag && (
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Tag</p>
                  <Badge variant="default">{spine.image.tag}</Badge>
                </div>
              )}
              {spine.image.digest && (
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Digest</p>
                  <p className="text-xs font-mono text-gray-900 dark:text-white break-all">
                    {spine.image.digest}
                  </p>
                </div>
              )}
            </Card.Body>
          </Card>

          {/* SBOM Information */}
          {spine.sbom && (
            <Card>
              <Card.Header>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Package className="w-5 h-5" />
                  SBOM
                </h2>
              </Card.Header>
              <Card.Body className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">Total Packages</span>
                  <span className="text-lg font-semibold text-gray-900 dark:text-white">
                    {spine.sbom.total_packages}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">OS Packages</span>
                  <span className="text-sm text-gray-900 dark:text-white">{spine.sbom.os_packages}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">Libraries</span>
                  <span className="text-sm text-gray-900 dark:text-white">
                    {spine.sbom.library_packages}
                  </span>
                </div>
                <div className="pt-3 border-t border-gray-200 dark:border-gray-700">
                  <Badge variant="default" size="sm">
                    {spine.sbom.format.toUpperCase()}
                  </Badge>
                </div>
                <Link
                  href="/sboms"
                  className="inline-flex items-center justify-center gap-2 w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
                >
                  View Full SBOM
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </Card.Body>
            </Card>
          )}

          {/* Policy Decision */}
          {spine.policy_eval && (
            <Card>
              <Card.Header>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <FileCode className="w-5 h-5" />
                  Policy Decision
                </h2>
              </Card.Header>
              <Card.Body className="space-y-3">
                <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <StatusIndicator
                    status={getPolicyDecisionStatus(spine.policy_eval.decision)}
                    label={spine.policy_eval.decision.toUpperCase()}
                    size="lg"
                  />
                </div>
                {spine.policy_eval.reason && (
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {spine.policy_eval.reason}
                  </p>
                )}
                {spine.policy_eval.warnings && spine.policy_eval.warnings.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-yellow-700 dark:text-yellow-400">Warnings:</p>
                    {spine.policy_eval.warnings.map((warning, idx) => (
                      <p key={idx} className="text-xs text-gray-600 dark:text-gray-400 pl-3">
                        • {warning}
                      </p>
                    ))}
                  </div>
                )}
                {spine.policy_eval.errors && spine.policy_eval.errors.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-red-700 dark:text-red-400">Errors:</p>
                    {spine.policy_eval.errors.map((error, idx) => (
                      <p key={idx} className="text-xs text-gray-600 dark:text-gray-400 pl-3">
                        • {error}
                      </p>
                    ))}
                  </div>
                )}
                <Link
                  href="/policies"
                  className="inline-flex items-center gap-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
                >
                  View Policy Rules
                  <ArrowRight className="w-3 h-3" />
                </Link>
              </Card.Body>
            </Card>
          )}

          {/* Runtime Information */}
          {spine.runtime && spine.runtime.container_id && (
            <Card>
              <Card.Header>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Runtime
                </h2>
              </Card.Header>
              <Card.Body className="space-y-3">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Container</p>
                  <p className="text-xs font-mono text-gray-900 dark:text-white break-all">
                    {spine.runtime.container_name}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Status</p>
                  <StatusIndicator
                    status={spine.runtime.container_status === "running" ? "healthy" : "critical"}
                    label={spine.runtime.container_status}
                    pulse={spine.runtime.container_status === "running"}
                    size="sm"
                  />
                </div>
                {spine.runtime.started_at && (
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Started</p>
                    <p className="text-sm text-gray-900 dark:text-white">
                      {new Date(spine.runtime.started_at).toLocaleString()}
                    </p>
                  </div>
                )}
                {spine.runtime.proxy_configured && (
                  <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/10 rounded-lg">
                    <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-green-700 dark:text-green-400">
                        Proxy Configured
                      </p>
                      {spine.runtime.proxy_url && (
                        <p className="text-xs text-green-600 dark:text-green-500 mt-0.5 truncate">
                          {spine.runtime.proxy_url}
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </Card.Body>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
