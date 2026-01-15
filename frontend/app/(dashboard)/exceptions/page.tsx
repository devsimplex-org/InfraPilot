"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Calendar,
  User,
  FileText,
  Plus,
  History,
} from "lucide-react";
import {
  api,
  RiskException,
  CreateExceptionRequest,
  DenyExceptionRequest,
  RevokeExceptionRequest,
} from "@/lib/api";
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

type PageTab = "active" | "pending" | "expired" | "all";

export default function ExceptionsPage() {
  const queryClient = useQueryClient();
  const [pageTab, setPageTab] = useState<PageTab>("active");
  const [selectedEx, setSelectedEx] = useState<RiskException | null>(null);
  const [scopeTypeFilter, setScopeTypeFilter] = useState<string | undefined>();
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Create exception form state
  const [createScopeType, setCreateScopeType] = useState<string>("cve");
  const [createScopeRef, setCreateScopeRef] = useState("");
  const [createJustification, setCreateJustification] = useState("");
  const [createBusinessImpact, setCreateBusinessImpact] = useState("");
  const [createMitigationPlan, setCreateMitigationPlan] = useState("");
  const [createDurationDays, setCreateDurationDays] = useState(30);

  const getStatusForTab = (tab: PageTab): string | undefined => {
    switch (tab) {
      case "active":
        return "approved";
      case "pending":
        return "pending";
      case "expired":
        return "expired";
      case "all":
        return undefined;
    }
  };

  // Fetch exceptions
  const { data: exceptionsData, isLoading } = useQuery({
    queryKey: ["exceptions", pageTab, scopeTypeFilter],
    queryFn: () =>
      api.listExceptions({
        status: getStatusForTab(pageTab),
        scope_type: scopeTypeFilter,
      }),
    refetchInterval: 10000,
  });

  // Create exception mutation
  const createExceptionMutation = useMutation({
    mutationFn: (request: CreateExceptionRequest) => api.createException(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setShowCreateModal(false);
      resetCreateForm();
    },
  });

  // Approve exception mutation
  const approveExceptionMutation = useMutation({
    mutationFn: (exceptionId: string) => api.approveException(exceptionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setSelectedEx(null);
    },
  });

  // Deny exception mutation
  const denyExceptionMutation = useMutation({
    mutationFn: ({ exceptionId, reason }: { exceptionId: string; reason: string }) =>
      api.denyException(exceptionId, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setSelectedEx(null);
    },
  });

  // Revoke exception mutation
  const revokeExceptionMutation = useMutation({
    mutationFn: ({ exceptionId, reason }: { exceptionId: string; reason: string }) =>
      api.revokeException(exceptionId, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setSelectedEx(null);
    },
  });

  const resetCreateForm = () => {
    setCreateScopeType("cve");
    setCreateScopeRef("");
    setCreateJustification("");
    setCreateBusinessImpact("");
    setCreateMitigationPlan("");
    setCreateDurationDays(30);
  };

  const handleCreateException = () => {
    if (createJustification.length < 50) {
      alert("Justification must be at least 50 characters");
      return;
    }

    createExceptionMutation.mutate({
      scope_type: createScopeType,
      scope_reference: createScopeRef,
      justification: createJustification,
      business_impact: createBusinessImpact || undefined,
      mitigation_plan: createMitigationPlan || undefined,
      duration_days: createDurationDays,
    });
  };

  const handleApprove = (exceptionId: string) => {
    if (confirm("Approve this risk exception? This will allow the deployment to proceed.")) {
      approveExceptionMutation.mutate(exceptionId);
    }
  };

  const handleDeny = (exceptionId: string) => {
    const reason = prompt("Reason for denial:");
    if (reason) {
      denyExceptionMutation.mutate({ exceptionId, reason });
    }
  };

  const handleRevoke = (exceptionId: string) => {
    const reason = prompt("Reason for revocation:");
    if (reason) {
      revokeExceptionMutation.mutate({ exceptionId, reason });
    }
  };

  const exceptions = exceptionsData?.exceptions || [];

  const getStatusIcon = (status: RiskException["status"]) => {
    switch (status) {
      case "approved":
        return <ShieldCheck className="h-4 w-4 text-green-600" />;
      case "pending":
        return <Clock className="h-4 w-4 text-yellow-600" />;
      case "denied":
        return <ShieldX className="h-4 w-4 text-red-600" />;
      case "expired":
        return <AlertTriangle className="h-4 w-4 text-orange-600" />;
      case "revoked":
        return <XCircle className="h-4 w-4 text-red-600" />;
    }
  };

  const getStatusBadgeClass = (status: RiskException["status"]) => {
    switch (status) {
      case "approved":
        return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
      case "pending":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "denied":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "expired":
        return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
      case "revoked":
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  const getScopeTypeLabel = (scopeType: RiskException["scope_type"]) => {
    switch (scopeType) {
      case "cve":
        return "CVE";
      case "policy_rule":
        return "Policy Rule";
      case "deployment":
        return "Deployment";
      case "package":
        return "Package";
      case "image":
        return "Image";
    }
  };

  const isExpiringSoon = (expiresAt: string) => {
    const expiry = new Date(expiresAt);
    const now = new Date();
    const daysLeft = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return daysLeft <= 7 && daysLeft >= 0;
  };

  return (
    <PageLayout
      title="Risk Exceptions"
      subtitle="Manage time-boxed security exceptions with approval workflow"
      icon={<ShieldAlert className="h-8 w-8" />}
      action={
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Request Exception
        </Button>
      }
    >
      <Tabs
        tabs={[
          { id: "active", label: "Active", icon: ShieldCheck },
          { id: "pending", label: "Pending Approval", icon: Clock },
          { id: "expired", label: "Expired", icon: AlertTriangle },
          { id: "all", label: "All Exceptions", icon: Shield },
        ]}
        activeTab={pageTab}
        onChange={(tab) => setPageTab(tab as PageTab)}
      />

      <div className="flex flex-col lg:flex-row gap-6 h-full">
        {/* Exception List */}
        <div className="lg:w-1/2">
          <div className="mb-4">
            <select
              value={scopeTypeFilter || ""}
              onChange={(e) => setScopeTypeFilter(e.target.value || undefined)}
              className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
            >
              <option value="">All Types</option>
              <option value="cve">CVE</option>
              <option value="policy_rule">Policy Rule</option>
              <option value="deployment">Deployment</option>
              <option value="package">Package</option>
              <option value="image">Image</option>
            </select>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <Clock className="h-8 w-8 animate-spin text-gray-400" />
            </div>
          ) : exceptions.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title={`No ${pageTab} exceptions`}
              description="Risk exceptions will appear here when created"
            />
          ) : (
            <div className="space-y-2">
              {exceptions.map((ex) => (
                <ListCard
                  key={ex.id}
                  selected={selectedEx?.id === ex.id}
                  onClick={() => setSelectedEx(ex)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase">
                          {getScopeTypeLabel(ex.scope_type)}
                        </span>
                        <span className="font-medium text-sm truncate">
                          {ex.scope_reference}
                        </span>
                      </div>
                      <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-2">
                        {ex.justification}
                      </p>
                      {ex.status === "approved" && isExpiringSoon(ex.expires_at) && (
                        <div className="flex items-center gap-1 mt-2 text-xs text-orange-600">
                          <AlertTriangle className="h-3 w-3" />
                          <span>Expires soon</span>
                        </div>
                      )}
                    </div>
                    <div className="flex flex-col items-end gap-1 ml-4">
                      <div className="flex items-center gap-1">
                        {getStatusIcon(ex.status)}
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs font-medium rounded-full",
                            getStatusBadgeClass(ex.status)
                          )}
                        >
                          {ex.status}
                        </span>
                      </div>
                      <span className="text-xs text-gray-500">
                        {new Date(ex.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </ListCard>
              ))}
            </div>
          )}
        </div>

        {/* Exception Detail */}
        <div className="lg:w-1/2">
          {selectedEx ? (
            <DetailPanel
              title={`${getScopeTypeLabel(selectedEx.scope_type)}: ${selectedEx.scope_reference}`}
              onClose={() => setSelectedEx(null)}
            >
              <DetailSection title="Status">
                <DetailRow label="Current Status">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(selectedEx.status)}
                    <span
                      className={cn(
                        "px-2 py-0.5 text-xs font-medium rounded-full",
                        getStatusBadgeClass(selectedEx.status)
                      )}
                    >
                      {selectedEx.status}
                    </span>
                  </div>
                </DetailRow>
                <DetailRow label="Expires At">
                  <div className="flex items-center gap-2">
                    <Calendar className="h-4 w-4" />
                    <span>{new Date(selectedEx.expires_at).toLocaleDateString()}</span>
                    {selectedEx.status === "approved" && isExpiringSoon(selectedEx.expires_at) && (
                      <span className="ml-2 px-2 py-0.5 text-xs font-medium rounded-full bg-orange-100 text-orange-700">
                        Expiring Soon
                      </span>
                    )}
                  </div>
                </DetailRow>
                {selectedEx.approved_by && (
                  <DetailRow label="Approved By">
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      <span className="text-sm">{selectedEx.approved_by}</span>
                    </div>
                  </DetailRow>
                )}
                {selectedEx.approved_at && (
                  <DetailRow label="Approved At">
                    {new Date(selectedEx.approved_at).toLocaleString()}
                  </DetailRow>
                )}
                {selectedEx.denial_reason && (
                  <DetailRow label="Denial Reason">
                    <span className="text-red-600 text-sm">{selectedEx.denial_reason}</span>
                  </DetailRow>
                )}
                {selectedEx.revoked_reason && (
                  <DetailRow label="Revocation Reason">
                    <span className="text-red-600 text-sm">{selectedEx.revoked_reason}</span>
                  </DetailRow>
                )}
              </DetailSection>

              <DetailSection title="Request Details">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      Justification
                    </h4>
                    <div className="prose prose-sm dark:prose-invert max-w-none bg-gray-50 dark:bg-gray-900 p-3 rounded-md">
                      <p className="text-sm whitespace-pre-wrap">{selectedEx.justification}</p>
                    </div>
                  </div>

                  {selectedEx.business_impact && (
                    <div>
                      <h4 className="font-medium text-sm mb-2">Business Impact</h4>
                      <div className="prose prose-sm dark:prose-invert max-w-none bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md">
                        <p className="text-sm whitespace-pre-wrap">
                          {selectedEx.business_impact}
                        </p>
                      </div>
                    </div>
                  )}

                  {selectedEx.mitigation_plan && (
                    <div>
                      <h4 className="font-medium text-sm mb-2">Mitigation Plan</h4>
                      <div className="prose prose-sm dark:prose-invert max-w-none bg-green-50 dark:bg-green-900/20 p-3 rounded-md">
                        <p className="text-sm whitespace-pre-wrap">
                          {selectedEx.mitigation_plan}
                        </p>
                      </div>
                    </div>
                  )}

                  {selectedEx.tags && selectedEx.tags.length > 0 && (
                    <div>
                      <h4 className="font-medium text-sm mb-2">Tags</h4>
                      <div className="flex flex-wrap gap-2">
                        {selectedEx.tags.map((tag, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </DetailSection>

              {/* Actions */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700 space-y-2">
                {selectedEx.status === "pending" && (
                  <>
                    <Button
                      onClick={() => handleApprove(selectedEx.id)}
                      disabled={approveExceptionMutation.isPending}
                      className="w-full bg-green-600 hover:bg-green-700"
                    >
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Approve Exception
                    </Button>
                    <Button
                      onClick={() => handleDeny(selectedEx.id)}
                      disabled={denyExceptionMutation.isPending}
                      className="w-full bg-red-600 hover:bg-red-700"
                    >
                      <XCircle className="h-4 w-4 mr-2" />
                      Deny Exception
                    </Button>
                  </>
                )}

                {selectedEx.status === "approved" && (
                  <Button
                    onClick={() => handleRevoke(selectedEx.id)}
                    disabled={revokeExceptionMutation.isPending}
                    className="w-full bg-orange-600 hover:bg-orange-700"
                  >
                    <ShieldX className="h-4 w-4 mr-2" />
                    Revoke Exception
                  </Button>
                )}
              </div>
            </DetailPanel>
          ) : (
            <EmptyState
              icon={ShieldAlert}
              title="Select an exception"
              description="Click on an exception to view details and take actions"
            />
          )}
        </div>
      </div>

      {/* Create Exception Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
            <h2 className="text-2xl font-bold mb-6">Request Risk Exception</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Scope Type</label>
                <select
                  value={createScopeType}
                  onChange={(e) => setCreateScopeType(e.target.value)}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                >
                  <option value="cve">CVE</option>
                  <option value="policy_rule">Policy Rule</option>
                  <option value="deployment">Deployment</option>
                  <option value="package">Package</option>
                  <option value="image">Image</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  {createScopeType === "cve" && "CVE ID (e.g., CVE-2024-1234)"}
                  {createScopeType === "policy_rule" && "Policy Rule Name"}
                  {createScopeType === "deployment" && "Deployment ID"}
                  {createScopeType === "package" && "Package Name"}
                  {createScopeType === "image" && "Image Reference"}
                </label>
                <input
                  type="text"
                  value={createScopeRef}
                  onChange={(e) => setCreateScopeRef(e.target.value)}
                  placeholder="Enter reference..."
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  Justification (minimum 50 characters)
                </label>
                <textarea
                  value={createJustification}
                  onChange={(e) => setCreateJustification(e.target.value)}
                  placeholder="Explain why this exception is needed..."
                  rows={4}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
                <p className="mt-1 text-xs text-gray-600">
                  {createJustification.length} / 50 characters
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  Business Impact (optional)
                </label>
                <textarea
                  value={createBusinessImpact}
                  onChange={(e) => setCreateBusinessImpact(e.target.value)}
                  placeholder="Describe the business impact if this is not excepted..."
                  rows={3}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  Mitigation Plan (optional)
                </label>
                <textarea
                  value={createMitigationPlan}
                  onChange={(e) => setCreateMitigationPlan(e.target.value)}
                  placeholder="Describe compensating controls or mitigation steps..."
                  rows={3}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  Duration (days, max 365)
                </label>
                <input
                  type="number"
                  value={createDurationDays}
                  onChange={(e) => setCreateDurationDays(parseInt(e.target.value))}
                  min={1}
                  max={365}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
                <p className="mt-1 text-xs text-gray-600">
                  Exception will expire on{" "}
                  {new Date(
                    Date.now() + createDurationDays * 24 * 60 * 60 * 1000
                  ).toLocaleDateString()}
                </p>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <Button
                onClick={handleCreateException}
                disabled={
                  createExceptionMutation.isPending ||
                  !createScopeRef ||
                  createJustification.length < 50
                }
                className="flex-1"
              >
                {createExceptionMutation.isPending ? "Creating..." : "Request Exception"}
              </Button>
              <Button
                onClick={() => {
                  setShowCreateModal(false);
                  resetCreateForm();
                }}
                className="flex-1 bg-gray-600 hover:bg-gray-700"
              >
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
