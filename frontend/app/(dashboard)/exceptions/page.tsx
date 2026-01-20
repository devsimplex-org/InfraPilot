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
} from "lucide-react";
import {
  api,
  RiskException,
  CreateExceptionRequest,
} from "@/lib/api";

// New Component Library Imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table, TableCell } from "@/components/ui/Table";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { Timeline } from "@/components/ui/Timeline";
import { FilterPanel, FilterGroup } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function ExceptionsPage() {
  const queryClient = useQueryClient();

  // Section 1: State Management
  const [selectedEx, setSelectedEx] = useState<RiskException | null>(null);
  const [showSlideOver, setShowSlideOver] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Filter state
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [scopeTypeFilter, setScopeTypeFilter] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");

  // Create exception form state
  const [createScopeType, setCreateScopeType] = useState<string>("cve");
  const [createScopeRef, setCreateScopeRef] = useState("");
  const [createJustification, setCreateJustification] = useState("");
  const [createBusinessImpact, setCreateBusinessImpact] = useState("");
  const [createMitigationPlan, setCreateMitigationPlan] = useState("");
  const [createDurationDays, setCreateDurationDays] = useState(30);

  // Section 2: Data Fetching
  const { data: exceptionsData, isLoading } = useQuery({
    queryKey: ["exceptions"],
    queryFn: () => api.listExceptions({}),
    refetchInterval: 10000,
  });

  // Section 3: Mutations
  const createExceptionMutation = useMutation({
    mutationFn: (request: CreateExceptionRequest) => api.createException(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setShowCreateModal(false);
      resetCreateForm();
    },
  });

  const approveExceptionMutation = useMutation({
    mutationFn: (exceptionId: string) => api.approveException(exceptionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setShowSlideOver(false);
      setSelectedEx(null);
    },
  });

  const denyExceptionMutation = useMutation({
    mutationFn: ({ exceptionId, reason }: { exceptionId: string; reason: string }) =>
      api.denyException(exceptionId, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setShowSlideOver(false);
      setSelectedEx(null);
    },
  });

  const revokeExceptionMutation = useMutation({
    mutationFn: ({ exceptionId, reason }: { exceptionId: string; reason: string }) =>
      api.revokeException(exceptionId, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setShowSlideOver(false);
      setSelectedEx(null);
    },
  });

  // Section 4: Helper Functions
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

  const getStatusIcon = (status: RiskException["status"]) => {
    switch (status) {
      case "approved":
        return ShieldCheck;
      case "pending":
        return Clock;
      case "denied":
        return ShieldX;
      case "expired":
        return AlertTriangle;
      case "revoked":
        return XCircle;
    }
  };

  const mapExceptionStatusToBadgeStatus = (status: RiskException["status"]) => {
    // Map exception statuses to badge status types
    switch (status) {
      case "approved":
        return "healthy";
      case "pending":
        return "warning";
      case "denied":
      case "revoked":
      case "expired":
        return "critical";
      default:
        return "degraded";
    }
  };

  const isExpiringSoon = (expiresAt: string) => {
    const expiry = new Date(expiresAt);
    const now = new Date();
    const daysLeft = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return daysLeft <= 7 && daysLeft >= 0;
  };

  // Filter data
  const exceptions = exceptionsData?.exceptions || [];

  const filteredExceptions = exceptions.filter((ex) => {
    // Status filter
    if (statusFilter.length > 0 && !statusFilter.includes(ex.status)) {
      return false;
    }

    // Scope type filter
    if (scopeTypeFilter.length > 0 && !scopeTypeFilter.includes(ex.scope_type)) {
      return false;
    }

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        ex.scope_reference.toLowerCase().includes(query) ||
        ex.justification.toLowerCase().includes(query)
      );
    }

    return true;
  });

  // Calculate metrics
  const metrics = {
    pending: exceptions.filter((ex) => ex.status === "pending").length,
    approved: exceptions.filter((ex) => ex.status === "approved").length,
    denied: exceptions.filter((ex) => ex.status === "denied").length,
    expired: exceptions.filter((ex) => ex.status === "expired").length,
  };

  // Define filter groups
  const filterGroups: FilterGroup[] = [
    {
      id: "status",
      label: "Status",
      type: "checkbox",
      value: statusFilter,
      onChange: (value) => setStatusFilter(value as string[]),
      options: [
        { label: "Pending", value: "pending", count: metrics.pending },
        { label: "Approved", value: "approved", count: metrics.approved },
        { label: "Denied", value: "denied", count: metrics.denied },
        { label: "Expired", value: "expired", count: metrics.expired },
      ],
    },
    {
      id: "scopeType",
      label: "Scope Type",
      type: "checkbox",
      value: scopeTypeFilter,
      onChange: (value) => setScopeTypeFilter(value as string[]),
      options: [
        { label: "CVE", value: "cve" },
        { label: "Policy Rule", value: "policy_rule" },
        { label: "Deployment", value: "deployment" },
        { label: "Package", value: "package" },
        { label: "Image", value: "image" },
      ],
    },
    {
      id: "search",
      label: "Search",
      type: "search",
      value: searchQuery,
      onChange: (value) => setSearchQuery(value as string),
    },
  ];

  const handleResetFilters = () => {
    setStatusFilter([]);
    setScopeTypeFilter([]);
    setSearchQuery("");
  };

  // Table columns
  const columns = [
    {
      key: "scope_type",
      header: "Type",
      sortable: true,
      width: "120px",
      render: (value: string) => (
        <span className="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase">
          {getScopeTypeLabel(value as RiskException["scope_type"])}
        </span>
      ),
    },
    {
      key: "scope_reference",
      header: "Reference",
      sortable: true,
      render: (value: string) => (
        <span className="font-medium text-sm">{value}</span>
      ),
    },
    {
      key: "justification",
      header: "Justification",
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
          {value}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      width: "140px",
      align: "center" as const,
      render: (value: string, row: RiskException) => (
        <div className="flex items-center justify-center gap-2">
          <StatusBadge
            status={mapExceptionStatusToBadgeStatus(value as RiskException["status"])}
            icon={getStatusIcon(value as RiskException["status"])}
            size="sm"
          >
            {value}
          </StatusBadge>
        </div>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      width: "120px",
      align: "right" as const,
      render: (value: string) => (
        <span className="text-sm text-gray-500">
          {new Date(value).toLocaleDateString()}
        </span>
      ),
    },
  ];

  const handleRowClick = (row: RiskException) => {
    setSelectedEx(row);
    setShowSlideOver(true);
  };

  // Build timeline events
  const buildTimeline = (ex: RiskException) => {
    const events = [];

    // Created event
    events.push({
      icon: FileText,
      iconColor: "text-blue-600 dark:text-blue-400",
      title: "Exception Requested",
      description: `Requested by ${ex.requested_by || "Unknown"}`,
      timestamp: new Date(ex.created_at).toLocaleString(),
    });

    // Approved event
    if (ex.approved_at && ex.approved_by) {
      events.push({
        icon: CheckCircle,
        iconColor: "text-green-600 dark:text-green-400",
        title: "Exception Approved",
        description: `Approved by ${ex.approved_by}`,
        timestamp: new Date(ex.approved_at).toLocaleString(),
      });
    }

    // Denial event
    if (ex.status === "denied" && ex.denial_reason) {
      events.push({
        icon: XCircle,
        iconColor: "text-red-600 dark:text-red-400",
        title: "Exception Denied",
        description: ex.denial_reason,
        timestamp: new Date(ex.created_at).toLocaleString(), // Using created_at as fallback
      });
    }

    // Revoked event
    if (ex.status === "revoked" && ex.revoked_reason) {
      events.push({
        icon: ShieldX,
        iconColor: "text-orange-600 dark:text-orange-400",
        title: "Exception Revoked",
        description: ex.revoked_reason,
        timestamp: new Date().toLocaleString(), // Current time as fallback
      });
    }

    // Expiration event
    if (ex.status === "approved") {
      events.push({
        icon: Calendar,
        iconColor: isExpiringSoon(ex.expires_at)
          ? "text-orange-600 dark:text-orange-400"
          : "text-gray-600 dark:text-gray-400",
        title: "Expires",
        description: isExpiringSoon(ex.expires_at) ? "Expiring soon!" : "Future expiration",
        timestamp: new Date(ex.expires_at).toLocaleString(),
      });
    }

    return events;
  };

  return (
    <div className="space-y-6">
      {/* Section 1: Header with Breadcrumbs */}
      <PageHeader
        title="Risk Exceptions"
        description="Manage time-boxed security exceptions with approval workflow"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Govern", href: "/govern" },
              { label: "Risk Exceptions" },
            ]}
          />
        }
        action={
          <button
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Plus className="h-4 w-4 mr-2" />
            Request Exception
          </button>
        }
      />

      {/* Section 2: Metrics Grid */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Pending Approval"
          value={metrics.pending}
          icon={Clock}
          iconColor="text-yellow-600"
          valueColor={metrics.pending > 0 ? "text-yellow-600 dark:text-yellow-400" : undefined}
        />
        <StatCard
          label="Approved"
          value={metrics.approved}
          icon={ShieldCheck}
          iconColor="text-green-600"
          valueColor={metrics.approved > 0 ? "text-green-600 dark:text-green-400" : undefined}
        />
        <StatCard
          label="Denied"
          value={metrics.denied}
          icon={ShieldX}
          iconColor="text-red-600"
          valueColor={metrics.denied > 0 ? "text-red-600 dark:text-red-400" : undefined}
        />
        <StatCard
          label="Expired"
          value={metrics.expired}
          icon={AlertTriangle}
          iconColor="text-orange-600"
          valueColor={metrics.expired > 0 ? "text-orange-600 dark:text-orange-400" : undefined}
        />
      </MetricsGrid>

      {/* Section 3: Filters and Table */}
      <div className="flex gap-6">
        {/* Filter Sidebar */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filterGroups}
            onReset={handleResetFilters}
          />
        </div>

        {/* Exceptions Table */}
        <div className="flex-1 min-w-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spinner size="lg" label="Loading exceptions..." />
            </div>
          ) : filteredExceptions.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="No exceptions found"
              description="All deployments comply with security policies. No exceptions have been requested."
              size="md"
            />
          ) : (
            <Table
              columns={columns}
              data={filteredExceptions}
              keyExtractor={(row) => row.id}
              onRowClick={handleRowClick}
              hoverable={true}
              stickyHeader={true}
            />
          )}
        </div>
      </div>

        {/* Section 4: SlideOver for Exception Details */}
        <SlideOver
          isOpen={showSlideOver}
          onClose={() => {
            setShowSlideOver(false);
            setSelectedEx(null);
          }}
          size="lg"
        >
          {selectedEx && (
            <>
              <SlideOver.Header onClose={() => setShowSlideOver(false)}>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                    {getScopeTypeLabel(selectedEx.scope_type)}: {selectedEx.scope_reference}
                  </h2>
                  <div className="mt-2 flex items-center gap-2">
                    <StatusBadge
                      status={mapExceptionStatusToBadgeStatus(selectedEx.status)}
                      icon={getStatusIcon(selectedEx.status)}
                    >
                      {selectedEx.status}
                    </StatusBadge>
                    {selectedEx.status === "approved" && isExpiringSoon(selectedEx.expires_at) && (
                      <Badge className="bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400">
                        <AlertTriangle className="h-3 w-3" />
                        Expiring Soon
                      </Badge>
                    )}
                  </div>
                </div>
              </SlideOver.Header>

              <SlideOver.Body>
                <div className="space-y-6">
                  {/* Exception Details */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Details
                    </h3>
                    <div className="space-y-3">
                      <div>
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          Expires At
                        </span>
                        <div className="flex items-center gap-2 mt-1">
                          <Calendar className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-900 dark:text-white">
                            {new Date(selectedEx.expires_at).toLocaleDateString()}
                          </span>
                        </div>
                      </div>

                      {selectedEx.approved_by && (
                        <div>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            Approved By
                          </span>
                          <div className="flex items-center gap-2 mt-1">
                            <User className="h-4 w-4 text-gray-400" />
                            <span className="text-sm text-gray-900 dark:text-white">
                              {selectedEx.approved_by}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Justification */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      Justification
                    </h3>
                    <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                      <p className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
                        {selectedEx.justification}
                      </p>
                    </div>
                  </div>

                  {/* Business Impact */}
                  {selectedEx.business_impact && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                        Business Impact
                      </h3>
                      <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                        <p className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
                          {selectedEx.business_impact}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Mitigation Plan */}
                  {selectedEx.mitigation_plan && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                        Mitigation Plan
                      </h3>
                      <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                        <p className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
                          {selectedEx.mitigation_plan}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Timeline */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Exception Lifecycle
                    </h3>
                    <Timeline>
                      {buildTimeline(selectedEx).map((event, idx) => (
                        <Timeline.Item
                          key={idx}
                          icon={event.icon}
                          iconColor={event.iconColor}
                          title={event.title}
                          description={event.description}
                          timestamp={event.timestamp}
                        />
                      ))}
                    </Timeline>
                  </div>
                </div>
              </SlideOver.Body>

              <SlideOver.Footer>
                {selectedEx.status === "pending" && (
                  <div className="flex gap-3 w-full">
                    <button
                      onClick={() => handleApprove(selectedEx.id)}
                      disabled={approveExceptionMutation.isPending}
                      className="flex-1 inline-flex items-center justify-center px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-300 text-white rounded-lg text-sm font-medium transition-colors"
                    >
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Approve
                    </button>
                    <button
                      onClick={() => handleDeny(selectedEx.id)}
                      disabled={denyExceptionMutation.isPending}
                      className="flex-1 inline-flex items-center justify-center px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-300 text-white rounded-lg text-sm font-medium transition-colors"
                    >
                      <XCircle className="h-4 w-4 mr-2" />
                      Deny
                    </button>
                  </div>
                )}

                {selectedEx.status === "approved" && (
                  <button
                    onClick={() => handleRevoke(selectedEx.id)}
                    disabled={revokeExceptionMutation.isPending}
                    className="w-full inline-flex items-center justify-center px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-300 text-white rounded-lg text-sm font-medium transition-colors"
                  >
                    <ShieldX className="h-4 w-4 mr-2" />
                    Revoke Exception
                  </button>
                )}
              </SlideOver.Footer>
            </>
          )}
        </SlideOver>

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
                <button
                  onClick={handleCreateException}
                  disabled={
                    createExceptionMutation.isPending ||
                    !createScopeRef ||
                    createJustification.length < 50
                  }
                  className="flex-1 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-300 text-white rounded-lg text-sm font-medium"
                >
                  {createExceptionMutation.isPending ? "Creating..." : "Request Exception"}
                </button>
                <button
                  onClick={() => {
                    setShowCreateModal(false);
                    resetCreateForm();
                  }}
                  className="flex-1 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg text-sm font-medium"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
    </div>
  );
}
