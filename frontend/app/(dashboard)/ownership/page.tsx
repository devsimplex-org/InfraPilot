"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Users,
  Building2,
  Mail,
  MessageSquare,
  Plus,
  Trash2,
  ExternalLink,
  FileText,
  Link as LinkIcon,
  UserPlus,
  Shield,
} from "lucide-react";
import {
  api,
  ServiceOwnership,
  Team,
  CreateServiceOwnershipRequest,
  CreateTeamRequest,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// New component library imports
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel, FilterGroup } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/page-layout";

type PageTab = "services" | "teams";

export default function OwnershipPage() {
  const queryClient = useQueryClient();
  const [pageTab, setPageTab] = useState<PageTab>("services");
  const [selectedOwnership, setSelectedOwnership] = useState<ServiceOwnership | null>(null);
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null);
  const [showCreateServiceModal, setShowCreateServiceModal] = useState(false);
  const [showCreateTeamModal, setShowCreateTeamModal] = useState(false);

  // Filter states
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");

  // Service ownership form state
  const [serviceName, setServiceName] = useState("");
  const [teamName, setTeamName] = useState("");
  const [teamEmail, setTeamEmail] = useState("");
  const [teamSlackChannel, setTeamSlackChannel] = useState("");
  const [primaryContactEmail, setPrimaryContactEmail] = useState("");
  const [description, setDescription] = useState("");
  const [repositoryURL, setRepositoryURL] = useState("");
  const [documentationURL, setDocumentationURL] = useState("");

  // Team form state
  const [newTeamName, setNewTeamName] = useState("");
  const [newTeamDisplayName, setNewTeamDisplayName] = useState("");
  const [newTeamEmail, setNewTeamEmail] = useState("");
  const [newTeamSlackChannel, setNewTeamSlackChannel] = useState("");
  const [newTeamDescription, setNewTeamDescription] = useState("");

  // Fetch service ownerships
  const { data: ownershipsData, isLoading: loadingOwnerships } = useQuery({
    queryKey: ["serviceOwnerships"],
    queryFn: () => api.listServiceOwnerships(),
    enabled: pageTab === "services",
  });

  // Fetch teams
  const { data: teamsData, isLoading: loadingTeams } = useQuery({
    queryKey: ["teams"],
    queryFn: () => api.listTeams(),
    enabled: pageTab === "teams",
  });

  // Create service ownership mutation
  const createOwnershipMutation = useMutation({
    mutationFn: (request: CreateServiceOwnershipRequest) => api.createServiceOwnership(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["serviceOwnerships"] });
      setShowCreateServiceModal(false);
      resetServiceForm();
    },
  });

  // Delete service ownership mutation
  const deleteOwnershipMutation = useMutation({
    mutationFn: (ownershipId: string) => api.deleteServiceOwnership(ownershipId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["serviceOwnerships"] });
      setSelectedOwnership(null);
    },
  });

  // Create team mutation
  const createTeamMutation = useMutation({
    mutationFn: (request: CreateTeamRequest) => api.createTeam(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      setShowCreateTeamModal(false);
      resetTeamForm();
    },
  });

  // Delete team mutation
  const deleteTeamMutation = useMutation({
    mutationFn: (teamId: string) => api.deleteTeam(teamId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      setSelectedTeam(null);
    },
  });

  const ownerships = ownershipsData?.ownerships || [];
  const teams = teamsData?.teams || [];

  // Filter and search logic
  const filteredOwnerships = useMemo(() => {
    let filtered = ownerships;

    // Apply status filter
    if (statusFilter.length > 0) {
      filtered = filtered.filter((o) => statusFilter.includes(o.status));
    }

    // Apply search
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (o) =>
          o.service_name.toLowerCase().includes(query) ||
          o.team_name.toLowerCase().includes(query)
      );
    }

    return filtered;
  }, [ownerships, statusFilter, searchQuery]);

  const filteredTeams = useMemo(() => {
    let filtered = teams;

    // Apply status filter
    if (statusFilter.length > 0) {
      filtered = filtered.filter((t) =>
        statusFilter.includes(t.active ? "active" : "inactive")
      );
    }

    // Apply search
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          (t.display_name && t.display_name.toLowerCase().includes(query)) ||
          (t.email && t.email.toLowerCase().includes(query))
      );
    }

    return filtered;
  }, [teams, statusFilter, searchQuery]);

  // Calculate metrics
  const servicesMetrics = {
    total: ownerships.length,
    active: ownerships.filter((o) => o.status === "active").length,
    teams: new Set(ownerships.map((o) => o.team_name)).size,
  };

  const teamsMetrics = {
    total: teams.length,
    active: teams.filter((t) => t.active).length,
    withEmail: teams.filter((t) => t.email).length,
    withSlack: teams.filter((t) => t.slack_channel).length,
  };

  const resetServiceForm = () => {
    setServiceName("");
    setTeamName("");
    setTeamEmail("");
    setTeamSlackChannel("");
    setPrimaryContactEmail("");
    setDescription("");
    setRepositoryURL("");
    setDocumentationURL("");
  };

  const resetTeamForm = () => {
    setNewTeamName("");
    setNewTeamDisplayName("");
    setNewTeamEmail("");
    setNewTeamSlackChannel("");
    setNewTeamDescription("");
  };

  const handleCreateOwnership = () => {
    if (!serviceName || !teamName) {
      alert("Service name and team name are required");
      return;
    }

    createOwnershipMutation.mutate({
      service_name: serviceName,
      team_name: teamName,
      team_email: teamEmail || undefined,
      team_slack_channel: teamSlackChannel || undefined,
      primary_contact_email: primaryContactEmail || undefined,
      description: description || undefined,
      repository_url: repositoryURL || undefined,
      documentation_url: documentationURL || undefined,
    });
  };

  const handleCreateTeam = () => {
    if (!newTeamName) {
      alert("Team name is required");
      return;
    }

    createTeamMutation.mutate({
      name: newTeamName,
      display_name: newTeamDisplayName || undefined,
      email: newTeamEmail || undefined,
      slack_channel: newTeamSlackChannel || undefined,
      description: newTeamDescription || undefined,
    });
  };

  const handleDeleteOwnership = (ownershipId: string) => {
    if (confirm("Delete this service ownership? This cannot be undone.")) {
      deleteOwnershipMutation.mutate(ownershipId);
    }
  };

  const handleDeleteTeam = (teamId: string) => {
    if (confirm("Delete this team? This cannot be undone.")) {
      deleteTeamMutation.mutate(teamId);
    }
  };

  const resetFilters = () => {
    setStatusFilter([]);
    setSearchQuery("");
  };

  // Service ownership table columns
  const serviceColumns = [
    {
      key: "service_name",
      header: "Service Name",
      sortable: true,
      render: (value: string, row: ServiceOwnership) => (
        <div className="flex items-center gap-2">
          <Building2 className="h-4 w-4 text-blue-600" />
          <span className="font-medium">{value}</span>
        </div>
      ),
    },
    {
      key: "team_name",
      header: "Team",
      sortable: true,
      render: (value: string) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-gray-500" />
          <span>{value}</span>
        </div>
      ),
    },
    {
      key: "team_slack_channel",
      header: "Slack",
      render: (value: string) =>
        value ? (
          <div className="flex items-center gap-1 text-sm text-gray-600">
            <MessageSquare className="h-3 w-3" />
            <span>{value}</span>
          </div>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (value: string) => (
        <StatusBadge status={value as any} size="sm">
          {value}
        </StatusBadge>
      ),
    },
  ];

  // Teams table columns
  const teamColumns = [
    {
      key: "name",
      header: "Team Name",
      sortable: true,
      render: (value: string, row: Team) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-purple-600" />
          <span className="font-medium">{row.display_name || value}</span>
        </div>
      ),
    },
    {
      key: "email",
      header: "Email",
      render: (value: string) =>
        value ? (
          <div className="flex items-center gap-1 text-sm text-gray-600">
            <Mail className="h-3 w-3" />
            <span>{value}</span>
          </div>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "slack_channel",
      header: "Slack",
      render: (value: string) =>
        value ? (
          <div className="flex items-center gap-1 text-sm text-gray-600">
            <MessageSquare className="h-3 w-3" />
            <span>{value}</span>
          </div>
        ) : (
          <span className="text-gray-400">-</span>
        ),
    },
    {
      key: "active",
      header: "Status",
      sortable: true,
      render: (value: boolean) => (
        <StatusBadge status={value ? "healthy" : "critical"} size="sm">
          {value ? "Active" : "Inactive"}
        </StatusBadge>
      ),
    },
  ];

  // Filter configuration
  const serviceFilters: FilterGroup[] = [
    {
      id: "search",
      label: "Search",
      type: "search",
      value: searchQuery,
      onChange: (value) => setSearchQuery(value as string),
    },
    {
      id: "status",
      label: "Status",
      type: "checkbox",
      options: [
        { label: "Active", value: "active", count: servicesMetrics.active },
        { label: "Inactive", value: "inactive", count: servicesMetrics.total - servicesMetrics.active },
      ],
      value: statusFilter,
      onChange: (value) => setStatusFilter(value as string[]),
    },
  ];

  const teamFilters: FilterGroup[] = [
    {
      id: "search",
      label: "Search",
      type: "search",
      value: searchQuery,
      onChange: (value) => setSearchQuery(value as string),
    },
    {
      id: "status",
      label: "Status",
      type: "checkbox",
      options: [
        { label: "Active", value: "active", count: teamsMetrics.active },
        { label: "Inactive", value: "inactive", count: teamsMetrics.total - teamsMetrics.active },
      ],
      value: statusFilter,
      onChange: (value) => setStatusFilter(value as string[]),
    },
  ];

  return (
    <div className="h-full flex flex-col">
      {/* Section 1: Header with Breadcrumb */}
      <PageHeader
        title="Teams & Ownership"
        description="Manage service ownership and team accountability"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Govern", href: "/govern" },
              { label: "Teams & Ownership", current: true },
            ]}
          />
        }
        action={
          <div className="flex gap-2">
            <Button
              variant="secondary"
              onClick={() => setPageTab(pageTab === "services" ? "teams" : "services")}
            >
              <Shield className="h-4 w-4" />
              View {pageTab === "services" ? "Teams" : "Services"}
            </Button>
            <Button
              variant="primary"
              onClick={() =>
                pageTab === "services" ? setShowCreateServiceModal(true) : setShowCreateTeamModal(true)
              }
            >
              <Plus className="h-4 w-4" />
              {pageTab === "services" ? "Assign Service" : "Create Team"}
            </Button>
          </div>
        }
      />

      {/* Section 2: Metrics */}
      <div className="px-6 pb-6">
        {pageTab === "services" ? (
          <MetricsGrid columns={4}>
            <StatCard
              label="Total Services"
              value={servicesMetrics.total}
              icon={Building2}
              iconColor="text-blue-600"
            />
            <StatCard
              label="Active Services"
              value={servicesMetrics.active}
              icon={Shield}
              iconColor="text-green-600"
            />
            <StatCard
              label="Unique Teams"
              value={servicesMetrics.teams}
              icon={Users}
              iconColor="text-purple-600"
            />
            <StatCard
              label="Pending Assignments"
              value={servicesMetrics.total - servicesMetrics.active}
              icon={UserPlus}
              iconColor="text-orange-600"
            />
          </MetricsGrid>
        ) : (
          <MetricsGrid columns={4}>
            <StatCard
              label="Total Teams"
              value={teamsMetrics.total}
              icon={Users}
              iconColor="text-purple-600"
            />
            <StatCard
              label="Active Teams"
              value={teamsMetrics.active}
              icon={Shield}
              iconColor="text-green-600"
            />
            <StatCard
              label="With Email"
              value={teamsMetrics.withEmail}
              icon={Mail}
              iconColor="text-blue-600"
            />
            <StatCard
              label="With Slack"
              value={teamsMetrics.withSlack}
              icon={MessageSquare}
              iconColor="text-indigo-600"
            />
          </MetricsGrid>
        )}
      </div>

      {/* Section 3: Filters & Content */}
      <div className="flex-1 flex gap-6 px-6 pb-6 overflow-hidden">
        {/* Filters */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={pageTab === "services" ? serviceFilters : teamFilters}
            onReset={resetFilters}
          />
        </div>

        {/* Section 4: Data Table */}
        <div className="flex-1 overflow-hidden">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg h-full flex flex-col">
            {pageTab === "services" ? (
              loadingOwnerships ? (
                <div className="flex items-center justify-center h-full">
                  <Spinner size="lg" label="Loading services..." />
                </div>
              ) : filteredOwnerships.length === 0 ? (
                <EmptyState
                  icon={Building2}
                  title={searchQuery || statusFilter.length > 0 ? "No services found" : "No service ownership assigned"}
                  description={
                    searchQuery || statusFilter.length > 0
                      ? "Try adjusting your filters"
                      : "Assign services to teams to enable accountability and routing"
                  }
                  action={
                    searchQuery || statusFilter.length > 0 ? (
                      <Button variant="secondary" onClick={resetFilters}>
                        Clear Filters
                      </Button>
                    ) : (
                      <Button variant="primary" onClick={() => setShowCreateServiceModal(true)}>
                        <Plus className="h-4 w-4" />
                        Assign Service
                      </Button>
                    )
                  }
                />
              ) : (
                <div className="overflow-auto">
                  <Table
                    columns={serviceColumns}
                    data={filteredOwnerships}
                    keyExtractor={(row) => row.id}
                    onRowClick={(row) => setSelectedOwnership(row)}
                    stickyHeader
                    hoverable
                  />
                </div>
              )
            ) : loadingTeams ? (
              <div className="flex items-center justify-center h-full">
                <Spinner size="lg" label="Loading teams..." />
              </div>
            ) : filteredTeams.length === 0 ? (
              <EmptyState
                icon={Users}
                title={searchQuery || statusFilter.length > 0 ? "No teams found" : "No teams created"}
                description={
                  searchQuery || statusFilter.length > 0
                    ? "Try adjusting your filters"
                    : "Create teams to organize service ownership"
                }
                action={
                  searchQuery || statusFilter.length > 0 ? (
                    <Button variant="secondary" onClick={resetFilters}>
                      Clear Filters
                    </Button>
                  ) : (
                    <Button variant="primary" onClick={() => setShowCreateTeamModal(true)}>
                      <Plus className="h-4 w-4" />
                      Create Team
                    </Button>
                  )
                }
              />
            ) : (
              <div className="overflow-auto">
                <Table
                  columns={teamColumns}
                  data={filteredTeams}
                  keyExtractor={(row) => row.id}
                  onRowClick={(row) => setSelectedTeam(row)}
                  stickyHeader
                  hoverable
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Service Ownership Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedOwnership}
        onClose={() => setSelectedOwnership(null)}
        size="lg"
      >
        {selectedOwnership && (
          <>
            <SlideOver.Header onClose={() => setSelectedOwnership(null)}>
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  {selectedOwnership.service_name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Service Ownership Details
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Team Information */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                    Team Information
                  </h3>
                  <div className="space-y-3">
                    <div>
                      <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                        Team Name
                      </label>
                      <div className="flex items-center gap-2 mt-1">
                        <Users className="h-4 w-4 text-gray-400" />
                        <span className="text-sm text-gray-900 dark:text-white">
                          {selectedOwnership.team_name}
                        </span>
                      </div>
                    </div>
                    {selectedOwnership.team_email && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          Team Email
                        </label>
                        <a
                          href={`mailto:${selectedOwnership.team_email}`}
                          className="flex items-center gap-2 mt-1 text-blue-600 hover:underline"
                        >
                          <Mail className="h-4 w-4" />
                          <span className="text-sm">{selectedOwnership.team_email}</span>
                        </a>
                      </div>
                    )}
                    {selectedOwnership.team_slack_channel && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          Slack Channel
                        </label>
                        <div className="flex items-center gap-2 mt-1">
                          <MessageSquare className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-900 dark:text-white">
                            {selectedOwnership.team_slack_channel}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Contacts */}
                {(selectedOwnership.primary_contact_email || selectedOwnership.secondary_contact_email) && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Contacts
                    </h3>
                    <div className="space-y-3">
                      {selectedOwnership.primary_contact_email && (
                        <div>
                          <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                            Primary Contact
                          </label>
                          <a
                            href={`mailto:${selectedOwnership.primary_contact_email}`}
                            className="block mt-1 text-sm text-blue-600 hover:underline"
                          >
                            {selectedOwnership.primary_contact_email}
                          </a>
                        </div>
                      )}
                      {selectedOwnership.secondary_contact_email && (
                        <div>
                          <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                            Secondary Contact
                          </label>
                          <a
                            href={`mailto:${selectedOwnership.secondary_contact_email}`}
                            className="block mt-1 text-sm text-blue-600 hover:underline"
                          >
                            {selectedOwnership.secondary_contact_email}
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Links */}
                {(selectedOwnership.repository_url ||
                  selectedOwnership.documentation_url ||
                  selectedOwnership.oncall_url) && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Links
                    </h3>
                    <div className="space-y-3">
                      {selectedOwnership.repository_url && (
                        <div>
                          <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                            Repository
                          </label>
                          <a
                            href={selectedOwnership.repository_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 mt-1 text-sm text-blue-600 hover:underline"
                          >
                            <LinkIcon className="h-3 w-3" />
                            {selectedOwnership.repository_url}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      )}
                      {selectedOwnership.documentation_url && (
                        <div>
                          <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                            Documentation
                          </label>
                          <a
                            href={selectedOwnership.documentation_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 mt-1 text-sm text-blue-600 hover:underline"
                          >
                            <FileText className="h-3 w-3" />
                            {selectedOwnership.documentation_url}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      )}
                      {selectedOwnership.oncall_url && (
                        <div>
                          <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                            On-Call
                          </label>
                          <a
                            href={selectedOwnership.oncall_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 mt-1 text-sm text-blue-600 hover:underline"
                          >
                            {selectedOwnership.oncall_url}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Description */}
                {selectedOwnership.description && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Description
                    </h3>
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {selectedOwnership.description}
                    </p>
                  </div>
                )}

                {/* Tags */}
                {selectedOwnership.tags && selectedOwnership.tags.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Tags
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedOwnership.tags.map((tag, idx) => (
                        <Badge key={idx}>{tag}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </SlideOver.Body>

            <SlideOver.Footer align="between">
              <Button variant="secondary" onClick={() => setSelectedOwnership(null)}>
                Close
              </Button>
              <Button
                variant="danger"
                onClick={() => handleDeleteOwnership(selectedOwnership.id)}
                disabled={deleteOwnershipMutation.isPending}
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </Button>
            </SlideOver.Footer>
          </>
        )}
      </SlideOver>

      {/* Team Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedTeam}
        onClose={() => setSelectedTeam(null)}
        size="lg"
      >
        {selectedTeam && (
          <>
            <SlideOver.Header onClose={() => setSelectedTeam(null)}>
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  {selectedTeam.display_name || selectedTeam.name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Team Details</p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Team Information */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                    Team Information
                  </h3>
                  <div className="space-y-3">
                    <div>
                      <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                        Name
                      </label>
                      <p className="text-sm text-gray-900 dark:text-white mt-1">
                        {selectedTeam.name}
                      </p>
                    </div>
                    {selectedTeam.display_name && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          Display Name
                        </label>
                        <p className="text-sm text-gray-900 dark:text-white mt-1">
                          {selectedTeam.display_name}
                        </p>
                      </div>
                    )}
                    {selectedTeam.email && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          Email
                        </label>
                        <a
                          href={`mailto:${selectedTeam.email}`}
                          className="block mt-1 text-sm text-blue-600 hover:underline"
                        >
                          {selectedTeam.email}
                        </a>
                      </div>
                    )}
                    {selectedTeam.slack_channel && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          Slack Channel
                        </label>
                        <p className="text-sm text-gray-900 dark:text-white mt-1">
                          {selectedTeam.slack_channel}
                        </p>
                      </div>
                    )}
                    {selectedTeam.pagerduty_integration_key && (
                      <div>
                        <label className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                          PagerDuty
                        </label>
                        <Badge className="mt-1">Configured</Badge>
                      </div>
                    )}
                  </div>
                </div>

                {/* Description */}
                {selectedTeam.description && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Description
                    </h3>
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {selectedTeam.description}
                    </p>
                  </div>
                )}

                {/* Tags */}
                {selectedTeam.tags && selectedTeam.tags.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                      Tags
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedTeam.tags.map((tag, idx) => (
                        <Badge key={idx}>{tag}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </SlideOver.Body>

            <SlideOver.Footer align="between">
              <Button variant="secondary" onClick={() => setSelectedTeam(null)}>
                Close
              </Button>
              <Button
                variant="danger"
                onClick={() => handleDeleteTeam(selectedTeam.id)}
                disabled={deleteTeamMutation.isPending}
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </Button>
            </SlideOver.Footer>
          </>
        )}
      </SlideOver>

      {/* Create Service Ownership Modal */}
      {showCreateServiceModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
            <h2 className="text-2xl font-bold mb-6">Assign Service Ownership</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Service Name *</label>
                <input
                  type="text"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  placeholder="e.g., payments-api"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Team Name *</label>
                <input
                  type="text"
                  value={teamName}
                  onChange={(e) => setTeamName(e.target.value)}
                  placeholder="e.g., Platform Team"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Team Email</label>
                <input
                  type="email"
                  value={teamEmail}
                  onChange={(e) => setTeamEmail(e.target.value)}
                  placeholder="platform-team@company.com"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Slack Channel</label>
                <input
                  type="text"
                  value={teamSlackChannel}
                  onChange={(e) => setTeamSlackChannel(e.target.value)}
                  placeholder="#platform-team"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Primary Contact Email</label>
                <input
                  type="email"
                  value={primaryContactEmail}
                  onChange={(e) => setPrimaryContactEmail(e.target.value)}
                  placeholder="alice@company.com"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Repository URL</label>
                <input
                  type="url"
                  value={repositoryURL}
                  onChange={(e) => setRepositoryURL(e.target.value)}
                  placeholder="https://github.com/org/repo"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Documentation URL</label>
                <input
                  type="url"
                  value={documentationURL}
                  onChange={(e) => setDocumentationURL(e.target.value)}
                  placeholder="https://docs.company.com/payments-api"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of the service and team responsibilities"
                  rows={3}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <Button
                onClick={handleCreateOwnership}
                disabled={createOwnershipMutation.isPending || !serviceName || !teamName}
                className="flex-1"
              >
                {createOwnershipMutation.isPending ? "Creating..." : "Create Ownership"}
              </Button>
              <Button
                onClick={() => {
                  setShowCreateServiceModal(false);
                  resetServiceForm();
                }}
                variant="secondary"
                className="flex-1"
              >
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Create Team Modal */}
      {showCreateTeamModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
            <h2 className="text-2xl font-bold mb-6">Create Team</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Team Name *</label>
                <input
                  type="text"
                  value={newTeamName}
                  onChange={(e) => setNewTeamName(e.target.value)}
                  placeholder="e.g., platform"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                  required
                />
                <p className="mt-1 text-xs text-gray-600">
                  Lowercase, no spaces (used as identifier)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Display Name</label>
                <input
                  type="text"
                  value={newTeamDisplayName}
                  onChange={(e) => setNewTeamDisplayName(e.target.value)}
                  placeholder="Platform Team"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Team Email</label>
                <input
                  type="email"
                  value={newTeamEmail}
                  onChange={(e) => setNewTeamEmail(e.target.value)}
                  placeholder="platform-team@company.com"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Slack Channel</label>
                <input
                  type="text"
                  value={newTeamSlackChannel}
                  onChange={(e) => setNewTeamSlackChannel(e.target.value)}
                  placeholder="#platform-team"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <textarea
                  value={newTeamDescription}
                  onChange={(e) => setNewTeamDescription(e.target.value)}
                  placeholder="Brief description of the team"
                  rows={3}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <Button
                onClick={handleCreateTeam}
                disabled={createTeamMutation.isPending || !newTeamName}
                className="flex-1"
              >
                {createTeamMutation.isPending ? "Creating..." : "Create Team"}
              </Button>
              <Button
                onClick={() => {
                  setShowCreateTeamModal(false);
                  resetTeamForm();
                }}
                variant="secondary"
                className="flex-1"
              >
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
