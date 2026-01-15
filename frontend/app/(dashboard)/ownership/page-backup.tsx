"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Users,
  Building2,
  Mail,
  MessageSquare,
  Plus,
  Edit2,
  Trash2,
  ExternalLink,
  FileText,
  Link as LinkIcon,
} from "lucide-react";
import {
  api,
  ServiceOwnership,
  Team,
  CreateServiceOwnershipRequest,
  CreateTeamRequest,
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

type PageTab = "services" | "teams";

export default function OwnershipPage() {
  const queryClient = useQueryClient();
  const [pageTab, setPageTab] = useState<PageTab>("services");
  const [selectedOwnership, setSelectedOwnership] = useState<ServiceOwnership | null>(null);
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null);
  const [showCreateServiceModal, setShowCreateServiceModal] = useState(false);
  const [showCreateTeamModal, setShowCreateTeamModal] = useState(false);

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

  return (
    <PageLayout
      title="Ownership & Teams"
      subtitle="Manage service ownership and team accountability"
      icon={<Users className="h-8 w-8" />}
      action={
        <Button
          onClick={() =>
            pageTab === "services" ? setShowCreateServiceModal(true) : setShowCreateTeamModal(true)
          }
        >
          <Plus className="h-4 w-4 mr-2" />
          {pageTab === "services" ? "Assign Service" : "Create Team"}
        </Button>
      }
    >
      <Tabs
        tabs={[
          { id: "services", label: "Service Ownership", icon: Building2 },
          { id: "teams", label: "Teams", icon: Users },
        ]}
        activeTab={pageTab}
        onChange={(tab) => setPageTab(tab as PageTab)}
      />

      {pageTab === "services" && (
        <div className="flex flex-col lg:flex-row gap-6 h-full">
          {/* Service Ownership List */}
          <div className="lg:w-1/2">
            {loadingOwnerships ? (
              <div className="flex items-center justify-center h-64">
                <Users className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : ownerships.length === 0 ? (
              <EmptyState
                icon={Building2}
                title="No service ownership assigned"
                description="Assign services to teams to enable accountability and routing"
              />
            ) : (
              <div className="space-y-2">
                {ownerships.map((ownership) => (
                  <ListCard
                    key={ownership.id}
                    selected={selectedOwnership?.id === ownership.id}
                    onClick={() => setSelectedOwnership(ownership)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Building2 className="h-4 w-4 text-blue-600" />
                          <span className="font-medium text-sm">
                            {ownership.service_name}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400">
                          <Users className="h-3 w-3" />
                          <span>{ownership.team_name}</span>
                        </div>
                        {ownership.team_slack_channel && (
                          <div className="flex items-center gap-1 mt-1 text-xs text-gray-500">
                            <MessageSquare className="h-3 w-3" />
                            <span>{ownership.team_slack_channel}</span>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs font-medium rounded-full",
                            ownership.status === "active"
                              ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                              : "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400"
                          )}
                        >
                          {ownership.status}
                        </span>
                      </div>
                    </div>
                  </ListCard>
                ))}
              </div>
            )}
          </div>

          {/* Service Ownership Detail */}
          <div className="lg:w-1/2">
            {selectedOwnership ? (
              <DetailPanel
                title={selectedOwnership.service_name}
                onClose={() => setSelectedOwnership(null)}
              >
                <DetailSection title="Team Information">
                  <DetailRow label="Team Name">
                    <div className="flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      <span>{selectedOwnership.team_name}</span>
                    </div>
                  </DetailRow>
                  {selectedOwnership.team_email && (
                    <DetailRow label="Team Email">
                      <a
                        href={`mailto:${selectedOwnership.team_email}`}
                        className="flex items-center gap-1 text-blue-600 hover:underline"
                      >
                        <Mail className="h-4 w-4" />
                        {selectedOwnership.team_email}
                      </a>
                    </DetailRow>
                  )}
                  {selectedOwnership.team_slack_channel && (
                    <DetailRow label="Slack Channel">
                      <div className="flex items-center gap-1">
                        <MessageSquare className="h-4 w-4" />
                        <span>{selectedOwnership.team_slack_channel}</span>
                      </div>
                    </DetailRow>
                  )}
                </DetailSection>

                <DetailSection title="Contacts">
                  {selectedOwnership.primary_contact_email && (
                    <DetailRow label="Primary Contact">
                      <a
                        href={`mailto:${selectedOwnership.primary_contact_email}`}
                        className="text-blue-600 hover:underline"
                      >
                        {selectedOwnership.primary_contact_email}
                      </a>
                    </DetailRow>
                  )}
                  {selectedOwnership.secondary_contact_email && (
                    <DetailRow label="Secondary Contact">
                      <a
                        href={`mailto:${selectedOwnership.secondary_contact_email}`}
                        className="text-blue-600 hover:underline"
                      >
                        {selectedOwnership.secondary_contact_email}
                      </a>
                    </DetailRow>
                  )}
                </DetailSection>

                <DetailSection title="Links">
                  {selectedOwnership.repository_url && (
                    <DetailRow label="Repository">
                      <a
                        href={selectedOwnership.repository_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-blue-600 hover:underline"
                      >
                        <LinkIcon className="h-3 w-3" />
                        {selectedOwnership.repository_url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </DetailRow>
                  )}
                  {selectedOwnership.documentation_url && (
                    <DetailRow label="Documentation">
                      <a
                        href={selectedOwnership.documentation_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-blue-600 hover:underline"
                      >
                        <FileText className="h-3 w-3" />
                        {selectedOwnership.documentation_url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </DetailRow>
                  )}
                  {selectedOwnership.oncall_url && (
                    <DetailRow label="On-Call">
                      <a
                        href={selectedOwnership.oncall_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-blue-600 hover:underline"
                      >
                        {selectedOwnership.oncall_url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </DetailRow>
                  )}
                </DetailSection>

                {selectedOwnership.description && (
                  <DetailSection title="Description">
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {selectedOwnership.description}
                    </p>
                  </DetailSection>
                )}

                {selectedOwnership.tags && selectedOwnership.tags.length > 0 && (
                  <DetailSection title="Tags">
                    <div className="flex flex-wrap gap-2">
                      {selectedOwnership.tags.map((tag, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </DetailSection>
                )}

                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <Button
                    onClick={() => handleDeleteOwnership(selectedOwnership.id)}
                    disabled={deleteOwnershipMutation.isPending}
                    className="w-full bg-red-600 hover:bg-red-700"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete Ownership
                  </Button>
                </div>
              </DetailPanel>
            ) : (
              <EmptyState
                icon={Building2}
                title="Select a service"
                description="Click on a service to view ownership details"
              />
            )}
          </div>
        </div>
      )}

      {pageTab === "teams" && (
        <div className="flex flex-col lg:flex-row gap-6 h-full">
          {/* Teams List */}
          <div className="lg:w-1/2">
            {loadingTeams ? (
              <div className="flex items-center justify-center h-64">
                <Users className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : teams.length === 0 ? (
              <EmptyState
                icon={Users}
                title="No teams created"
                description="Create teams to organize service ownership"
              />
            ) : (
              <div className="space-y-2">
                {teams.map((team) => (
                  <ListCard
                    key={team.id}
                    selected={selectedTeam?.id === team.id}
                    onClick={() => setSelectedTeam(team)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Users className="h-4 w-4 text-purple-600" />
                          <span className="font-medium text-sm">
                            {team.display_name || team.name}
                          </span>
                        </div>
                        {team.email && (
                          <div className="flex items-center gap-1 text-xs text-gray-600 dark:text-gray-400">
                            <Mail className="h-3 w-3" />
                            <span>{team.email}</span>
                          </div>
                        )}
                        {team.slack_channel && (
                          <div className="flex items-center gap-1 mt-1 text-xs text-gray-500">
                            <MessageSquare className="h-3 w-3" />
                            <span>{team.slack_channel}</span>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs font-medium rounded-full",
                            team.active
                              ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                              : "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400"
                          )}
                        >
                          {team.active ? "active" : "inactive"}
                        </span>
                      </div>
                    </div>
                  </ListCard>
                ))}
              </div>
            )}
          </div>

          {/* Team Detail */}
          <div className="lg:w-1/2">
            {selectedTeam ? (
              <DetailPanel
                title={selectedTeam.display_name || selectedTeam.name}
                onClose={() => setSelectedTeam(null)}
              >
                <DetailSection title="Team Information">
                  <DetailRow label="Name">{selectedTeam.name}</DetailRow>
                  {selectedTeam.display_name && (
                    <DetailRow label="Display Name">{selectedTeam.display_name}</DetailRow>
                  )}
                  {selectedTeam.email && (
                    <DetailRow label="Email">
                      <a
                        href={`mailto:${selectedTeam.email}`}
                        className="text-blue-600 hover:underline"
                      >
                        {selectedTeam.email}
                      </a>
                    </DetailRow>
                  )}
                  {selectedTeam.slack_channel && (
                    <DetailRow label="Slack Channel">{selectedTeam.slack_channel}</DetailRow>
                  )}
                  {selectedTeam.pagerduty_integration_key && (
                    <DetailRow label="PagerDuty">
                      <span className="text-xs font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                        Configured
                      </span>
                    </DetailRow>
                  )}
                </DetailSection>

                {selectedTeam.description && (
                  <DetailSection title="Description">
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {selectedTeam.description}
                    </p>
                  </DetailSection>
                )}

                {selectedTeam.tags && selectedTeam.tags.length > 0 && (
                  <DetailSection title="Tags">
                    <div className="flex flex-wrap gap-2">
                      {selectedTeam.tags.map((tag, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </DetailSection>
                )}

                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <Button
                    onClick={() => handleDeleteTeam(selectedTeam.id)}
                    disabled={deleteTeamMutation.isPending}
                    className="w-full bg-red-600 hover:bg-red-700"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete Team
                  </Button>
                </div>
              </DetailPanel>
            ) : (
              <EmptyState
                icon={Users}
                title="Select a team"
                description="Click on a team to view details"
              />
            )}
          </div>
        </div>
      )}

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
                className="flex-1 bg-gray-600 hover:bg-gray-700"
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
