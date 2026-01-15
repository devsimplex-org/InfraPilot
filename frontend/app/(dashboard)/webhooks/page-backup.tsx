"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Webhook,
  GitBranch,
  Clock,
  Plus,
  Eye,
  Copy,
  CheckCircle,
  XCircle,
  Trash2,
  Settings,
} from "lucide-react";
import { api } from "@/lib/api";
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

type WebhookTab = "all" | "events";

interface WebhookConfig {
  id: string;
  name: string;
  provider: "github" | "gitlab" | "jenkins" | "generic";
  service_name: string;
  environment: "dev" | "staging" | "prod";
  enabled: boolean;
  webhook_url: string;
  created_at: string;
  last_used_at?: string;
}

interface WebhookEvent {
  id: string;
  webhook_id: string;
  provider: string;
  event_type: string;
  verified: boolean;
  processed: boolean;
  deployment_id?: string;
  error?: string;
  created_at: string;
  processed_at?: string;
}

interface CreateWebhookData {
  name: string;
  provider: "github" | "gitlab" | "jenkins" | "generic";
  service_name: string;
  environment: "dev" | "staging" | "prod";
}

const providerIcons: Record<string, string> = {
  github: "🐙",
  gitlab: "🦊",
  jenkins: "🤖",
  generic: "⚡",
};

const providerColors: Record<string, string> = {
  github: "text-gray-900 dark:text-gray-100",
  gitlab: "text-orange-600 dark:text-orange-400",
  jenkins: "text-red-600 dark:text-red-400",
  generic: "text-blue-600 dark:text-blue-400",
};

export default function WebhooksPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<WebhookTab>("all");
  const [selectedWebhook, setSelectedWebhook] = useState<WebhookConfig | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedURL, setCopiedURL] = useState(false);

  // Fetch default agent
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.fetchAPI<any[]>("/agents"),
  });

  const defaultAgent = agents?.[0];

  // Fetch webhooks
  const { data: webhooks, isLoading } = useQuery({
    queryKey: ["webhooks", defaultAgent?.id],
    queryFn: () =>
      api.fetchAPI<WebhookConfig[]>(`/agents/${defaultAgent?.id}/webhooks`),
    enabled: !!defaultAgent?.id,
  });

  // Fetch webhook events
  const { data: webhookEvents } = useQuery({
    queryKey: ["webhook-events", selectedWebhook?.id],
    queryFn: () =>
      api.fetchAPI<WebhookEvent[]>(
        `/agents/${defaultAgent?.id}/webhooks/${selectedWebhook?.id}/events`
      ),
    enabled: !!defaultAgent?.id && !!selectedWebhook?.id,
  });

  // Calculate statistics
  const stats = webhooks
    ? {
        total: webhooks.length,
        enabled: webhooks.filter((w) => w.enabled).length,
        github: webhooks.filter((w) => w.provider === "github").length,
        gitlab: webhooks.filter((w) => w.provider === "gitlab").length,
      }
    : { total: 0, enabled: 0, github: 0, gitlab: 0 };

  const copyToClipboard = (text: string, type: "secret" | "url") => {
    navigator.clipboard.writeText(text);
    if (type === "secret") {
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    } else {
      setCopiedURL(true);
      setTimeout(() => setCopiedURL(false), 2000);
    }
  };

  return (
    <PageLayout
      title="CI/CD Webhooks"
      description="Manage webhook integrations for automated deployments"
      panel={
        selectedWebhook && (
          <DetailPanel
            open={!!selectedWebhook}
            onClose={() => setSelectedWebhook(null)}
            title={selectedWebhook.name}
            subtitle={`${providerIcons[selectedWebhook.provider]} ${selectedWebhook.provider}`}
          >
            <DetailSection title="Configuration">
              <DetailRow label="Service" value={selectedWebhook.service_name} />
              <DetailRow
                label="Environment"
                value={
                  <span
                    className={cn(
                      "px-2 py-1 text-xs font-medium rounded-full",
                      selectedWebhook.environment === "prod"
                        ? "bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400"
                        : selectedWebhook.environment === "staging"
                        ? "bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400"
                        : "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                    )}
                  >
                    {selectedWebhook.environment}
                  </span>
                }
              />
              <DetailRow
                label="Status"
                value={
                  <span
                    className={cn(
                      "px-2 py-1 text-xs font-medium rounded-full",
                      selectedWebhook.enabled
                        ? "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                        : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
                    )}
                  >
                    {selectedWebhook.enabled ? "Enabled" : "Disabled"}
                  </span>
                }
              />
              <DetailRow
                label="Created"
                value={new Date(selectedWebhook.created_at).toLocaleString()}
              />
              {selectedWebhook.last_used_at && (
                <DetailRow
                  label="Last Used"
                  value={new Date(selectedWebhook.last_used_at).toLocaleString()}
                />
              )}
            </DetailSection>

            <DetailSection title="Webhook URL">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={`${window.location.origin}${selectedWebhook.webhook_url}`}
                    className="flex-1 px-3 py-2 text-sm bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                  />
                  <button
                    onClick={() =>
                      copyToClipboard(
                        `${window.location.origin}${selectedWebhook.webhook_url}`,
                        "url"
                      )
                    }
                    className="p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
                  >
                    {copiedURL ? (
                      <CheckCircle className="w-4 h-4 text-green-600" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Configure this URL in your CI/CD provider to trigger deployments
                </p>
              </div>
            </DetailSection>

            {webhookEvents && webhookEvents.length > 0 && (
              <DetailSection title="Recent Events">
                <div className="space-y-2">
                  {webhookEvents.slice(0, 5).map((event) => (
                    <div
                      key={event.id}
                      className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {event.event_type || "Deployment"}
                        </span>
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs font-medium rounded-full",
                            event.processed
                              ? "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                              : event.error
                              ? "bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400"
                              : "bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400"
                          )}
                        >
                          {event.processed ? "Processed" : event.error ? "Failed" : "Pending"}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {new Date(event.created_at).toLocaleString()}
                      </p>
                      {event.error && (
                        <p className="mt-1 text-xs text-red-600 dark:text-red-400">
                          {event.error}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </DetailSection>
            )}

            <DetailSection title="Actions">
              <div className="space-y-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    /* TODO: Implement toggle */
                  }}
                  className="w-full"
                >
                  <Settings className="w-4 h-4 mr-2" />
                  {selectedWebhook.enabled ? "Disable Webhook" : "Enable Webhook"}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    /* TODO: Implement delete */
                  }}
                  className="w-full text-red-600 hover:text-red-700"
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete Webhook
                </Button>
              </div>
            </DetailSection>
          </DetailPanel>
        )
      }
      panelOpen={!!selectedWebhook}
    >
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Webhooks</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.total}
              </p>
            </div>
            <Webhook className="w-8 h-8 text-primary-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Enabled</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.enabled}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">GitHub Actions</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.github}
              </p>
            </div>
            <span className="text-4xl">{providerIcons.github}</span>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">GitLab CI</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {stats.gitlab}
              </p>
            </div>
            <span className="text-4xl">{providerIcons.gitlab}</span>
          </div>
        </div>
      </div>

      {/* Create Webhook Button */}
      <div className="mb-6">
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="w-4 h-4 mr-2" />
          Create Webhook
        </Button>
      </div>

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "all", label: "All Webhooks", count: stats.total },
          { id: "events", label: "Recent Events", count: webhookEvents?.length || 0 },
        ]}
        activeTab={activeTab}
        onChange={(id) => setActiveTab(id as WebhookTab)}
      />

      <div className="mt-6">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : webhooks && webhooks.length === 0 ? (
          <EmptyState
            icon={Webhook}
            title="No Webhooks Configured"
            description="Create a webhook to enable automated deployments from your CI/CD pipeline"
            action={
              <Button onClick={() => setShowCreateDialog(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create Your First Webhook
              </Button>
            }
          />
        ) : (
          <div className="space-y-4">
            {/* All Webhooks Tab */}
            {activeTab === "all" &&
              webhooks?.map((webhook) => (
                <ListCard
                  key={webhook.id}
                  selected={selectedWebhook?.id === webhook.id}
                  onClick={() => setSelectedWebhook(webhook)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <span className="text-2xl flex-shrink-0">
                        {providerIcons[webhook.provider]}
                      </span>
                      <div className="flex-1 min-w-0">
                        <h3 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {webhook.name}
                        </h3>
                        <div className="flex items-center gap-4 mt-1">
                          <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
                            <GitBranch className="w-3 h-3" />
                            {webhook.service_name}
                          </div>
                          <span
                            className={cn(
                              "px-2 py-0.5 text-xs font-medium rounded-full",
                              webhook.environment === "prod"
                                ? "bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400"
                                : webhook.environment === "staging"
                                ? "bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400"
                                : "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                            )}
                          >
                            {webhook.environment}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        {webhook.last_used_at ? (
                          <>
                            <p className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              Last used
                            </p>
                            <p className="text-xs text-gray-600 dark:text-gray-300">
                              {new Date(webhook.last_used_at).toLocaleDateString()}
                            </p>
                          </>
                        ) : (
                          <p className="text-xs text-gray-400 dark:text-gray-500">Never used</p>
                        )}
                      </div>
                      <div
                        className={cn(
                          "px-3 py-1 rounded-full text-xs font-medium",
                          webhook.enabled
                            ? "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                            : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
                        )}
                      >
                        {webhook.enabled ? "Enabled" : "Disabled"}
                      </div>
                      <Eye className="w-4 h-4 text-gray-400" />
                    </div>
                  </div>
                </ListCard>
              ))}

            {/* Events Tab */}
            {activeTab === "events" && webhookEvents && (
              <div className="space-y-4">
                {webhookEvents.map((event) => (
                  <div
                    key={event.id}
                    className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{providerIcons[event.provider]}</span>
                        <div>
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                            {event.event_type || "Deployment Event"}
                          </h3>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            {new Date(event.created_at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {event.verified && (
                          <CheckCircle className="w-4 h-4 text-green-600" />
                        )}
                        <span
                          className={cn(
                            "px-2 py-1 text-xs font-medium rounded-full",
                            event.processed
                              ? "bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                              : event.error
                              ? "bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400"
                              : "bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400"
                          )}
                        >
                          {event.processed ? "Processed" : event.error ? "Failed" : "Pending"}
                        </span>
                      </div>
                    </div>
                    {event.error && (
                      <div className="mt-2 p-2 bg-red-50 dark:bg-red-900/10 rounded text-xs text-red-600 dark:text-red-400">
                        {event.error}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
