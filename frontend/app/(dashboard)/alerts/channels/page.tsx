"use client";

import { useState, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings,
  Mail,
  MessageSquare,
  Webhook,
  Trash2,
  Pencil,
  Send,
  Bell,
  X,
} from "lucide-react";
import { api, AlertChannel } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";

export default function AlertChannelsPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [editingChannel, setEditingChannel] = useState<AlertChannel | null>(null);

  const [form, setForm] = useState({
    name: "",
    channel_type: "slack" as "smtp" | "slack" | "webhook",
    enabled: true,
    webhook_url: "",
    slack_channel: "",
    smtp_host: "",
    smtp_port: 587,
    smtp_from: "",
    smtp_to: "",
    webhook_method: "POST",
    webhook_headers: "",
  });

  useEffect(() => {
    if (searchParams.get("action") === "add") {
      resetForm();
      setEditingChannel(null);
      setShowModal(true);
      router.replace("/alerts/channels");
    }
  }, [searchParams, router]);

  const { data: channels, isLoading } = useQuery({
    queryKey: ["alertChannels"],
    queryFn: () => api.getAlertChannels(),
  });

  const createMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.createAlertChannel>[0]) =>
      api.createAlertChannel(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alertChannels"] });
      setShowModal(false);
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof api.updateAlertChannel>[1] }) =>
      api.updateAlertChannel(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alertChannels"] });
      setShowModal(false);
      setEditingChannel(null);
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteAlertChannel(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alertChannels"] }),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => api.testAlertChannel(id),
  });

  const resetForm = () => {
    setForm({
      name: "",
      channel_type: "slack",
      enabled: true,
      webhook_url: "",
      slack_channel: "",
      smtp_host: "",
      smtp_port: 587,
      smtp_from: "",
      smtp_to: "",
      webhook_method: "POST",
      webhook_headers: "",
    });
  };

  const openEdit = (channel: AlertChannel) => {
    setEditingChannel(channel);
    const config = channel.config as Record<string, unknown>;
    setForm({
      name: channel.name,
      channel_type: channel.channel_type,
      enabled: channel.enabled,
      webhook_url: (config.webhook_url as string) || "",
      slack_channel: (config.channel as string) || "",
      smtp_host: (config.host as string) || "",
      smtp_port: (config.port as number) || 587,
      smtp_from: (config.from as string) || "",
      smtp_to: ((config.to as string[]) || []).join(", "),
      webhook_method: (config.method as string) || "POST",
      webhook_headers: JSON.stringify(config.headers || {}, null, 2),
    });
    setShowModal(true);
  };

  const buildConfig = () => {
    switch (form.channel_type) {
      case "slack":
        return { webhook_url: form.webhook_url, channel: form.slack_channel || undefined };
      case "smtp":
        return {
          host: form.smtp_host,
          port: form.smtp_port,
          from: form.smtp_from,
          to: form.smtp_to.split(",").map((e) => e.trim()),
          use_tls: true,
        };
      case "webhook":
        return {
          url: form.webhook_url,
          method: form.webhook_method,
          headers: form.webhook_headers ? JSON.parse(form.webhook_headers) : {},
        };
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data = {
      name: form.name,
      channel_type: form.channel_type,
      config: buildConfig(),
      enabled: form.enabled,
    };
    if (editingChannel) {
      updateMutation.mutate({ id: editingChannel.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  const getChannelIcon = (type: string) => {
    switch (type) {
      case "smtp":    return <Mail className="h-4 w-4" />;
      case "slack":   return <MessageSquare className="h-4 w-4" />;
      case "webhook": return <Webhook className="h-4 w-4" />;
      default:        return <Bell className="h-4 w-4" />;
    }
  };

  return (
    <>
      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Spinner size="lg" />
          </div>
        ) : channels && channels.length > 0 ? (
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {channels.map((channel) => (
              <div
                key={channel.id}
                className="flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={cn(
                      "p-2 rounded-lg",
                      channel.enabled
                        ? "bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400"
                        : "bg-gray-100 dark:bg-gray-800 text-gray-500"
                    )}
                  >
                    {getChannelIcon(channel.channel_type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-900 dark:text-white font-medium">{channel.name}</span>
                      <Badge size="sm">{channel.channel_type}</Badge>
                      {!channel.enabled && (
                        <Badge
                          size="sm"
                          className="bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400"
                        >
                          Disabled
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-gray-500 mt-0.5">
                      Created {formatRelativeTime(channel.created_at)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => testMutation.mutate(channel.id)}
                    disabled={testMutation.isPending}
                    className="p-2 text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                    title="Send test"
                  >
                    <Send className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => openEdit(channel)}
                    className="p-2 text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                    title="Edit"
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(channel.id)}
                    className="p-2 text-gray-400 hover:text-red-500 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                    title="Delete"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12">
            <EmptyState
              icon={Settings}
              title="No notification channels configured"
              description="Add a channel to receive alerts"
            />
          </div>
        )}
      </Card>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-md border border-gray-200 dark:border-gray-800 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                {editingChannel ? "Edit Channel" : "Add Channel"}
              </h2>
              <button
                onClick={() => { setShowModal(false); setEditingChannel(null); }}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="space-y-4">
              <Input
                label="Name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
                placeholder="My Slack Channel"
              />
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">Type</label>
                <select
                  value={form.channel_type}
                  onChange={(e) => setForm({ ...form, channel_type: e.target.value as "smtp" | "slack" | "webhook" })}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="slack">Slack</option>
                  <option value="smtp">Email (SMTP)</option>
                  <option value="webhook">Webhook</option>
                </select>
              </div>

              {form.channel_type === "slack" && (
                <Input
                  label="Webhook URL"
                  type="url"
                  value={form.webhook_url}
                  onChange={(e) => setForm({ ...form, webhook_url: e.target.value })}
                  required
                  placeholder="https://hooks.slack.com/services/..."
                />
              )}

              {form.channel_type === "smtp" && (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <Input
                      label="SMTP Host"
                      value={form.smtp_host}
                      onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
                      required
                      placeholder="smtp.example.com"
                    />
                    <Input
                      label="Port"
                      type="number"
                      value={form.smtp_port}
                      onChange={(e) => setForm({ ...form, smtp_port: parseInt(e.target.value) })}
                      required
                    />
                  </div>
                  <Input
                    label="From Email"
                    type="email"
                    value={form.smtp_from}
                    onChange={(e) => setForm({ ...form, smtp_from: e.target.value })}
                    required
                    placeholder="alerts@example.com"
                  />
                  <Input
                    label="To Emails (comma-separated)"
                    value={form.smtp_to}
                    onChange={(e) => setForm({ ...form, smtp_to: e.target.value })}
                    required
                    placeholder="admin@example.com, ops@example.com"
                  />
                </>
              )}

              {form.channel_type === "webhook" && (
                <>
                  <Input
                    label="Webhook URL"
                    type="url"
                    value={form.webhook_url}
                    onChange={(e) => setForm({ ...form, webhook_url: e.target.value })}
                    required
                    placeholder="https://api.example.com/webhook"
                  />
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">Method</label>
                    <select
                      value={form.webhook_method}
                      onChange={(e) => setForm({ ...form, webhook_method: e.target.value })}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                    >
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                    </select>
                  </div>
                </>
              )}

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="channel-enabled"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                />
                <label htmlFor="channel-enabled" className="text-sm text-gray-700 dark:text-gray-300">
                  Enabled
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => { setShowModal(false); setEditingChannel(null); }}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={createMutation.isPending || updateMutation.isPending}
                >
                  {editingChannel ? "Save" : "Create"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
