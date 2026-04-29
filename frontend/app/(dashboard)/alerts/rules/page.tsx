"use client";

import { useState, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  Trash2,
  Pencil,
  ToggleLeft,
  ToggleRight,
  X,
} from "lucide-react";
import { api, AlertRule } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";

const ruleTypes = [
  { value: "container_crash",    label: "Container Crash" },
  { value: "high_restart_count", label: "High Restart Count" },
  { value: "container_stopped",  label: "Container Stopped" },
  { value: "high_cpu",           label: "High CPU Usage" },
  { value: "high_memory",        label: "High Memory Usage" },
  { value: "oom_kill",           label: "OOM Kill" },
  { value: "ssl_expiry",         label: "SSL Certificate Expiring" },
  { value: "high_error_rate",    label: "High Error Rate" },
  { value: "agent_offline",      label: "Agent Offline" },
];

export default function AlertRulesPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [editingRule, setEditingRule] = useState<AlertRule | null>(null);

  const [form, setForm] = useState({
    name: "",
    rule_type: "container_crash",
    enabled: true,
    cooldown_mins: 15,
    channels: [] as string[],
    threshold: 3,
    duration_mins: 5,
    warning_days: 14,
    critical_days: 7,
    window_mins: 5,
    container_pattern: "",
  });

  useEffect(() => {
    if (searchParams.get("action") === "add") {
      resetForm();
      setEditingRule(null);
      setShowModal(true);
      router.replace("/alerts/rules");
    }
  }, [searchParams, router]);

  const { data: rules, isLoading } = useQuery({
    queryKey: ["alertRules"],
    queryFn: () => api.getAlertRules(),
  });

  const { data: channels } = useQuery({
    queryKey: ["alertChannels"],
    queryFn: () => api.getAlertChannels(),
  });

  const createMutation = useMutation({
    mutationFn: (data: Parameters<typeof api.createAlertRule>[0]) => api.createAlertRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alertRules"] });
      setShowModal(false);
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof api.updateAlertRule>[1] }) =>
      api.updateAlertRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alertRules"] });
      setShowModal(false);
      setEditingRule(null);
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteAlertRule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alertRules"] }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.updateAlertRule(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alertRules"] }),
  });

  const resetForm = () => {
    setForm({
      name: "",
      rule_type: "container_crash",
      enabled: true,
      cooldown_mins: 15,
      channels: [],
      threshold: 3,
      duration_mins: 5,
      warning_days: 14,
      critical_days: 7,
      window_mins: 5,
      container_pattern: "",
    });
  };

  const openEdit = (rule: AlertRule) => {
    setEditingRule(rule);
    const conditions = rule.conditions as Record<string, unknown>;
    setForm({
      name: rule.name,
      rule_type: rule.rule_type,
      enabled: rule.enabled,
      cooldown_mins: rule.cooldown_mins,
      channels: rule.channels,
      threshold: (conditions.threshold as number) || (conditions.threshold_mins as number) || 3,
      duration_mins: (conditions.duration_mins as number) || 5,
      warning_days: (conditions.warning_days as number) || 14,
      critical_days: (conditions.critical_days as number) || 7,
      window_mins: (conditions.window_mins as number) || 5,
      container_pattern: (conditions.container_pattern as string) || "",
    });
    setShowModal(true);
  };

  const buildConditions = () => {
    switch (form.rule_type) {
      case "ssl_expiry":
        return { warning_days: form.warning_days, critical_days: form.critical_days };
      case "high_error_rate":
        return {
          threshold: form.threshold,
          window_mins: form.window_mins,
          container_pattern: form.container_pattern || undefined,
        };
      case "high_cpu":
      case "high_memory":
      case "high_restart_count":
        return { threshold: form.threshold };
      case "agent_offline":
        return { threshold_mins: form.threshold };
      default:
        return {};
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data = {
      name: form.name,
      rule_type: form.rule_type,
      conditions: buildConditions(),
      channels: form.channels,
      cooldown_mins: form.cooldown_mins,
      enabled: form.enabled,
    };
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  return (
    <>
      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Spinner size="lg" />
          </div>
        ) : rules && rules.length > 0 ? (
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => toggleMutation.mutate({ id: rule.id, enabled: !rule.enabled })}
                    className={cn(
                      "transition-colors",
                      rule.enabled ? "text-green-500" : "text-gray-400"
                    )}
                  >
                    {rule.enabled ? (
                      <ToggleRight className="h-6 w-6" />
                    ) : (
                      <ToggleLeft className="h-6 w-6" />
                    )}
                  </button>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-900 dark:text-white font-medium">{rule.name}</span>
                      <Badge size="sm">
                        {ruleTypes.find((t) => t.value === rule.rule_type)?.label || rule.rule_type}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-500 mt-0.5">
                      Cooldown: {rule.cooldown_mins} mins | {rule.channels.length} channel(s)
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => openEdit(rule)}
                    className="p-2 text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                    title="Edit"
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(rule.id)}
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
              icon={Bell}
              title="No alert rules configured"
              description="Create a rule to start monitoring"
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
                {editingRule ? "Edit Rule" : "Add Rule"}
              </h2>
              <button
                onClick={() => { setShowModal(false); setEditingRule(null); }}
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
                placeholder="Container crash alert"
              />
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  Rule Type
                </label>
                <select
                  value={form.rule_type}
                  onChange={(e) => setForm({ ...form, rule_type: e.target.value })}
                  className="w-full px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  {ruleTypes.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  Notification Channels
                </label>
                {channels && channels.length > 0 ? (
                  <div className="space-y-2 p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
                    {channels.map((channel) => (
                      <label key={channel.id} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={form.channels.includes(channel.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setForm({ ...form, channels: [...form.channels, channel.id] });
                            } else {
                              setForm({
                                ...form,
                                channels: form.channels.filter((c) => c !== channel.id),
                              });
                            }
                          }}
                          className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">{channel.name}</span>
                        <span className="text-xs text-gray-500">({channel.channel_type})</span>
                      </label>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500 p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
                    No channels configured. Create a channel first.
                  </p>
                )}
              </div>

              {(form.rule_type === "high_cpu" ||
                form.rule_type === "high_memory" ||
                form.rule_type === "high_restart_count" ||
                form.rule_type === "high_error_rate" ||
                form.rule_type === "agent_offline") && (
                <Input
                  label={
                    form.rule_type === "high_cpu" || form.rule_type === "high_memory"
                      ? "Threshold (%)"
                      : form.rule_type === "high_error_rate"
                      ? "Threshold (errors/min)"
                      : form.rule_type === "agent_offline"
                      ? "Offline threshold (minutes)"
                      : "Threshold (restarts)"
                  }
                  type="number"
                  value={form.threshold}
                  onChange={(e) => setForm({ ...form, threshold: parseFloat(e.target.value) })}
                />
              )}

              {form.rule_type === "high_error_rate" && (
                <>
                  <Input
                    label="Time Window (minutes)"
                    type="number"
                    value={form.window_mins}
                    onChange={(e) => setForm({ ...form, window_mins: parseInt(e.target.value) })}
                  />
                  <Input
                    label="Container Pattern (optional)"
                    value={form.container_pattern}
                    onChange={(e) => setForm({ ...form, container_pattern: e.target.value })}
                    placeholder="e.g., nginx, api-"
                  />
                </>
              )}

              {form.rule_type === "ssl_expiry" && (
                <div className="grid grid-cols-2 gap-4">
                  <Input
                    label="Warning (days)"
                    type="number"
                    value={form.warning_days}
                    onChange={(e) => setForm({ ...form, warning_days: parseInt(e.target.value) })}
                  />
                  <Input
                    label="Critical (days)"
                    type="number"
                    value={form.critical_days}
                    onChange={(e) => setForm({ ...form, critical_days: parseInt(e.target.value) })}
                  />
                </div>
              )}

              <Input
                label="Cooldown (minutes)"
                type="number"
                value={form.cooldown_mins}
                onChange={(e) => setForm({ ...form, cooldown_mins: parseInt(e.target.value) })}
              />

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="rule-enabled"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                />
                <label htmlFor="rule-enabled" className="text-sm text-gray-700 dark:text-gray-300">
                  Enabled
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => { setShowModal(false); setEditingRule(null); }}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={createMutation.isPending || updateMutation.isPending}
                >
                  {editingRule ? "Save" : "Create"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
