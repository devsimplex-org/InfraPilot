"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Server, Trash2, Copy, Check } from "lucide-react";
import { api, Agent } from "@/lib/api";
import { formatRelativeTime, getStatusBadgeColor, cn } from "@/lib/utils";

export default function AgentsPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newAgentName, setNewAgentName] = useState("");
  const [copiedToken, setCopiedToken] = useState<string | null>(null);

  const { data: agents, isLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const createMutation = useMutation({
    mutationFn: (name: string) => api.createAgent(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      setShowCreateModal(false);
      setNewAgentName("");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteAgent(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const copyToClipboard = (token: string) => {
    navigator.clipboard.writeText(token);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Agents</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Agent
        </button>
      </div>

      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800">
              <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Name
              </th>
              <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Hostname
              </th>
              <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Status
              </th>
              <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Version
              </th>
              <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Last Seen
              </th>
              <th className="text-right py-4 px-6 text-sm font-medium text-gray-500 dark:text-gray-400">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {agents?.map((agent) => (
              <tr
                key={agent.id}
                className="border-b border-gray-200 dark:border-gray-800 last:border-0"
              >
                <td className="py-4 px-6">
                  <div className="flex items-center gap-3">
                    <Server className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                    <span className="text-gray-900 dark:text-white font-medium">{agent.name}</span>
                  </div>
                </td>
                <td className="py-4 px-6 text-gray-600 dark:text-gray-400">
                  {agent.hostname || "—"}
                </td>
                <td className="py-4 px-6">
                  <span
                    className={cn(
                      "px-2 py-1 text-xs font-medium rounded border",
                      getStatusBadgeColor(agent.status)
                    )}
                  >
                    {agent.status}
                  </span>
                </td>
                <td className="py-4 px-6 text-gray-600 dark:text-gray-400">
                  {agent.version || "—"}
                </td>
                <td className="py-4 px-6 text-gray-600 dark:text-gray-400">
                  {agent.last_seen_at
                    ? formatRelativeTime(agent.last_seen_at)
                    : "Never"}
                </td>
                <td className="py-4 px-6">
                  <div className="flex items-center justify-end gap-2">
                    {agent.enrollment_token && (
                      <button
                        onClick={() => copyToClipboard(agent.enrollment_token!)}
                        className="p-2 text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                        title="Copy enrollment token"
                      >
                        {copiedToken === agent.enrollment_token ? (
                          <Check className="h-4 w-4 text-green-400" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </button>
                    )}
                    <button
                      onClick={() => deleteMutation.mutate(agent.id)}
                      className="p-2 text-gray-400 hover:text-red-500 dark:hover:text-red-400 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                      title="Delete agent"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {agents?.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500">
                  No agents found. Click "Add Agent" to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-lg p-6 w-full max-w-md border border-gray-200 dark:border-gray-800">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Add New Agent</h2>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createMutation.mutate(newAgentName);
              }}
            >
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Agent Name
                </label>
                <input
                  type="text"
                  value={newAgentName}
                  onChange={(e) => setNewAgentName(e.target.value)}
                  required
                  className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-gray-900 dark:text-white"
                  placeholder="e.g., production-server-1"
                />
              </div>
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-800 text-white rounded-lg transition-colors"
                >
                  {createMutation.isPending ? "Creating..." : "Create Agent"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
