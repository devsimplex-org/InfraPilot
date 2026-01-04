"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  History,
  ChevronLeft,
  ChevronRight,
  User,
  Server,
  Shield,
  Globe,
  Box,
  Bell,
  Settings,
  Filter,
} from "lucide-react";
import { api, AuditLogEntry } from "@/lib/api";

const actionIcons: Record<string, React.ReactNode> = {
  "user.login": <User className="h-4 w-4" />,
  "user.logout": <User className="h-4 w-4" />,
  "user.created": <User className="h-4 w-4" />,
  "user.updated": <User className="h-4 w-4" />,
  "user.deleted": <User className="h-4 w-4" />,
  "agent.created": <Server className="h-4 w-4" />,
  "agent.deleted": <Server className="h-4 w-4" />,
  "proxy.created": <Globe className="h-4 w-4" />,
  "proxy.updated": <Globe className="h-4 w-4" />,
  "proxy.deleted": <Globe className="h-4 w-4" />,
  "container.start": <Box className="h-4 w-4" />,
  "container.stop": <Box className="h-4 w-4" />,
  "container.restart": <Box className="h-4 w-4" />,
  "alert.created": <Bell className="h-4 w-4" />,
  "alert.updated": <Bell className="h-4 w-4" />,
  "settings.updated": <Settings className="h-4 w-4" />,
};

const actionColors: Record<string, string> = {
  created: "text-green-400 bg-green-500/10",
  updated: "text-blue-400 bg-blue-500/10",
  deleted: "text-red-400 bg-red-500/10",
  login: "text-purple-400 bg-purple-500/10",
  logout: "text-gray-600 dark:text-gray-400 bg-gray-500/10",
  start: "text-green-400 bg-green-500/10",
  stop: "text-red-400 bg-red-500/10",
  restart: "text-yellow-400 bg-yellow-500/10",
};

function getActionColor(action: string): string {
  for (const [key, color] of Object.entries(actionColors)) {
    if (action.includes(key)) return color;
  }
  return "text-gray-600 dark:text-gray-400 bg-gray-500/10";
}

export default function AuditPage() {
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [resourceFilter, setResourceFilter] = useState("");
  const limit = 50;

  const { data, isLoading } = useQuery({
    queryKey: ["audit-logs", page, actionFilter, resourceFilter],
    queryFn: () =>
      api.getAuditLogs({
        limit,
        offset: page * limit,
        action: actionFilter || undefined,
        resource_type: resourceFilter || undefined,
      }),
  });

  const logs = data?.logs || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <History className="h-7 w-7 text-purple-400" />
            Audit Log
          </h1>
          <p className="text-gray-600 dark:text-gray-400">Track all actions performed in your organization</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-4">
        <div className="flex items-center gap-4">
          <Filter className="h-4 w-4 text-gray-600 dark:text-gray-400" />
          <select
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(0);
            }}
            className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All Actions</option>
            <option value="user.login">User Login</option>
            <option value="user.created">User Created</option>
            <option value="user.updated">User Updated</option>
            <option value="user.deleted">User Deleted</option>
            <option value="agent.created">Agent Created</option>
            <option value="proxy.created">Proxy Created</option>
            <option value="proxy.updated">Proxy Updated</option>
            <option value="proxy.deleted">Proxy Deleted</option>
            <option value="container.start">Container Start</option>
            <option value="container.stop">Container Stop</option>
          </select>

          <select
            value={resourceFilter}
            onChange={(e) => {
              setResourceFilter(e.target.value);
              setPage(0);
            }}
            className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All Resources</option>
            <option value="user">Users</option>
            <option value="agent">Agents</option>
            <option value="proxy">Proxies</option>
            <option value="container">Containers</option>
            <option value="alert">Alerts</option>
          </select>

          <span className="text-sm text-gray-500">
            {total} total entries
          </span>
        </div>
      </div>

      {/* Audit log table */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading audit logs...</div>
        ) : logs.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No audit logs found</div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-100 dark:bg-gray-800/50">
              <tr className="text-left text-xs text-gray-600 dark:text-gray-400 uppercase">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Resource</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-gray-100 dark:bg-gray-800/30">
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400 whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-2 px-2 py-1 rounded text-xs font-medium ${getActionColor(
                        log.action
                      )}`}
                    >
                      {actionIcons[log.action] || <Shield className="h-4 w-4" />}
                      {log.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {log.user_email ? (
                      <span className="text-gray-900 dark:text-white">{log.user_email}</span>
                    ) : (
                      <span className="text-gray-500">System</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {log.resource_type && (
                      <span className="text-purple-400">
                        {log.resource_type}
                        {log.resource_id && (
                          <span className="text-gray-500 ml-1">
                            ({log.resource_id.slice(0, 8)}...)
                          </span>
                        )}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400 font-mono">
                    {log.ip_address || "-"}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">
                    {log.request_body ? JSON.stringify(log.request_body) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800 flex items-center justify-between">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Page {page + 1} of {totalPages}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
