"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Database,
  Shield,
  HardDrive,
  Activity,
  Clock,
  Server,
  Lock,
  Globe,
  Edit2,
  Trash2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Archive,
  Tag,
} from "lucide-react";
import { api, DatabaseInventoryItem } from "@/lib/api";
import { useDatabase } from "@/lib/database-context";
import { SlideOver, SlideOverHeader, SlideOverBody } from "@/components/ui/SlideOver";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { cn, formatBytes } from "@/lib/utils";

type Tab = "details" | "backups" | "governance";

const CLASSIFICATION_COLORS: Record<string, string> = {
  restricted: "text-red-700 bg-red-50 dark:text-red-400 dark:bg-red-900/20",
  confidential: "text-orange-700 bg-orange-50 dark:text-orange-400 dark:bg-orange-900/20",
  internal: "text-blue-700 bg-blue-50 dark:text-blue-400 dark:bg-blue-900/20",
  public: "text-gray-700 bg-gray-50 dark:text-gray-300 dark:bg-gray-800",
};

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between py-2.5 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span className="text-sm text-gray-500 dark:text-gray-400 shrink-0 w-36">{label}</span>
      <span className="text-sm text-gray-900 dark:text-white text-right">{value ?? "—"}</span>
    </div>
  );
}

export function DatabasePanel() {
  const queryClient = useQueryClient();
  const { selectedAgent, selectedDatabaseId, closeDatabasePanel } = useDatabase();
  const [tab, setTab] = useState<Tab>("details");
  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState<Partial<DatabaseInventoryItem>>({});
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Reset on open
  useEffect(() => {
    if (selectedDatabaseId) {
      setTab("details");
      setEditing(false);
    }
  }, [selectedDatabaseId]);

  const { data: db, isLoading } = useQuery({
    queryKey: ["database-detail", selectedDatabaseId],
    queryFn: () => api.getDatabase(selectedDatabaseId!),
    enabled: !!selectedDatabaseId,
  });

  const { data: backupsData, isLoading: loadingBackups } = useQuery({
    queryKey: ["database-backups", selectedDatabaseId],
    queryFn: () => api.getDatabaseBackups(selectedDatabaseId!, { limit: 10 }),
    enabled: !!selectedDatabaseId && tab === "backups",
  });

  const { data: metrics } = useQuery({
    queryKey: ["database-metrics", selectedAgent, selectedDatabaseId],
    queryFn: () => api.getAgentDatabaseMetrics(selectedAgent!, selectedDatabaseId!),
    enabled: !!selectedAgent && !!selectedDatabaseId && tab === "details",
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<DatabaseInventoryItem>) =>
      api.updateDatabase(selectedDatabaseId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["database-detail", selectedDatabaseId] });
      queryClient.invalidateQueries({ queryKey: ["databases"] });
      setEditing(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteDatabase(selectedDatabaseId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["databases"] });
      closeDatabasePanel();
    },
  });

  const tabs: { id: Tab; label: string }[] = [
    { id: "details", label: "Details" },
    { id: "backups", label: "Backups" },
    { id: "governance", label: "Governance" },
  ];

  const statusLevel = (s: string) =>
    s === "healthy" ? "healthy" : s === "degraded" ? "warning" : "critical";

  return (
    <SlideOver isOpen={!!selectedDatabaseId} onClose={closeDatabasePanel} size="lg">
      <SlideOverHeader onClose={closeDatabasePanel}>
        {isLoading ? (
          <div className="h-6 w-40 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
        ) : db ? (
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg shrink-0">
              <Database className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-gray-900 dark:text-white truncate">{db.name}</h2>
              <p className="text-xs text-gray-500 truncate">
                {db.db_type} {db.version ? `v${db.version}` : ""} · {db.environment}
              </p>
            </div>
            <StatusIndicator status={statusLevel(db.status)} size="sm" />
          </div>
        ) : null}
      </SlideOverHeader>

      <SlideOverBody noPadding>
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <Spinner size="md" />
          </div>
        ) : !db ? (
          <div className="flex flex-col items-center justify-center h-64 text-gray-400">
            <Database className="h-12 w-12 mb-3 opacity-30" />
            <p className="text-sm">Database not found</p>
          </div>
        ) : (
          <div className="flex flex-col h-full">
            {/* Tab Bar */}
            <div className="flex border-b border-gray-200 dark:border-gray-700 px-6 shrink-0">
              {tabs.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={cn(
                    "py-3 px-1 mr-6 text-sm font-medium border-b-2 transition-colors",
                    tab === t.id
                      ? "border-primary-500 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto px-6 py-4">

              {/* ── DETAILS TAB ── */}
              {tab === "details" && (
                <div className="space-y-6">
                  {/* Connection */}
                  <section>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Connection</h3>
                    <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3">
                      <DetailRow label="Host" value={db.host || "—"} />
                      <DetailRow label="Port" value={db.port} />
                      <DetailRow label="Database Name" value={db.database_name} />
                      <DetailRow label="Type" value={<span className="capitalize">{db.db_type}</span>} />
                      <DetailRow label="Version" value={db.version} />
                    </div>
                  </section>

                  {/* Metrics */}
                  {metrics && (
                    <section>
                      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Metrics</h3>
                      <div className="grid grid-cols-3 gap-3">
                        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3 text-center">
                          <HardDrive className="h-4 w-4 text-gray-400 mx-auto mb-1" />
                          <div className="text-sm font-semibold text-gray-900 dark:text-white">
                            {metrics.size_bytes ? formatBytes(metrics.size_bytes) : "—"}
                          </div>
                          <div className="text-xs text-gray-500">Size</div>
                        </div>
                        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3 text-center">
                          <Activity className="h-4 w-4 text-gray-400 mx-auto mb-1" />
                          <div className="text-sm font-semibold text-gray-900 dark:text-white">
                            {metrics.connection_count ?? "—"}
                          </div>
                          <div className="text-xs text-gray-500">Connections</div>
                        </div>
                        <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3 text-center">
                          <Server className="h-4 w-4 text-gray-400 mx-auto mb-1" />
                          <div className="text-sm font-semibold text-gray-900 dark:text-white">
                            {metrics.max_connections ?? "—"}
                          </div>
                          <div className="text-xs text-gray-500">Max Conn.</div>
                        </div>
                      </div>
                    </section>
                  )}

                  {/* Configuration */}
                  <section>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Configuration</h3>
                    <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3">
                      <DetailRow label="Environment" value={
                        <Badge variant={db.environment === "production" ? "severity" : undefined} severity={db.environment === "production" ? "critical" : undefined}>
                          {db.environment}
                        </Badge>
                      } />
                      <DetailRow label="Role" value={
                        db.is_replica ? "Replica" : db.is_primary ? "Primary" : "Standalone"
                      } />
                      {db.replica_of && <DetailRow label="Replica Of" value={db.replica_of} />}
                      {db.replication_lag_seconds !== undefined && (
                        <DetailRow label="Replication Lag" value={`${db.replication_lag_seconds}s`} />
                      )}
                      <DetailRow label="Container" value={db.container_name} />
                      <DetailRow label="Auto-Discovered" value={db.auto_discovered ? "Yes" : "No"} />
                    </div>
                  </section>

                  {/* Ownership */}
                  {(db.owner_team || db.owner_contact || db.description) && (
                    <section>
                      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Ownership</h3>
                      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3">
                        <DetailRow label="Team" value={db.owner_team} />
                        <DetailRow label="Contact" value={db.owner_contact} />
                        {db.description && (
                          <div className="pt-2">
                            <p className="text-xs text-gray-500 mb-1">Description</p>
                            <p className="text-sm text-gray-700 dark:text-gray-300">{db.description}</p>
                          </div>
                        )}
                      </div>
                    </section>
                  )}

                  {/* Tags */}
                  {db.tags && db.tags.length > 0 && (
                    <section>
                      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Tags</h3>
                      <div className="flex flex-wrap gap-2">
                        {db.tags.map((tag) => (
                          <span key={tag} className="flex items-center gap-1 px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-xs text-gray-600 dark:text-gray-400">
                            <Tag className="h-3 w-3" />{tag}
                          </span>
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Timestamps */}
                  <section>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Timestamps</h3>
                    <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3">
                      <DetailRow label="Discovered" value={new Date(db.discovered_at).toLocaleString()} />
                      <DetailRow label="Registered" value={new Date(db.created_at).toLocaleString()} />
                      {db.last_health_check && (
                        <DetailRow label="Last Health Check" value={new Date(db.last_health_check).toLocaleString()} />
                      )}
                    </div>
                  </section>
                </div>
              )}

              {/* ── BACKUPS TAB ── */}
              {tab === "backups" && (
                <div className="space-y-4">
                  {loadingBackups ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : backupsData?.backups && backupsData.backups.length > 0 ? (
                    backupsData.backups.map((backup) => (
                      <div key={backup.id} className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Archive className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                              {backup.backup_type} backup
                            </span>
                          </div>
                          <span className={cn(
                            "px-2 py-0.5 rounded text-xs font-medium",
                            backup.status === "completed" ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400" :
                            backup.status === "failed" ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" :
                            backup.status === "running" ? "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400" :
                            "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300"
                          )}>
                            {backup.status}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-gray-500">
                          <span>Started: {new Date(backup.started_at).toLocaleString()}</span>
                          {backup.size_bytes && <span>Size: {formatBytes(backup.size_bytes)}</span>}
                          {backup.duration_seconds && <span>Duration: {backup.duration_seconds}s</span>}
                          <span>Encrypted: {backup.encryption_enabled ? "Yes" : "No"}</span>
                          {backup.retention_days && <span>Retention: {backup.retention_days}d</span>}
                          {backup.verification_status && (
                            <span className="flex items-center gap-1">
                              Verified: {backup.verification_status === "verified"
                                ? <CheckCircle2 className="h-3 w-3 text-green-500" />
                                : <XCircle className="h-3 w-3 text-red-500" />}
                            </span>
                          )}
                        </div>
                        {backup.error_message && (
                          <p className="mt-2 text-xs text-red-600">{backup.error_message}</p>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="flex flex-col items-center justify-center h-32 text-gray-400">
                      <Archive className="h-8 w-8 mb-2 opacity-30" />
                      <p className="text-sm">No backups recorded</p>
                    </div>
                  )}
                </div>
              )}

              {/* ── GOVERNANCE TAB ── */}
              {tab === "governance" && (
                <div className="space-y-6">
                  {/* Classification */}
                  <section>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Data Classification</h3>
                    <div className="grid grid-cols-2 gap-3">
                      {(["public", "internal", "confidential", "restricted"] as const).map((cls) => (
                        <div
                          key={cls}
                          className={cn(
                            "p-3 rounded-lg border text-center",
                            db.data_classification === cls
                              ? "border-primary-500 bg-primary-50 dark:bg-primary-900/20"
                              : "border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50"
                          )}
                        >
                          <div className={cn(
                            "text-xs font-medium capitalize",
                            db.data_classification === cls ? "text-primary-700 dark:text-primary-300" : "text-gray-500"
                          )}>{cls}</div>
                          {db.data_classification === cls && (
                            <CheckCircle2 className="h-4 w-4 text-primary-600 mx-auto mt-1" />
                          )}
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* Compliance Flags */}
                  <section>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Compliance Flags</h3>
                    <div className="space-y-2">
                      {([
                        { key: "pii_data", label: "PII Data", description: "Contains personally identifiable information", color: "purple" },
                        { key: "pci_data", label: "PCI Data", description: "In scope for payment card compliance", color: "red" },
                        { key: "hipaa_data", label: "HIPAA", description: "Contains protected health information", color: "blue" },
                        { key: "gdpr_relevant", label: "GDPR Relevant", description: "Subject to GDPR data protection rules", color: "green" },
                      ] as const).map(({ key, label, description, color }) => {
                        const isSet = !!db[key];
                        return (
                          <div key={key} className={cn(
                            "flex items-center justify-between p-3 rounded-lg border",
                            isSet
                              ? `border-${color}-200 bg-${color}-50 dark:border-${color}-800 dark:bg-${color}-900/10`
                              : "border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50"
                          )}>
                            <div>
                              <div className={cn("text-sm font-medium", isSet ? `text-${color}-700 dark:text-${color}-300` : "text-gray-500")}>{label}</div>
                              <div className="text-xs text-gray-400">{description}</div>
                            </div>
                            {isSet
                              ? <CheckCircle2 className={`h-5 w-5 text-${color}-500`} />
                              : <XCircle className="h-5 w-5 text-gray-300 dark:text-gray-600" />}
                          </div>
                        );
                      })}
                    </div>
                  </section>

                  {/* Edit Governance Button */}
                  {!editing ? (
                    <button
                      onClick={() => {
                        setEditForm({
                          data_classification: db.data_classification,
                          pii_data: db.pii_data,
                          pci_data: db.pci_data,
                          hipaa_data: db.hipaa_data,
                          gdpr_relevant: db.gdpr_relevant,
                          owner_team: db.owner_team,
                          owner_contact: db.owner_contact,
                          description: db.description,
                        });
                        setEditing(true);
                      }}
                      className="w-full py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center justify-center gap-2"
                    >
                      <Edit2 className="h-4 w-4" /> Edit Governance Settings
                    </button>
                  ) : (
                    <div className="space-y-4 border border-primary-200 dark:border-primary-800 rounded-lg p-4 bg-primary-50/30 dark:bg-primary-900/10">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">Edit Governance</h4>

                      <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Classification</label>
                        <select
                          value={editForm.data_classification || "internal"}
                          onChange={(e) => setEditForm((f) => ({ ...f, data_classification: e.target.value as DatabaseInventoryItem["data_classification"] }))}
                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                        >
                          <option value="public">Public</option>
                          <option value="internal">Internal</option>
                          <option value="confidential">Confidential</option>
                          <option value="restricted">Restricted</option>
                        </select>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        {([
                          { key: "pii_data" as const, label: "PII Data" },
                          { key: "pci_data" as const, label: "PCI Data" },
                          { key: "hipaa_data" as const, label: "HIPAA" },
                          { key: "gdpr_relevant" as const, label: "GDPR" },
                        ]).map(({ key, label }) => (
                          <label key={key} className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={!!editForm[key]}
                              onChange={(e) => setEditForm((f) => ({ ...f, [key]: e.target.checked }))}
                              className="rounded border-gray-300"
                            />
                            <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
                          </label>
                        ))}
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Owner Team</label>
                        <input
                          type="text"
                          value={editForm.owner_team || ""}
                          onChange={(e) => setEditForm((f) => ({ ...f, owner_team: e.target.value }))}
                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                          placeholder="platform-team"
                        />
                      </div>

                      {updateMutation.isError && (
                        <p className="text-xs text-red-600">{(updateMutation.error as Error)?.message}</p>
                      )}

                      <div className="flex gap-2">
                        <button
                          onClick={() => setEditing(false)}
                          className="flex-1 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => updateMutation.mutate(editForm)}
                          disabled={updateMutation.isPending}
                          className="flex-1 py-2 text-sm bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
                        >
                          {updateMutation.isPending ? "Saving..." : "Save"}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer Actions */}
            <div className="shrink-0 border-t border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-between bg-gray-50 dark:bg-gray-800/50">
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="flex items-center gap-2 px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
              >
                <Trash2 className="h-4 w-4" /> Remove
              </button>
              <button
                onClick={() => queryClient.invalidateQueries({ queryKey: ["database-detail", selectedDatabaseId] })}
                className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <RefreshCw className="h-4 w-4" /> Refresh
              </button>
            </div>
          </div>
        )}
      </SlideOverBody>

      {/* Delete Confirm */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowDeleteConfirm(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-sm w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <Trash2 className="h-5 w-5 text-red-600" />
              </div>
              <h3 className="text-base font-semibold text-gray-900 dark:text-white">Remove Database</h3>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-5">
              Remove <strong>{db?.name}</strong> from inventory? This does not affect the actual database.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowDeleteConfirm(false)} className="flex-1 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800">
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
                className="flex-1 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                {deleteMutation.isPending ? "Removing..." : "Remove"}
              </button>
            </div>
          </div>
        </div>
      )}
    </SlideOver>
  );
}
