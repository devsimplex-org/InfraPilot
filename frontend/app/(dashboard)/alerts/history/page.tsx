"use client";

import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Bell,
  AlertTriangle,
  Check,
  History,
  Clock,
  Info,
  ShieldAlert,
} from "lucide-react";
import { api, AlertHistoryEntry } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import {
  SlideOver,
  SlideOverHeader,
  SlideOverBody,
} from "@/components/ui/SlideOver";

// ── helpers ────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 border-red-200 dark:border-red-800",
  warning:  "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800",
  info:     "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 border-blue-200 dark:border-blue-800",
};

function severityStyle(s: string) {
  return SEVERITY_STYLES[s] ?? "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400 border-gray-200 dark:border-gray-700";
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded border font-medium capitalize", severityStyle(severity))}>
      {severity}
    </span>
  );
}

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-2 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span className="text-sm text-gray-500 dark:text-gray-400 shrink-0">{label}</span>
      <span className="text-sm text-gray-900 dark:text-white text-right break-all">{value}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-6">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500 mb-3">
        {title}
      </h3>
      <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg px-4 py-1">
        {children}
      </div>
    </div>
  );
}

// ── detail pane ───────────────────────────────────────────────────────────

function AlertDetailPane({
  entry,
  onClose,
}: {
  entry: AlertHistoryEntry;
  onClose: () => void;
}) {
  const meta = entry.metadata ?? {};
  const metaKeys = Object.keys(meta).filter(
    (k) => !["container_id"].includes(k) // hide internal keys
  );

  return (
    <SlideOver isOpen onClose={onClose} size="md">
      <SlideOverHeader onClose={onClose}>
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "p-2 rounded-lg shrink-0",
              entry.resolved_at
                ? "bg-green-100 dark:bg-green-900/30"
                : entry.severity === "critical"
                ? "bg-red-100 dark:bg-red-900/30"
                : "bg-yellow-100 dark:bg-yellow-900/30"
            )}
          >
            {entry.resolved_at ? (
              <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
            ) : entry.severity === "critical" ? (
              <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
            )}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">
              {entry.rule_name ?? "Alert"}
            </p>
            <div className="flex items-center gap-2 mt-0.5">
              <SeverityBadge severity={entry.severity} />
              {entry.resolved_at && (
                <span className="text-xs text-green-600 dark:text-green-400">Resolved</span>
              )}
            </div>
          </div>
        </div>
      </SlideOverHeader>

      <SlideOverBody>
        {/* Alert info */}
        <Section title="Alert">
          <DetailRow label="Message"     value={entry.message} />
          <DetailRow label="Severity"    value={<SeverityBadge severity={entry.severity} />} />
          <DetailRow
            label="Triggered"
            value={
              <span title={new Date(entry.triggered_at).toLocaleString()}>
                {formatRelativeTime(entry.triggered_at)}
                <span className="block text-xs text-gray-400 dark:text-gray-500">
                  {new Date(entry.triggered_at).toLocaleString()}
                </span>
              </span>
            }
          />
          {entry.resolved_at && (
            <DetailRow
              label="Resolved"
              value={
                <span className="text-green-600 dark:text-green-400" title={new Date(entry.resolved_at).toLocaleString()}>
                  {formatRelativeTime(entry.resolved_at)}
                </span>
              }
            />
          )}
        </Section>

        {/* Rule info */}
        {(entry.rule_name || entry.rule_id) && (
          <Section title="Rule">
            {entry.rule_name && <DetailRow label="Name" value={entry.rule_name} />}
            {entry.rule_id   && (
              <DetailRow
                label="ID"
                value={<span className="font-mono text-xs text-gray-500">{entry.rule_id}</span>}
              />
            )}
          </Section>
        )}

        {/* Agent */}
        {entry.agent_name && (
          <Section title="Agent">
            <DetailRow label="Name" value={entry.agent_name} />
            {entry.agent_id && (
              <DetailRow
                label="ID"
                value={<span className="font-mono text-xs text-gray-500">{entry.agent_id}</span>}
              />
            )}
          </Section>
        )}

        {/* Metadata */}
        {metaKeys.length > 0 && (
          <Section title="Details">
            {metaKeys.map((key) => {
              const val = meta[key];
              const display =
                typeof val === "number"
                  ? key.includes("percent") || key.includes("pct")
                    ? `${Number(val).toFixed(1)}%`
                    : key.includes("mb") || key.includes("memory") || key.includes("disk")
                    ? `${Number(val).toFixed(0)} MB`
                    : String(val)
                  : String(val ?? "");
              const label = key
                .replace(/_/g, " ")
                .replace(/\b\w/g, (c) => c.toUpperCase());
              return <DetailRow key={key} label={label} value={display} />;
            })}
          </Section>
        )}

        {/* Entry ID */}
        <div className="mt-4">
          <p className="text-xs text-gray-400 dark:text-gray-600 font-mono break-all">
            ID: {entry.id}
          </p>
        </div>
      </SlideOverBody>
    </SlideOver>
  );
}

// ── main page ─────────────────────────────────────────────────────────────

export default function AlertHistoryPage() {
  const [selected, setSelected] = useState<AlertHistoryEntry | null>(null);

  const { data: history, isLoading } = useQuery({
    queryKey: ["alertHistory"],
    queryFn: () => api.getAlertHistory(50),
  });

  const activeAlerts   = history?.filter((h) => !h.resolved_at).length ?? 0;
  const criticalAlerts = history?.filter((h) => !h.resolved_at && h.severity === "critical").length ?? 0;
  const resolvedAlerts = history?.filter((h) => !!h.resolved_at).length ?? 0;
  const totalAlerts    = history?.length ?? 0;

  return (
    <>
      <div className="space-y-6">
        <MetricsGrid columns={4}>
          <StatCard label="Active Alerts" value={activeAlerts}   icon={Bell}          iconColor="text-yellow-600" />
          <StatCard label="Critical"       value={criticalAlerts} icon={AlertTriangle}  iconColor="text-red-600" />
          <StatCard label="Resolved"       value={resolvedAlerts} icon={Check}          iconColor="text-green-600" />
          <StatCard label="Total Alerts"   value={totalAlerts}    icon={History}        iconColor="text-blue-600" />
        </MetricsGrid>

        <Card>
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <Spinner size="lg" />
            </div>
          ) : history && history.length > 0 ? (
            <div className="divide-y divide-gray-100 dark:divide-gray-800">
              {history.map((entry) => (
                <button
                  key={entry.id}
                  onClick={() => setSelected(entry)}
                  className="w-full flex items-center gap-4 p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors text-left cursor-pointer"
                >
                  <div
                    className={cn(
                      "p-2 rounded-lg shrink-0",
                      entry.resolved_at
                        ? "bg-green-100 dark:bg-green-900/30"
                        : "bg-red-100 dark:bg-red-900/30"
                    )}
                  >
                    {entry.resolved_at ? (
                      <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-gray-900 dark:text-white font-medium">{entry.message}</span>
                      <SeverityBadge severity={entry.severity} />
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-500 mt-1 flex-wrap">
                      {entry.rule_name  && <span>Rule: {entry.rule_name}</span>}
                      {entry.agent_name && <span>Agent: {entry.agent_name}</span>}
                      {!!entry.metadata?.container_name && (
                        <span>Container: {String(entry.metadata.container_name)}</span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatRelativeTime(entry.triggered_at)}
                      </span>
                      {entry.resolved_at && (
                        <span className="text-green-600 dark:text-green-400">
                          Resolved {formatRelativeTime(entry.resolved_at)}
                        </span>
                      )}
                    </div>
                  </div>
                  {/* Chevron hint */}
                  <Info className="h-4 w-4 text-gray-300 dark:text-gray-600 shrink-0" />
                </button>
              ))}
            </div>
          ) : (
            <div className="py-12">
              <EmptyState
                icon={History}
                title="No alert history"
                description="Triggered alerts will appear here"
              />
            </div>
          )}
        </Card>
      </div>

      {selected && (
        <AlertDetailPane entry={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
