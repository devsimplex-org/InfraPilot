"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Plus,
  RefreshCw,
  Trash2,
  RotateCcw,
  Star,
  X,
  ScanLine,
  Copy,
  Check,
} from "lucide-react";
import { api, SSLCertificateRecord } from "@/lib/api";
import { SSLWizard } from "@/components/ssl-wizard";
import { Card } from "@/components/ui/Card";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function daysUntil(dateStr?: string): number | null {
  if (!dateStr) return null;
  return Math.floor((new Date(dateStr).getTime() - Date.now()) / 86_400_000);
}

type CertStatus = "healthy" | "expiring" | "critical" | "expired" | "unknown";

function certStatus(days: number | null): CertStatus {
  if (days === null) return "unknown";
  if (days < 0) return "expired";
  if (days < 14) return "critical";
  if (days < 30) return "expiring";
  return "healthy";
}

const statusConfig: Record<CertStatus, { label: string; icon: React.ReactNode; classes: string }> = {
  healthy:  { label: "Valid",    icon: <ShieldCheck className="h-4 w-4" />, classes: "text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20" },
  expiring: { label: "Expiring", icon: <ShieldAlert className="h-4 w-4" />, classes: "text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20" },
  critical: { label: "Critical", icon: <ShieldAlert className="h-4 w-4" />, classes: "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20" },
  expired:  { label: "Expired",  icon: <ShieldX className="h-4 w-4" />,    classes: "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20" },
  unknown:  { label: "Unknown",  icon: <ShieldCheck className="h-4 w-4" />, classes: "text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-800" },
};

function ExpiryBadge({ days }: { days: number | null }) {
  if (days === null) return <span className="text-gray-400">—</span>;
  if (days < 0) return <span className="text-red-600 dark:text-red-400 font-medium">Expired</span>;
  const color = days < 14 ? "text-red-600 dark:text-red-400" : days < 30 ? "text-amber-600 dark:text-amber-400" : "text-gray-700 dark:text-gray-300";
  return (
    <div>
      <span className={`font-medium tabular-nums ${color}`}>{days}d</span>
      <span className="text-xs text-gray-400 ml-1">
        {new Date(Date.now() + days * 86_400_000).toLocaleDateString()}
      </span>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors"
      title="Copy path"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const queryClient = useQueryClient();

  const [showDomainModal, setShowDomainModal] = useState(false);
  const [domainInput, setDomainInput] = useState("");
  const [wizardDomain, setWizardDomain] = useState("");
  const [showWizard, setShowWizard] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SSLCertificateRecord | null>(null);

  const { data: certs, isLoading } = useQuery({
    queryKey: ["ssl-certificates"],
    queryFn: api.listSSLCertificates,
    refetchInterval: 60_000,
  });

  const scanMutation = useMutation({
    mutationFn: api.scanSSLCertificates,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ssl-certificates"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSSLCertificate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ssl-certificates"] });
      setDeleteTarget(null);
    },
  });

  const openWizard = (domain: string) => {
    setWizardDomain(domain);
    setShowWizard(true);
  };

  const handleAddSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const d = domainInput.trim();
    if (!d) return;
    setShowDomainModal(false);
    setDomainInput("");
    openWizard(d);
  };

  // Derived stats
  const total = certs?.length ?? 0;
  const withExpiry = certs?.map(c => ({ cert: c, days: daysUntil(c.expires_at) })) ?? [];
  const validCount   = withExpiry.filter(x => x.days !== null && x.days >= 30).length;
  const expiringCount = withExpiry.filter(x => x.days !== null && x.days >= 0 && x.days < 30).length;
  const expiredCount = withExpiry.filter(x => x.days !== null && x.days < 0).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">SSL Certificates</h2>
          <p className="text-sm text-gray-500">Manage Let&apos;s Encrypt and custom certificates</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
            title="Scan /etc/letsencrypt/live/ for certificates"
          >
            {scanMutation.isPending ? <Spinner size="sm" /> : <ScanLine className="h-4 w-4" />}
            Scan
          </button>
          <button
            onClick={() => setShowDomainModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Plus className="h-4 w-4" />
            Add Certificate
          </button>
        </div>
      </div>

      {/* Stats */}
      <MetricsGrid columns={4}>
        <StatCard label="Total" value={total} icon={ShieldCheck} iconColor="text-blue-500" />
        <StatCard label="Valid" value={validCount} icon={ShieldCheck} iconColor="text-green-500" />
        <StatCard label="Expiring soon" value={expiringCount} description="< 30 days" icon={ShieldAlert} iconColor="text-amber-500" />
        <StatCard label="Expired" value={expiredCount} icon={ShieldX} iconColor="text-red-500" />
      </MetricsGrid>

      {/* Certificate Table */}
      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <Spinner size="lg" />
          </div>
        ) : !certs || certs.length === 0 ? (
          <div className="py-16">
            <EmptyState
              icon={ShieldCheck}
              title="No certificates yet"
              description="Add a Let's Encrypt or custom SSL certificate to get started"
              action={
                <button
                  onClick={() => setShowDomainModal(true)}
                  className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm"
                >
                  Add Certificate
                </button>
              }
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-800/50 border-b border-gray-200 dark:border-gray-800">
                <tr className="text-left text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                  <th className="px-4 py-3 font-medium">Domain</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Issuer</th>
                  <th className="px-4 py-3 font-medium">Expires</th>
                  <th className="px-4 py-3 font-medium">Certificate Path</th>
                  <th className="px-4 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                {withExpiry.map(({ cert, days }) => {
                  const status = certStatus(days);
                  const cfg = statusConfig[status];
                  return (
                    <tr key={cert.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/30 transition-colors">
                      {/* Domain */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-gray-900 dark:text-white text-sm">
                            {cert.is_wildcard ? `*.${cert.domain}` : cert.domain}
                          </span>
                          {cert.is_wildcard && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">
                              <Star className="h-2.5 w-2.5" />
                              Wildcard
                            </span>
                          )}
                          {cert.auto_detected && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400">
                              Auto
                            </span>
                          )}
                        </div>
                        {cert.san && (
                          <p className="text-xs text-gray-400 mt-0.5 truncate max-w-xs">{cert.san}</p>
                        )}
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${cfg.classes}`}>
                          {cfg.icon}
                          {cfg.label}
                        </span>
                      </td>

                      {/* Issuer */}
                      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                        {cert.issuer
                          ? cert.issuer.replace(/^.*CN=/, "").replace(/,.*$/, "")
                          : <span className="text-gray-400">—</span>}
                      </td>

                      {/* Expiry */}
                      <td className="px-4 py-3 text-sm">
                        <ExpiryBadge days={days} />
                      </td>

                      {/* Path */}
                      <td className="px-4 py-3">
                        {cert.cert_path ? (
                          <div className="flex items-center gap-1">
                            <code className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate max-w-[200px]">
                              {cert.cert_path}
                            </code>
                            <CopyButton text={cert.cert_path} />
                          </div>
                        ) : (
                          <span className="text-gray-400 text-sm">—</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => openWizard(cert.is_wildcard ? `*.${cert.domain}` : cert.domain)}
                            className="p-2 text-gray-500 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg transition-colors"
                            title="Renew certificate"
                          >
                            <RotateCcw className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => setDeleteTarget(cert)}
                            className="p-2 text-gray-500 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                            title="Delete certificate"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Add Certificate — Domain Input Modal */}
      {showDomainModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 w-full max-w-md shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Add Certificate</h2>
                <p className="text-sm text-gray-500 mt-0.5">Enter the domain to issue or upload a certificate for</p>
              </div>
              <button onClick={() => { setShowDomainModal(false); setDomainInput(""); }} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleAddSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Domain</label>
                <input
                  type="text"
                  value={domainInput}
                  onChange={e => setDomainInput(e.target.value)}
                  placeholder="example.com or *.example.com"
                  className="w-full bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  autoFocus
                  required
                />
                <p className="mt-1 text-xs text-gray-400">Use *.domain.com for a wildcard certificate (requires DNS-01 challenge)</p>
              </div>
              <div className="flex justify-end gap-3 pt-1">
                <button type="button" onClick={() => { setShowDomainModal(false); setDomainInput(""); }} className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm font-medium transition-colors">
                  Continue
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 w-full max-w-md shadow-xl">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Delete Certificate</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Remove <span className="font-medium text-gray-900 dark:text-white">
                {deleteTarget.is_wildcard ? `*.${deleteTarget.domain}` : deleteTarget.domain}
              </span> from InfraPilot? This does not delete the certificate file from disk.
            </p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setDeleteTarget(null)} className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm disabled:opacity-50 transition-colors"
              >
                {deleteMutation.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SSL Wizard */}
      {showWizard && wizardDomain && (
        <SSLWizard
          domain={wizardDomain.startsWith("*.") ? wizardDomain.slice(2) : wizardDomain}
          open={showWizard}
          onOpenChange={setShowWizard}
          onSuccess={() => {
            setShowWizard(false);
            queryClient.invalidateQueries({ queryKey: ["ssl-certificates"] });
          }}
        />
      )}
    </div>
  );
}
