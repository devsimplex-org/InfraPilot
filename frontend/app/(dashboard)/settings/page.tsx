"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Globe,
  Lock,
  Trash2,
  Loader2,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";

function InfraPilotDomainSection() {
  const queryClient = useQueryClient();
  const [domain, setDomain] = useState("");
  const [sslEnabled, setSSLEnabled] = useState(true);
  const [forceSSL, setForceSSL] = useState(true);
  const [http2Enabled, setHTTP2Enabled] = useState(true);
  const [hasChanges, setHasChanges] = useState(false);
  const [showDelete, setShowDelete] = useState(false);

  const { data: domainSettings, isLoading } = useQuery({
    queryKey: ["infrapilotDomain"],
    queryFn: () => api.getInfraPilotDomain(),
  });

  useEffect(() => {
    if (domainSettings?.domain) {
      setDomain(domainSettings.domain);
      setSSLEnabled(domainSettings.ssl_enabled);
      setForceSSL(domainSettings.force_ssl);
      setHTTP2Enabled(domainSettings.http2_enabled);
    }
  }, [domainSettings]);

  const saveMutation = useMutation({
    mutationFn: () =>
      api.updateInfraPilotDomain({
        domain,
        ssl_enabled: sslEnabled,
        force_ssl: forceSSL,
        http2_enabled: http2Enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["infrapilotDomain"] });
      setHasChanges(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteInfraPilotDomain(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["infrapilotDomain"] });
      setDomain("");
      setSSLEnabled(true);
      setForceSSL(true);
      setHTTP2Enabled(true);
      setShowDelete(false);
      setHasChanges(false);
    },
  });

  const handleDomainChange = (value: string) => {
    setDomain(value);
    setHasChanges(true);
  };

  const isConfigured = domainSettings?.domain && domainSettings.domain.length > 0;

  return (
    <Card>
      <Card.Header>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Globe className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">InfraPilot Domain</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Configure a custom domain to access InfraPilot
            </p>
          </div>
        </div>
      </Card.Header>
      <Card.Body>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 text-gray-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-6">
            {isConfigured && (
              <div className="flex items-center justify-between p-4 bg-green-500/5 border border-green-500/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {domainSettings.domain}
                    </p>
                    <p className="text-sm text-gray-500">
                      {domainSettings.ssl_enabled ? "HTTPS enabled" : "HTTP only"}
                    </p>
                  </div>
                </div>
                <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
                  Active
                </Badge>
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Domain Name
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => handleDomainChange(e.target.value)}
                placeholder="infrapilot.example.com"
                className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
              <p className="mt-1.5 text-xs text-gray-500">
                Make sure DNS is pointed to this server before enabling SSL
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Lock className="h-4 w-4 text-gray-500" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">Enable SSL/HTTPS</p>
                    <p className="text-xs text-gray-500">Automatically provision Let's Encrypt certificate</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSSLEnabled(!sslEnabled);
                    setHasChanges(true);
                  }}
                  className={cn(
                    "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                    sslEnabled ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                      sslEnabled ? "translate-x-6" : "translate-x-1"
                    )}
                  />
                </button>
              </div>

              {sslEnabled && (
                <>
                  <div className="flex items-center justify-between pl-7">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">Force HTTPS</p>
                      <p className="text-xs text-gray-500">Redirect all HTTP requests to HTTPS</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setForceSSL(!forceSSL);
                        setHasChanges(true);
                      }}
                      className={cn(
                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                        forceSSL ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                          forceSSL ? "translate-x-6" : "translate-x-1"
                        )}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between pl-7">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">HTTP/2</p>
                      <p className="text-xs text-gray-500">Enable HTTP/2 protocol for better performance</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setHTTP2Enabled(!http2Enabled);
                        setHasChanges(true);
                      }}
                      className={cn(
                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                        http2Enabled ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                          http2Enabled ? "translate-x-6" : "translate-x-1"
                        )}
                      />
                    </button>
                  </div>
                </>
              )}
            </div>

            {(saveMutation.isError || deleteMutation.isError) && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                {saveMutation.error?.message || deleteMutation.error?.message || "An error occurred"}
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              {isConfigured && !showDelete ? (
                <button
                  onClick={() => setShowDelete(true)}
                  className="text-sm text-red-400 hover:text-red-300 flex items-center gap-1.5"
                >
                  <Trash2 className="h-4 w-4" />
                  Remove Domain
                </button>
              ) : showDelete ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500">Are you sure?</span>
                  <button
                    onClick={() => deleteMutation.mutate()}
                    disabled={deleteMutation.isPending}
                    className="px-3 py-1.5 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
                  >
                    {deleteMutation.isPending ? "Removing..." : "Yes, Remove"}
                  </button>
                  <button
                    onClick={() => setShowDelete(false)}
                    className="px-3 py-1.5 text-sm text-gray-500 hover:text-gray-300"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div />
              )}

              {hasChanges && domain && (
                <button
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending || !domain}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white rounded-lg transition-colors flex items-center gap-2"
                >
                  {saveMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Check className="h-4 w-4" />
                  )}
                  {saveMutation.isPending ? "Saving..." : "Save Domain"}
                </button>
              )}
            </div>
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

export default function SettingsGeneralPage() {
  return <InfraPilotDomainSection />;
}
