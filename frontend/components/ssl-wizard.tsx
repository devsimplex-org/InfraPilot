"use client";

import { useState, useEffect } from "react";
import { api, SSLCertificateInfo, SSLStatus, DNSVerifyResult } from "@/lib/api";
import { Button, Input } from "@/components/ui/page-layout";
import { cn } from "@/lib/utils";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  Mail,
  RefreshCw,
  Check,
  X,
  AlertTriangle,
  Clock,
  ArrowRight,
  ArrowLeft,
  Loader2,
  Copy,
  Lock,
} from "lucide-react";

interface SSLWizardProps {
  domain: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

type WizardStep = "check" | "dns" | "email" | "request" | "complete";

export function SSLWizard({
  domain,
  open,
  onOpenChange,
  onSuccess,
}: SSLWizardProps) {
  const [step, setStep] = useState<WizardStep>("check");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Certificate check state
  const [certInfo, setCertInfo] = useState<SSLCertificateInfo | null>(null);
  const [wildcardCerts, setWildcardCerts] = useState<SSLCertificateInfo[]>([]);

  // DNS verification state
  const [dnsResult, setDnsResult] = useState<DNSVerifyResult | null>(null);
  const [serverIP, setServerIP] = useState<string>("");

  // Email/SSL config state
  const [sslStatus, setSSLStatus] = useState<SSLStatus | null>(null);
  const [email, setEmail] = useState("");
  const [staging, setStaging] = useState(false);

  // Request state
  const [requestStatus, setRequestStatus] = useState<"pending" | "success" | "error" | null>(null);
  const [resultMessage, setResultMessage] = useState<string>("");

  // Reset state when dialog opens/closes
  useEffect(() => {
    if (open) {
      setStep("check");
      setCertInfo(null);
      setWildcardCerts([]);
      setDnsResult(null);
      setServerIP("");
      setSSLStatus(null);
      setEmail("");
      setStaging(false);
      setRequestStatus(null);
      setResultMessage("");
      setError(null);
      // Start certificate check
      checkCertificate();
    }
  }, [open, domain]);

  const checkCertificate = async () => {
    if (!domain) return;

    setLoading(true);
    setError(null);

    try {
      // Check both local and remote certificates
      const [remoteCheck, wildcardCheck] = await Promise.all([
        api.checkSSL(domain, true),
        api.checkWildcardSSL(domain),
      ]);

      setCertInfo(remoteCheck);
      setWildcardCerts(wildcardCheck.certificates || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to check certificate");
    } finally {
      setLoading(false);
    }
  };

  const verifyDNS = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dnsCheck, instructions] = await Promise.all([
        api.verifyDNS(domain),
        api.getDNSInstructions(domain),
      ]);
      setDnsResult(dnsCheck);
      setServerIP(instructions.server_ip);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to verify DNS");
    } finally {
      setLoading(false);
    }
  };

  const loadSSLSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const status = await api.getSSLStatus();
      setSSLStatus(status);
      if (status.letsencrypt_email) {
        setEmail(status.letsencrypt_email);
      }
      setStaging(status.letsencrypt_staging);
    } catch {
      // Settings might not exist yet
      setSSLStatus(null);
    } finally {
      setLoading(false);
    }
  };

  const saveEmail = async () => {
    if (!email) {
      setError("Email is required for Let's Encrypt");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.updateSSLSettings({ email, staging });
      setStep("request");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setLoading(false);
    }
  };

  const requestCertificate = async () => {
    setLoading(true);
    setError(null);
    setRequestStatus("pending");
    setResultMessage("");
    try {
      const response = await api.requestSSLCertificate({
        domain,
        email,
        staging,
      });
      if (response.success) {
        setRequestStatus("success");
        setResultMessage(response.message || "SSL certificate issued successfully");
        setStep("complete");
        onSuccess?.();
      } else {
        setRequestStatus("error");
        setError(response.error || "Failed to request certificate");
      }
    } catch (err: unknown) {
      setRequestStatus("error");
      // Try to extract error message from response
      const error = err as { message?: string; error?: string };
      const errorMessage = error?.error || error?.message || "Failed to request certificate";
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const goToStep = (newStep: WizardStep) => {
    setError(null);
    if (newStep === "dns") {
      verifyDNS();
    } else if (newStep === "email") {
      loadSSLSettings();
    }
    setStep(newStep);
  };

  if (!open) return null;

  const steps: { key: WizardStep; label: string; icon: typeof Shield }[] = [
    { key: "check", label: "Check", icon: Shield },
    { key: "dns", label: "DNS", icon: Globe },
    { key: "email", label: "Email", icon: Mail },
    { key: "request", label: "Request", icon: Lock },
  ];

  const currentStepIndex = steps.findIndex((s) => s.key === step);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={() => onOpenChange(false)}
      />

      {/* Dialog */}
      <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-hidden mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary-600" />
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                SSL Certificate Wizard
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Set up HTTPS for {domain}
              </p>
            </div>
          </div>
          <button
            onClick={() => onOpenChange(false)}
            className="p-2 text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Steps indicator */}
        {step !== "complete" && (
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <div className="flex items-center justify-center">
              {steps.map((s, index) => {
                const Icon = s.icon;
                const isActive = s.key === step;
                const isCompleted = index < currentStepIndex;

                return (
                  <div key={s.key} className="flex items-center">
                    <div
                      className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors",
                        isActive
                          ? "bg-primary-600 text-white"
                          : isCompleted
                          ? "bg-green-500 text-white"
                          : "bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400"
                      )}
                    >
                      {isCompleted ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Icon className="h-4 w-4" />
                      )}
                    </div>
                    {index < steps.length - 1 && (
                      <div
                        className={cn(
                          "w-12 h-0.5 mx-1",
                          index < currentStepIndex
                            ? "bg-green-500"
                            : "bg-gray-200 dark:bg-gray-700"
                        )}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Content */}
        <div className="px-6 py-6 overflow-y-auto max-h-[50vh]">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}

          {/* Step: Check */}
          {step === "check" && (
            <div className="space-y-4">
              <div className="text-center mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Checking SSL Certificate Status
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Verifying existing certificates for {domain}
                </p>
              </div>

              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
                </div>
              ) : certInfo ? (
                <div className="space-y-4">
                  {/* Current certificate status */}
                  <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div className="flex items-start gap-3">
                      {certInfo.exists && certInfo.valid_for_domain ? (
                        <ShieldCheck className="h-6 w-6 text-green-500 flex-shrink-0 mt-0.5" />
                      ) : certInfo.exists ? (
                        <ShieldAlert className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-0.5" />
                      ) : (
                        <ShieldAlert className="h-6 w-6 text-gray-400 flex-shrink-0 mt-0.5" />
                      )}
                      <div className="flex-1">
                        <h4 className="font-medium text-gray-900 dark:text-white">
                          {certInfo.exists
                            ? certInfo.valid_for_domain
                              ? "Valid Certificate Found"
                              : "Certificate Found (Not Valid for Domain)"
                            : "No Certificate Found"}
                        </h4>
                        {certInfo.exists && (
                          <div className="mt-2 text-sm text-gray-500 dark:text-gray-400 space-y-1">
                            <p>
                              <span className="font-medium">Issuer:</span> {certInfo.issuer}
                            </p>
                            {certInfo.expires_at && (
                              <p>
                                <span className="font-medium">Expires:</span>{" "}
                                {new Date(certInfo.expires_at).toLocaleDateString()} ({certInfo.days_left} days left)
                              </p>
                            )}
                            {certInfo.is_wildcard && (
                              <p className="text-blue-600 dark:text-blue-400">
                                This is a wildcard certificate
                              </p>
                            )}
                          </div>
                        )}
                        {!certInfo.exists && !certInfo.error && (
                          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                            This domain doesn't have an SSL certificate yet. Continue to set one up with Let's Encrypt.
                          </p>
                        )}
                        {certInfo.error && (
                          <p className="mt-2 text-sm text-red-500">{certInfo.error}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Wildcard certificates */}
                  {wildcardCerts.length > 0 && wildcardCerts.some((w) => w.exists && w.valid_for_domain) && (
                    <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
                      <div className="flex items-start gap-3">
                        <Shield className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
                        <div>
                          <h4 className="font-medium text-blue-700 dark:text-blue-300">
                            Wildcard Certificate Available
                          </h4>
                          <p className="text-sm text-blue-600 dark:text-blue-400 mt-1">
                            A wildcard certificate exists that covers this domain. You may not need a new certificate.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex justify-between pt-4">
                    <Button variant="secondary" onClick={() => onOpenChange(false)}>
                      Cancel
                    </Button>
                    <div className="flex gap-2">
                      <Button variant="ghost" onClick={checkCertificate} icon={RefreshCw}>
                        Recheck
                      </Button>
                      {(!certInfo.exists || !certInfo.valid_for_domain || (certInfo.days_left && certInfo.days_left < 30)) && (
                        <Button variant="primary" onClick={() => goToStep("dns")} icon={ArrowRight}>
                          Get Certificate
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {/* Step: DNS */}
          {step === "dns" && (
            <div className="space-y-4">
              <div className="text-center mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Verify DNS Configuration
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Ensure {domain} points to your server
                </p>
              </div>

              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
                </div>
              ) : dnsResult ? (
                <div className="space-y-4">
                  {/* DNS Status */}
                  <div
                    className={cn(
                      "p-4 rounded-lg border",
                      dnsResult.matches
                        ? "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800"
                        : "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800"
                    )}
                  >
                    <div className="flex items-start gap-3">
                      {dnsResult.matches ? (
                        <Check className="h-6 w-6 text-green-500 flex-shrink-0" />
                      ) : (
                        <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0" />
                      )}
                      <div className="flex-1">
                        <h4
                          className={cn(
                            "font-medium",
                            dnsResult.matches
                              ? "text-green-700 dark:text-green-400"
                              : "text-yellow-700 dark:text-yellow-400"
                          )}
                        >
                          {dnsResult.matches ? "DNS Configured Correctly" : "DNS Not Configured"}
                        </h4>
                        <div className="mt-2 text-sm space-y-1 text-gray-600 dark:text-gray-400">
                          <p>
                            <span className="font-medium">Domain:</span> {dnsResult.domain}
                          </p>
                          <p>
                            <span className="font-medium">Expected IP:</span> {dnsResult.expected_ip || serverIP}
                          </p>
                          <p>
                            <span className="font-medium">Resolved IPs:</span>{" "}
                            {dnsResult.resolved_ips?.length > 0
                              ? dnsResult.resolved_ips.join(", ")
                              : "None"}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* DNS Instructions */}
                  {!dnsResult.matches && (
                    <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                      <h4 className="font-medium text-gray-900 dark:text-white mb-2">
                        Add this DNS record:
                      </h4>
                      <div className="bg-white dark:bg-gray-900 p-3 rounded font-mono text-sm flex items-center justify-between border border-gray-200 dark:border-gray-700">
                        <span className="text-gray-900 dark:text-white">
                          A {domain} {serverIP || dnsResult.expected_ip}
                        </span>
                        <button
                          onClick={() => copyToClipboard(`${domain} A ${serverIP || dnsResult.expected_ip}`)}
                          className="p-1 text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        DNS changes can take 1-48 hours to propagate. Usually 1-5 minutes.
                      </p>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex justify-between pt-4">
                    <Button variant="secondary" onClick={() => goToStep("check")} icon={ArrowLeft}>
                      Back
                    </Button>
                    <div className="flex gap-2">
                      <Button variant="ghost" onClick={verifyDNS} icon={RefreshCw}>
                        Recheck DNS
                      </Button>
                      <Button
                        variant="primary"
                        onClick={() => goToStep("email")}
                        disabled={!dnsResult.configured && !dnsResult.matches}
                        icon={ArrowRight}
                      >
                        Continue
                      </Button>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {/* Step: Email */}
          {step === "email" && (
            <div className="space-y-4">
              <div className="text-center mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Let's Encrypt Configuration
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Configure email for certificate notifications
                </p>
              </div>

              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-start gap-2">
                    <Mail className="h-5 w-5 mt-8 text-gray-400" />
                    <Input
                      label="Email Address"
                      type="email"
                      placeholder="admin@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="flex-1"
                    />
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 ml-7">
                    Let's Encrypt will send expiry notifications to this email
                  </p>

                  <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        Use Staging Environment
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Test with staging first to avoid rate limits
                      </p>
                    </div>
                    <button
                      onClick={() => setStaging(!staging)}
                      className={cn(
                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                        staging ? "bg-primary-600" : "bg-gray-300 dark:bg-gray-600"
                      )}
                    >
                      <span
                        className={cn(
                          "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                          staging ? "translate-x-6" : "translate-x-1"
                        )}
                      />
                    </button>
                  </div>

                  {staging && (
                    <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-yellow-600 flex-shrink-0 mt-0.5" />
                        <span className="text-sm text-yellow-700 dark:text-yellow-300">
                          Staging certificates are not trusted by browsers. Disable staging for production use.
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex justify-between pt-4">
                    <Button variant="secondary" onClick={() => goToStep("dns")} icon={ArrowLeft}>
                      Back
                    </Button>
                    <Button
                      variant="primary"
                      onClick={saveEmail}
                      disabled={loading || !email}
                      icon={loading ? Loader2 : ArrowRight}
                    >
                      Continue
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step: Request */}
          {step === "request" && (
            <div className="space-y-4">
              <div className="text-center mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Request Certificate
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Ready to request SSL certificate for {domain}
                </p>
              </div>

              <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 space-y-3">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-gray-400" />
                  <span className="font-medium text-gray-700 dark:text-gray-300">Domain:</span>
                  <span className="text-gray-900 dark:text-white">{domain}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Mail className="h-4 w-4 text-gray-400" />
                  <span className="font-medium text-gray-700 dark:text-gray-300">Email:</span>
                  <span className="text-gray-900 dark:text-white">{email}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-gray-400" />
                  <span className="font-medium text-gray-700 dark:text-gray-300">Environment:</span>
                  <span className="text-gray-900 dark:text-white">{staging ? "Staging (Test)" : "Production"}</span>
                </div>
              </div>

              {requestStatus === "pending" && (
                <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Loader2 className="h-5 w-5 animate-spin text-blue-500" />
                    <div>
                      <p className="font-medium text-blue-700 dark:text-blue-300">
                        Requesting Certificate...
                      </p>
                      <p className="text-sm text-blue-600 dark:text-blue-400">
                        This may take up to 60 seconds
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="flex justify-between pt-4">
                <Button variant="secondary" onClick={() => goToStep("email")} disabled={loading} icon={ArrowLeft}>
                  Back
                </Button>
                <Button
                  variant="primary"
                  onClick={requestCertificate}
                  disabled={loading}
                  icon={loading ? Loader2 : ShieldCheck}
                >
                  Request Certificate
                </Button>
              </div>
            </div>
          )}

          {/* Step: Complete */}
          {step === "complete" && (
            <div className="space-y-4 text-center py-4">
              <div className="flex justify-center">
                <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                  <ShieldCheck className="h-8 w-8 text-green-600" />
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  SSL Certificate Issued!
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {resultMessage || `SSL certificate has been issued for ${domain}`}
                </p>
              </div>

              <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800 text-sm text-left space-y-2">
                <p className="flex items-center gap-2 text-green-700 dark:text-green-400">
                  <Check className="h-4 w-4" />
                  <span>Certificate successfully issued by Let's Encrypt</span>
                </p>
                <p className="flex items-center gap-2 text-green-700 dark:text-green-400">
                  <Check className="h-4 w-4" />
                  <span>Nginx configuration updated</span>
                </p>
                {staging && (
                  <p className="flex items-center gap-2 text-yellow-600 dark:text-yellow-400">
                    <AlertTriangle className="h-4 w-4" />
                    <span>This is a staging certificate (not trusted by browsers)</span>
                  </p>
                )}
              </div>

              <p className="text-sm text-gray-500 dark:text-gray-400">
                Your site is now accessible via HTTPS at{" "}
                <a
                  href={`https://${domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary-600 hover:underline"
                >
                  https://{domain}
                </a>
              </p>

              <Button variant="primary" onClick={() => onOpenChange(false)} className="mt-4">
                Done
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
