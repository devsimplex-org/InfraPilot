const API_BASE = process.env.NEXT_PUBLIC_API_URL || "/api/v1";

async function fetchAPI<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("access_token") : null;

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: "Request failed" }));
    throw new Error(error.error || "Request failed");
  }

  return res.json();
}

// Types
export interface Agent {
  id: string;
  org_id: string;
  name: string;
  hostname: string | null;
  status: "pending" | "active" | "offline";
  version: string | null;
  last_seen_at: string | null;
  created_at: string;
  enrollment_token?: string;
}

export interface Container {
  id: string;
  agent_id?: string;
  container_id: string;
  name: string;
  image: string;
  stack_name?: string | null;
  status: string;
  state?: string;
  cpu_percent?: number;
  memory_mb?: number;
  memory_limit_mb?: number;
  restart_count?: number;
  networks?: string[];
  created_at?: string;
}

export interface PortMapping {
  container_port: number;
  host_port: number;
  protocol: string;
  host_ip?: string;
}

export interface MountInfo {
  type: string;
  source: string;
  destination: string;
  mode: string;
  read_only: boolean;
}

export interface EnvVar {
  key: string;
  value: string;
}

export interface ContainerConfig {
  hostname: string;
  domainname: string;
  user: string;
  working_dir: string;
  entrypoint: string[];
  cmd: string[];
  restart_policy: string;
  privileged: boolean;
  tty: boolean;
  open_stdin: boolean;
}

export interface HealthCheckConfig {
  test: string[];
  interval: string;
  timeout: string;
  start_period: string;
  retries: number;
}

export interface HealthLogEntry {
  start: string;
  end: string;
  exit_code: number;
  output: string;
}

export interface NetworkDetail {
  name: string;
  network_id: string;
  ip_address: string;
  gateway: string;
  mac_address: string;
  aliases?: string[];
}

export interface ResourceLimits {
  cpu_shares: number;
  cpu_quota: number;
  cpu_period: number;
  cpuset_cpus: string;
  memory_limit: number;
  memory_swap: number;
  pids_limit: number;
}

export interface ContainerDetail extends Container {
  ports: PortMapping[];
  mounts: MountInfo[];
  environment: EnvVar[];
  config: ContainerConfig;
  health_check?: HealthCheckConfig;
  health_status?: string;
  health_log?: HealthLogEntry[];
  labels: Record<string, string>;
  network_details: NetworkDetail[];
  resources: ResourceLimits;
}

export interface Stack {
  name: string;
  container_count: number;
  running_count: number;
  status: "running" | "partial" | "stopped";
  containers: Container[];
}

export interface ProxyHost {
  id: string;
  agent_id: string;
  domain: string;
  upstream_target: string;
  ssl_enabled: boolean;
  ssl_expires_at: string | null;
  force_ssl: boolean;
  http2_enabled: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface LoginResponse {
  access_token?: string;
  refresh_token?: string;
  mfa_required?: boolean;
  mfa_token?: string;
}

export interface User {
  id: string;
  org_id: string;
  email: string;
  role: string;
  mfa_enabled: boolean;
}

// Network types for cross-network proxying
export interface DockerNetwork {
  id: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  containers: Record<string, string>;
}

export interface ContainerNetworkInfo {
  network_id: string;
  network_name: string;
  ip_address: string;
}

export interface NetworkCheckResult {
  connected: boolean;
  network_id: string;
  network_name?: string;
}

export interface NginxNetworkAttachment {
  id: string;
  agent_id: string;
  network_id: string;
  network_name: string;
  attached_at: string;
  attached_by?: string;
  status: "attached" | "detached" | "error";
  error_message?: string;
}

// Extended Docker Resource Types

export interface DockerNetworkDetail extends DockerNetwork {
  attachable: boolean;
  ipam: {
    driver: string;
    configs: Array<{
      subnet: string;
      gateway: string;
      ip_range?: string;
    }>;
  };
  options: Record<string, string>;
  labels: Record<string, string>;
  created_at: string;
}

export interface NetworkEndpoint {
  name: string;
  endpoint_id: string;
  mac_address: string;
  ipv4_address: string;
  ipv6_address?: string;
}

export interface CreateNetworkRequest {
  name: string;
  driver?: string;
  internal?: boolean;
  attachable?: boolean;
  labels?: Record<string, string>;
}

export interface DockerVolume {
  name: string;
  driver: string;
  mountpoint: string;
  scope: string;
  labels: Record<string, string>;
  created_at: string;
  used_by: string[];
}

export interface CreateVolumeRequest {
  name: string;
  driver?: string;
  driver_opts?: Record<string, string>;
  labels?: Record<string, string>;
}

export interface DockerImage {
  id: string;
  tags: string[];
  size: number;
  size_mb: number;
  created: string;
  repo_digests: string[];
  used_by: string[];
}

export interface SecurityHeaders {
  id?: string;
  proxy_host_id?: string;
  hsts_enabled: boolean;
  hsts_max_age: number;
  x_frame_options: string;
  x_content_type_options: boolean;
  x_xss_protection: boolean;
  content_security_policy?: string | null;
}

// Rate limit types
export interface RateLimit {
  id: string;
  proxy_host_id: string;
  zone_name: string;
  requests_per: number;
  time_window: string;
  burst: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// MFA types
export interface MFASetupResponse {
  secret: string;
  otpauth: string;
}

export interface MFAConfirmResponse {
  message: string;
  backup_codes: string[];
}

// Alert types
export interface AlertChannel {
  id: string;
  org_id: string;
  name: string;
  channel_type: "smtp" | "slack" | "webhook";
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertRule {
  id: string;
  org_id: string;
  name: string;
  rule_type: string;
  conditions: Record<string, unknown>;
  channels: string[];
  cooldown_mins: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertHistoryEntry {
  id: string;
  rule_id?: string;
  rule_name?: string;
  agent_id?: string;
  agent_name?: string;
  triggered_at: string;
  resolved_at?: string;
  severity: string;
  message: string;
  metadata?: Record<string, unknown>;
}

// Log types
export interface LogEntry {
  timestamp: string;
  source: string;
  container_id?: string;
  container_name?: string;
  stream: string;
  level: string;
  message: string;
}

export interface UnifiedLogsResponse {
  logs: LogEntry[];
  count: number;
}

export interface NginxLogsResponse {
  logs: LogEntry[];
  type: string;
  count: number;
}

// Audit types
export interface AuditLogEntry {
  id: string;
  org_id?: string;
  user_id?: string;
  user_email?: string;
  agent_id?: string;
  agent_name?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  request_body?: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogsResponse {
  logs: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

// User management types
export interface UserAccount {
  id: string;
  org_id: string;
  email: string;
  role: "super_admin" | "admin" | "operator" | "viewer";
  mfa_enabled: boolean;
  last_login?: string;
  created_at: string;
  updated_at: string;
}

// Health monitoring types
export interface TLSHealthResult {
  domain: string;
  proxy_id: string;
  ssl_enabled: boolean;
  valid: boolean;
  issuer?: string;
  expires_at?: string;
  days_left?: number;
  score: number;
  status: "healthy" | "warning" | "critical" | "expired" | "none";
  error_message?: string;
}

export interface TLSHealthSummary {
  total_proxies: number;
  ssl_enabled: number;
  healthy: number;
  warning: number;
  critical: number;
  expired: number;
  overall_score: number;
  certificates: TLSHealthResult[];
}

export interface DatabaseHealth {
  status: "healthy" | "degraded" | "unhealthy";
  connected: boolean;
  latency_ms: number;
  active_connections: number;
  max_connections: number;
  idle_connections: number;
  database_size?: string;
  table_count: number;
  score: number;
}

export interface SystemHealth {
  status: string;
  uptime: string;
  goroutines: number;
  memory_mb: number;
  cpu_cores: number;
}

// SSL/Certificate types
export interface SSLCertificateInfo {
  exists: boolean;
  domain: string;
  issuer?: string;
  subject?: string;
  expires_at?: string;
  days_left?: number;
  is_wildcard?: boolean;
  valid_for_domain: boolean;
  error?: string;
  sans?: string[];
}

export interface SSLStatus {
  letsencrypt_email: string;
  letsencrypt_staging: boolean;
  account_configured: boolean;
  cert_directory: string;
}

export interface SSLRequestOptions {
  domain: string;
  email?: string;
  dns_provider?: string;
  staging?: boolean;
  force_renew?: boolean;
  ssl_source?: 'letsencrypt' | 'wildcard' | 'external';
  certificate_id?: string;
}

// SSL Certificate Management types
export type SSLSource = 'letsencrypt' | 'wildcard' | 'external' | 'dns_challenge';

export interface SSLCertificateRecord {
  id: string;
  org_id: string;
  name: string;
  domain: string;
  is_wildcard: boolean;
  cert_path: string;
  key_path: string;
  issuer?: string;
  subject?: string;
  san?: string;
  expires_at?: string;
  auto_detected: boolean;
  created_at: string;
  updated_at: string;
}

export interface SSLCertificateScanResult {
  certificates: SSLCertificateRecord[];
  scanned_dir: string;
}

export interface DNSInstructions {
  domain: string;
  server_ip: string;
  records: Array<{
    type: string;
    name: string;
    value: string;
    ttl: number;
  }>;
  instructions: string;
}

export interface DNSVerifyResult {
  domain: string;
  configured: boolean;
  resolved_ips: string[];
  expected_ip: string;
  matches: boolean;
  error?: string;
}

// Setup types
export interface SetupStatusResponse {
  setup_required: boolean;
  user_count: number;
}

export interface SetupResponse {
  message: string;
  user_id: string;
  access_token?: string;
  refresh_token?: string;
}

// System Settings types
export interface InfraPilotDomainSettings {
  domain: string;
  ssl_enabled: boolean;
  force_ssl: boolean;
  http2_enabled: boolean;
  proxy_host_id?: string;
  status?: string;
  ssl_source?: SSLSource;
  ssl_certificate_id?: string;
  ssl_cert_path?: string;
  ssl_key_path?: string;
}

// Default Pages types
export type DefaultPageType = "welcome" | "404" | "500" | "502" | "503" | "maintenance";

export interface DefaultPage {
  id?: string;
  org_id?: string;
  page_type: DefaultPageType;
  enabled: boolean;
  title: string;
  heading: string;
  message: string;
  show_logo: boolean;
  custom_css?: string;
  created_at?: string;
  updated_at?: string;
}

// SSO types
export type SSOProviderType = "saml" | "oidc" | "ldap";

export interface SSOProvider {
  id: string;
  org_id: string;
  name: string;
  provider_type: SSOProviderType;
  enabled: boolean;
  // SAML
  saml_entity_id?: string;
  saml_sso_url?: string;
  saml_slo_url?: string;
  saml_certificate?: string;
  saml_sign_requests?: boolean;
  saml_name_id_format?: string;
  // OIDC
  oidc_issuer?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_scopes?: string;
  oidc_redirect_uri?: string;
  // LDAP
  ldap_host?: string;
  ldap_port?: number;
  ldap_use_tls?: boolean;
  ldap_skip_verify?: boolean;
  ldap_bind_dn?: string;
  ldap_bind_password?: string;
  ldap_base_dn?: string;
  ldap_user_filter?: string;
  ldap_group_filter?: string;
  ldap_email_attr?: string;
  ldap_name_attr?: string;
  ldap_group_attr?: string;
  // Common
  default_role: string;
  auto_create_users: boolean;
  created_at: string;
  updated_at: string;
}

export interface SSOPublicProvider {
  id: string;
  name: string;
  provider_type: SSOProviderType;
}

export interface SSORoleMapping {
  id: string;
  provider_id: string;
  external_group: string;
  role: string;
  created_at: string;
}

export interface CreateSSOProviderRequest {
  name: string;
  provider_type: SSOProviderType;
  enabled?: boolean;
  // Type-specific fields
  saml_entity_id?: string;
  saml_sso_url?: string;
  saml_certificate?: string;
  oidc_issuer?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_scopes?: string;
  ldap_host?: string;
  ldap_port?: number;
  ldap_use_tls?: boolean;
  ldap_bind_dn?: string;
  ldap_bind_password?: string;
  ldap_base_dn?: string;
  ldap_user_filter?: string;
  // Common
  default_role?: string;
  auto_create_users?: boolean;
}

// Enterprise Audit & Compliance types
export interface AuditConfig {
  id: string;
  org_id: string;
  retention_days: number;
  retention_policy: "delete" | "archive" | "export";
  forwarding_enabled: boolean;
  forwarding_type?: "syslog" | "webhook" | "splunk" | "s3";
  forwarding_config?: Record<string, unknown>;
  compliance_mode?: "soc2" | "hipaa" | "gdpr" | "pci";
  immutable_logs: boolean;
  hash_chain_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditExport {
  id: string;
  org_id: string;
  format: "csv" | "json" | "cef" | "syslog";
  status: "pending" | "processing" | "completed" | "failed";
  start_date?: string;
  end_date?: string;
  filters?: Record<string, unknown>;
  row_count?: number;
  file_size?: number;
  download_url?: string;
  expires_at?: string;
  created_at: string;
  completed_at?: string;
}

export interface ComplianceReport {
  id: string;
  org_id: string;
  report_type: "soc2" | "hipaa" | "access" | "activity" | "security";
  status: "pending" | "generating" | "completed" | "failed";
  start_date: string;
  end_date: string;
  summary?: Record<string, unknown>;
  download_url?: string;
  created_at: string;
  completed_at?: string;
}

export interface IntegrityCheckResult {
  status: "valid" | "compromised";
  verified: number;
  broken_chain: number;
  broken_entries?: Array<{
    id: string;
    expected_prev: string;
    actual_prev: string;
  }>;
}

// License types
export type LicenseEdition = "community" | "enterprise";

export interface LicenseLimits {
  max_users: number;
  max_agents: number;
  max_resources: number;
}

export interface LicenseFeatureInfo {
  feature: string;
  name: string;
  description: string;
  licensed: boolean;
}

export interface LicenseInfo {
  edition: LicenseEdition;
  organization: string;
  features: LicenseFeatureInfo[];
  limits: LicenseLimits;
  valid: boolean;
  expires_at: string | null;
}

// Multi-tenancy types
export type OrgPlan = "free" | "pro" | "team" | "enterprise";
export type OrgMemberRole = "owner" | "admin" | "member" | "viewer";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: OrgPlan;
  stripe_customer_id?: string;
  subscription_status?: string;
  max_users: number;
  max_agents: number;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  member_role?: OrgMemberRole; // When listing user's orgs
}

export interface OrganizationMember {
  id: string;
  org_id: string;
  user_id: string;
  role: OrgMemberRole;
  invited_by?: string;
  joined_at: string;
  email?: string;
  user_name?: string;
}

export interface OrganizationInvitation {
  id: string;
  org_id: string;
  email: string;
  role: OrgMemberRole;
  token?: string;
  expires_at: string;
  accepted_at?: string;
  created_by?: string;
  created_at: string;
}

export interface EnrollmentToken {
  id: string;
  org_id: string;
  token?: string;
  name?: string;
  created_by?: string;
  expires_at?: string;
  max_uses?: number;
  use_count: number;
  labels: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  last_used_at?: string;
}

export interface OrgUsage {
  users: number;
  max_users: number;
  agents: number;
  max_agents: number;
}

export interface CreateOrgRequest {
  name: string;
  slug: string;
}

export interface UpdateOrgRequest {
  name?: string;
  max_users?: number;
  max_agents?: number;
  settings?: Record<string, unknown>;
}

export interface CreateInvitationRequest {
  email: string;
  role: OrgMemberRole;
}

export interface CreateEnrollmentTokenRequest {
  name?: string;
  expires_at?: string;
  max_uses?: number;
  labels?: Record<string, unknown>;
}

// Policy Engine types
export type PolicyType = "container" | "proxy" | "access" | "security";
export type PolicyAction = "block" | "warn" | "audit";

export interface Policy {
  id: string;
  org_id: string;
  name: string;
  description?: string;
  policy_type: PolicyType;
  conditions: Record<string, unknown>;
  action: PolicyAction;
  applies_to?: Record<string, unknown>;
  enabled: boolean;
  priority: number;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyTemplate {
  id: string;
  name: string;
  description?: string;
  policy_type: PolicyType;
  conditions: Record<string, unknown>;
  recommended_action: PolicyAction;
  category?: string;
  created_at: string;
}

export interface PolicyViolation {
  id: string;
  policy_id: string;
  policy_name?: string;
  org_id: string;
  agent_id?: string;
  agent_name?: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  message: string;
  details?: Record<string, unknown>;
  action_taken: PolicyAction;
  resolved: boolean;
  resolved_by?: string;
  resolved_at?: string;
  resolution_note?: string;
  created_at: string;
}

export interface PolicyStats {
  total_policies: number;
  enabled_policies: number;
  total_violations: number;
  unresolved_violations: number;
  blocked_actions: number;
  warned_actions: number;
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  policy_type: PolicyType;
  conditions: Record<string, unknown>;
  action: PolicyAction;
  applies_to?: Record<string, unknown>;
  enabled?: boolean;
  priority?: number;
}

export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  conditions?: Record<string, unknown>;
  action?: PolicyAction;
  applies_to?: Record<string, unknown>;
  enabled?: boolean;
  priority?: number;
}

// Deployments & Security Scanning
export interface Deployment {
  id: string;
  org_id: string;
  agent_id: string;
  service_name: string;
  environment: string;
  image_registry?: string;
  image_repository: string;
  image_tag?: string;
  image_digest?: string;
  git_repo?: string;
  git_branch?: string;
  git_commit?: string;
  ci_provider?: string;
  ci_pipeline_id?: string;
  ci_build_url?: string;
  scan_result_id?: string;
  sbom_id?: string;
  policy_decision?: "allow" | "warn" | "deny";
  policy_reason?: string;
  status: "pending" | "scanning" | "policy_check" | "deploying" | "running" | "failed" | "rolled_back" | "stopped";
  status_message?: string;
  container_id?: string;
  container_name?: string;
  proxy_host_id?: string;
  replaces_deployment_id?: string;
  rollback_of_deployment_id?: string;
  deployed_by?: string;
  deployed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanResult {
  id: string;
  org_id: string;
  image_digest?: string;
  image_repository: string;
  image_tag?: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  unknown_count: number;
  total_count: number;
  fixable_count: number;
  scanner_name: string;
  scanner_version?: string;
  scan_duration_ms?: number;
  scanned_at: string;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  package_name: string;
  package_version?: string;
  package_type?: string;
  fixed_version?: string;
  fix_available: boolean;
  title?: string;
  description?: string;
  cvss_score?: number;
  cvss_vector?: string;
  created_at: string;
}

export interface SBOM {
  id: string;
  org_id: string;
  image_digest?: string;
  image_repository: string;
  format: string;
  spec_version: string;
  total_packages: number;
  os_packages: number;
  library_packages: number;
  generator_name: string;
  generator_version?: string;
  created_at: string;
}

export interface CreateDeploymentRequest {
  service_name: string;
  environment: string;
  image_repository: string;
  image_tag?: string;
  image_digest?: string;
  git_repo?: string;
  git_branch?: string;
  git_commit?: string;
  ci_provider?: string;
  ci_pipeline_id?: string;
  ci_build_url?: string;
}

// Developer Feedback (Epic 8)
export interface Feedback {
  id: string;
  org_id: string;
  source_type: "vulnerability" | "policy_violation" | "sbom" | "drift" | "code_quality";
  source_id: string;
  provider: "github" | "gitlab" | "bitbucket" | "azure_devops";
  repo_full_name: string;
  pull_request_number?: number;
  commit_sha?: string;
  branch_name?: string;
  severity?: string;
  title: string;
  message: string;
  remediation?: string;
  metadata?: Record<string, any>;
  delivery_status: "pending" | "delivered" | "failed" | "skipped";
  delivered_at?: string;
  delivery_error?: string;
  external_id?: string;
  created_at: string;
  updated_at: string;
}

export interface VCSConfiguration {
  id: string;
  org_id: string;
  provider: "github" | "gitlab" | "bitbucket" | "azure_devops";
  enabled: boolean;
  auth_type: string;
  app_id?: string;
  installation_id?: string;
  default_repo?: string;
  auto_comment_on_pr: boolean;
  auto_comment_on_commit: boolean;
  created_at: string;
  updated_at: string;
}

export interface SaveVCSConfigRequest {
  provider: string;
  enabled: boolean;
  token?: string;
  default_repo?: string;
  auto_comment_on_pr: boolean;
  auto_comment_on_commit: boolean;
}

// Risk Exceptions (Epic 9)
export interface RiskException {
  id: string;
  org_id: string;
  scope_type: "cve" | "policy_rule" | "deployment" | "package" | "image";
  scope_reference: string;
  deployment_id?: string;
  scan_result_id?: string;
  requested_by: string;
  justification: string;
  business_impact?: string;
  mitigation_plan?: string;
  status: "pending" | "approved" | "denied" | "expired" | "revoked";
  approved_by?: string;
  approved_at?: string;
  denial_reason?: string;
  expires_at: string;
  auto_renewed: boolean;
  renewal_count: number;
  revoked_at?: string;
  revoked_by?: string;
  revoked_reason?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateExceptionRequest {
  scope_type: string;
  scope_reference: string;
  deployment_id?: string;
  scan_result_id?: string;
  justification: string;
  business_impact?: string;
  mitigation_plan?: string;
  duration_days: number;
  tags?: string[];
}

export interface ApproveExceptionRequest {
  comment?: string;
}

export interface DenyExceptionRequest {
  reason: string;
}

export interface RevokeExceptionRequest {
  reason: string;
}

// Service Ownership (Epic 10)
export interface ServiceOwnership {
  id: string;
  org_id: string;
  service_name: string;
  team_name: string;
  team_email?: string;
  team_slack_channel?: string;
  team_slack_webhook?: string;
  primary_contact_id?: string;
  secondary_contact_id?: string;
  primary_contact_email?: string;
  secondary_contact_email?: string;
  description?: string;
  repository_url?: string;
  documentation_url?: string;
  oncall_url?: string;
  tags?: string[];
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Team {
  id: string;
  org_id: string;
  name: string;
  display_name?: string;
  email?: string;
  slack_channel?: string;
  slack_webhook?: string;
  pagerduty_integration_key?: string;
  description?: string;
  manager_id?: string;
  tags?: string[];
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateServiceOwnershipRequest {
  service_name: string;
  team_name: string;
  team_email?: string;
  team_slack_channel?: string;
  team_slack_webhook?: string;
  primary_contact_email?: string;
  secondary_contact_email?: string;
  description?: string;
  repository_url?: string;
  documentation_url?: string;
  oncall_url?: string;
  tags?: string[];
  status?: string;
}

export interface CreateTeamRequest {
  name: string;
  display_name?: string;
  email?: string;
  slack_channel?: string;
  slack_webhook?: string;
  pagerduty_integration_key?: string;
  description?: string;
  tags?: string[];
}

// Security Maturity (Epic 11)
export interface SecurityScore {
  id: string;
  org_id: string;
  scope_type: string;
  scope_reference: string;
  overall_score: number;
  vulnerability_score?: number;
  policy_score?: number;
  deployment_score?: number;
  exception_score?: number;
  response_score?: number;
  total_deployments: number;
  vulnerable_deployments: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  policy_violations: number;
  active_exceptions: number;
  mean_time_to_fix_hours?: number;
  calculated_at: string;
  period_start: string;
  period_end: string;
  created_at: string;
}

export interface TeamScore {
  org_id: string;
  team_name: string;
  overall_score: number;
  vulnerability_score?: number;
  policy_score?: number;
  deployment_score?: number;
  exception_score?: number;
  response_score?: number;
  total_deployments: number;
  vulnerable_deployments: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  mean_time_to_fix_hours?: number;
  calculated_at: string;
}

export interface TeamLeaderboard {
  org_id: string;
  team_name: string;
  overall_score: number;
  rank: number;
  vulnerability_score?: number;
  policy_score?: number;
  response_score?: number;
  calculated_at: string;
}

export interface ScoreTrendPoint {
  id: string;
  overall_score: number;
  vulnerability_score?: number;
  policy_score?: number;
  response_score?: number;
  calculated_at: string;
  period_start: string;
  period_end: string;
}

export interface CalculateScoreRequest {
  scope_type: string;
  scope_reference: string;
  period_days?: number;
}

// Code Quality (Epic 12)
export interface CodeQualityResult {
  id: string;
  org_id: string;
  deployment_id?: string;
  tool: string;
  tool_version?: string;
  project_key: string;
  project_name?: string;
  git_repo?: string;
  git_branch?: string;
  commit_sha?: string;
  commit_author?: string;
  bugs: number;
  vulnerabilities: number;
  code_smells: number;
  security_hotspots: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  info_issues: number;
  coverage?: number;
  complexity?: number;
  duplication?: number;
  technical_debt_minutes?: number;
  quality_gate?: string;
  quality_gate_details?: string;
  scan_duration_ms?: number;
  lines_of_code?: number;
  files_analyzed?: number;
  raw_report?: any;
  created_at: string;
  updated_at: string;
}

export interface CodeQualityIssue {
  id: string;
  code_quality_result_id: string;
  issue_key?: string;
  rule_id: string;
  rule_name?: string;
  severity: string;
  issue_type: string;
  file_path: string;
  start_line?: number;
  end_line?: number;
  start_column?: number;
  end_column?: number;
  message: string;
  description?: string;
  cwe_ids?: string[];
  owasp_category?: string;
  confidence?: string;
  fix_available: boolean;
  fix_suggestion?: string;
  metadata?: any;
  created_at: string;
}

export interface CodeQualityPolicy {
  id: string;
  org_id: string;
  name: string;
  description?: string;
  environments: string[];
  projects: string[];
  tools: string[];
  max_critical?: number;
  max_high?: number;
  max_medium?: number;
  max_vulnerabilities?: number;
  max_bugs?: number;
  max_code_smells?: number;
  min_coverage?: number;
  max_complexity?: number;
  max_duplication?: number;
  enforcement: string;
  block_deployment: boolean;
  version: number;
  enabled: boolean;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyEvaluation {
  id: string;
  code_quality_result_id: string;
  policy_id?: string;
  decision: string;
  reason?: string;
  violations?: any;
  evaluation_time_ms?: number;
  created_at: string;
}

export interface ProjectQualitySummary {
  org_id: string;
  project_key: string;
  project_name?: string;
  tool: string;
  total_scans: number;
  avg_coverage?: number;
  avg_complexity?: number;
  avg_duplication?: number;
  total_bugs: number;
  total_vulnerabilities: number;
  total_code_smells: number;
  total_critical: number;
  total_high: number;
  failed_gates: number;
  passed_gates: number;
  last_scan_at: string;
}

export interface QualityLeaderboard {
  org_id: string;
  project_key: string;
  project_name?: string;
  tool: string;
  coverage?: number;
  complexity?: number;
  total_issues: number;
  critical_issues: number;
  high_issues: number;
  quality_gate?: string;
  last_scan_at: string;
  quality_score: number;
}

export interface CreateCodeQualityResultRequest {
  deployment_id?: string;
  tool: string;
  tool_version?: string;
  project_key: string;
  project_name?: string;
  git_repo?: string;
  git_branch?: string;
  commit_sha?: string;
  commit_author?: string;
  bugs: number;
  vulnerabilities: number;
  code_smells: number;
  security_hotspots: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  info_issues: number;
  coverage?: number;
  complexity?: number;
  duplication?: number;
  technical_debt_minutes?: number;
  quality_gate?: string;
  quality_gate_details?: string;
  scan_duration_ms?: number;
  lines_of_code?: number;
  files_analyzed?: number;
  raw_report?: any;
  issues?: CreateCodeQualityIssueRequest[];
}

export interface CreateCodeQualityIssueRequest {
  issue_key?: string;
  rule_id: string;
  rule_name?: string;
  severity: string;
  issue_type: string;
  file_path: string;
  start_line?: number;
  end_line?: number;
  start_column?: number;
  end_column?: number;
  message: string;
  description?: string;
  cwe_ids?: string[];
  owasp_category?: string;
  confidence?: string;
  fix_available: boolean;
  fix_suggestion?: string;
  metadata?: any;
}

// Platform Security (Epic 6)
export interface PlatformSecurityConfig {
  id: string;
  org_id: string;
  mfa_required_for_admins: boolean;
  docker_socket_read_only: boolean;
  tls_only: boolean;
  min_password_length: number;
  password_require_uppercase: boolean;
  password_require_lowercase: boolean;
  password_require_numbers: boolean;
  password_require_special: boolean;
  session_timeout_minutes: number;
  audit_logging_enabled: boolean;
  audit_logging_immutable: boolean;
  block_privileged_containers: boolean;
  block_docker_socket_mounts: boolean;
  block_docker_api_exposure: boolean;
  block_root_containers: boolean;
  block_host_network: boolean;
  block_host_pid: boolean;
  block_host_ipc: boolean;
  block_capability_additions: boolean;
  track_violation_attempts: boolean;
  alert_on_violations: boolean;
  max_violations_before_lockout?: number;
  created_at: string;
  updated_at: string;
}

export interface PolicyViolation {
  id: string;
  org_id: string;
  violation_type: string;
  severity: string;
  user_id?: string;
  user_email?: string;
  ip_address?: string;
  user_agent?: string;
  attempted_action: string;
  blocked: boolean;
  policy_rule?: string;
  description: string;
  request_payload?: any;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  notes?: string;
  created_at: string;
}

export interface SecurityCheck {
  check_name: string;
  status: string;
  severity: string;
  message: string;
  recommendation?: string;
}

export interface SecurityPosture {
  org_id: string;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  critical_failures: number;
  high_failures: number;
  last_check_at: string;
  overall_status: string;
}

export interface ViolationSummary {
  org_id: string;
  violation_type: string;
  violation_count: number;
  blocked_count: number;
  allowed_count: number;
  max_severity: string;
  last_violation_at: string;
  unique_users: number;
}

// Runtime Security (Epic 3)
export interface DriftEvent {
  id: string;
  org_id: string;
  agent_id: string;
  deployment_id: string;
  container_id: string;
  container_name: string;
  drift_type: string;
  severity: string;
  description: string;
  expected_state: any;
  actual_state: any;
  diff?: any;
  resolved: boolean;
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
  detected_at: string;
  created_at: string;
}

export interface BehavioralAnomaly {
  id: string;
  org_id: string;
  agent_id: string;
  deployment_id?: string;
  container_id?: string;
  container_name?: string;
  anomaly_type: string;
  severity: string;
  description: string;
  metrics: any;
  threshold: any;
  resolved: boolean;
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
  detected_at: string;
  first_seen_at: string;
  occurrence_count: number;
  created_at: string;
}

export interface RuntimeSecurityConfig {
  id: string;
  org_id: string;
  drift_detection_enabled: boolean;
  behavioral_monitoring_enabled: boolean;
  auto_resolve_info_drift: boolean;
  auto_resolve_after_hours: number;
  alert_on_critical_drift: boolean;
  alert_on_high_drift: boolean;
  alert_on_critical_anomaly: boolean;
  alert_on_high_anomaly: boolean;
  crash_loop_threshold: number;
  crash_loop_window_minutes: number;
  log_volume_spike_multiplier: number;
  error_rate_spike_multiplier: number;
  cpu_exhaustion_threshold_percent: number;
  mem_exhaustion_threshold_percent: number;
  network_spike_multiplier: number;
  process_spawn_threshold: number;
  created_at: string;
  updated_at: string;
}

export interface ContainerDriftSummary {
  container_name: string;
  deployment_id: string;
  total_drift: number;
  unresolved_drift: number;
  last_drift_at: string;
}

export interface RuntimeSecurityPosture {
  overall_status: string;
  drift_events_last_24h: number;
  anomalies_last_24h: number;
  unresolved_drift: number;
  unresolved_anomalies: number;
  critical_drift: number;
  critical_anomalies: number;
  drift_by_type: Record<string, number>;
  anomaly_by_type: Record<string, number>;
  top_affected_containers: ContainerDriftSummary[];
  recent_events: any[];
}

// Container Registry Types
export type RegistryProvider = 'ghcr' | 'dockerhub';
export type RegistryConnectionStatus = 'pending' | 'connected' | 'failed';

export interface ContainerRegistry {
  id: string;
  name: string;
  provider: RegistryProvider;
  enabled: boolean;
  namespace?: string;
  connection_status: RegistryConnectionStatus;
  connection_error?: string;
  last_connected_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateRegistryRequest {
  name: string;
  provider: RegistryProvider;
  namespace?: string;
  token?: string; // For GHCR
  username?: string; // For Docker Hub
  password?: string; // For Docker Hub
}

export interface UpdateRegistryRequest {
  name?: string;
  enabled?: boolean;
  namespace?: string;
  token?: string;
  username?: string;
  password?: string;
}

export interface RegistryRepository {
  name: string;
  full_name: string;
  description?: string;
  is_private: boolean;
  pull_count: number;
  updated_at?: string;
}

export interface RegistryTag {
  name: string;
  digest?: string;
  size_bytes: number;
  pushed_at?: string;
}

export interface ListRepositoriesResponse {
  repositories: RegistryRepository[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface ListTagsResponse {
  tags: RegistryTag[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface TestConnectionResponse {
  success: boolean;
  message?: string;
  error?: string;
}

// API methods
export const api = {
  // Setup (first-run)
  getSetupStatus: () => fetchAPI<SetupStatusResponse>("/setup/status"),

  createInitialAdmin: (email: string, password: string) =>
    fetchAPI<SetupResponse>("/setup", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  // Auth
  login: (email: string, password: string) =>
    fetchAPI<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  logout: () =>
    fetchAPI("/auth/logout", {
      method: "POST",
    }),

  refreshToken: (refreshToken: string) =>
    fetchAPI<{ access_token: string }>("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),

  getCurrentUser: () => fetchAPI<User>("/auth/me"),

  // Agents
  getAgents: () => fetchAPI<Agent[]>("/agents"),

  getAgent: (id: string) => fetchAPI<Agent>(`/agents/${id}`),

  createAgent: (name: string) =>
    fetchAPI<Agent>("/agents", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  deleteAgent: (id: string) =>
    fetchAPI(`/agents/${id}`, {
      method: "DELETE",
    }),

  // Containers
  getContainers: (agentId: string) =>
    fetchAPI<Container[]>(`/agents/${agentId}/containers`),

  getContainerDetail: (agentId: string, containerId: string) =>
    fetchAPI<ContainerDetail>(`/agents/${agentId}/containers/${containerId}`),

  startContainer: (agentId: string, containerId: string) =>
    fetchAPI(`/agents/${agentId}/containers/${containerId}/start`, {
      method: "POST",
    }),

  stopContainer: (agentId: string, containerId: string) =>
    fetchAPI(`/agents/${agentId}/containers/${containerId}/stop`, {
      method: "POST",
    }),

  restartContainer: (agentId: string, containerId: string) =>
    fetchAPI(`/agents/${agentId}/containers/${containerId}/restart`, {
      method: "POST",
    }),

  deleteContainer: (agentId: string, containerId: string, confirmName: string, force: boolean = false) =>
    fetchAPI<{ message: string; container_id: string; name: string }>(
      `/agents/${agentId}/containers/${containerId}`,
      {
        method: "DELETE",
        body: JSON.stringify({ confirm_name: confirmName, force }),
      }
    ),

  getContainerLogs: (agentId: string, containerId: string, tail: number = 100) =>
    fetchAPI<{ container_id: string; logs: string }>(
      `/agents/${agentId}/containers/${containerId}/logs?tail=${tail}`
    ),

  getStacks: (agentId: string) =>
    fetchAPI<Stack[]>(`/agents/${agentId}/stacks`),

  // Proxies
  getProxyHosts: (agentId: string) =>
    fetchAPI<ProxyHost[]>(`/agents/${agentId}/proxies`),

  getProxyHost: (agentId: string, proxyId: string) =>
    fetchAPI<ProxyHost>(`/agents/${agentId}/proxies/${proxyId}`),

  createProxyHost: (
    agentId: string,
    data: {
      domain: string;
      upstream_target: string;
      force_ssl?: boolean;
      http2_enabled?: boolean;
    }
  ) =>
    fetchAPI<ProxyHost>(`/agents/${agentId}/proxies`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateProxyHost: (
    agentId: string,
    proxyId: string,
    data: Partial<{
      domain: string;
      upstream_target: string;
      force_ssl: boolean;
      http2_enabled: boolean;
      status: string;
    }>
  ) =>
    fetchAPI<ProxyHost>(`/agents/${agentId}/proxies/${proxyId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteProxyHost: (agentId: string, proxyId: string) =>
    fetchAPI(`/agents/${agentId}/proxies/${proxyId}`, {
      method: "DELETE",
    }),

  requestSSL: (agentId: string, proxyId: string) =>
    fetchAPI(`/agents/${agentId}/proxies/${proxyId}/ssl`, {
      method: "POST",
    }),

  applyWildcardSSL: (
    agentId: string,
    proxyId: string,
    data: {
      ssl_enabled: boolean;
      force_ssl: boolean;
      http2_enabled: boolean;
      ssl_source: SSLSource;
      ssl_cert_path: string;
      ssl_key_path: string;
    }
  ) =>
    fetchAPI(`/agents/${agentId}/proxies/${proxyId}/ssl/wildcard`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getProxyConfig: (agentId: string, proxyId: string) =>
    fetchAPI<{ domain: string; config: string }>(
      `/agents/${agentId}/proxies/${proxyId}/config`
    ),

  getSecurityHeaders: (agentId: string, proxyId: string) =>
    fetchAPI<SecurityHeaders>(
      `/agents/${agentId}/proxies/${proxyId}/security-headers`
    ),

  updateSecurityHeaders: (
    agentId: string,
    proxyId: string,
    data: Omit<SecurityHeaders, "id" | "proxy_host_id">
  ) =>
    fetchAPI<SecurityHeaders>(
      `/agents/${agentId}/proxies/${proxyId}/security-headers`,
      {
        method: "PUT",
        body: JSON.stringify(data),
      }
    ),

  // Alerts - Channels
  getAlertChannels: () => fetchAPI<AlertChannel[]>("/alerts/channels"),

  createAlertChannel: (data: {
    name: string;
    channel_type: "smtp" | "slack" | "webhook";
    config: Record<string, unknown>;
    enabled?: boolean;
  }) =>
    fetchAPI<AlertChannel>("/alerts/channels", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateAlertChannel: (
    channelId: string,
    data: {
      name?: string;
      config?: Record<string, unknown>;
      enabled?: boolean;
    }
  ) =>
    fetchAPI<AlertChannel>(`/alerts/channels/${channelId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteAlertChannel: (channelId: string) =>
    fetchAPI(`/alerts/channels/${channelId}`, {
      method: "DELETE",
    }),

  testAlertChannel: (channelId: string) =>
    fetchAPI<{ success: boolean; message: string }>(`/alerts/channels/${channelId}/test`, {
      method: "POST",
    }),

  // Alerts - Rules
  getAlertRules: () => fetchAPI<AlertRule[]>("/alerts/rules"),

  createAlertRule: (data: {
    name: string;
    rule_type: string;
    conditions: Record<string, unknown>;
    channels: string[];
    cooldown_mins?: number;
    enabled?: boolean;
  }) =>
    fetchAPI<AlertRule>("/alerts/rules", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateAlertRule: (
    ruleId: string,
    data: {
      name?: string;
      conditions?: Record<string, unknown>;
      channels?: string[];
      cooldown_mins?: number;
      enabled?: boolean;
    }
  ) =>
    fetchAPI<AlertRule>(`/alerts/rules/${ruleId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteAlertRule: (ruleId: string) =>
    fetchAPI(`/alerts/rules/${ruleId}`, {
      method: "DELETE",
    }),

  // Alerts - History
  getAlertHistory: (limit?: number) =>
    fetchAPI<AlertHistoryEntry[]>(`/alerts/history${limit ? `?limit=${limit}` : ""}`),

  // Networks (for cross-network proxying)
  getNetworks: (agentId: string) =>
    fetchAPI<DockerNetwork[]>(`/agents/${agentId}/networks`),

  getContainerNetworks: (agentId: string, containerId: string) =>
    fetchAPI<ContainerNetworkInfo[]>(
      `/agents/${agentId}/containers/${containerId}/networks`
    ),

  checkNginxNetwork: (agentId: string, networkId: string) =>
    fetchAPI<NetworkCheckResult>(
      `/agents/${agentId}/networks/${networkId}/check-nginx`
    ),

  getNginxNetworkAttachments: (agentId: string) =>
    fetchAPI<NginxNetworkAttachment[]>(`/agents/${agentId}/networks/attachments`),

  attachNginxNetwork: (agentId: string, networkId: string) =>
    fetchAPI<{ success: boolean; id: string; network_id: string; network_name: string }>(
      `/agents/${agentId}/networks/attach`,
      {
        method: "POST",
        body: JSON.stringify({ network_id: networkId }),
      }
    ),

  detachNginxNetwork: (agentId: string, networkId: string) =>
    fetchAPI<{ success: boolean; network_id: string }>(
      `/agents/${agentId}/networks/detach`,
      {
        method: "POST",
        body: JSON.stringify({ network_id: networkId }),
      }
    ),

  // Docker Resources (Networks, Volumes, Images)

  // Docker Networks
  getDockerNetworks: (agentId: string) =>
    fetchAPI<DockerNetwork[]>(`/agents/${agentId}/docker/networks`),

  getDockerNetwork: (agentId: string, networkId: string) =>
    fetchAPI<DockerNetworkDetail>(`/agents/${agentId}/docker/networks/${networkId}`),

  createDockerNetwork: (agentId: string, data: CreateNetworkRequest) =>
    fetchAPI<DockerNetwork>(`/agents/${agentId}/docker/networks`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteDockerNetwork: (agentId: string, networkId: string, force?: boolean) =>
    fetchAPI<{ success: boolean; message: string }>(
      `/agents/${agentId}/docker/networks/${networkId}${force ? "?force=true" : ""}`,
      { method: "DELETE" }
    ),

  // Docker Volumes
  getDockerVolumes: (agentId: string) =>
    fetchAPI<DockerVolume[]>(`/agents/${agentId}/docker/volumes`),

  getDockerVolume: (agentId: string, name: string) =>
    fetchAPI<DockerVolume>(`/agents/${agentId}/docker/volumes/${encodeURIComponent(name)}`),

  createDockerVolume: (agentId: string, data: CreateVolumeRequest) =>
    fetchAPI<DockerVolume>(`/agents/${agentId}/docker/volumes`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteDockerVolume: (agentId: string, name: string, force?: boolean) =>
    fetchAPI<{ success: boolean; message: string }>(
      `/agents/${agentId}/docker/volumes/${encodeURIComponent(name)}${force ? "?force=true" : ""}`,
      { method: "DELETE" }
    ),

  // Docker Images
  getDockerImages: (agentId: string) =>
    fetchAPI<DockerImage[]>(`/agents/${agentId}/docker/images`),

  getDockerImage: (agentId: string, imageId: string) =>
    fetchAPI<DockerImage>(`/agents/${agentId}/docker/images/${encodeURIComponent(imageId)}`),

  pullDockerImage: (agentId: string, image: string) =>
    fetchAPI<{ success: boolean; message: string }>(
      `/agents/${agentId}/docker/images/pull`,
      {
        method: "POST",
        body: JSON.stringify({ image }),
      }
    ),

  deleteDockerImage: (agentId: string, imageId: string, force?: boolean) =>
    fetchAPI<{ success: boolean; message: string }>(
      `/agents/${agentId}/docker/images/${encodeURIComponent(imageId)}${force ? "?force=true" : ""}`,
      { method: "DELETE" }
    ),

  // Logs
  getUnifiedLogs: (
    agentId: string,
    options?: {
      sources?: string[];
      levels?: string[];
      search?: string;
      tail?: number;
      containers?: string[];
    }
  ) => {
    const params = new URLSearchParams();
    if (options?.sources) options.sources.forEach(s => params.append("sources", s));
    if (options?.levels) options.levels.forEach(l => params.append("levels", l));
    if (options?.search) params.set("search", options.search);
    if (options?.tail) params.set("tail", options.tail.toString());
    if (options?.containers) options.containers.forEach(c => params.append("containers", c));
    const query = params.toString();
    return fetchAPI<UnifiedLogsResponse>(`/agents/${agentId}/logs/unified${query ? `?${query}` : ""}`);
  },

  getNginxLogs: (agentId: string, type: "access" | "error" = "access", tail: number = 100) =>
    fetchAPI<NginxLogsResponse>(`/agents/${agentId}/logs/nginx?type=${type}&tail=${tail}`),

  // Audit logs
  getAuditLogs: (options?: { limit?: number; offset?: number; action?: string; resource_type?: string }) => {
    const params = new URLSearchParams();
    if (options?.limit) params.set("limit", options.limit.toString());
    if (options?.offset) params.set("offset", options.offset.toString());
    if (options?.action) params.set("action", options.action);
    if (options?.resource_type) params.set("resource_type", options.resource_type);
    const query = params.toString();
    return fetchAPI<AuditLogsResponse>(`/audit${query ? `?${query}` : ""}`);
  },

  // User management
  getUsers: () => fetchAPI<UserAccount[]>("/users"),

  createUser: (data: { email: string; password: string; role: string }) =>
    fetchAPI<UserAccount>("/users", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateUser: (userId: string, data: { email?: string; password?: string; role?: string }) =>
    fetchAPI<UserAccount>(`/users/${userId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteUser: (userId: string) =>
    fetchAPI(`/users/${userId}`, {
      method: "DELETE",
    }),

  // Health monitoring
  getTLSHealth: () => fetchAPI<TLSHealthSummary>("/health/tls"),
  getDBHealth: () => fetchAPI<DatabaseHealth>("/health/database"),
  getSystemHealth: () => fetchAPI<SystemHealth>("/health/system"),

  // Rate Limits
  getRateLimits: (agentId: string, proxyId: string) =>
    fetchAPI<RateLimit[]>(`/agents/${agentId}/proxies/${proxyId}/rate-limits`),

  createRateLimit: (
    agentId: string,
    proxyId: string,
    data: {
      zone_name: string;
      requests_per: number;
      time_window: string;
      burst?: number;
      enabled?: boolean;
    }
  ) =>
    fetchAPI<RateLimit>(`/agents/${agentId}/proxies/${proxyId}/rate-limits`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateRateLimit: (
    agentId: string,
    proxyId: string,
    rateLimitId: string,
    data: {
      zone_name: string;
      requests_per: number;
      time_window: string;
      burst?: number;
      enabled?: boolean;
    }
  ) =>
    fetchAPI<RateLimit>(
      `/agents/${agentId}/proxies/${proxyId}/rate-limits/${rateLimitId}`,
      {
        method: "PUT",
        body: JSON.stringify(data),
      }
    ),

  deleteRateLimit: (agentId: string, proxyId: string, rateLimitId: string) =>
    fetchAPI(`/agents/${agentId}/proxies/${proxyId}/rate-limits/${rateLimitId}`, {
      method: "DELETE",
    }),

  // MFA
  verifyMFA: (mfaToken: string, code: string) =>
    fetchAPI<LoginResponse>("/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    }),

  setupMFA: () => fetchAPI<MFASetupResponse>("/auth/mfa/setup", { method: "POST" }),

  confirmMFA: (code: string) =>
    fetchAPI<MFAConfirmResponse>("/auth/mfa/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),

  disableMFA: (password: string, code: string) =>
    fetchAPI<{ message: string }>("/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password, code }),
    }),

  regenerateBackupCodes: (code: string) =>
    fetchAPI<MFAConfirmResponse>("/auth/mfa/backup-codes", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),

  // System Settings
  getSystemSettings: () =>
    fetchAPI<Record<string, unknown>>("/settings"),

  getInfraPilotDomain: () =>
    fetchAPI<InfraPilotDomainSettings>("/settings/domain"),

  updateInfraPilotDomain: (data: {
    domain: string;
    ssl_enabled?: boolean;
    force_ssl?: boolean;
    http2_enabled?: boolean;
    ssl_source?: SSLSource;
    ssl_certificate_id?: string;
    ssl_cert_path?: string;
    ssl_key_path?: string;
  }) =>
    fetchAPI<InfraPilotDomainSettings>("/settings/domain", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteInfraPilotDomain: () =>
    fetchAPI<{ message: string }>("/settings/domain", {
      method: "DELETE",
    }),

  // SSL/TLS Certificate Management
  checkSSL: (domain: string, remote: boolean = false) =>
    fetchAPI<SSLCertificateInfo>(`/ssl/check/${encodeURIComponent(domain)}${remote ? '?remote=true' : ''}`),

  checkWildcardSSL: (domain: string) =>
    fetchAPI<{ domain: string; certificates: SSLCertificateInfo[] }>(
      `/ssl/check-wildcard/${encodeURIComponent(domain)}`
    ),

  getSSLStatus: () =>
    fetchAPI<SSLStatus>("/ssl/status"),

  updateSSLSettings: (data: { email: string; staging: boolean }) =>
    fetchAPI<{ email: string; staging: boolean; message: string }>("/ssl/settings", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  requestSSLCertificate: async (options: SSLRequestOptions): Promise<{
    success: boolean;
    message?: string;
    error?: string;
    domain: string;
    email?: string;
    staging?: boolean;
  }> => {
    const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
    const res = await fetch(`${API_BASE}/ssl/request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(options),
    });
    const data = await res.json();
    // Return the full response regardless of status code
    return data;
  },

  getDNSInstructions: (domain: string) =>
    fetchAPI<DNSInstructions>(`/ssl/dns-instructions/${encodeURIComponent(domain)}`),

  verifyDNS: (domain: string) =>
    fetchAPI<DNSVerifyResult>(`/ssl/verify-dns/${encodeURIComponent(domain)}`),

  // DNS-01 Challenge (for wildcard certificates)
  startDNSChallenge: async (options: { domain: string; email?: string; staging?: boolean }): Promise<{
    success: boolean;
    message?: string;
    error?: string;
    domain: string;
    txt_record?: string;
    txt_name?: string;
    txt_records?: { name: string; value: string }[];
    instructions?: string;
  }> => {
    const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
    const res = await fetch(`${API_BASE}/ssl/dns-challenge/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(options),
    });
    return res.json();
  },

  completeDNSChallenge: async (options: { domain: string; email?: string; staging?: boolean }): Promise<{
    success: boolean;
    message?: string;
    error?: string;
    domain: string;
  }> => {
    const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
    const res = await fetch(`${API_BASE}/ssl/dns-challenge/complete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(options),
    });
    return res.json();
  },

  getDNSChallenge: (domain: string) =>
    fetchAPI<{ success: boolean; domain: string; txt_record?: string; txt_name?: string; created_at?: string; error?: string }>(`/ssl/dns-challenge/${encodeURIComponent(domain)}`),

  verifyDNSTXTRecord: (domain: string, expectedValue?: string) =>
    fetchAPI<{ verified: boolean; txt_name: string; found: string[]; expected?: string; error?: string }>(
      `/ssl/dns-challenge/verify/${encodeURIComponent(domain)}${expectedValue ? `?value=${encodeURIComponent(expectedValue)}` : ''}`
    ),

  // SSL Certificate Management
  listSSLCertificates: () =>
    fetchAPI<SSLCertificateRecord[]>("/ssl/certificates"),

  scanSSLCertificates: () =>
    fetchAPI<SSLCertificateScanResult>("/ssl/certificates/scan"),

  registerSSLCertificate: (data: { name?: string; domain?: string; cert_path: string; key_path: string }) =>
    fetchAPI<{ id: string; name: string; domain: string; is_wildcard: boolean; issuer?: string; expires_at?: string; message: string }>("/ssl/certificates", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getSSLCertificate: (id: string) =>
    fetchAPI<SSLCertificateRecord>(`/ssl/certificates/${id}`),

  deleteSSLCertificate: (id: string) =>
    fetchAPI<{ message: string }>(`/ssl/certificates/${id}`, {
      method: "DELETE",
    }),

  // Default Pages
  getDefaultPages: () =>
    fetchAPI<DefaultPage[]>("/settings/default-pages"),

  getDefaultPage: (pageType: string) =>
    fetchAPI<DefaultPage>(`/settings/default-pages/${pageType}`),

  updateDefaultPage: (pageType: string, data: Partial<DefaultPage>) =>
    fetchAPI<DefaultPage>(`/settings/default-pages/${pageType}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  previewDefaultPage: (pageType: string) =>
    fetchAPI<{ html: string }>(`/settings/default-pages/${pageType}/preview`),

  // Nginx Management
  testNginxConfig: (agentId: string) =>
    fetchAPI<{ success: boolean; message: string }>(`/agents/${agentId}/nginx/test`, {
      method: "POST",
    }),

  reloadNginx: (agentId: string) =>
    fetchAPI<{ success: boolean; message: string }>(`/agents/${agentId}/nginx/reload`, {
      method: "POST",
    }),

  // License
  getLicenseInfo: () => fetchAPI<LicenseInfo>("/license"),

  // SSO Providers (admin)
  getSSOProviders: () => fetchAPI<SSOProvider[]>("/sso/providers"),
  getSSOProvider: (id: string) => fetchAPI<SSOProvider>(`/sso/providers/${id}`),
  createSSOProvider: (data: CreateSSOProviderRequest) =>
    fetchAPI<SSOProvider>("/sso/providers", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateSSOProvider: (id: string, data: Partial<CreateSSOProviderRequest>) =>
    fetchAPI<SSOProvider>(`/sso/providers/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  deleteSSOProvider: (id: string) =>
    fetchAPI(`/sso/providers/${id}`, {
      method: "DELETE",
    }),
  getSSOProviderMappings: (id: string) =>
    fetchAPI<SSORoleMapping[]>(`/sso/providers/${id}/mappings`),
  createSSOProviderMapping: (id: string, external_group: string, role: string) =>
    fetchAPI<SSORoleMapping>(`/sso/providers/${id}/mappings`, {
      method: "POST",
      body: JSON.stringify({ external_group, role }),
    }),
  deleteSSOProviderMapping: (providerId: string, mappingId: string) =>
    fetchAPI(`/sso/providers/${providerId}/mappings/${mappingId}`, {
      method: "DELETE",
    }),

  // SSO Public (for login page)
  getPublicSSOProviders: () => fetchAPI<SSOPublicProvider[]>("/auth/sso/providers"),

  // Enterprise Audit & Compliance
  getAuditConfig: () => fetchAPI<AuditConfig>("/audit/config"),

  updateAuditConfig: (data: {
    retention_days?: number;
    retention_policy?: "delete" | "archive" | "export";
    forwarding_enabled?: boolean;
    forwarding_type?: "syslog" | "webhook" | "splunk" | "s3";
    forwarding_config?: Record<string, unknown>;
    compliance_mode?: "soc2" | "hipaa" | "gdpr" | "pci" | null;
    immutable_logs?: boolean;
    hash_chain_enabled?: boolean;
  }) =>
    fetchAPI<{ message: string }>("/audit/config", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  // Audit Exports
  getAuditExports: () => fetchAPI<AuditExport[]>("/audit/exports"),

  createAuditExport: (data: {
    format: "csv" | "json" | "cef" | "syslog";
    start_date?: string;
    end_date?: string;
    filters?: Record<string, unknown>;
  }) =>
    fetchAPI<{ id: string; status: string; message: string }>("/audit/exports", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getAuditExport: (id: string) => fetchAPI<AuditExport>(`/audit/exports/${id}`),

  downloadAuditExport: (id: string) => `${API_BASE}/audit/exports/${id}/download`,

  // Compliance Reports
  getComplianceReports: () => fetchAPI<ComplianceReport[]>("/audit/reports"),

  createComplianceReport: (data: {
    report_type: "soc2" | "hipaa" | "access" | "activity" | "security";
    start_date: string;
    end_date: string;
  }) =>
    fetchAPI<{ id: string; status: string; message: string }>("/audit/reports", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getComplianceReport: (id: string) => fetchAPI<ComplianceReport>(`/audit/reports/${id}`),

  // Forwarding Test
  testAuditForwarding: () =>
    fetchAPI<{ message: string }>("/audit/forwarding/test", {
      method: "POST",
    }),

  // Retention Cleanup
  runRetentionCleanup: () =>
    fetchAPI<{ message: string; deleted: number; cutoff_date: string }>("/audit/retention/cleanup", {
      method: "POST",
    }),

  // Integrity Verification
  verifyAuditIntegrity: (limit?: number) =>
    fetchAPI<IntegrityCheckResult>(`/audit/integrity${limit ? `?limit=${limit}` : ""}`),

  // Organizations (Multi-tenancy)
  getOrganizations: () => fetchAPI<Organization[]>("/orgs"),

  getOrganization: (id: string) => fetchAPI<Organization>(`/orgs/${id}`),

  createOrganization: (data: CreateOrgRequest) =>
    fetchAPI<{ id: string }>("/orgs", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateOrganization: (id: string, data: UpdateOrgRequest) =>
    fetchAPI<{ status: string }>(`/orgs/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteOrganization: (id: string) =>
    fetchAPI<{ status: string }>(`/orgs/${id}`, {
      method: "DELETE",
    }),

  getOrganizationUsage: (id: string) => fetchAPI<OrgUsage>(`/orgs/${id}/usage`),

  // Organization Members
  getOrganizationMembers: (orgId: string) =>
    fetchAPI<OrganizationMember[]>(`/orgs/${orgId}/members`),

  addOrganizationMember: (orgId: string, userId: string, role: OrgMemberRole) =>
    fetchAPI<{ id: string }>(`/orgs/${orgId}/members`, {
      method: "POST",
      body: JSON.stringify({ user_id: userId, role }),
    }),

  updateOrganizationMember: (orgId: string, userId: string, role: OrgMemberRole) =>
    fetchAPI<{ status: string }>(`/orgs/${orgId}/members/${userId}`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    }),

  removeOrganizationMember: (orgId: string, userId: string) =>
    fetchAPI<{ status: string }>(`/orgs/${orgId}/members/${userId}`, {
      method: "DELETE",
    }),

  // Organization Invitations
  getOrganizationInvitations: (orgId: string) =>
    fetchAPI<OrganizationInvitation[]>(`/orgs/${orgId}/invitations`),

  createOrganizationInvitation: (orgId: string, data: CreateInvitationRequest) =>
    fetchAPI<{ id: string; token: string; expires_at: string }>(`/orgs/${orgId}/invitations`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  revokeOrganizationInvitation: (orgId: string, invitationId: string) =>
    fetchAPI<{ status: string }>(`/orgs/${orgId}/invitations/${invitationId}`, {
      method: "DELETE",
    }),

  acceptInvitation: (token: string) =>
    fetchAPI<{ status: string; org_id: string }>(`/invitations/${token}/accept`, {
      method: "POST",
    }),

  // Enrollment Tokens
  getEnrollmentTokens: (orgId: string) =>
    fetchAPI<EnrollmentToken[]>(`/orgs/${orgId}/enrollment-tokens`),

  createEnrollmentToken: (orgId: string, data: CreateEnrollmentTokenRequest) =>
    fetchAPI<{ id: string; token: string }>(`/orgs/${orgId}/enrollment-tokens`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  revokeEnrollmentToken: (orgId: string, tokenId: string) =>
    fetchAPI<{ status: string }>(`/orgs/${orgId}/enrollment-tokens/${tokenId}/revoke`, {
      method: "PUT",
    }),

  deleteEnrollmentToken: (orgId: string, tokenId: string) =>
    fetchAPI<{ status: string }>(`/orgs/${orgId}/enrollment-tokens/${tokenId}`, {
      method: "DELETE",
    }),

  // Policy Engine
  getPolicies: (options?: { type?: PolicyType; enabled?: boolean }) => {
    const params = new URLSearchParams();
    if (options?.type) params.set("type", options.type);
    if (options?.enabled !== undefined) params.set("enabled", options.enabled.toString());
    const query = params.toString();
    return fetchAPI<Policy[]>(`/policies${query ? `?${query}` : ""}`);
  },

  getPolicy: (id: string) => fetchAPI<Policy>(`/policies/${id}`),

  createPolicy: (data: CreatePolicyRequest) =>
    fetchAPI<{ id: string }>("/policies", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updatePolicy: (id: string, data: UpdatePolicyRequest) =>
    fetchAPI<{ status: string }>(`/policies/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deletePolicy: (id: string) =>
    fetchAPI<{ status: string }>(`/policies/${id}`, {
      method: "DELETE",
    }),

  // Policy Templates
  getPolicyTemplates: (category?: string) => {
    const query = category ? `?category=${category}` : "";
    return fetchAPI<PolicyTemplate[]>(`/policies/templates${query}`);
  },

  createPolicyFromTemplate: (templateId: string, data: { name: string; action?: PolicyAction; applies_to?: Record<string, unknown> }) =>
    fetchAPI<{ id: string; template: string }>(`/policies/templates/${templateId}/create`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Policy Violations
  getPolicyViolations: (options?: { resolved?: boolean; policy_id?: string; agent_id?: string }) => {
    const params = new URLSearchParams();
    if (options?.resolved !== undefined) params.set("resolved", options.resolved.toString());
    if (options?.policy_id) params.set("policy_id", options.policy_id);
    if (options?.agent_id) params.set("agent_id", options.agent_id);
    const query = params.toString();
    return fetchAPI<PolicyViolation[]>(`/policies/violations${query ? `?${query}` : ""}`);
  },

  getPolicyViolation: (id: string) => fetchAPI<PolicyViolation>(`/policies/violations/${id}`),

  resolvePolicyViolation: (id: string, resolutionNote: string) =>
    fetchAPI<{ status: string }>(`/policies/violations/${id}/resolve`, {
      method: "POST",
      body: JSON.stringify({ resolution_note: resolutionNote }),
    }),

  getPolicyStats: () => fetchAPI<PolicyStats>("/policies/stats"),

  // Deployments
  getDeployments: (agentId: string, params?: { service?: string; environment?: string; status?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.service) searchParams.set("service", params.service);
    if (params?.environment) searchParams.set("environment", params.environment);
    if (params?.status) searchParams.set("status", params.status);
    const query = searchParams.toString();
    return fetchAPI<Deployment[]>(`/agents/${agentId}/deployments${query ? `?${query}` : ""}`);
  },

  getDeployment: (agentId: string, deploymentId: string) =>
    fetchAPI<Deployment>(`/agents/${agentId}/deployments/${deploymentId}`),

  createDeployment: (agentId: string, request: CreateDeploymentRequest) =>
    fetchAPI<{ id: string; status: string; message: string }>(`/agents/${agentId}/deployments`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  rollbackDeployment: (agentId: string, deploymentId: string) =>
    fetchAPI<{ id: string; status: string; message: string }>(`/agents/${agentId}/deployments/${deploymentId}/rollback`, {
      method: "POST",
    }),

  // Services view (cross-agent)
  listServices: () => fetchAPI<Array<{ service_name: string; environment: string; agent_count: number }>>("/services"),

  listServiceDeployments: (serviceName: string) =>
    fetchAPI<Deployment[]>(`/services/${serviceName}/deployments`),

  getCurrentDeployment: (serviceName: string, params?: { environment?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.environment) searchParams.set("environment", params.environment);
    const query = searchParams.toString();
    return fetchAPI<Deployment>(`/services/${serviceName}/current${query ? `?${query}` : ""}`);
  },

  // Scan Results
  listScans: (params?: { org_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.org_id) searchParams.set("org_id", params.org_id);
    const query = searchParams.toString();
    return fetchAPI<ScanResult[]>(`/scans${query ? `?${query}` : ""}`);
  },

  getScanDetails: (scanId: string) => fetchAPI<ScanResult>(`/scans/${scanId}`),

  getScanVulnerabilities: (scanId: string, params?: { severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set("severity", params.severity);
    const query = searchParams.toString();
    return fetchAPI<Vulnerability[]>(`/scans/${scanId}/vulnerabilities${query ? `?${query}` : ""}`);
  },

  triggerImageScan: (request: { image: string; image_digest?: string; image_tag?: string }) =>
    fetchAPI<{ id: string; image: string; status: string }>("/scans", {
      method: "POST",
      body: JSON.stringify(request),
    }),

  // SBOMs
  listSBOMs: (params?: { org_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.org_id) searchParams.set("org_id", params.org_id);
    const query = searchParams.toString();
    return fetchAPI<SBOM[]>(`/sboms${query ? `?${query}` : ""}`);
  },

  generateSBOM: (request: { image: string }) =>
    fetchAPI<{ id: string; image: string; format: string; total_packages: number }>("/sboms", {
      method: "POST",
      body: JSON.stringify(request),
    }),

  downloadSBOM: (sbomId: string) => {
    const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
    window.open(`${API_BASE}/sboms/${sbomId}/download${token ? `?token=${token}` : ""}`, "_blank");
  },

  // Developer Feedback (Epic 8)
  listFeedback: (params?: { source_type?: string; status?: string; repo?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.source_type) searchParams.set("source_type", params.source_type);
    if (params?.status) searchParams.set("status", params.status);
    if (params?.repo) searchParams.set("repo", params.repo);
    const query = searchParams.toString();
    return fetchAPI<{ feedbacks: Feedback[]; count: number }>(`/feedback${query ? `?${query}` : ""}`);
  },

  getFeedback: (feedbackId: string) =>
    fetchAPI<Feedback>(`/feedback/${feedbackId}`),

  deliverFeedback: (feedbackId: string) =>
    fetchAPI<{ message: string }>(`/feedback/${feedbackId}/deliver`, {
      method: "POST",
    }),

  // VCS Configuration
  getVCSConfig: (provider: string) =>
    fetchAPI<VCSConfiguration>(`/vcs/${provider}`),

  saveVCSConfig: (provider: string, config: SaveVCSConfigRequest) =>
    fetchAPI<VCSConfiguration>(`/vcs/${provider}`, {
      method: "PUT",
      body: JSON.stringify(config),
    }),

  deleteVCSConfig: (provider: string) =>
    fetchAPI<{ message: string }>(`/vcs/${provider}`, {
      method: "DELETE",
    }),

  // Risk Exceptions (Epic 9)
  listExceptions: (params?: { scope_type?: string; status?: string; scope_reference?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.scope_type) searchParams.set("scope_type", params.scope_type);
    if (params?.status) searchParams.set("status", params.status);
    if (params?.scope_reference) searchParams.set("scope_reference", params.scope_reference);
    const query = searchParams.toString();
    return fetchAPI<{ exceptions: RiskException[]; count: number }>(`/exceptions${query ? `?${query}` : ""}`);
  },

  getException: (exceptionId: string) =>
    fetchAPI<RiskException>(`/exceptions/${exceptionId}`),

  createException: (request: CreateExceptionRequest) =>
    fetchAPI<RiskException>(`/exceptions`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  approveException: (exceptionId: string, request?: ApproveExceptionRequest) =>
    fetchAPI<{ message: string }>(`/exceptions/${exceptionId}/approve`, {
      method: "POST",
      body: JSON.stringify(request || {}),
    }),

  denyException: (exceptionId: string, request: DenyExceptionRequest) =>
    fetchAPI<{ message: string }>(`/exceptions/${exceptionId}/deny`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  revokeException: (exceptionId: string, request: RevokeExceptionRequest) =>
    fetchAPI<{ message: string }>(`/exceptions/${exceptionId}/revoke`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  getExceptionHistory: (exceptionId: string) =>
    fetchAPI<{ history: any[]; count: number }>(`/exceptions/${exceptionId}/history`),

  // Service Ownership (Epic 10)
  listServiceOwnerships: (params?: { service_name?: string; team_name?: string; status?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.service_name) searchParams.set("service_name", params.service_name);
    if (params?.team_name) searchParams.set("team_name", params.team_name);
    if (params?.status) searchParams.set("status", params.status);
    const query = searchParams.toString();
    return fetchAPI<{ ownerships: ServiceOwnership[]; count: number }>(`/ownership/services${query ? `?${query}` : ""}`);
  },

  getServiceOwnership: (ownershipId: string) =>
    fetchAPI<ServiceOwnership>(`/ownership/services/${ownershipId}`),

  createServiceOwnership: (request: CreateServiceOwnershipRequest) =>
    fetchAPI<{ id: string; message: string }>(`/ownership/services`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  updateServiceOwnership: (ownershipId: string, request: CreateServiceOwnershipRequest) =>
    fetchAPI<{ message: string }>(`/ownership/services/${ownershipId}`, {
      method: "PUT",
      body: JSON.stringify(request),
    }),

  deleteServiceOwnership: (ownershipId: string) =>
    fetchAPI<{ message: string }>(`/ownership/services/${ownershipId}`, {
      method: "DELETE",
    }),

  // Teams
  listTeams: (params?: { active?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.active !== undefined) searchParams.set("active", params.active.toString());
    const query = searchParams.toString();
    return fetchAPI<{ teams: Team[]; count: number }>(`/ownership/teams${query ? `?${query}` : ""}`);
  },

  createTeam: (request: CreateTeamRequest) =>
    fetchAPI<{ id: string; message: string }>(`/ownership/teams`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  updateTeam: (teamId: string, request: CreateTeamRequest) =>
    fetchAPI<{ message: string }>(`/ownership/teams/${teamId}`, {
      method: "PUT",
      body: JSON.stringify(request),
    }),

  deleteTeam: (teamId: string) =>
    fetchAPI<{ message: string }>(`/ownership/teams/${teamId}`, {
      method: "DELETE",
    }),

  // Security Maturity (Epic 11)
  listSecurityScores: (params?: { scope_type?: string; scope_reference?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.scope_type) searchParams.set("scope_type", params.scope_type);
    if (params?.scope_reference) searchParams.set("scope_reference", params.scope_reference);
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    const query = searchParams.toString();
    return fetchAPI<{ scores: SecurityScore[]; count: number }>(`/maturity/scores${query ? `?${query}` : ""}`);
  },

  getLatestTeamScores: () =>
    fetchAPI<{ team_scores: TeamScore[]; count: number }>(`/maturity/scores/teams`),

  getTeamLeaderboard: () =>
    fetchAPI<{ leaderboard: TeamLeaderboard[]; count: number }>(`/maturity/scores/leaderboard`),

  calculateSecurityScore: (request: CalculateScoreRequest) =>
    fetchAPI<SecurityScore>(`/maturity/scores/calculate`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  calculateAllTeamScores: () =>
    fetchAPI<{ message: string; total_teams: number; calculated: number }>(`/maturity/scores/calculate-all`, {
      method: "POST",
    }),

  getScoreTrend: (params: { scope_type: string; scope_reference: string }) => {
    const searchParams = new URLSearchParams();
    searchParams.set("scope_type", params.scope_type);
    searchParams.set("scope_reference", params.scope_reference);
    return fetchAPI<{
      scope_type: string;
      scope_reference: string;
      trend: ScoreTrendPoint[];
      trend_direction: string;
      data_points: number;
    }>(`/maturity/scores/trend?${searchParams.toString()}`);
  },

  // Code Quality (Epic 12)
  listCodeQualityResults: (params?: {
    tool?: string;
    project_key?: string;
    commit_sha?: string;
    quality_gate?: string;
    limit?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.tool) searchParams.set("tool", params.tool);
    if (params?.project_key) searchParams.set("project_key", params.project_key);
    if (params?.commit_sha) searchParams.set("commit_sha", params.commit_sha);
    if (params?.quality_gate) searchParams.set("quality_gate", params.quality_gate);
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    const query = searchParams.toString();
    return fetchAPI<{ results: CodeQualityResult[]; count: number; total: number }>(
      `/code-quality/results${query ? `?${query}` : ""}`
    );
  },

  getCodeQualityResult: (resultId: string) =>
    fetchAPI<CodeQualityResult>(`/code-quality/results/${resultId}`),

  createCodeQualityResult: (request: CreateCodeQualityResultRequest) =>
    fetchAPI<{ id: string; message: string }>(`/code-quality/results`, {
      method: "POST",
      body: JSON.stringify(request),
    }),

  getCodeQualityIssues: (resultId: string, params?: { severity?: string; issue_type?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.issue_type) searchParams.set("issue_type", params.issue_type);
    const query = searchParams.toString();
    return fetchAPI<{ issues: CodeQualityIssue[]; count: number }>(
      `/code-quality/results/${resultId}/issues${query ? `?${query}` : ""}`
    );
  },

  getProjectQualitySummary: () =>
    fetchAPI<{ summaries: ProjectQualitySummary[]; count: number }>(
      `/code-quality/summary`
    ),

  getCodeQualityLeaderboard: () =>
    fetchAPI<{ leaderboard: QualityLeaderboard[]; count: number }>(
      `/code-quality/leaderboard`
    ),

  // Code Quality Policies
  listCodeQualityPolicies: () =>
    fetchAPI<{ policies: CodeQualityPolicy[]; count: number }>(
      `/code-quality/policies`
    ),

  createCodeQualityPolicy: (policy: Partial<CodeQualityPolicy>) =>
    fetchAPI<CodeQualityPolicy>(`/code-quality/policies`, {
      method: "POST",
      body: JSON.stringify(policy),
    }),

  updateCodeQualityPolicy: (policyId: string, policy: Partial<CodeQualityPolicy>) =>
    fetchAPI<{ message: string }>(`/code-quality/policies/${policyId}`, {
      method: "PUT",
      body: JSON.stringify(policy),
    }),

  deleteCodeQualityPolicy: (policyId: string) =>
    fetchAPI<{ message: string }>(`/code-quality/policies/${policyId}`, {
      method: "DELETE",
    }),

  getCodeQualityPolicyEvaluations: (resultId: string) =>
    fetchAPI<{ evaluations: PolicyEvaluation[]; count: number }>(
      `/code-quality/results/${resultId}/evaluations`
    ),

  evaluateCodeQualityPolicies: (resultId: string) =>
    fetchAPI<{ results: any[]; count: number }>(
      `/code-quality/results/${resultId}/evaluate`,
      { method: "POST" }
    ),

  // Platform Security (Epic 6)
  getPlatformSecurityConfig: () =>
    fetchAPI<PlatformSecurityConfig>(`/security/config`),

  updatePlatformSecurityConfig: (config: Partial<PlatformSecurityConfig>) =>
    fetchAPI<{ message: string }>(`/security/config`, {
      method: "PUT",
      body: JSON.stringify(config),
    }),

  runSecuritySelfCheck: () =>
    fetchAPI<{ checks: SecurityCheck[]; summary: any }>(`/security/self-check`, {
      method: "POST",
    }),

  getSecurityPosture: () =>
    fetchAPI<SecurityPosture>(`/security/posture`),

  listPolicyViolations: (params?: {
    violation_type?: string;
    severity?: string;
    blocked?: boolean;
    acknowledged?: boolean;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.violation_type) searchParams.set("violation_type", params.violation_type);
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.blocked !== undefined) searchParams.set("blocked", params.blocked.toString());
    if (params?.acknowledged !== undefined) searchParams.set("acknowledged", params.acknowledged.toString());
    const query = searchParams.toString();
    return fetchAPI<{ violations: PolicyViolation[]; count: number }>(
      `/security/violations${query ? `?${query}` : ""}`
    );
  },

  getViolationSummary: () =>
    fetchAPI<{ summaries: ViolationSummary[]; count: number }>(
      `/security/violations/summary`
    ),

  acknowledgeViolation: (violationId: string, notes: string) =>
    fetchAPI<{ message: string }>(`/security/violations/${violationId}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  // Runtime Security (Epic 3)
  listDriftEvents: (params?: {
    severity?: string;
    drift_type?: string;
    resolved?: boolean;
    container_name?: string;
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.drift_type) searchParams.set("drift_type", params.drift_type);
    if (params?.resolved !== undefined) searchParams.set("resolved", params.resolved.toString());
    if (params?.container_name) searchParams.set("container_name", params.container_name);
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.offset) searchParams.set("offset", params.offset.toString());
    const query = searchParams.toString();
    return fetchAPI<{ drift_events: DriftEvent[]; total: number }>(
      `/runtime/drift-events${query ? `?${query}` : ""}`
    );
  },

  getDriftEvent: (eventId: string) =>
    fetchAPI<DriftEvent>(`/runtime/drift-events/${eventId}`),

  resolveDriftEvent: (eventId: string, notes: string) =>
    fetchAPI<{ message: string }>(`/runtime/drift-events/${eventId}/resolve`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  listBehavioralAnomalies: (params?: {
    severity?: string;
    anomaly_type?: string;
    resolved?: boolean;
    container_name?: string;
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.anomaly_type) searchParams.set("anomaly_type", params.anomaly_type);
    if (params?.resolved !== undefined) searchParams.set("resolved", params.resolved.toString());
    if (params?.container_name) searchParams.set("container_name", params.container_name);
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.offset) searchParams.set("offset", params.offset.toString());
    const query = searchParams.toString();
    return fetchAPI<{ anomalies: BehavioralAnomaly[]; total: number }>(
      `/runtime/anomalies${query ? `?${query}` : ""}`
    );
  },

  getBehavioralAnomaly: (anomalyId: string) =>
    fetchAPI<BehavioralAnomaly>(`/runtime/anomalies/${anomalyId}`),

  resolveBehavioralAnomaly: (anomalyId: string, notes: string) =>
    fetchAPI<{ message: string }>(`/runtime/anomalies/${anomalyId}/resolve`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  getRuntimeSecurityConfig: () =>
    fetchAPI<RuntimeSecurityConfig>(`/runtime/config`),

  updateRuntimeSecurityConfig: (config: Partial<RuntimeSecurityConfig>) =>
    fetchAPI<{ message: string }>(`/runtime/config`, {
      method: "PUT",
      body: JSON.stringify(config),
    }),

  getRuntimeSecurityPosture: () =>
    fetchAPI<RuntimeSecurityPosture>(`/runtime/posture`),

  // Container Registries
  getRegistries: () =>
    fetchAPI<ContainerRegistry[]>("/registries"),

  getRegistry: (registryId: string) =>
    fetchAPI<ContainerRegistry>(`/registries/${registryId}`),

  createRegistry: (data: CreateRegistryRequest) =>
    fetchAPI<ContainerRegistry>("/registries", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateRegistry: (registryId: string, data: UpdateRegistryRequest) =>
    fetchAPI<{ message: string }>(`/registries/${registryId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteRegistry: (registryId: string) =>
    fetchAPI<{ message: string }>(`/registries/${registryId}`, {
      method: "DELETE",
    }),

  testRegistryConnection: (registryId: string) =>
    fetchAPI<TestConnectionResponse>(`/registries/${registryId}/test`, {
      method: "POST",
    }),

  getRegistryRepositories: (registryId: string, page: number = 1, pageSize: number = 20) =>
    fetchAPI<ListRepositoriesResponse>(
      `/registries/${registryId}/repositories?page=${page}&page_size=${pageSize}`
    ),

  getRegistryTags: (registryId: string, repository: string, page: number = 1, pageSize: number = 20) =>
    fetchAPI<ListTagsResponse>(
      `/registries/${registryId}/repositories/${encodeURIComponent(repository)}/tags?page=${page}&page_size=${pageSize}`
    ),

  // Generic fetch for custom endpoints
  fetchAPI: <T>(endpoint: string, options?: RequestInit) => fetchAPI<T>(endpoint, options),
};
