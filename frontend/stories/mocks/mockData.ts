/**
 * Mock Data Factory for Storybook
 *
 * Provides consistent mock data generation for all stories.
 * This ensures realistic and varied test data across components.
 */

import type { Agent, Container, Deployment, ScanResult } from '@/lib/api';

// ==================== Agent Mocks ====================

export const mockAgent = (overrides: Partial<Agent> = {}): Agent => ({
  id: 'agent-1',
  org_id: 'org-1',
  name: 'Production Agent',
  hostname: 'prod-server-01',
  status: 'active',
  version: '1.0.0',
  last_seen_at: new Date().toISOString(),
  created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
  ...overrides,
});

export const mockAgents = (count: number = 3): Agent[] =>
  Array.from({ length: count }, (_, i) =>
    mockAgent({
      id: `agent-${i + 1}`,
      name: i === 0 ? 'Production Agent' : i === 1 ? 'Staging Agent' : `Agent ${i + 1}`,
      hostname: `server-${String(i + 1).padStart(2, '0')}`,
      status: i === count - 1 ? 'offline' : 'active',
    })
  );

// ==================== Container Mocks ====================

export const mockContainer = (overrides: Partial<Container> = {}): Container => ({
  id: 'container-1',
  agent_id: 'agent-1',
  container_id: 'abc123def456',
  name: 'production-api',
  image: 'myorg/api:v2.3.1',
  stack_name: 'production',
  status: 'running',
  state: 'running',
  cpu_percent: 45.2,
  memory_mb: 512,
  memory_limit_mb: 2048,
  restart_count: 0,
  networks: ['bridge', 'internal'],
  created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
  ...overrides,
});

export const mockContainers = (count: number = 8): Container[] => {
  const names = [
    'production-api',
    'redis-cache',
    'postgres-db',
    'nginx-proxy',
    'worker-queue',
    'monitoring-agent',
    'log-aggregator',
    'backup-service',
  ];

  const images = [
    'myorg/api:v2.3.1',
    'redis:7-alpine',
    'postgres:15',
    'nginx:1.25-alpine',
    'myorg/worker:v1.5.2',
    'prometheus/node-exporter:latest',
    'grafana/loki:2.9.0',
    'myorg/backup:v0.8.1',
  ];

  return Array.from({ length: count }, (_, i) =>
    mockContainer({
      id: `container-${i + 1}`,
      container_id: `abc${i}def${i}123${i}`,
      name: names[i % names.length],
      image: images[i % images.length],
      status: i === count - 1 ? 'exited' : 'running',
      state: i === count - 1 ? 'exited' : 'running',
      cpu_percent: Math.random() * 80,
      memory_mb: Math.floor(Math.random() * 1536) + 256,
      restart_count: Math.floor(Math.random() * 3),
      created_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
    })
  );
};

// ==================== Deployment Mocks ====================

export const mockDeployment = (overrides: Partial<Deployment> = {}): Deployment => ({
  id: 'deploy-1',
  agent_id: 'agent-1',
  service_name: 'production-api',
  environment: 'production',
  image_repository: 'myorg/api',
  image_tag: 'v2.3.1',
  image_digest: 'sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  status: 'running',
  status_message: null,
  scan_result_id: 'scan-1',
  sbom_id: 'sbom-1',
  policy_decision: 'allow',
  policy_reason: null,
  git_repo: 'https://github.com/myorg/api',
  git_branch: 'main',
  git_commit: 'abc1234567890def1234567890abc1234567890d',
  ci_provider: 'github-actions',
  ci_pipeline_id: '12345678',
  ci_build_url: 'https://github.com/myorg/api/actions/runs/12345678',
  deployed_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  ...overrides,
});

export const mockDeployments = (count: number = 5): Deployment[] => {
  const services = ['api', 'web', 'worker', 'admin', 'mobile-api'];
  const environments = ['production', 'staging', 'development'];

  return Array.from({ length: count }, (_, i) => {
    const service = services[i % services.length];
    const env = environments[i % environments.length];

    return mockDeployment({
      id: `deploy-${i + 1}`,
      service_name: `${env}-${service}`,
      environment: env,
      image_repository: `myorg/${service}`,
      image_tag: `v${Math.floor(i / 2) + 1}.${i % 10}.${Math.floor(Math.random() * 10)}`,
      scan_result_id: `scan-${i + 1}`,
      sbom_id: `sbom-${i + 1}`,
      status: i === count - 1 ? 'failed' : 'running',
      policy_decision: i === 1 ? 'warn' : i === count - 2 ? 'deny' : 'allow',
      policy_reason: i === 1 ? 'Contains 2 high severity vulnerabilities' : i === count - 2 ? 'Critical vulnerabilities detected' : null,
      deployed_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
    });
  });
};

// ==================== Scan Result Mocks ====================

export const mockScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  id: 'scan-1',
  deployment_id: 'deploy-1',
  scanner_name: 'trivy',
  scanner_version: '0.48.1',
  total_count: 15,
  critical_count: 2,
  high_count: 5,
  medium_count: 6,
  low_count: 2,
  fixable_count: 10,
  scanned_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  scan_duration_ms: 12500,
  ...overrides,
});

export const mockScanResults = (severityProfile: 'clean' | 'low' | 'medium' | 'high' | 'critical' = 'medium'): ScanResult => {
  const profiles = {
    clean: { total: 0, critical: 0, high: 0, medium: 0, low: 0, fixable: 0 },
    low: { total: 8, critical: 0, high: 0, medium: 2, low: 6, fixable: 5 },
    medium: { total: 25, critical: 0, high: 5, medium: 12, low: 8, fixable: 18 },
    high: { total: 45, critical: 3, high: 15, medium: 18, low: 9, fixable: 35 },
    critical: { total: 68, critical: 12, high: 24, medium: 22, low: 10, fixable: 52 },
  };

  const profile = profiles[severityProfile];

  return mockScanResult({
    total_count: profile.total,
    critical_count: profile.critical,
    high_count: profile.high,
    medium_count: profile.medium,
    low_count: profile.low,
    fixable_count: profile.fixable,
  });
};

// ==================== Vulnerability Mocks ====================

export interface MockVulnerability {
  id: string;
  scan_result_id: string;
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  title: string;
  description: string;
  package_name: string;
  package_version: string;
  fixed_version: string | null;
  fix_available: boolean;
}

export const mockVulnerability = (
  id: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  overrides: Partial<MockVulnerability> = {}
): MockVulnerability => {
  const packages = ['openssl', 'libcurl', 'zlib', 'systemd', 'glibc', 'python3', 'nginx'];
  const pkg = packages[parseInt(id.split('-')[1]) % packages.length];

  const titles = {
    critical: `Critical buffer overflow in ${pkg}`,
    high: `Remote code execution vulnerability in ${pkg}`,
    medium: `Information disclosure in ${pkg}`,
    low: `Minor security issue in ${pkg}`,
  };

  const cvssScores = {
    critical: 9.0 + Math.random() * 1.0,
    high: 7.0 + Math.random() * 2.0,
    medium: 4.0 + Math.random() * 3.0,
    low: 1.0 + Math.random() * 3.0,
  };

  return {
    id,
    scan_result_id: 'scan-1',
    cve_id: `CVE-2024-${10000 + parseInt(id.split('-')[1])}`,
    severity: severity.toUpperCase(),
    cvss_score: parseFloat(cvssScores[severity].toFixed(1)),
    title: titles[severity],
    description: `This is a ${severity} severity vulnerability that affects ${pkg} and could potentially compromise system security.`,
    package_name: pkg,
    package_version: '1.0.0',
    fixed_version: severity !== 'low' ? '1.1.0' : null,
    fix_available: severity !== 'low',
    ...overrides,
  };
};

export const mockVulnerabilities = (
  count: number = 10,
  severityDistribution?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  }
): MockVulnerability[] => {
  const dist = severityDistribution || {
    critical: Math.floor(count * 0.1),
    high: Math.floor(count * 0.3),
    medium: Math.floor(count * 0.4),
    low: Math.floor(count * 0.2),
  };

  const severities: Array<'critical' | 'high' | 'medium' | 'low'> = [
    ...Array(dist.critical || 0).fill('critical'),
    ...Array(dist.high || 0).fill('high'),
    ...Array(dist.medium || 0).fill('medium'),
    ...Array(dist.low || 0).fill('low'),
  ];

  return Array.from({ length: Math.min(count, severities.length) }, (_, i) =>
    mockVulnerability(`vuln-${i + 1}`, severities[i])
  );
};

// ==================== CVE Summary Mocks ====================

export interface MockCVESummary {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  affected_packages: string[];
  running_count: number;
  blocked_count: number;
  first_seen: string;
  last_seen: string;
}

export const mockCVESummary = (
  severity: 'critical' | 'high' | 'medium' | 'low',
  runningCount: number = 0,
  blockedCount: number = 0,
  overrides: Partial<MockCVESummary> = {}
): MockCVESummary => {
  const packages = ['openssl', 'libcurl', 'zlib', 'systemd', 'glibc'];
  const id = Math.floor(Math.random() * 10000);

  const descriptions = {
    critical: 'Remote code execution vulnerability allowing arbitrary command execution with elevated privileges',
    high: 'Privilege escalation vulnerability in authentication mechanism allowing unauthorized access',
    medium: 'Information disclosure vulnerability exposing sensitive configuration data',
    low: 'Minor information leak in error messages under specific conditions',
  };

  const cvssScores = {
    critical: 9.0 + Math.random() * 1.0,
    high: 7.0 + Math.random() * 2.0,
    medium: 4.0 + Math.random() * 3.0,
    low: 1.0 + Math.random() * 3.0,
  };

  return {
    cve_id: `CVE-2024-${10000 + id}`,
    severity,
    cvss_v3_score: parseFloat(cvssScores[severity].toFixed(1)),
    description: descriptions[severity],
    affected_packages: packages.slice(0, Math.floor(Math.random() * 3) + 1),
    running_count: runningCount,
    blocked_count: blockedCount,
    first_seen: new Date(Date.now() - 86400000 * 30).toISOString(),
    last_seen: new Date(Date.now() - 86400000 * Math.floor(Math.random() * 7)).toISOString(),
    ...overrides,
  };
};

export const mockCVESummaries = (
  distribution: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  } = {}
): MockCVESummary[] => {
  const dist = {
    critical: distribution.critical || 2,
    high: distribution.high || 5,
    medium: distribution.medium || 8,
    low: distribution.low || 10,
  };

  const cves: MockCVESummary[] = [];

  for (let i = 0; i < dist.critical; i++) {
    cves.push(mockCVESummary('critical', Math.floor(Math.random() * 5) + 1, Math.floor(Math.random() * 3)));
  }
  for (let i = 0; i < dist.high; i++) {
    cves.push(mockCVESummary('high', Math.floor(Math.random() * 8) + 1, Math.floor(Math.random() * 2)));
  }
  for (let i = 0; i < dist.medium; i++) {
    cves.push(mockCVESummary('medium', Math.floor(Math.random() * 12) + 1, 0));
  }
  for (let i = 0; i < dist.low; i++) {
    cves.push(mockCVESummary('low', Math.floor(Math.random() * 15) + 5, 0));
  }

  return cves;
};

// ==================== Alert Mocks ====================

export interface MockAlert {
  id: string;
  message: string;
  severity: string;
  triggered_at: string;
  resolved_at: string | null;
}

export const mockAlert = (overrides: Partial<MockAlert> = {}): MockAlert => ({
  id: 'alert-1',
  message: 'High CPU usage detected on container production-api',
  severity: 'warning',
  triggered_at: new Date(Date.now() - 3600000).toISOString(),
  resolved_at: null,
  ...overrides,
});

export const mockAlerts = (count: number = 5, criticalCount: number = 0): MockAlert[] => {
  const messages = [
    'Critical vulnerability detected in production deployment',
    'High CPU usage detected on container',
    'Memory limit exceeded',
    'Container restart detected',
    'New security scan completed',
    'Policy violation detected',
    'Deployment failed health check',
    'SSL certificate expiring soon',
  ];

  const severities = ['critical', 'high', 'medium', 'low'];

  return Array.from({ length: count }, (_, i) => ({
    id: `alert-${i + 1}`,
    message: messages[i % messages.length],
    severity: i < criticalCount ? 'critical' : severities[Math.min(i, severities.length - 1)],
    triggered_at: new Date(Date.now() - 1000 * 60 * (i * 15 + 5)).toISOString(),
    resolved_at: i >= count - 2 ? new Date(Date.now() - 1000 * 60 * (i * 10)).toISOString() : null,
  }));
};

// ==================== Proxy Mocks ====================

export interface MockProxy {
  id: string;
  domain: string;
  upstream_target: string;
  status: string;
  ssl_enabled: boolean;
  created_at: string;
}

export const mockProxy = (overrides: Partial<MockProxy> = {}): MockProxy => ({
  id: 'proxy-1',
  domain: 'api.example.com',
  upstream_target: 'http://api:3000',
  status: 'active',
  ssl_enabled: true,
  created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  ...overrides,
});

export const mockProxies = (count: number = 5): MockProxy[] => {
  const domains = ['api', 'app', 'admin', 'docs', 'cdn'];

  return Array.from({ length: count }, (_, i) => ({
    id: `proxy-${i + 1}`,
    domain: `${domains[i % domains.length]}.example.com`,
    upstream_target: `http://${domains[i % domains.length]}:${3000 + i * 1000}`,
    status: i === count - 1 ? 'inactive' : 'active',
    ssl_enabled: i < 3,
    created_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
  }));
};

// ==================== SBOM Mocks ====================

export interface MockSBOM {
  id: string;
  deployment_id: string;
  format: string;
  spec_version: string;
  generator_name: string;
  generator_version: string;
  total_packages: number;
  os_packages: number;
  library_packages: number;
  created_at: string;
}

export const mockSBOM = (overrides: Partial<MockSBOM> = {}): MockSBOM => ({
  id: 'sbom-1',
  deployment_id: 'deploy-1',
  format: 'cyclonedx',
  spec_version: '1.5',
  generator_name: 'syft',
  generator_version: '0.100.0',
  total_packages: 245,
  os_packages: 180,
  library_packages: 65,
  created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  ...overrides,
});

// ==================== Export All ====================

export const mockData = {
  // Single items
  agent: mockAgent,
  container: mockContainer,
  deployment: mockDeployment,
  scanResult: mockScanResult,
  vulnerability: mockVulnerability,
  cveSummary: mockCVESummary,
  alert: mockAlert,
  proxy: mockProxy,
  sbom: mockSBOM,

  // Collections
  agents: mockAgents,
  containers: mockContainers,
  deployments: mockDeployments,
  scanResults: mockScanResults,
  vulnerabilities: mockVulnerabilities,
  cveSummaries: mockCVESummaries,
  alerts: mockAlerts,
  proxies: mockProxies,
};
