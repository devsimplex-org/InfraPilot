import type { Meta, StoryObj } from '@storybook/react';
import { Table, Column } from '@/components/ui/Table';
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { AlertTriangle, CheckCircle2, XCircle, Clock, Package } from 'lucide-react';
import { useState } from 'react';

const meta: Meta<typeof Table> = {
  title: 'Components/Table',
  component: Table,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Table>;

// Sample data types
interface User {
  id: number;
  name: string;
  email: string;
  role: string;
  status: 'active' | 'inactive';
}

interface Vulnerability {
  id: string;
  cve_id: string;
  package_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fixed_version?: string;
  discovered_at: string;
}

interface Deployment {
  id: string;
  name: string;
  environment: string;
  status: 'healthy' | 'warning' | 'degraded' | 'critical';
  version: string;
  deployed_at: string;
  vulnerabilities: number;
}

// Sample data
const sampleUsers: User[] = [
  { id: 1, name: 'John Doe', email: 'john@example.com', role: 'Admin', status: 'active' },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'Developer', status: 'active' },
  { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'Viewer', status: 'inactive' },
  { id: 4, name: 'Alice Williams', email: 'alice@example.com', role: 'Developer', status: 'active' },
  { id: 5, name: 'Charlie Brown', email: 'charlie@example.com', role: 'Admin', status: 'active' },
];

const sampleVulnerabilities: Vulnerability[] = [
  {
    id: '1',
    cve_id: 'CVE-2024-12345',
    package_name: 'openssl',
    severity: 'critical',
    description: 'Remote code execution vulnerability in OpenSSL',
    fixed_version: '3.0.8',
    discovered_at: '2024-01-15T10:30:00Z',
  },
  {
    id: '2',
    cve_id: 'CVE-2024-12346',
    package_name: 'redis',
    severity: 'high',
    description: 'Authentication bypass in Redis server',
    fixed_version: '7.0.10',
    discovered_at: '2024-01-15T09:15:00Z',
  },
  {
    id: '3',
    cve_id: 'CVE-2024-12347',
    package_name: 'node',
    severity: 'high',
    description: 'Denial of service vulnerability in Node.js',
    fixed_version: '20.11.0',
    discovered_at: '2024-01-14T16:45:00Z',
  },
  {
    id: '4',
    cve_id: 'CVE-2024-12348',
    package_name: 'nginx',
    severity: 'medium',
    description: 'Information disclosure in Nginx',
    fixed_version: '1.24.0',
    discovered_at: '2024-01-14T14:20:00Z',
  },
  {
    id: '5',
    cve_id: 'CVE-2024-12349',
    package_name: 'postgresql',
    severity: 'low',
    description: 'Minor security issue in PostgreSQL',
    fixed_version: '16.1',
    discovered_at: '2024-01-13T11:00:00Z',
  },
];

const sampleDeployments: Deployment[] = [
  {
    id: '1',
    name: 'production-api-v2',
    environment: 'production',
    status: 'healthy',
    version: 'v2.4.1',
    deployed_at: '2024-01-15T08:00:00Z',
    vulnerabilities: 0,
  },
  {
    id: '2',
    name: 'staging-web-app',
    environment: 'staging',
    status: 'warning',
    version: 'v3.1.0-beta',
    deployed_at: '2024-01-15T06:30:00Z',
    vulnerabilities: 3,
  },
  {
    id: '3',
    name: 'production-worker',
    environment: 'production',
    status: 'degraded',
    version: 'v1.8.2',
    deployed_at: '2024-01-14T22:15:00Z',
    vulnerabilities: 5,
  },
  {
    id: '4',
    name: 'dev-api-gateway',
    environment: 'development',
    status: 'critical',
    version: 'v4.0.0-alpha',
    deployed_at: '2024-01-14T18:45:00Z',
    vulnerabilities: 12,
  },
];

// Basic Table
export const Default: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
  },
};

// Sortable columns
export const Sortable: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name', sortable: true },
      { key: 'email', header: 'Email', sortable: true },
      { key: 'role', header: 'Role', sortable: true },
      { key: 'status', header: 'Status', sortable: true },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
  },
};

// With custom rendering
export const CustomRendering: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      {
        key: 'status',
        header: 'Status',
        render: (value: string) => (
          <StatusBadge status={value === 'active' ? 'healthy' : 'critical'} size="sm">
            {value.toUpperCase()}
          </StatusBadge>
        ),
      },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
  },
};

// Clickable rows
export const ClickableRows: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
    onRowClick: (row: User) => alert(`Clicked on ${row.name}`),
  },
};

// With row selection
export const WithRowSelection: Story = {
  render: () => {
    const [selectedRows, setSelectedRows] = useState<Set<string | number>>(new Set());

    return (
      <div>
        <div className="mb-4 text-sm text-gray-600 dark:text-gray-400">
          Selected: {selectedRows.size} row(s)
        </div>
        <Table
          columns={[
            { key: 'name', header: 'Name' },
            { key: 'email', header: 'Email' },
            { key: 'role', header: 'Role' },
            { key: 'status', header: 'Status' },
          ]}
          data={sampleUsers}
          keyExtractor={(row: User) => row.id}
          selectedRows={selectedRows}
          onRowSelect={setSelectedRows}
        />
      </div>
    );
  },
};

// Sticky header
export const StickyHeader: Story = {
  render: () => (
    <div className="h-96 overflow-auto border border-gray-200 dark:border-gray-700 rounded-lg">
      <Table
        columns={[
          { key: 'name', header: 'Name' },
          { key: 'email', header: 'Email' },
          { key: 'role', header: 'Role' },
          { key: 'status', header: 'Status' },
        ]}
        data={[...sampleUsers, ...sampleUsers, ...sampleUsers]}
        keyExtractor={(row: User, index: number) => `${row.id}-${index}`}
        stickyHeader
      />
    </div>
  ),
};

// Loading state
export const LoadingState: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
    loading: true,
  },
};

// Empty state
export const EmptyState: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
    ] as Column<User>[],
    data: [],
    keyExtractor: (row: User) => row.id,
    emptyState: (
      <div className="text-center">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">No users found</h3>
        <p className="text-gray-500 dark:text-gray-400">
          Get started by adding your first user.
        </p>
      </div>
    ),
  },
};

// Real-world: Vulnerabilities Table
export const VulnerabilitiesTable: Story = {
  render: () => {
    const columns: Column<Vulnerability>[] = [
      {
        key: 'cve_id',
        header: 'CVE ID',
        sortable: true,
        render: (value) => (
          <span className="font-mono text-sm font-medium text-gray-900 dark:text-white">
            {value}
          </span>
        ),
      },
      {
        key: 'package_name',
        header: 'Package',
        sortable: true,
        render: (value) => (
          <span className="font-mono text-sm text-gray-700 dark:text-gray-300">
            {value}
          </span>
        ),
      },
      {
        key: 'severity',
        header: 'Severity',
        sortable: true,
        align: 'center',
        width: '120px',
        render: (value) => <SeverityBadge severity={value} size="sm" />,
      },
      {
        key: 'description',
        header: 'Description',
        render: (value) => (
          <span className="text-sm text-gray-600 dark:text-gray-400 line-clamp-1">
            {value}
          </span>
        ),
      },
      {
        key: 'fixed_version',
        header: 'Fixed In',
        align: 'center',
        render: (value) =>
          value ? (
            <span className="inline-flex items-center gap-1 text-xs font-medium text-green-700 dark:text-green-400">
              <CheckCircle2 className="h-3 w-3" />
              {value}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
              <XCircle className="h-3 w-3" />
              No fix
            </span>
          ),
      },
      {
        key: 'discovered_at',
        header: 'Discovered',
        sortable: true,
        align: 'right',
        render: (value) => (
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {new Date(value).toLocaleDateString()}
          </span>
        ),
      },
    ];

    return (
      <div className="w-full">
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Vulnerabilities
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            {sampleVulnerabilities.length} vulnerabilities detected in your deployments
          </p>
        </div>
        <Table
          columns={columns}
          data={sampleVulnerabilities}
          keyExtractor={(row: Vulnerability) => row.id}
          onRowClick={(row) => alert(`View details for ${row.cve_id}`)}
        />
      </div>
    );
  },
};

// Real-world: Deployments Table
export const DeploymentsTable: Story = {
  render: () => {
    const [selectedRows, setSelectedRows] = useState<Set<string | number>>(new Set());

    const columns: Column<Deployment>[] = [
      {
        key: 'name',
        header: 'Deployment Name',
        sortable: true,
        render: (value, row) => (
          <div>
            <div className="flex items-center gap-2">
              <Package className="h-4 w-4 text-gray-400" />
              <span className="font-medium text-gray-900 dark:text-white">{value}</span>
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {row.environment}
            </div>
          </div>
        ),
      },
      {
        key: 'status',
        header: 'Status',
        sortable: true,
        align: 'center',
        width: '120px',
        render: (value) => <StatusBadge status={value} size="sm" />,
      },
      {
        key: 'version',
        header: 'Version',
        align: 'center',
        render: (value) => (
          <span className="font-mono text-sm text-gray-700 dark:text-gray-300">
            {value}
          </span>
        ),
      },
      {
        key: 'vulnerabilities',
        header: 'Vulnerabilities',
        sortable: true,
        align: 'center',
        width: '140px',
        render: (value) => {
          if (value === 0) {
            return (
              <span className="inline-flex items-center gap-1 text-sm font-medium text-green-600 dark:text-green-400">
                <CheckCircle2 className="h-4 w-4" />
                None
              </span>
            );
          }
          return (
            <span className="inline-flex items-center gap-1 text-sm font-medium text-red-600 dark:text-red-400">
              <AlertTriangle className="h-4 w-4" />
              {value}
            </span>
          );
        },
      },
      {
        key: 'deployed_at',
        header: 'Deployed',
        sortable: true,
        align: 'right',
        render: (value) => {
          const date = new Date(value);
          const now = new Date();
          const diffHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));

          return (
            <div className="text-right">
              <div className="flex items-center justify-end gap-1 text-xs text-gray-500 dark:text-gray-400">
                <Clock className="h-3 w-3" />
                {diffHours < 1 ? 'Just now' : `${diffHours}h ago`}
              </div>
              <div className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                {date.toLocaleDateString()}
              </div>
            </div>
          );
        },
      },
    ];

    return (
      <div className="w-full">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              Deployments
            </h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {sampleDeployments.length} active deployments
            </p>
          </div>
          {selectedRows.size > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {selectedRows.size} selected
              </span>
              <button className="px-3 py-1.5 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700">
                Rollback
              </button>
            </div>
          )}
        </div>
        <Table
          columns={columns}
          data={sampleDeployments}
          keyExtractor={(row: Deployment) => row.id}
          selectedRows={selectedRows}
          onRowSelect={setSelectedRows}
          onRowClick={(row) => alert(`View deployment: ${row.name}`)}
        />
      </div>
    );
  },
};

// Different column alignments
export const ColumnAlignment: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name (Left)', align: 'left' },
      { key: 'email', header: 'Email (Center)', align: 'center' },
      { key: 'role', header: 'Role (Right)', align: 'right' },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
  },
};

// Custom row styling
export const CustomRowStyling: Story = {
  args: {
    columns: [
      { key: 'name', header: 'Name' },
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
    ] as Column<User>[],
    data: sampleUsers,
    keyExtractor: (row: User) => row.id,
    rowClassName: (row: User) =>
      row.status === 'inactive' ? 'opacity-50' : '',
  },
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <div className="mb-6">
          <h2 className="text-xl font-semibold text-white mb-2">
            Vulnerabilities (Dark Mode)
          </h2>
          <p className="text-sm text-gray-400">
            {sampleVulnerabilities.length} vulnerabilities detected
          </p>
        </div>
        <Table
          columns={[
            {
              key: 'cve_id',
              header: 'CVE ID',
              sortable: true,
              render: (value) => (
                <span className="font-mono text-sm font-medium text-white">{value}</span>
              ),
            },
            {
              key: 'package_name',
              header: 'Package',
              sortable: true,
            },
            {
              key: 'severity',
              header: 'Severity',
              sortable: true,
              align: 'center',
              render: (value) => <SeverityBadge severity={value} size="sm" />,
            },
            {
              key: 'description',
              header: 'Description',
              render: (value) => (
                <span className="text-sm text-gray-400 line-clamp-1">{value}</span>
              ),
            },
          ]}
          data={sampleVulnerabilities}
          keyExtractor={(row: Vulnerability) => row.id}
        />
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
