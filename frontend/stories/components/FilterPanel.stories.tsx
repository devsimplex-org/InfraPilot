import type { Meta, StoryObj } from '@storybook/react';
import { FilterPanel, FilterGroup } from '@/components/ui/FilterPanel';
import { useState } from 'react';

const meta: Meta<typeof FilterPanel> = {
  title: 'Components/FilterPanel',
  component: FilterPanel,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof FilterPanel>;

// Basic filter panel
export const Default: Story = {
  render: () => {
    const [filters, setFilters] = useState<FilterGroup[]>([
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
          { label: 'Low', value: 'low', count: 256 },
        ],
        onChange: (value) => {
          console.log('Severity changed:', value);
        },
      },
      {
        id: 'status',
        label: 'Status',
        type: 'radio',
        value: '',
        options: [
          { label: 'All', value: 'all' },
          { label: 'Resolved', value: 'resolved', count: 234 },
          { label: 'Unresolved', value: 'unresolved', count: 207 },
        ],
        onChange: (value) => {
          console.log('Status changed:', value);
        },
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel
          filters={filters}
          onReset={() => {
            setFilters(
              filters.map((f) => ({
                ...f,
                value: f.type === 'checkbox' ? [] : '',
              }))
            );
          }}
        />
      </div>
    );
  },
};

// With search filter
export const WithSearch: Story = {
  render: () => {
    const [filters] = useState<FilterGroup[]>([
      {
        id: 'search',
        label: 'Container Name',
        type: 'search',
        value: '',
        onChange: (value) => {
          console.log('Search changed:', value);
        },
      },
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
        ],
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel filters={filters} />
      </div>
    );
  },
};

// Collapsible
export const Collapsible: Story = {
  render: () => {
    const [filters] = useState<FilterGroup[]>([
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: ['critical', 'high'],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
          { label: 'Low', value: 'low', count: 256 },
        ],
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel filters={filters} collapsible />
      </div>
    );
  },
};

// Default collapsed
export const DefaultCollapsed: Story = {
  render: () => {
    const [filters] = useState<FilterGroup[]>([
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: ['critical'],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
        ],
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel filters={filters} collapsible defaultCollapsed />
      </div>
    );
  },
};

// Real-world: Vulnerability Filters
export const VulnerabilityFilters: Story = {
  render: () => {
    const [filters, setFilters] = useState<FilterGroup[]>([
      {
        id: 'cve',
        label: 'CVE ID',
        type: 'search',
        value: '',
        onChange: (value) => {
          console.log('CVE search:', value);
        },
      },
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
          { label: 'Low', value: 'low', count: 256 },
          { label: 'Info', value: 'info', count: 89 },
        ],
        onChange: (value) => {
          console.log('Severity filter:', value);
        },
      },
      {
        id: 'status',
        label: 'Resolution Status',
        type: 'radio',
        value: 'all',
        options: [
          { label: 'All', value: 'all', count: 530 },
          { label: 'Resolved', value: 'resolved', count: 234 },
          { label: 'Unresolved', value: 'unresolved', count: 296 },
          { label: 'Ignored', value: 'ignored', count: 45 },
        ],
        onChange: (value) => {
          console.log('Status filter:', value);
        },
      },
      {
        id: 'package',
        label: 'Package',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'openssl', value: 'openssl', count: 8 },
          { label: 'nginx', value: 'nginx', count: 12 },
          { label: 'node', value: 'node', count: 15 },
          { label: 'postgresql', value: 'postgresql', count: 6 },
          { label: 'redis', value: 'redis', count: 4 },
        ],
        onChange: (value) => {
          console.log('Package filter:', value);
        },
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel
          filters={filters}
          onReset={() => {
            setFilters(
              filters.map((f) => ({
                ...f,
                value: f.type === 'checkbox' ? [] : f.id === 'status' ? 'all' : '',
              }))
            );
          }}
        />
      </div>
    );
  },
};

// Real-world: Deployment Filters
export const DeploymentFilters: Story = {
  render: () => {
    const [filters, setFilters] = useState<FilterGroup[]>([
      {
        id: 'search',
        label: 'Deployment Name',
        type: 'search',
        value: '',
        onChange: (value) => {
          console.log('Search:', value);
        },
      },
      {
        id: 'environment',
        label: 'Environment',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Production', value: 'production', count: 12 },
          { label: 'Staging', value: 'staging', count: 8 },
          { label: 'Development', value: 'development', count: 15 },
        ],
        onChange: (value) => {
          console.log('Environment filter:', value);
        },
      },
      {
        id: 'status',
        label: 'Health Status',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Healthy', value: 'healthy', count: 28 },
          { label: 'Warning', value: 'warning', count: 4 },
          { label: 'Degraded', value: 'degraded', count: 2 },
          { label: 'Critical', value: 'critical', count: 1 },
        ],
        onChange: (value) => {
          console.log('Status filter:', value);
        },
      },
      {
        id: 'vulnerabilities',
        label: 'Vulnerabilities',
        type: 'radio',
        value: 'all',
        options: [
          { label: 'All deployments', value: 'all' },
          { label: 'Has critical', value: 'has-critical', count: 5 },
          { label: 'Has high', value: 'has-high', count: 12 },
          { label: 'Clean', value: 'clean', count: 18 },
        ],
        onChange: (value) => {
          console.log('Vulnerabilities filter:', value);
        },
      },
    ]);

    return (
      <div className="w-80">
        <FilterPanel
          filters={filters}
          collapsible
          onReset={() => {
            setFilters(
              filters.map((f) => ({
                ...f,
                value: f.type === 'checkbox' ? [] : f.id === 'vulnerabilities' ? 'all' : '',
              }))
            );
          }}
        />
      </div>
    );
  },
};

// With table
export const WithTable: Story = {
  render: () => {
    const [filters, setFilters] = useState<FilterGroup[]>([
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: [],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
        ],
      },
      {
        id: 'status',
        label: 'Status',
        type: 'radio',
        value: 'all',
        options: [
          { label: 'All', value: 'all' },
          { label: 'Resolved', value: 'resolved', count: 100 },
          { label: 'Unresolved', value: 'unresolved', count: 85 },
        ],
      },
    ]);

    return (
      <div className="flex gap-6">
        {/* Filter Panel */}
        <div className="w-80 flex-shrink-0">
          <FilterPanel
            filters={filters}
            onReset={() => {
              setFilters(
                filters.map((f) => ({
                  ...f,
                  value: f.type === 'checkbox' ? [] : 'all',
                }))
              );
            }}
          />
        </div>

        {/* Table */}
        <div className="flex-1 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
                  CVE ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
                  Severity
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
              <tr>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  CVE-2024-12345
                </td>
                <td className="px-6 py-4 text-sm text-red-600 dark:text-red-400">
                  Critical
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  Unresolved
                </td>
              </tr>
              <tr>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  CVE-2024-12346
                </td>
                <td className="px-6 py-4 text-sm text-orange-600 dark:text-orange-400">
                  High
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  Unresolved
                </td>
              </tr>
              <tr>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  CVE-2024-12347
                </td>
                <td className="px-6 py-4 text-sm text-yellow-600 dark:text-yellow-400">
                  Medium
                </td>
                <td className="px-6 py-4 text-sm text-green-600 dark:text-green-400">
                  Resolved
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    );
  },
};

// Dark Mode
export const DarkMode: Story = {
  render: () => {
    const [filters] = useState<FilterGroup[]>([
      {
        id: 'search',
        label: 'Search',
        type: 'search',
        value: '',
      },
      {
        id: 'severity',
        label: 'Severity',
        type: 'checkbox',
        value: ['critical', 'high'],
        options: [
          { label: 'Critical', value: 'critical', count: 12 },
          { label: 'High', value: 'high', count: 45 },
          { label: 'Medium', value: 'medium', count: 128 },
          { label: 'Low', value: 'low', count: 256 },
        ],
      },
      {
        id: 'status',
        label: 'Status',
        type: 'radio',
        value: 'unresolved',
        options: [
          { label: 'All', value: 'all', count: 441 },
          { label: 'Resolved', value: 'resolved', count: 234 },
          { label: 'Unresolved', value: 'unresolved', count: 207 },
        ],
      },
    ]);

    return (
      <div className="dark">
        <div className="bg-gray-950 p-8 rounded-lg">
          <div className="w-80">
            <FilterPanel filters={filters} onReset={() => {}} />
          </div>
        </div>
      </div>
    );
  },
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
