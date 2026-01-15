import type { Meta, StoryObj } from '@storybook/react';
import { Spinner } from '@/components/ui/Spinner';
import { useState } from 'react';

const meta: Meta<typeof Spinner> = {
  title: 'Components/Spinner',
  component: Spinner,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Spinner>;

// Basic sizes
export const Small: Story = {
  args: {
    size: 'sm',
  },
};

export const Medium: Story = {
  args: {
    size: 'md',
  },
};

export const Large: Story = {
  args: {
    size: 'lg',
  },
};

export const ExtraLarge: Story = {
  args: {
    size: 'xl',
  },
};

// With label
export const WithLabel: Story = {
  args: {
    size: 'lg',
    label: 'Loading data...',
  },
};

// All sizes comparison
export const AllSizes: Story = {
  render: () => (
    <div className="flex items-end gap-8">
      <div className="flex flex-col items-center gap-2">
        <Spinner size="sm" />
        <span className="text-xs text-gray-500">Small</span>
      </div>
      <div className="flex flex-col items-center gap-2">
        <Spinner size="md" />
        <span className="text-xs text-gray-500">Medium</span>
      </div>
      <div className="flex flex-col items-center gap-2">
        <Spinner size="lg" />
        <span className="text-xs text-gray-500">Large</span>
      </div>
      <div className="flex flex-col items-center gap-2">
        <Spinner size="xl" />
        <span className="text-xs text-gray-500">Extra Large</span>
      </div>
    </div>
  ),
};

// PageSpinner
export const PageSpinner: Story = {
  render: () => (
    <div className="h-screen w-full">
      <Spinner.Page label="Loading application..." />
    </div>
  ),
};

// OverlaySpinner
export const OverlaySpinner: Story = {
  render: () => {
    const [loading, setLoading] = useState(false);

    return (
      <div className="relative">
        <div className="p-8 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Content Area
          </h3>
          <p className="text-gray-700 dark:text-gray-300 mb-4">
            Click the button below to show the overlay spinner.
          </p>
          <button
            onClick={() => {
              setLoading(true);
              setTimeout(() => setLoading(false), 2000);
            }}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
          >
            Show Overlay (2s)
          </button>
        </div>
        <Spinner.Overlay visible={loading} label="Processing..." />
      </div>
    );
  },
};

// In button
export const InButton: Story = {
  render: () => (
    <div className="flex gap-4">
      <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        <Spinner size="sm" className="text-white" />
        Loading...
      </button>
      <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
        <Spinner size="sm" className="text-gray-700 dark:text-gray-300" />
        Processing...
      </button>
      <button
        disabled
        className="inline-flex items-center gap-2 px-4 py-2 bg-primary-400 text-white rounded-lg cursor-not-allowed"
      >
        <Spinner size="sm" className="text-white" />
        Saving...
      </button>
    </div>
  ),
};

// In card
export const InCard: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-8">
      <Spinner size="lg" label="Loading data..." />
    </div>
  ),
};

// Inline with text
export const InlineWithText: Story = {
  render: () => (
    <div className="flex items-center gap-2 text-gray-700 dark:text-gray-300">
      <Spinner size="sm" />
      <span>Fetching latest deployments...</span>
    </div>
  ),
};

// Loading states in table
export const InTable: Story = {
  render: () => (
    <div className="w-full max-w-4xl border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <table className="min-w-full">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Name
            </th>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Action
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          <tr>
            <td colSpan={3} className="px-6 py-12">
              <Spinner size="md" label="Loading data..." />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  ),
};

// Custom color
export const CustomColor: Story = {
  render: () => (
    <div className="flex gap-8">
      <Spinner size="lg" className="text-red-600" />
      <Spinner size="lg" className="text-green-600" />
      <Spinner size="lg" className="text-blue-600" />
      <Spinner size="lg" className="text-purple-600" />
      <Spinner size="lg" className="text-orange-600" />
    </div>
  ),
};

// Real-world: Loading Dashboard
export const LoadingDashboard: Story = {
  render: () => (
    <div className="w-full max-w-6xl min-h-screen bg-gray-50 dark:bg-gray-950 p-8">
      <div className="mb-6">
        <div className="h-8 w-64 bg-gray-200 dark:bg-gray-800 rounded mb-2 animate-pulse" />
        <div className="h-5 w-96 bg-gray-200 dark:bg-gray-800 rounded animate-pulse" />
      </div>
      <div className="flex items-center justify-center py-32">
        <Spinner size="xl" label="Loading dashboard..." />
      </div>
    </div>
  ),
};

// Real-world: Form Submission
export const FormSubmission: Story = {
  render: () => {
    const [submitting, setSubmitting] = useState(false);

    return (
      <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Create Deployment
        </h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Name
            </label>
            <input
              type="text"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              placeholder="production-api"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Environment
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
              <option>Production</option>
              <option>Staging</option>
              <option>Development</option>
            </select>
          </div>
          <div className="flex gap-2 pt-2">
            <button
              onClick={() => {
                setSubmitting(true);
                setTimeout(() => setSubmitting(false), 2000);
              }}
              disabled={submitting}
              className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:bg-primary-400 disabled:cursor-not-allowed"
            >
              {submitting && <Spinner size="sm" className="text-white" />}
              {submitting ? 'Creating...' : 'Create'}
            </button>
            <button className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  },
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <div className="space-y-8">
          <Spinner size="xl" label="Loading application..." />
          <div className="flex gap-4">
            <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg">
              <Spinner size="sm" className="text-white" />
              Loading...
            </button>
            <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-300 rounded-lg">
              <Spinner size="sm" className="text-gray-300" />
              Processing...
            </button>
          </div>
        </div>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
