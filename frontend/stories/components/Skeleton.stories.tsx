import type { Meta, StoryObj } from '@storybook/react';
import { Skeleton } from '@/components/ui/Skeleton';

const meta: Meta<typeof Skeleton> = {
  title: 'Components/Skeleton',
  component: Skeleton,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Skeleton>;

// Basic variants
export const Rectangular: Story = {
  args: {
    variant: 'rectangular',
    width: 200,
    height: 100,
  },
};

export const Circular: Story = {
  args: {
    variant: 'circular',
    width: 80,
    height: 80,
  },
};

export const Text: Story = {
  args: {
    variant: 'text',
    width: '100%',
    height: 16,
  },
};

// Without animation
export const WithoutAnimation: Story = {
  args: {
    variant: 'rectangular',
    width: 200,
    height: 100,
    animate: false,
  },
};

// SkeletonText
export const TextLines: Story = {
  render: () => (
    <div className="w-96">
      <Skeleton.Text lines={3} />
    </div>
  ),
};

export const TextLinesCustomWidth: Story = {
  render: () => (
    <div className="w-96">
      <Skeleton.Text lines={5} lastLineWidth="30%" />
    </div>
  ),
};

// SkeletonCard
export const CardSkeleton: Story = {
  render: () => (
    <div className="w-96">
      <Skeleton.Card />
    </div>
  ),
};

export const CardSkeletonWithImage: Story = {
  render: () => (
    <div className="w-96">
      <Skeleton.Card hasImage />
    </div>
  ),
};

// SkeletonTable
export const TableSkeleton: Story = {
  render: () => (
    <div className="w-full max-w-4xl">
      <Skeleton.Table rows={5} columns={4} />
    </div>
  ),
};

export const TableSkeletonLarge: Story = {
  render: () => (
    <div className="w-full max-w-6xl">
      <Skeleton.Table rows={10} columns={6} />
    </div>
  ),
};

// Real-world: Loading Dashboard
export const LoadingDashboard: Story = {
  render: () => (
    <div className="w-full max-w-6xl space-y-6">
      {/* Page Header */}
      <div>
        <Skeleton height={32} width="40%" className="mb-2" />
        <Skeleton height={20} width="60%" />
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div
            key={index}
            className="p-4 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg"
          >
            <Skeleton height={16} width="60%" className="mb-3" />
            <Skeleton height={32} width="40%" className="mb-2" />
            <Skeleton height={12} width="80%" />
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <Skeleton height={24} width="30%" />
        </div>
        <Skeleton.Table rows={5} columns={5} />
      </div>
    </div>
  ),
};

// Real-world: Loading Vulnerability Card
export const LoadingVulnerabilityCard: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <Skeleton variant="circular" width={40} height={40} />
          <div className="flex-1">
            <Skeleton height={20} width="60%" className="mb-2" />
            <Skeleton height={16} width="40%" />
          </div>
        </div>
      </div>
      <div className="px-6 py-4">
        <Skeleton.Text lines={3} lastLineWidth="50%" />
      </div>
      <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex gap-2">
        <Skeleton height={36} width={80} />
        <Skeleton height={36} width={120} />
      </div>
    </div>
  ),
};

// Real-world: Loading User Profile
export const LoadingUserProfile: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
      <div className="flex items-center gap-4 mb-6">
        <Skeleton variant="circular" width={80} height={80} />
        <div className="flex-1">
          <Skeleton height={24} width="70%" className="mb-2" />
          <Skeleton height={16} width="50%" />
        </div>
      </div>
      <div className="space-y-4">
        <div>
          <Skeleton height={14} width="30%" className="mb-2" />
          <Skeleton height={20} width="100%" />
        </div>
        <div>
          <Skeleton height={14} width="30%" className="mb-2" />
          <Skeleton height={20} width="100%" />
        </div>
        <div>
          <Skeleton height={14} width="30%" className="mb-2" />
          <Skeleton height={60} width="100%" />
        </div>
      </div>
    </div>
  ),
};

// Real-world: Loading List
export const LoadingList: Story = {
  render: () => (
    <div className="w-full max-w-2xl space-y-3">
      {Array.from({ length: 5 }).map((_, index) => (
        <div
          key={index}
          className="flex items-center gap-4 p-4 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg"
        >
          <Skeleton variant="circular" width={48} height={48} />
          <div className="flex-1">
            <Skeleton height={20} width="60%" className="mb-2" />
            <Skeleton height={16} width="40%" />
          </div>
          <Skeleton height={32} width={80} />
        </div>
      ))}
    </div>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg space-y-6">
        <div>
          <Skeleton height={32} width="40%" className="mb-2" />
          <Skeleton height={20} width="60%" />
        </div>
        <div className="grid grid-cols-3 gap-4">
          <Skeleton.Card />
          <Skeleton.Card />
          <Skeleton.Card />
        </div>
        <Skeleton.Table rows={5} columns={4} />
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
