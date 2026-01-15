/**
 * Mock Data and Utilities for Storybook
 *
 * This module provides:
 * - Mock data factories for all entities (agents, deployments, vulnerabilities, etc.)
 * - React Query provider decorators for stories
 * - Utilities for creating realistic test data
 *
 * @example
 * ```tsx
 * import { mockData, createMockQueryDecorator } from '@/stories/mocks';
 *
 * export const MyStory: Story = {
 *   decorators: [
 *     createMockQueryDecorator({
 *       agents: mockData.agents(3),
 *       deployments: mockData.deployments(5),
 *     })
 *   ]
 * };
 * ```
 */

// Export all mock data factories
export * from './mockData';

// Export query provider utilities
export * from './queryProvider';

// Re-export commonly used items for convenience
export { mockData } from './mockData';
export { createMockQueryDecorator, createStoryQueryClient, MockQueryProvider } from './queryProvider';
