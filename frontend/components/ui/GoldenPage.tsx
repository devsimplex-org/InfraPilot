"use client";

import React, { ReactNode, useState } from "react";
import { LucideIcon, Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Breadcrumb, BreadcrumbItem } from "./Breadcrumb";
import { StatCard, StatCardProps, MetricsGrid } from "./StatCard";
import { Tabs } from "./page-layout";

// ============================================================================
// Types
// ============================================================================

export interface GoldenPageTab {
  id: string;
  label: string;
  count?: number;
}

export interface GoldenPageBreadcrumb {
  label: string;
  href?: string;
}

export interface GoldenPageStat extends Omit<StatCardProps, "onClick"> {
  id: string;
  onClick?: (id: string) => void;
}

export interface GoldenPageProps {
  /** Page title */
  title: string;
  /** Page description/subtitle */
  description?: string;
  /** Breadcrumb navigation */
  breadcrumbs?: GoldenPageBreadcrumb[];
  /** Action buttons in header */
  actions?: ReactNode;
  /** Stats cards to display */
  stats?: GoldenPageStat[];
  /** Number of stat columns (1-6) */
  statColumns?: 1 | 2 | 3 | 4 | 5 | 6;
  /** Tab navigation */
  tabs?: GoldenPageTab[];
  /** Currently active tab */
  activeTab?: string;
  /** Tab change handler */
  onTabChange?: (tabId: string) => void;
  /** Enable search bar */
  searchable?: boolean;
  /** Search placeholder */
  searchPlaceholder?: string;
  /** Search value */
  searchValue?: string;
  /** Search change handler */
  onSearchChange?: (value: string) => void;
  /** Filter panel content */
  filterPanel?: ReactNode;
  /** Whether filter panel is visible */
  showFilters?: boolean;
  /** Toggle filter panel visibility */
  onToggleFilters?: () => void;
  /** Main content */
  children: ReactNode;
  /** Detail panel on the right */
  detailPanel?: ReactNode;
  /** Additional class names */
  className?: string;
  /** Loading state */
  isLoading?: boolean;
  /** Error state */
  error?: Error | null;
}

// ============================================================================
// Loading Skeleton
// ============================================================================

function GoldenPageSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      {/* Header skeleton */}
      <div className="space-y-2">
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-48" />
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-64" />
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-96" />
      </div>

      {/* Stats skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-24 bg-gray-200 dark:bg-gray-700 rounded-lg" />
        ))}
      </div>

      {/* Content skeleton */}
      <div className="space-y-4">
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded w-full" />
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-16 bg-gray-200 dark:bg-gray-700 rounded" />
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Error State
// ============================================================================

function GoldenPageError({ error }: { error: Error }) {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center mb-4">
        <X className="h-8 w-8 text-red-600 dark:text-red-400" />
      </div>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
        Error Loading Data
      </h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 text-center max-w-md">
        {error.message || "An unexpected error occurred. Please try again."}
      </p>
    </div>
  );
}

// ============================================================================
// GoldenPage Component
// ============================================================================

export function GoldenPage({
  title,
  description,
  breadcrumbs,
  actions,
  stats,
  statColumns = 4,
  tabs,
  activeTab,
  onTabChange,
  searchable,
  searchPlaceholder = "Search...",
  searchValue = "",
  onSearchChange,
  filterPanel,
  showFilters,
  onToggleFilters,
  children,
  detailPanel,
  className,
  isLoading,
  error,
}: GoldenPageProps) {
  if (isLoading) {
    return (
      <div className={cn("space-y-6", className)}>
        <GoldenPageSkeleton />
      </div>
    );
  }

  if (error) {
    return (
      <div className={cn("space-y-6", className)}>
        <GoldenPageError error={error} />
      </div>
    );
  }

  return (
    <div className={cn("flex h-full", className)}>
      {/* Main content area */}
      <div className="flex-1 flex flex-col min-w-0 space-y-6">
        {/* Header Section */}
        <div className="flex-shrink-0">
          {/* Breadcrumbs */}
          {breadcrumbs && breadcrumbs.length > 0 && (
            <Breadcrumb className="mb-2">
              {breadcrumbs.map((crumb, index) => (
                <BreadcrumbItem
                  key={index}
                  href={crumb.href}
                  isLast={index === breadcrumbs.length - 1}
                >
                  {crumb.label}
                </BreadcrumbItem>
              ))}
            </Breadcrumb>
          )}

          {/* Title and Actions */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                {title}
              </h1>
              {description && (
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  {description}
                </p>
              )}
            </div>
            {actions && <div className="flex items-center gap-2 ml-4">{actions}</div>}
          </div>
        </div>

        {/* Stats Section */}
        {stats && stats.length > 0 && (
          <MetricsGrid columns={statColumns}>
            {stats.map((stat) => (
              <StatCard
                key={stat.id}
                label={stat.label}
                value={stat.value}
                description={stat.description}
                icon={stat.icon}
                trend={stat.trend}
                trendValue={stat.trendValue}
                iconColor={stat.iconColor}
                valueColor={stat.valueColor}
                onClick={stat.onClick ? () => stat.onClick!(stat.id) : undefined}
              />
            ))}
          </MetricsGrid>
        )}

        {/* Tabs and Search Bar */}
        {(tabs || searchable) && (
          <div className="flex items-center justify-between flex-wrap gap-4">
            {tabs && tabs.length > 0 && (
              <Tabs
                tabs={tabs}
                activeTab={activeTab || tabs[0]?.id || ""}
                onChange={(id) => onTabChange?.(id)}
              />
            )}

            {searchable && (
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={searchValue}
                  onChange={(e) => onSearchChange?.(e.target.value)}
                  placeholder={searchPlaceholder}
                  className="pl-9 pr-4 py-2 w-64 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                {searchValue && (
                  <button
                    onClick={() => onSearchChange?.("")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* Filter Panel */}
        {filterPanel && showFilters && (
          <div className="flex-shrink-0">{filterPanel}</div>
        )}

        {/* Main Content */}
        <div className="flex-1 min-h-0">{children}</div>
      </div>

      {/* Detail Panel */}
      {detailPanel && (
        <div className="w-96 flex-shrink-0 ml-6 hidden lg:block">{detailPanel}</div>
      )}
    </div>
  );
}

// ============================================================================
// GoldenPage Subcomponents for Composition
// ============================================================================

export interface GoldenPageSectionProps {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function GoldenPageSection({
  title,
  description,
  actions,
  children,
  className,
}: GoldenPageSectionProps) {
  return (
    <div className={cn("space-y-4", className)}>
      {(title || description || actions) && (
        <div className="flex items-start justify-between">
          <div>
            {title && (
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                {title}
              </h2>
            )}
            {description && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {description}
              </p>
            )}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

export interface GoldenPageGridProps {
  children: ReactNode;
  columns?: 1 | 2 | 3 | 4;
  className?: string;
}

export function GoldenPageGrid({
  children,
  columns = 2,
  className,
}: GoldenPageGridProps) {
  const gridColsClass = {
    1: "lg:grid-cols-1",
    2: "lg:grid-cols-2",
    3: "lg:grid-cols-3",
    4: "lg:grid-cols-4",
  };

  return (
    <div
      className={cn(
        "grid grid-cols-1 gap-4",
        gridColsClass[columns],
        className
      )}
    >
      {children}
    </div>
  );
}
