'use client';

import React, { useState, ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { X, ChevronDown, Search, SlidersHorizontal } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface FilterOption {
  label: string;
  value: string;
  count?: number;
}

export interface FilterGroup {
  id: string;
  label: string;
  type: 'checkbox' | 'radio' | 'search';
  options?: FilterOption[];
  value?: string | string[];
  onChange?: (value: string | string[]) => void;
}

export interface FilterPanelProps {
  filters: FilterGroup[];
  onReset?: () => void;
  className?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}

// ============================================================================
// FilterCheckboxGroup Component
// ============================================================================

function FilterCheckboxGroup({
  group,
  onChange,
}: {
  group: FilterGroup;
  onChange: (value: string[]) => void;
}) {
  const selectedValues = Array.isArray(group.value) ? group.value : [];

  const handleChange = (optionValue: string, checked: boolean) => {
    const newValues = checked
      ? [...selectedValues, optionValue]
      : selectedValues.filter((v) => v !== optionValue);
    onChange(newValues);
    group.onChange?.(newValues);
  };

  return (
    <div className="space-y-2">
      {group.options?.map((option) => (
        <label
          key={option.value}
          className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded px-2 py-1.5 transition-colors"
        >
          <input
            type="checkbox"
            checked={selectedValues.includes(option.value)}
            onChange={(e) => handleChange(option.value, e.target.checked)}
            className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
          />
          <span className="flex-1 text-sm text-gray-700 dark:text-gray-300">
            {option.label}
          </span>
          {option.count !== undefined && (
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {option.count}
            </span>
          )}
        </label>
      ))}
    </div>
  );
}

// ============================================================================
// FilterRadioGroup Component
// ============================================================================

function FilterRadioGroup({
  group,
  onChange,
}: {
  group: FilterGroup;
  onChange: (value: string) => void;
}) {
  const selectedValue = typeof group.value === 'string' ? group.value : '';

  const handleChange = (optionValue: string) => {
    onChange(optionValue);
    group.onChange?.(optionValue);
  };

  return (
    <div className="space-y-2">
      {group.options?.map((option) => (
        <label
          key={option.value}
          className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded px-2 py-1.5 transition-colors"
        >
          <input
            type="radio"
            name={group.id}
            checked={selectedValue === option.value}
            onChange={() => handleChange(option.value)}
            className="border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
          />
          <span className="flex-1 text-sm text-gray-700 dark:text-gray-300">
            {option.label}
          </span>
          {option.count !== undefined && (
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {option.count}
            </span>
          )}
        </label>
      ))}
    </div>
  );
}

// ============================================================================
// FilterSearchGroup Component
// ============================================================================

function FilterSearchGroup({
  group,
  onChange,
}: {
  group: FilterGroup;
  onChange: (value: string) => void;
}) {
  const searchValue = typeof group.value === 'string' ? group.value : '';

  const handleChange = (value: string) => {
    onChange(value);
    group.onChange?.(value);
  };

  return (
    <div className="relative">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
      <input
        type="text"
        value={searchValue}
        onChange={(e) => handleChange(e.target.value)}
        placeholder={`Search ${group.label.toLowerCase()}...`}
        className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
      />
    </div>
  );
}

// ============================================================================
// FilterPanel Component
// ============================================================================

export function FilterPanel({
  filters,
  onReset,
  className,
  collapsible = false,
  defaultCollapsed = false,
}: FilterPanelProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    new Set(filters.map((f) => f.id))
  );

  const toggleGroup = (groupId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  };

  const hasActiveFilters = filters.some((filter) => {
    if (Array.isArray(filter.value)) {
      return filter.value.length > 0;
    }
    return filter.value !== '' && filter.value !== undefined;
  });

  if (collapsible && collapsed) {
    return (
      <button
        onClick={() => setCollapsed(false)}
        className={cn(
          'inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors',
          className
        )}
      >
        <SlidersHorizontal className="h-4 w-4" />
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Filters
        </span>
        {hasActiveFilters && (
          <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-primary-100 dark:bg-primary-900 text-xs font-medium text-primary-700 dark:text-primary-300">
            {filters.filter((f) =>
              Array.isArray(f.value) ? f.value.length > 0 : f.value
            ).length}
          </span>
        )}
      </button>
    );
  }

  return (
    <div
      className={cn(
        'bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4',
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="h-4 w-4 text-gray-600 dark:text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
            Filters
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {hasActiveFilters && onReset && (
            <button
              onClick={onReset}
              className="text-xs text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 font-medium"
            >
              Reset
            </button>
          )}
          {collapsible && (
            <button
              onClick={() => setCollapsed(true)}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Filter Groups */}
      <div className="space-y-4">
        {filters.map((filter) => (
          <div key={filter.id}>
            <button
              onClick={() => toggleGroup(filter.id)}
              className="flex items-center justify-between w-full text-left mb-2"
            >
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {filter.label}
              </span>
              <ChevronDown
                className={cn(
                  'h-4 w-4 text-gray-400 transition-transform',
                  expandedGroups.has(filter.id) ? 'rotate-180' : ''
                )}
              />
            </button>

            {expandedGroups.has(filter.id) && (
              <div className="mt-2">
                {filter.type === 'checkbox' && (
                  <FilterCheckboxGroup
                    group={filter}
                    onChange={(value) => {
                      filter.value = value;
                    }}
                  />
                )}
                {filter.type === 'radio' && (
                  <FilterRadioGroup
                    group={filter}
                    onChange={(value) => {
                      filter.value = value;
                    }}
                  />
                )}
                {filter.type === 'search' && (
                  <FilterSearchGroup
                    group={filter}
                    onChange={(value) => {
                      filter.value = value;
                    }}
                  />
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
