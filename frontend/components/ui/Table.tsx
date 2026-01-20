'use client';

import React, { useState, ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export type SortDirection = 'asc' | 'desc' | null;

export interface Column<T = any> {
  key: string;
  header: string | ReactNode;
  sortable?: boolean;
  width?: string;
  align?: 'left' | 'center' | 'right';
  render?: (value: any, row: T, index: number) => ReactNode;
}

export interface TableProps<T = any> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string | number;
  onRowClick?: (row: T, index: number) => void;
  selectedRows?: Set<string | number>;
  onRowSelect?: (keys: Set<string | number>) => void;
  stickyHeader?: boolean;
  loading?: boolean;
  emptyState?: ReactNode;
  className?: string;
  containerClassName?: string;
  rowClassName?: string | ((row: T, index: number) => string);
  hoverable?: boolean;
}

export interface TableHeaderProps {
  children: ReactNode;
  className?: string;
  sortable?: boolean;
  sortDirection?: SortDirection;
  onSort?: () => void;
  align?: 'left' | 'center' | 'right';
  width?: string;
}

export interface TableRowProps {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
  selected?: boolean;
  hoverable?: boolean;
}

export interface TableCellProps {
  children: ReactNode;
  className?: string;
  align?: 'left' | 'center' | 'right';
}

// ============================================================================
// TableHeader Component
// ============================================================================

export function TableHeader({
  children,
  className,
  sortable = false,
  sortDirection = null,
  onSort,
  align = 'left',
  width,
}: TableHeaderProps) {
  const alignClass = {
    left: 'text-left',
    center: 'text-center',
    right: 'text-right',
  };

  const content = (
    <>
      <span>{children}</span>
      {sortable && (
        <span className="ml-1 inline-flex">
          {sortDirection === 'asc' && <ChevronUp className="h-4 w-4" />}
          {sortDirection === 'desc' && <ChevronDown className="h-4 w-4" />}
          {sortDirection === null && <ChevronsUpDown className="h-4 w-4 text-gray-400" />}
        </span>
      )}
    </>
  );

  return (
    <th
      style={{ width }}
      className={cn(
        'px-6 py-3 text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50',
        alignClass[align],
        sortable && 'cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-gray-800',
        className
      )}
      onClick={sortable ? onSort : undefined}
    >
      <div className="flex items-center justify-between">
        {content}
      </div>
    </th>
  );
}

// ============================================================================
// TableRow Component
// ============================================================================

export function TableRow({
  children,
  className,
  onClick,
  selected = false,
  hoverable = true,
}: TableRowProps) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        'border-b border-gray-200 dark:border-gray-700 transition-colors',
        hoverable && 'hover:bg-gray-50 dark:hover:bg-gray-800/50',
        onClick && 'cursor-pointer',
        selected && 'bg-primary-50 dark:bg-primary-900/20',
        className
      )}
    >
      {children}
    </tr>
  );
}

// ============================================================================
// TableCell Component
// ============================================================================

export function TableCell({ children, className, align = 'left' }: TableCellProps) {
  const alignClass = {
    left: 'text-left',
    center: 'text-center',
    right: 'text-right',
  };

  return (
    <td
      className={cn(
        'px-6 py-4 text-sm text-gray-900 dark:text-gray-100',
        alignClass[align],
        className
      )}
    >
      {children}
    </td>
  );
}

// ============================================================================
// TableSkeleton Component
// ============================================================================

export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="animate-pulse">
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex gap-6 px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <div
              key={colIndex}
              className="h-4 bg-gray-200 dark:bg-gray-700 rounded flex-1"
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Table Component
// ============================================================================

export function Table<T = any>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  selectedRows,
  onRowSelect,
  stickyHeader = false,
  loading = false,
  emptyState,
  className,
  containerClassName,
  rowClassName,
  hoverable = true,
}: TableProps<T>) {
  const [sortConfig, setSortConfig] = useState<{
    key: string;
    direction: SortDirection;
  }>({ key: '', direction: null });

  // Handle sorting
  const handleSort = (columnKey: string) => {
    let direction: SortDirection = 'asc';

    if (sortConfig.key === columnKey) {
      if (sortConfig.direction === 'asc') {
        direction = 'desc';
      } else if (sortConfig.direction === 'desc') {
        direction = null;
      }
    }

    setSortConfig({ key: columnKey, direction });
  };

  // Sort data if needed
  const sortedData = React.useMemo(() => {
    if (!data) return [];
    if (!sortConfig.direction || !sortConfig.key) {
      return data;
    }

    return [...data].sort((a, b) => {
      const aValue = (a as any)[sortConfig.key];
      const bValue = (b as any)[sortConfig.key];

      if (aValue === bValue) return 0;

      const comparison = aValue < bValue ? -1 : 1;
      return sortConfig.direction === 'asc' ? comparison : -comparison;
    });
  }, [data, sortConfig]);

  // Handle row selection
  const handleRowSelect = (key: string | number) => {
    if (!onRowSelect || !selectedRows) return;

    const newSelectedRows = new Set(selectedRows);
    if (newSelectedRows.has(key)) {
      newSelectedRows.delete(key);
    } else {
      newSelectedRows.add(key);
    }
    onRowSelect(newSelectedRows);
  };

  // Empty state
  if (!loading && (!data || data.length === 0)) {
    return (
      <div className={cn('overflow-x-auto', containerClassName)}>
        <div className="min-w-full">
          <table className={cn('min-w-full divide-y divide-gray-200 dark:divide-gray-700', className)}>
            <thead className={cn(stickyHeader && 'sticky top-0 z-10')}>
              <tr>
                {columns.map((column) => (
                  <TableHeader
                    key={column.key}
                    align={column.align}
                    width={column.width}
                  >
                    {column.header}
                  </TableHeader>
                ))}
              </tr>
            </thead>
          </table>
          <div className="py-12">
            {emptyState || (
              <div className="text-center">
                <p className="text-gray-500 dark:text-gray-400">No data available</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={cn('overflow-x-auto', containerClassName)}>
      <table className={cn('min-w-full divide-y divide-gray-200 dark:divide-gray-700', className)}>
        <thead className={cn(stickyHeader && 'sticky top-0 z-10')}>
          <tr>
            {onRowSelect && (
              <TableHeader width="48px" align="center">
                <input
                  type="checkbox"
                  className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                  checked={selectedRows?.size === data?.length && (data?.length ?? 0) > 0}
                  onChange={(e) => {
                    if (!selectedRows || !onRowSelect || !data) return;
                    if (e.target.checked) {
                      onRowSelect(new Set(data.map((row, index) => keyExtractor(row, index))));
                    } else {
                      onRowSelect(new Set());
                    }
                  }}
                />
              </TableHeader>
            )}
            {columns.map((column) => (
              <TableHeader
                key={column.key}
                sortable={column.sortable}
                sortDirection={sortConfig.key === column.key ? sortConfig.direction : null}
                onSort={() => column.sortable && handleSort(column.key)}
                align={column.align}
                width={column.width}
              >
                {column.header}
              </TableHeader>
            ))}
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {loading ? (
            <tr>
              <td colSpan={columns.length + (onRowSelect ? 1 : 0)} className="p-0">
                <TableSkeleton rows={5} columns={columns.length} />
              </td>
            </tr>
          ) : (
            sortedData.map((row, index) => {
              const key = keyExtractor(row, index);
              const isSelected = selectedRows?.has(key) || false;
              const computedRowClassName = typeof rowClassName === 'function'
                ? rowClassName(row, index)
                : rowClassName;

              return (
                <TableRow
                  key={key}
                  onClick={() => onRowClick?.(row, index)}
                  selected={isSelected}
                  hoverable={hoverable}
                  className={computedRowClassName}
                >
                  {onRowSelect && (
                    <TableCell align="center">
                      <input
                        type="checkbox"
                        className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                        checked={isSelected}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleRowSelect(key);
                        }}
                      />
                    </TableCell>
                  )}
                  {columns.map((column) => {
                    const value = (row as any)[column.key];
                    const content = column.render
                      ? column.render(value, row, index)
                      : value;

                    return (
                      <TableCell key={column.key} align={column.align}>
                        {content}
                      </TableCell>
                    );
                  })}
                </TableRow>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

// Export compound components
Table.Header = TableHeader;
Table.Row = TableRow;
Table.Cell = TableCell;
Table.Skeleton = TableSkeleton;
