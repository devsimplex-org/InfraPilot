"use client";

import { useState, useRef, useEffect, ReactNode } from "react";
import {
  Search,
  Globe,
  RefreshCw,
  Download,
  ChevronDown,
  X,
  Play,
  Pause,
  Terminal,
  FileJson,
  FileSpreadsheet,
  Server,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardBody } from "@/components/ui/Card";
import { Input } from "@/components/ui/page-layout";

// =============================================================================
// Types
// =============================================================================

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface ToggleOption {
  value: string;
  label: string;
  color?: "default" | "green" | "yellow" | "red" | "blue";
}

export interface TimeRangeOption {
  label: string;
  value: number;
  unit: "minutes" | "hours";
  interval?: string;
}

export interface ExportOption {
  format: string;
  label: string;
  icon?: ReactNode;
}

export interface FilterToolbarProps {
  // Agent filter
  agents?: SelectOption[];
  selectedAgent?: string | null;
  onAgentChange?: (value: string | null) => void;
  showAgentFilter?: boolean;

  // Domain filter
  domains?: string[];
  selectedDomain?: string;
  onDomainChange?: (value: string) => void;
  showDomainFilter?: boolean;

  // Primary toggle (e.g., log type, view mode)
  primaryToggle?: {
    options: ToggleOption[];
    value: string;
    onChange: (value: string) => void;
  };

  // Time range selector
  timeRange?: {
    options: TimeRangeOption[];
    value: TimeRangeOption;
    onChange: (value: TimeRangeOption) => void;
  };

  // Dropdown selector (e.g., line count)
  dropdownSelector?: {
    options: SelectOption[];
    value: string;
    onChange: (value: string) => void;
    icon?: ReactNode;
    label?: string;
  };

  // Search
  searchQuery?: string;
  onSearchChange?: (value: string) => void;
  searchPlaceholder?: string;
  showSearch?: boolean;

  // Status/Level filter
  statusFilter?: {
    options: ToggleOption[];
    value: string;
    onChange: (value: string) => void;
  };

  // Auto-refresh
  autoRefresh?: boolean;
  onAutoRefreshChange?: (value: boolean) => void;
  showAutoRefresh?: boolean;
  autoRefreshLabel?: { active: string; inactive: string };

  // Manual refresh
  onRefresh?: () => void;
  isRefreshing?: boolean;
  showRefresh?: boolean;

  // Export
  exportOptions?: ExportOption[];
  onExport?: (format: string) => void;
  showExport?: boolean;

  // Custom actions
  customActions?: ReactNode;

  // Layout
  className?: string;
  compact?: boolean;
  singleRow?: boolean;
}

// =============================================================================
// Sub-components
// =============================================================================

function AgentSelector({
  agents,
  value,
  onChange,
}: {
  agents: SelectOption[];
  value: string | null;
  onChange: (value: string | null) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
        Agent
      </label>
      <select
        value={value || ""}
        onChange={(e) => onChange(e.target.value || null)}
        className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
      >
        <option value="">Select agent...</option>
        {agents.map((agent) => (
          <option key={agent.value} value={agent.value} disabled={agent.disabled}>
            {agent.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function DomainSelector({
  domains,
  value,
  onChange,
}: {
  domains: string[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <Globe className="h-4 w-4 text-gray-400" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
      >
        <option value="">All Domains</option>
        {domains.map((domain) => (
          <option key={domain} value={domain}>
            {domain}
          </option>
        ))}
      </select>
    </div>
  );
}

function ToggleGroup({
  options,
  value,
  onChange,
  size = "default",
}: {
  options: ToggleOption[];
  value: string;
  onChange: (value: string) => void;
  size?: "default" | "small";
}) {
  const getButtonStyle = (option: ToggleOption, isActive: boolean) => {
    const baseStyle = size === "small"
      ? "px-2.5 py-1 rounded text-xs font-medium transition-colors"
      : "px-3 py-1.5 rounded-md text-sm font-medium transition-colors";

    if (!isActive) {
      return cn(baseStyle, "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white");
    }

    switch (option.color) {
      case "green":
        return cn(baseStyle, "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300");
      case "yellow":
        return cn(baseStyle, "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300");
      case "red":
        return cn(baseStyle, "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300");
      case "blue":
        return cn(baseStyle, "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300");
      default:
        return cn(baseStyle, "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow");
    }
  };

  return (
    <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={getButtonStyle(option, value === option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function TimeRangeSelector({
  options,
  value,
  onChange,
}: {
  options: TimeRangeOption[];
  value: TimeRangeOption;
  onChange: (value: TimeRangeOption) => void;
}) {
  return (
    <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
      {options.map((option) => (
        <button
          key={option.label}
          onClick={() => onChange(option)}
          className={cn(
            "px-2.5 py-1 rounded text-xs font-medium transition-colors",
            value.label === option.label
              ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
              : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function DropdownSelector({
  options,
  value,
  onChange,
  icon,
  label,
}: {
  options: SelectOption[];
  value: string;
  onChange: (value: string) => void;
  icon?: ReactNode;
  label?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      {label && (
        <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
          {label}
        </label>
      )}
      {icon}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function SearchInput({
  value,
  onChange,
  placeholder = "Search...",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="relative flex-1 min-w-[200px] max-w-md">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
      <Input
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pl-10 w-full"
      />
      {value && (
        <button
          onClick={() => onChange("")}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

function AutoRefreshButton({
  isActive,
  onChange,
  labels = { active: "Live", inactive: "Paused" },
}: {
  isActive: boolean;
  onChange: (value: boolean) => void;
  labels?: { active: string; inactive: string };
}) {
  return (
    <button
      onClick={() => onChange(!isActive)}
      className={cn(
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
        isActive
          ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 border border-green-300 dark:border-green-800"
          : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
      )}
    >
      {isActive ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
      {isActive ? labels.active : labels.inactive}
    </button>
  );
}

function RefreshButton({
  onClick,
  isRefreshing,
}: {
  onClick: () => void;
  isRefreshing: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={isRefreshing}
      className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
    >
      <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
      Refresh
    </button>
  );
}

function ExportDropdown({
  options,
  onExport,
}: {
  options: ExportOption[];
  onExport: (format: string) => void;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleExport = (format: string) => {
    onExport(format);
    setIsOpen(false);
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-lg text-sm font-medium transition-colors"
      >
        <Download className="h-4 w-4" />
        Export
        <ChevronDown className="h-3 w-3" />
      </button>
      {isOpen && (
        <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-10">
          {options.map((option, index) => (
            <button
              key={option.format}
              onClick={() => handleExport(option.format)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800",
                index === 0 && "rounded-t-lg",
                index === options.length - 1 && "rounded-b-lg"
              )}
            >
              {option.icon}
              {option.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// =============================================================================
// Main Component
// =============================================================================

export function FilterToolbar({
  // Agent
  agents,
  selectedAgent,
  onAgentChange,
  showAgentFilter = true,
  // Domain
  domains,
  selectedDomain,
  onDomainChange,
  showDomainFilter = false,
  // Primary toggle
  primaryToggle,
  // Time range
  timeRange,
  // Dropdown
  dropdownSelector,
  // Search
  searchQuery,
  onSearchChange,
  searchPlaceholder = "Search...",
  showSearch = true,
  // Status filter
  statusFilter,
  // Auto-refresh
  autoRefresh,
  onAutoRefreshChange,
  showAutoRefresh = false,
  autoRefreshLabel,
  // Refresh
  onRefresh,
  isRefreshing = false,
  showRefresh = true,
  // Export
  exportOptions,
  onExport,
  showExport = false,
  // Custom
  customActions,
  // Layout
  className,
  compact = false,
  singleRow = false,
}: FilterToolbarProps) {
  const content = singleRow ? (
    <div className="flex flex-wrap items-center gap-4">
      {/* Agent Selector */}
      {showAgentFilter && agents && onAgentChange && (
        <AgentSelector
          agents={agents}
          value={selectedAgent ?? null}
          onChange={onAgentChange}
        />
      )}

      {/* Domain Selector */}
      {showDomainFilter && domains && onDomainChange && (
        <DomainSelector
          domains={domains}
          value={selectedDomain || ""}
          onChange={onDomainChange}
        />
      )}

      {/* Primary Toggle */}
      {primaryToggle && (
        <ToggleGroup
          options={primaryToggle.options}
          value={primaryToggle.value}
          onChange={primaryToggle.onChange}
        />
      )}

      {/* Time Range Selector */}
      {timeRange && (
        <TimeRangeSelector
          options={timeRange.options}
          value={timeRange.value}
          onChange={timeRange.onChange}
        />
      )}

      {/* Dropdown Selector */}
      {dropdownSelector && (
        <DropdownSelector
          options={dropdownSelector.options}
          value={dropdownSelector.value}
          onChange={dropdownSelector.onChange}
          icon={dropdownSelector.icon}
          label={dropdownSelector.label}
        />
      )}

      {/* Search */}
      {showSearch && onSearchChange && (
        <SearchInput
          value={searchQuery || ""}
          onChange={onSearchChange}
          placeholder={searchPlaceholder}
        />
      )}

      {/* Status Filter */}
      {statusFilter && (
        <ToggleGroup
          options={statusFilter.options}
          value={statusFilter.value}
          onChange={statusFilter.onChange}
          size="small"
        />
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 ml-auto">
        {showAutoRefresh && onAutoRefreshChange && (
          <AutoRefreshButton
            isActive={autoRefresh || false}
            onChange={onAutoRefreshChange}
            labels={autoRefreshLabel}
          />
        )}

        {showRefresh && onRefresh && (
          <RefreshButton onClick={onRefresh} isRefreshing={isRefreshing} />
        )}

        {showExport && exportOptions && onExport && (
          <ExportDropdown options={exportOptions} onExport={onExport} />
        )}

        {customActions}
      </div>
    </div>
  ) : (
    <div className={cn("space-y-4", compact && "space-y-3")}>
      {/* Top row: Selectors and toggles */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Agent Selector */}
        {showAgentFilter && agents && onAgentChange && (
          <AgentSelector
            agents={agents}
            value={selectedAgent ?? null}
            onChange={onAgentChange}
          />
        )}

        {/* Domain Selector */}
        {showDomainFilter && domains && onDomainChange && (
          <DomainSelector
            domains={domains}
            value={selectedDomain || ""}
            onChange={onDomainChange}
          />
        )}

        {/* Primary Toggle */}
        {primaryToggle && (
          <ToggleGroup
            options={primaryToggle.options}
            value={primaryToggle.value}
            onChange={primaryToggle.onChange}
          />
        )}

        {/* Time Range Selector */}
        {timeRange && (
          <TimeRangeSelector
            options={timeRange.options}
            value={timeRange.value}
            onChange={timeRange.onChange}
          />
        )}

        {/* Dropdown Selector */}
        {dropdownSelector && (
          <DropdownSelector
            options={dropdownSelector.options}
            value={dropdownSelector.value}
            onChange={dropdownSelector.onChange}
            icon={dropdownSelector.icon}
            label={dropdownSelector.label}
          />
        )}
      </div>

      {/* Bottom row: Search, filters, and actions */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Search */}
        {showSearch && onSearchChange && (
          <SearchInput
            value={searchQuery || ""}
            onChange={onSearchChange}
            placeholder={searchPlaceholder}
          />
        )}

        {/* Status Filter */}
        {statusFilter && (
          <ToggleGroup
            options={statusFilter.options}
            value={statusFilter.value}
            onChange={statusFilter.onChange}
            size="small"
          />
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 ml-auto">
          {showAutoRefresh && onAutoRefreshChange && (
            <AutoRefreshButton
              isActive={autoRefresh || false}
              onChange={onAutoRefreshChange}
              labels={autoRefreshLabel}
            />
          )}

          {showRefresh && onRefresh && (
            <RefreshButton onClick={onRefresh} isRefreshing={isRefreshing} />
          )}

          {showExport && exportOptions && onExport && (
            <ExportDropdown options={exportOptions} onExport={onExport} />
          )}

          {customActions}
        </div>
      </div>
    </div>
  );

  return (
    <Card className={className}>
      <CardBody className={cn(compact && "py-3")}>
        {content}
      </CardBody>
    </Card>
  );
}

// =============================================================================
// Preset Configurations
// =============================================================================

export const DEFAULT_EXPORT_OPTIONS: ExportOption[] = [
  { format: "txt", label: "Plain Text (.txt)", icon: <Terminal className="h-4 w-4" /> },
  { format: "json", label: "JSON (.json)", icon: <FileJson className="h-4 w-4" /> },
  { format: "csv", label: "CSV (.csv)", icon: <FileSpreadsheet className="h-4 w-4" /> },
];

export const DEFAULT_LINE_OPTIONS: SelectOption[] = [
  { value: "50", label: "Last 50" },
  { value: "100", label: "Last 100" },
  { value: "250", label: "Last 250" },
  { value: "500", label: "Last 500" },
];

export const DEFAULT_TIME_RANGES: TimeRangeOption[] = [
  { label: "5m", value: 5, unit: "minutes", interval: "1m" },
  { label: "15m", value: 15, unit: "minutes", interval: "1m" },
  { label: "30m", value: 30, unit: "minutes", interval: "1m" },
  { label: "1h", value: 1, unit: "hours", interval: "1m" },
  { label: "6h", value: 6, unit: "hours", interval: "5m" },
  { label: "24h", value: 24, unit: "hours", interval: "1h" },
  { label: "7d", value: 168, unit: "hours", interval: "1h" },
  { label: "30d", value: 720, unit: "hours", interval: "1d" },
];

export const LOG_STATUS_FILTERS: ToggleOption[] = [
  { value: "all", label: "All" },
  { value: "success", label: "2xx/3xx", color: "green" },
  { value: "warning", label: "4xx", color: "yellow" },
  { value: "error", label: "5xx", color: "red" },
];

export default FilterToolbar;
