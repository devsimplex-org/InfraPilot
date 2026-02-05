"use client";

import { useState, useRef, useEffect } from "react";
import { Server, ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";

interface ContainerListPopoverProps {
  // Supports both formats:
  // - Record<string, string> for networks (containerId -> containerName)
  // - string[] for images/volumes (container names)
  containers: Record<string, string> | string[];
  onContainerClick: (containerIdOrName: string) => void;
  label?: string; // e.g., "connected", "container", "containers"
}

export function ContainerListPopover({
  containers,
  onContainerClick,
  label = "container",
}: ContainerListPopoverProps) {
  const [isOpen, setIsOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Normalize to array of { id, name } objects
  const containerList = Array.isArray(containers)
    ? containers.map((name) => ({ id: name, name }))
    : Object.entries(containers).map(([id, name]) => ({ id, name }));

  const count = containerList.length;

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(event.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen]);

  if (count === 0) {
    return (
      <Badge className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
        Unused
      </Badge>
    );
  }

  const labelText = count === 1 ? label : `${label}s`;

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={(e) => {
          e.stopPropagation();
          setIsOpen(!isOpen);
        }}
        className="inline-flex items-center gap-1 px-2 py-0.5 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded hover:bg-green-200 dark:hover:bg-green-900/50 transition-colors"
      >
        {count} {labelText}
        <ChevronDown className={cn("h-3 w-3 transition-transform", isOpen && "rotate-180")} />
      </button>

      {isOpen && (
        <div
          ref={popoverRef}
          className="absolute z-50 top-full left-0 mt-1 min-w-[200px] max-w-[300px] bg-white dark:bg-gray-900 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1"
        >
          <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-700">
            <p className="text-xs font-medium text-gray-500 dark:text-gray-400">
              {count} {labelText}
            </p>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {containerList.map(({ id, name }) => (
              <button
                key={id}
                onClick={(e) => {
                  e.stopPropagation();
                  onContainerClick(id);
                  setIsOpen(false);
                }}
                className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-left"
              >
                <Server className="h-3.5 w-3.5 text-gray-400 flex-shrink-0" />
                <span className="text-sm text-gray-900 dark:text-white truncate">{name}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
