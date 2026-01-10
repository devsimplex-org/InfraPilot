"use client";

import { cn } from "@/lib/utils";
import { Info, CheckCircle, AlertTriangle, XCircle, X } from "lucide-react";
import Link from "next/link";

type AlertVariant = "info" | "success" | "warning" | "error";

interface AlertBarProps {
  variant: AlertVariant;
  message: string;
  title?: string;
  dismissible?: boolean;
  onDismiss?: () => void;
  action?: {
    label: string;
    href?: string;
    onClick?: () => void;
  };
  className?: string;
}

const variantStyles: Record<AlertVariant, string> = {
  info: "bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800",
  success: "bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800",
  warning: "bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800",
  error: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border-red-300 dark:border-red-800",
};

const variantIcons: Record<AlertVariant, React.ElementType> = {
  info: Info,
  success: CheckCircle,
  warning: AlertTriangle,
  error: XCircle,
};

const actionStyles: Record<AlertVariant, string> = {
  info: "text-blue-700 dark:text-blue-300 hover:text-blue-800 dark:hover:text-blue-200 underline underline-offset-2",
  success: "text-green-700 dark:text-green-300 hover:text-green-800 dark:hover:text-green-200 underline underline-offset-2",
  warning: "text-red-700 dark:text-red-300 hover:text-red-800 dark:hover:text-red-200 underline underline-offset-2",
  error: "text-red-700 dark:text-red-300 hover:text-red-800 dark:hover:text-red-200 underline underline-offset-2",
};

export function AlertBar({
  variant,
  message,
  title,
  dismissible = false,
  onDismiss,
  action,
  className,
}: AlertBarProps) {
  const Icon = variantIcons[variant];

  return (
    <div
      className={cn(
        "flex items-center gap-3 px-4 py-3 border-b",
        variantStyles[variant],
        className
      )}
      role="alert"
    >
      <Icon className="h-5 w-5 flex-shrink-0" />

      <div className="flex-1 flex items-center gap-2 min-w-0">
        {title && (
          <span className="font-medium flex-shrink-0">{title}</span>
        )}
        <span className={cn(title && "text-opacity-90")}>{message}</span>
      </div>

      {action && (
        <>
          {action.href ? (
            <Link
              href={action.href}
              className={cn(
                "font-medium flex-shrink-0 transition-colors",
                actionStyles[variant]
              )}
            >
              {action.label}
            </Link>
          ) : (
            <button
              onClick={action.onClick}
              className={cn(
                "font-medium flex-shrink-0 transition-colors",
                actionStyles[variant]
              )}
            >
              {action.label}
            </button>
          )}
        </>
      )}

      {dismissible && (
        <button
          onClick={onDismiss}
          className={cn(
            "p-1 rounded-md flex-shrink-0 transition-colors",
            "hover:bg-black/5 dark:hover:bg-white/5"
          )}
          aria-label="Dismiss"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}
