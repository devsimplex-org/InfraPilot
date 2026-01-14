import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function formatRelativeTime(date: string | Date): string {
  const now = new Date();
  const then = new Date(date);
  const diffMs = now.getTime() - then.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 604800) return `${Math.floor(diffSec / 86400)}d ago`;

  return then.toLocaleDateString();
}

export function getStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "running":
    case "active":
    case "healthy":
      return "text-green-400";
    case "stopped":
    case "offline":
    case "pending":
      return "text-yellow-400";
    case "error":
    case "unhealthy":
    case "exited":
      return "text-red-400";
    default:
      return "text-gray-400";
  }
}

export function getStatusBadgeColor(status: string): string {
  switch (status.toLowerCase()) {
    case "running":
    case "active":
    case "healthy":
      return "bg-green-500/10 text-green-400 border-green-500/30";
    case "stopped":
    case "offline":
    case "pending":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    case "error":
    case "unhealthy":
    case "exited":
      return "bg-red-500/10 text-red-400 border-red-500/30";
    default:
      return "bg-gray-500/10 text-gray-400 border-gray-500/30";
  }
}

export function isIPAddress(hostname: string): boolean {
  // IPv4 pattern: 1-3 digits separated by dots
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6 pattern: hex digits separated by colons (simplified)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  // Also check for localhost
  return (
    ipv4Pattern.test(hostname) ||
    ipv6Pattern.test(hostname) ||
    hostname === "localhost" ||
    hostname === "[::1]"
  );
}
