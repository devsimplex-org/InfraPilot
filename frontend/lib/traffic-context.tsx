"use client";

import { createContext, useContext, useState, ReactNode } from "react";

interface TrafficContextType {
  // Selected agent
  selectedAgent: string | null;
  setSelectedAgent: (id: string | null) => void;

  // Proxy panel
  proxyPanelId: string | null;
  openProxyPanel: (id: string) => void;
  closeProxyPanel: () => void;

  // Delete confirmation
  forceDelete: boolean;
  setForceDelete: (force: boolean) => void;
}

const TrafficContext = createContext<TrafficContextType | undefined>(undefined);

export function TrafficProvider({ children }: { children: ReactNode }) {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [proxyPanelId, setProxyPanelId] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);

  const openProxyPanel = (id: string) => {
    setProxyPanelId(id);
  };

  const closeProxyPanel = () => {
    setProxyPanelId(null);
  };

  return (
    <TrafficContext.Provider
      value={{
        selectedAgent,
        setSelectedAgent,
        proxyPanelId,
        openProxyPanel,
        closeProxyPanel,
        forceDelete,
        setForceDelete,
      }}
    >
      {children}
    </TrafficContext.Provider>
  );
}

export function useTraffic() {
  const context = useContext(TrafficContext);
  if (context === undefined) {
    throw new Error("useTraffic must be used within a TrafficProvider");
  }
  return context;
}

// Helper functions
export function getSSLStatus(proxy: { ssl_enabled: boolean; ssl_expires_at: string | null }): "healthy" | "warning" | "critical" {
  if (!proxy.ssl_enabled) return "warning";
  if (proxy.ssl_expires_at) {
    const daysUntilExpiry = Math.ceil((new Date(proxy.ssl_expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysUntilExpiry < 7) return "critical";
    if (daysUntilExpiry < 30) return "warning";
  }
  return "healthy";
}

export function getProxyStatus(status: string): "healthy" | "warning" | "critical" | "degraded" {
  switch (status) {
    case "active":
      return "healthy";
    case "ssl_pending":
      return "warning";
    case "error":
      return "critical";
    default:
      return "degraded";
  }
}
