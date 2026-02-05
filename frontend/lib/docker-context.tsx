"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Agent } from "@/lib/api";

interface DockerContextType {
  // Agents
  agents: Agent[] | undefined;
  activeAgents: Agent[];
  selectedAgent: string | null;
  setSelectedAgent: (agentId: string | null) => void;
  isLoadingAgents: boolean;

  // Common state
  forceDelete: boolean;
  setForceDelete: (force: boolean) => void;
}

const DockerContext = createContext<DockerContextType | undefined>(undefined);

export function DockerProvider({ children }: { children: ReactNode }) {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);

  // Fetch agents
  const { data: agents, isLoading: isLoadingAgents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Filter to active agents only
  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first agent when available
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  return (
    <DockerContext.Provider
      value={{
        agents,
        activeAgents,
        selectedAgent,
        setSelectedAgent,
        isLoadingAgents,
        forceDelete,
        setForceDelete,
      }}
    >
      {children}
    </DockerContext.Provider>
  );
}

export function useDocker() {
  const context = useContext(DockerContext);
  if (context === undefined) {
    throw new Error("useDocker must be used within a DockerProvider");
  }
  return context;
}

// Common utility functions
export const formatSize = (bytes: number) => {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

export const getStatusLevel = (status: string): "healthy" | "warning" | "degraded" | "critical" => {
  if (status === "running") return "healthy";
  if (status === "exited") return "critical";
  if (status === "paused") return "warning";
  return "degraded";
};
