"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Agent } from "@/lib/api";

interface DatabaseContextType {
  agents: Agent[] | undefined;
  activeAgents: Agent[];
  selectedAgent: string | null;
  setSelectedAgent: (agentId: string | null) => void;
  isLoadingAgents: boolean;
  // Detail panel state
  selectedDatabaseId: string | null;
  openDatabasePanel: (id: string) => void;
  closeDatabasePanel: () => void;
}

const DatabaseContext = createContext<DatabaseContextType | undefined>(undefined);

export function DatabaseProvider({ children }: { children: ReactNode }) {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedDatabaseId, setSelectedDatabaseId] = useState<string | null>(null);

  const { data: agents, isLoading: isLoadingAgents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  return (
    <DatabaseContext.Provider
      value={{
        agents,
        activeAgents,
        selectedAgent,
        setSelectedAgent,
        isLoadingAgents,
        selectedDatabaseId,
        openDatabasePanel: (id) => setSelectedDatabaseId(id),
        closeDatabasePanel: () => setSelectedDatabaseId(null),
      }}
    >
      {children}
    </DatabaseContext.Provider>
  );
}

export function useDatabase() {
  const context = useContext(DatabaseContext);
  if (context === undefined) {
    throw new Error("useDatabase must be used within a DatabaseProvider");
  }
  return context;
}

// Known database image patterns for auto-discovery
export const DB_IMAGE_PATTERNS: { pattern: RegExp; type: string; defaultPort: number; label: string }[] = [
  { pattern: /timescale/i,                   type: "postgresql",    defaultPort: 5432,  label: "TimescaleDB" },
  { pattern: /postgres|postgresql/i,         type: "postgresql",    defaultPort: 5432,  label: "PostgreSQL" },
  { pattern: /mysql/i,                       type: "mysql",         defaultPort: 3306,  label: "MySQL" },
  { pattern: /mariadb/i,                     type: "mysql",         defaultPort: 3306,  label: "MariaDB" },
  { pattern: /mongo/i,                       type: "mongodb",       defaultPort: 27017, label: "MongoDB" },
  { pattern: /redis/i,                       type: "redis",         defaultPort: 6379,  label: "Redis" },
  { pattern: /elastic/i,                     type: "elasticsearch", defaultPort: 9200,  label: "Elasticsearch" },
  { pattern: /cassandra/i,                   type: "cassandra",     defaultPort: 9042,  label: "Cassandra" },
  { pattern: /cockroach/i,                   type: "postgresql",    defaultPort: 26257, label: "CockroachDB" },
  { pattern: /clickhouse/i,                  type: "clickhouse",    defaultPort: 8123,  label: "ClickHouse" },
  { pattern: /mssql|sqlserver/i,             type: "mssql",         defaultPort: 1433,  label: "SQL Server" },
];

export function detectDatabaseFromImage(image: string): { type: string; defaultPort: number; label: string } | null {
  const imageName = image.split(":")[0].split("/").pop() || "";
  for (const entry of DB_IMAGE_PATTERNS) {
    if (entry.pattern.test(imageName)) {
      return entry;
    }
  }
  return null;
}
