"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Server,
  Trash2,
  Copy,
  Check,
} from "lucide-react";
import { api, DockerNetwork } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Button, Input } from "@/components/ui/page-layout";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/utils";

export default function DockerNetworksPage() {
  const queryClient = useQueryClient();
  const { selectedAgent } = useDocker();

  // Local state
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedNetwork, setSelectedNetwork] = useState<DockerNetwork | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Fetch networks
  const { data: networks, isLoading } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
  });

  // Filtered networks
  const filteredNetworks = (networks || []).filter((n) => {
    if (!searchFilter) return true;
    return n.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      n.driver.toLowerCase().includes(searchFilter.toLowerCase()) ||
      n.id.toLowerCase().includes(searchFilter.toLowerCase());
  });

  // Metrics
  const metrics = {
    total: networks?.length || 0,
    bridge: networks?.filter((n) => n.driver === "bridge").length || 0,
    host: networks?.filter((n) => n.driver === "host").length || 0,
    overlay: networks?.filter((n) => n.driver === "overlay").length || 0,
  };

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteDockerNetwork(selectedAgent!, selectedNetwork!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowDeleteModal(false);
      setSelectedNetwork(null);
      setDeleteError(null);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Table columns
  const columns = [
    {
      key: "name",
      header: "Name",
      sortable: true,
      render: (value: string, row: DockerNetwork) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <Network className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{value}</p>
            <p className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</p>
          </div>
        </div>
      ),
    },
    {
      key: "driver",
      header: "Driver",
      sortable: true,
      render: (value: string) => (
        <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">
          {value}
        </Badge>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">{value}</span>
      ),
    },
    {
      key: "containers",
      header: "Containers",
      align: "center" as const,
      render: (value: Record<string, string>) => {
        const count = Object.keys(value || {}).length;
        return count > 0 ? (
          <Badge className="px-2 py-0.5 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
            {count} connected
          </Badge>
        ) : (
          <span className="text-sm text-gray-400">None</span>
        );
      },
    },
    {
      key: "internal",
      header: "Internal",
      align: "center" as const,
      render: (value: boolean) => (
        <span className={cn("text-sm", value ? "text-yellow-600 dark:text-yellow-400" : "text-gray-400")}>
          {value ? "Yes" : "No"}
        </span>
      ),
    },
  ];

  if (!selectedAgent) {
    return <Spinner.LogoPage label="Selecting agent..." />;
  }

  return (
    <div className="space-y-4">
      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard label="Total Networks" value={metrics.total} icon={Network} iconColor="text-orange-600 dark:text-orange-400" />
        <StatCard label="Bridge" value={metrics.bridge} icon={Network} iconColor="text-blue-600 dark:text-blue-400" />
        <StatCard label="Host" value={metrics.host} icon={Network} iconColor="text-green-600 dark:text-green-400" />
        <StatCard label="Overlay" value={metrics.overlay} icon={Network} iconColor="text-purple-600 dark:text-purple-400" />
      </MetricsGrid>

      {/* Filters */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Input placeholder="Search networks..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="w-64" />
          {searchFilter && (
            <button onClick={() => setSearchFilter("")} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400">Reset</button>
          )}
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <Spinner.LogoPage label="Loading networks..." />
      ) : filteredNetworks.length > 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <Table
            data={filteredNetworks}
            columns={columns}
            keyExtractor={(row) => row.id}
            onRowClick={(row) => setSelectedNetwork(row)}
            hoverable
            rowClassName={(row) =>
              cn(selectedNetwork?.id === row.id && "bg-primary-50 dark:bg-primary-900/20")
            }
          />
        </div>
      ) : (
        <EmptyState
          icon={Network}
          title="No networks found"
          description={networks?.length === 0 ? "No networks are configured on this agent" : "No networks match the search"}
        />
      )}

      {/* Network SlideOver */}
      <SlideOver isOpen={!!selectedNetwork} onClose={() => setSelectedNetwork(null)} size="md">
        {selectedNetwork && (
          <>
            <SlideOver.Header onClose={() => setSelectedNetwork(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedNetwork.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedNetwork.driver} network</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Network Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Network Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.name}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                      <div className="flex items-center gap-1">
                        <code className="text-sm">{selectedNetwork.id.slice(0, 12)}</code>
                        <button onClick={() => handleCopy(selectedNetwork.id, "network-id")} className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded">
                          {copied === "network-id" ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                      <Badge className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded border-0">{selectedNetwork.driver}</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.scope}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Internal</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedNetwork.internal ? "Yes" : "No"}</span>
                    </div>
                  </div>
                </div>

                {/* Connected Containers */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Connected Containers</h3>
                  {Object.entries(selectedNetwork.containers || {}).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(selectedNetwork.containers).map(([id, name]) => (
                        <div key={id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-gray-400" />
                            <span className="text-sm font-medium text-gray-900 dark:text-white">{name}</span>
                          </div>
                          <span className="text-xs text-gray-500 font-mono">{id.slice(0, 12)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">No containers connected</span>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => { setDeleteError(null); setShowDeleteModal(true); }}
                    disabled={Object.keys(selectedNetwork.containers || {}).length > 0}
                  >
                    <Trash2 className="h-4 w-4 mr-1" />Delete Network
                  </Button>
                  {Object.keys(selectedNetwork.containers || {}).length > 0 && (
                    <p className="text-xs text-gray-500 mt-2">Cannot delete network with connected containers</p>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteModal && !!selectedNetwork}
        onClose={() => { setShowDeleteModal(false); setDeleteError(null); }}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Network"
        message={`Are you sure you want to delete network "${selectedNetwork?.name}"?`}
        confirmText="Delete Network"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
        error={deleteError}
      />
    </div>
  );
}
