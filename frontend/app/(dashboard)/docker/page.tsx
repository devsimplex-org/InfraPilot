"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Container as ContainerIcon,
  Image as ImageIcon,
  HardDrive,
  Network,
  Play,
  Square,
  Layers,
  Cpu,
  MemoryStick,
  Server,
  Box,
  RotateCcw,
  RefreshCw,
  Copy,
  Check,
  Trash2,
  ExternalLink,
  Terminal as TerminalIcon,
  FileText,
  Globe,
  FolderOpen,
  Download,
  Plus,
  Tag,
  Shield,
  CheckSquare,
  MinusSquare,
  Rocket,
  AlertTriangle,
  X,
  Database,
} from "lucide-react";
import { api, Container, DockerImage, DockerVolume, DockerNetwork } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Tabs, Button, Input } from "@/components/ui/page-layout";
import { Table } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { Terminal } from "@/components/containers/Terminal";
import { ScanModal, ScanImage } from "@/components/ui/ScanModal";
import { DeployWizard } from "@/components/DeployWizard";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "containers", label: "Containers" },
  { id: "images", label: "Images" },
  { id: "volumes", label: "Volumes" },
  { id: "networks", label: "Networks" },
];

type ContainerPanelTab = "details" | "logs" | "terminal";
type StatusFilter = "all" | "running" | "exited" | "paused";

export default function DockerPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const validTabIds = tabs.map(t => t.id);

  // Get initial tab from URL hash
  const getTabFromHash = () => {
    if (typeof window === "undefined") return "overview";
    const hash = window.location.hash.replace("#", "");
    return validTabIds.includes(hash) ? hash : "overview";
  };

  const [activeTab, setActiveTab] = useState(getTabFromHash);
  const [selectedAgent, setSelectedAgent] = useState<string>("");

  // Selected items for slide-over panels
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [selectedImage, setSelectedImage] = useState<DockerImage | null>(null);
  const [selectedVolume, setSelectedVolume] = useState<DockerVolume | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<DockerNetwork | null>(null);

  // Panel tabs and state
  const [containerPanelTab, setContainerPanelTab] = useState<ContainerPanelTab>("details");
  const [logsTail, setLogsTail] = useState(100);
  const [copied, setCopied] = useState<string | null>(null);

  // Container filters
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [searchFilter, setSearchFilter] = useState("");

  // Image multi-selection
  const [selectedImageIds, setSelectedImageIds] = useState<Set<string>>(new Set());
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);
  const [bulkDeleteProgress, setBulkDeleteProgress] = useState<{
    total: number;
    completed: number;
    failed: string[];
  } | null>(null);

  // Image modals
  const [showPullModal, setShowPullModal] = useState(false);
  const [pullImageRef, setPullImageRef] = useState("");
  const [pullError, setPullError] = useState<string | null>(null);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanImages, setScanImages] = useState<ScanImage[]>([]);

  // Deploy dialog
  const [showDeployWizard, setShowDeployWizard] = useState(false);
  const [deployImageInfo, setDeployImageInfo] = useState<{ repository: string; tag: string } | null>(null);

  // Volume create modal
  const [showCreateVolumeModal, setShowCreateVolumeModal] = useState(false);
  const [newVolumeName, setNewVolumeName] = useState("");
  const [newVolumeDriver, setNewVolumeDriver] = useState("local");
  const [createVolumeError, setCreateVolumeError] = useState<string | null>(null);

  // Delete modals
  const [showDeleteContainerModal, setShowDeleteContainerModal] = useState(false);
  const [showDeleteImageModal, setShowDeleteImageModal] = useState(false);
  const [showDeleteVolumeModal, setShowDeleteVolumeModal] = useState(false);
  const [showDeleteNetworkModal, setShowDeleteNetworkModal] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [forceDelete, setForceDelete] = useState(false);

  // Container action modals
  const [showStopModal, setShowStopModal] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);

  // Sync tab with URL hash
  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", `#${activeTab}`);
    }

    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      if (validTabIds.includes(hash) && hash !== activeTab) {
        setActiveTab(hash);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [activeTab, validTabIds]);

  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    window.history.pushState(null, "", `#${tabId}`);
  };

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  // Clear image selection when agent changes
  useEffect(() => {
    setSelectedImageIds(new Set());
  }, [selectedAgent]);

  // Fetch containers
  const { data: containers, isLoading: loadingContainers } = useQuery({
    queryKey: ["containers", selectedAgent],
    queryFn: () => selectedAgent ? api.getContainers(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "containers"),
  });

  // Fetch images
  const { data: images, isLoading: loadingImages } = useQuery({
    queryKey: ["docker-images", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerImages(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "images"),
  });

  // Fetch volumes
  const { data: volumes, isLoading: loadingVolumes } = useQuery({
    queryKey: ["docker-volumes", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerVolumes(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "volumes"),
  });

  // Fetch networks
  const { data: networks, isLoading: loadingNetworks } = useQuery({
    queryKey: ["docker-networks", selectedAgent],
    queryFn: () => selectedAgent ? api.getDockerNetworks(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent && (activeTab === "overview" || activeTab === "networks"),
  });

  // Fetch container logs
  const { data: logsData, isLoading: logsLoading, refetch: refetchLogs } = useQuery({
    queryKey: ["containerLogs", selectedAgent, selectedContainer?.container_id, logsTail],
    queryFn: () =>
      selectedAgent && selectedContainer
        ? api.getContainerLogs(selectedAgent, selectedContainer.container_id, logsTail)
        : Promise.resolve(null),
    enabled: !!selectedAgent && !!selectedContainer && containerPanelTab === "logs",
  });

  // Container mutations
  const startMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.startContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
    },
  });

  const stopMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.stopContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowStopModal(false);
    },
  });

  const restartMutation = useMutation({
    mutationFn: ({ containerId }: { containerId: string }) =>
      api.restartContainer(selectedAgent, containerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowRestartModal(false);
    },
  });

  const deleteContainerMutation = useMutation({
    mutationFn: () =>
      api.deleteContainer(selectedAgent, selectedContainer!.container_id, selectedContainer!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers", selectedAgent] });
      setShowDeleteContainerModal(false);
      setSelectedContainer(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Image mutations
  const pullMutation = useMutation({
    mutationFn: () => api.pullDockerImage(selectedAgent, pullImageRef),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
      setShowPullModal(false);
      setPullImageRef("");
      setPullError(null);
    },
    onError: (error: Error) => setPullError(error.message),
  });

  const deleteImageMutation = useMutation({
    mutationFn: () => api.deleteDockerImage(selectedAgent, selectedImage!.id, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });
      setShowDeleteImageModal(false);
      setSelectedImage(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Volume mutations
  const createVolumeMutation = useMutation({
    mutationFn: () =>
      api.createDockerVolume(selectedAgent, { name: newVolumeName, driver: newVolumeDriver }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowCreateVolumeModal(false);
      setNewVolumeName("");
      setNewVolumeDriver("local");
      setCreateVolumeError(null);
    },
    onError: (error: Error) => setCreateVolumeError(error.message),
  });

  const deleteVolumeMutation = useMutation({
    mutationFn: () => api.deleteDockerVolume(selectedAgent, selectedVolume!.name, forceDelete),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-volumes", selectedAgent] });
      setShowDeleteVolumeModal(false);
      setSelectedVolume(null);
      setDeleteError(null);
      setForceDelete(false);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Network mutations
  const deleteNetworkMutation = useMutation({
    mutationFn: () => api.deleteDockerNetwork(selectedAgent, selectedNetwork!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docker-networks", selectedAgent] });
      setShowDeleteNetworkModal(false);
      setSelectedNetwork(null);
      setDeleteError(null);
    },
    onError: (error: Error) => setDeleteError(error.message),
  });

  // Update selected container from fresh data
  useEffect(() => {
    if (selectedContainer && containers) {
      const updated = containers.find(c => c.container_id === selectedContainer.container_id);
      if (updated) setSelectedContainer(updated);
    }
  }, [containers, selectedContainer]);

  // Filter containers
  const filteredContainers = containers?.filter((container) => {
    const matchesStatus = statusFilter === "all" || container.status === statusFilter;
    const matchesSearch = !searchFilter ||
      container.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      container.image.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesStatus && matchesSearch;
  }) || [];

  // Image selection helpers
  const toggleImageSelection = (id: string) => {
    setSelectedImageIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const selectAllImages = () => {
    if (images) {
      setSelectedImageIds(new Set(images.map((img) => img.id)));
    }
  };

  const selectNoImages = () => {
    setSelectedImageIds(new Set());
  };

  const selectUnusedImages = () => {
    if (images) {
      setSelectedImageIds(new Set(images.filter((img) => img.used_by.length === 0).map((img) => img.id)));
    }
  };

  const selectDanglingImages = () => {
    if (images) {
      setSelectedImageIds(new Set(images.filter((img) => img.tags.length === 0).map((img) => img.id)));
    }
  };

  const isAllImagesSelected = images && images.length > 0 && selectedImageIds.size === images.length;
  const isSomeImagesSelected = selectedImageIds.size > 0 && !isAllImagesSelected;
  const selectedImagesData = images?.filter((img) => selectedImageIds.has(img.id)) || [];
  const selectedImagesSize = selectedImagesData.reduce((sum, img) => sum + img.size, 0);
  const unusedImagesCount = images?.filter((img) => img.used_by.length === 0).length || 0;
  const danglingImagesCount = images?.filter((img) => img.tags.length === 0).length || 0;

  // Scan helpers
  const getImageReference = (image: DockerImage): string => {
    if (image.tags.length > 0) return image.tags[0];
    if (image.repo_digests.length > 0) return image.repo_digests[0];
    return image.id;
  };

  const handleScanSelected = () => {
    const imagesToScan: ScanImage[] = selectedImagesData.map((img) => ({
      reference: getImageReference(img),
      digest: img.repo_digests[0]?.split("@")[1],
      tag: img.tags[0]?.split(":")[1],
    }));
    setScanImages(imagesToScan);
    setShowScanModal(true);
  };

  const handleScanSingle = (image: DockerImage) => {
    setScanImages([{
      reference: getImageReference(image),
      digest: image.repo_digests[0]?.split("@")[1],
      tag: image.tags[0]?.split(":")[1],
    }]);
    setShowScanModal(true);
  };

  const handleDeploy = (image: DockerImage) => {
    const tag = image.tags[0] || "";
    const parts = tag.split(":");
    const repository = parts.slice(0, -1).join(":") || parts[0] || image.id;
    const tagName = parts.length > 1 ? parts[parts.length - 1] : "latest";
    setDeployImageInfo({ repository, tag: tagName });
    setShowDeployWizard(true);
  };

  // Bulk delete
  const handleBulkDeleteImages = async () => {
    if (!selectedAgent || selectedImageIds.size === 0) return;

    const imagesToDelete = Array.from(selectedImageIds);
    setBulkDeleteProgress({ total: imagesToDelete.length, completed: 0, failed: [] });

    const failed: string[] = [];

    for (let i = 0; i < imagesToDelete.length; i++) {
      try {
        await api.deleteDockerImage(selectedAgent, imagesToDelete[i], forceDelete);
      } catch (error) {
        const img = images?.find((img) => img.id === imagesToDelete[i]);
        failed.push(img?.tags[0] || imagesToDelete[i].slice(0, 12));
      }
      setBulkDeleteProgress({ total: imagesToDelete.length, completed: i + 1, failed });
    }

    queryClient.invalidateQueries({ queryKey: ["docker-images", selectedAgent] });

    if (failed.length === 0) {
      setShowBulkDeleteModal(false);
      setSelectedImageIds(new Set());
      setBulkDeleteProgress(null);
      setForceDelete(false);
    }
  };

  // Metrics
  const containerMetrics = {
    total: containers?.length || 0,
    running: containers?.filter(c => c.status === "running").length || 0,
    stopped: containers?.filter(c => c.status === "exited").length || 0,
  };

  const imageMetrics = {
    total: images?.length || 0,
    totalSize: images?.reduce((sum, img) => sum + img.size, 0) || 0,
    inUse: images?.filter(img => img.used_by && img.used_by.length > 0).length || 0,
  };

  const volumeMetrics = {
    total: volumes?.length || 0,
    inUse: volumes?.filter((v) => v.used_by.length > 0).length || 0,
  };

  const networkMetrics = {
    total: networks?.length || 0,
    bridge: networks?.filter((n) => n.driver === "bridge").length || 0,
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const getStatusLevel = (status: string) => {
    if (status === "running") return "healthy";
    if (status === "exited") return "critical";
    if (status === "paused") return "warning";
    return "degraded";
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const getImageName = (image: DockerImage) => {
    if (image.tags.length > 0) return image.tags[0].split(":")[0];
    return `<none>`;
  };

  const getImageTag = (image: DockerImage) => {
    if (image.tags.length > 0) {
      const parts = image.tags[0].split(":");
      return parts.length > 1 ? parts[1] : "latest";
    }
    return image.id.slice(0, 12);
  };

  // Table columns - Containers (with filters)
  const containerColumns = [
    {
      key: "status",
      header: "Status",
      width: "120px",
      render: (value: string) => (
        <StatusIndicator status={getStatusLevel(value)} label={value} size="sm" />
      ),
    },
    {
      key: "name",
      header: "Container Name",
      render: (value: string, row: Container) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">{row.image}</div>
        </div>
      ),
    },
    {
      key: "stack_name",
      header: "Stack",
      render: (value: string) => value ? (
        <Badge size="sm">
          <Layers className="h-3 w-3" />
          {value}
        </Badge>
      ) : (
        <span className="text-gray-400 text-sm">Standalone</span>
      ),
    },
    {
      key: "cpu_percent",
      header: "CPU",
      align: "right" as const,
      render: (value: number) => (
        <div className="flex items-center gap-1 justify-end text-sm">
          <Cpu className="h-3 w-3 text-gray-400" />
          <span>{value?.toFixed(1) || 0}%</span>
        </div>
      ),
    },
    {
      key: "memory_mb",
      header: "Memory",
      align: "right" as const,
      render: (value: number, row: Container) => (
        <div className="flex items-center gap-1 justify-end text-sm">
          <MemoryStick className="h-3 w-3 text-gray-400" />
          <span>
            {value || 0} MB
            {row.memory_limit_mb && row.memory_limit_mb > 0 && (
              <span className="text-gray-400"> / {row.memory_limit_mb} MB</span>
            )}
          </span>
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      width: "100px",
      render: (_: unknown, row: Container) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/docker/containers/${selectedAgent}/${row.container_id}`);
          }}
          className="flex items-center gap-1 text-xs text-primary-600 dark:text-primary-400 hover:underline"
        >
          <ExternalLink className="h-3 w-3" />
          Details
        </button>
      ),
    },
  ];

  // Table columns - Images (with checkbox)
  const imageColumns = [
    {
      key: "checkbox",
      header: (
        <button
          onClick={(e) => {
            e.stopPropagation();
            if (isAllImagesSelected) {
              selectNoImages();
            } else {
              selectAllImages();
            }
          }}
          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
        >
          {isAllImagesSelected ? (
            <CheckSquare className="h-4 w-4 text-primary-600" />
          ) : isSomeImagesSelected ? (
            <MinusSquare className="h-4 w-4 text-primary-600" />
          ) : (
            <Square className="h-4 w-4 text-gray-400" />
          )}
        </button>
      ),
      width: "40px",
      render: (_: unknown, row: DockerImage) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            toggleImageSelection(row.id);
          }}
          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
        >
          {selectedImageIds.has(row.id) ? (
            <CheckSquare className="h-4 w-4 text-primary-600" />
          ) : (
            <Square className="h-4 w-4 text-gray-400" />
          )}
        </button>
      ),
    },
    {
      key: "name",
      header: "Image Name",
      sortable: true,
      render: (_: unknown, row: DockerImage) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <ImageIcon className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">{getImageName(row)}</p>
            <p className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</p>
          </div>
        </div>
      ),
    },
    {
      key: "tags",
      header: "Tags",
      render: (value: string[]) => {
        if (value.length === 0) {
          return (
            <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
              No tags
            </Badge>
          );
        }
        const tag = getImageTag({ tags: value } as DockerImage);
        return (
          <Badge className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">
            <Tag className="h-3 w-3 mr-1" />
            {tag}
            {value.length > 1 && ` +${value.length - 1}`}
          </Badge>
        );
      },
    },
    {
      key: "size",
      header: "Size",
      sortable: true,
      align: "right" as const,
      render: (value: number) => <span className="text-sm">{formatSize(value)}</span>,
    },
    {
      key: "created",
      header: "Created",
      sortable: true,
      render: (value: string) => (
        <span className="text-sm text-gray-500">{new Date(value).toLocaleDateString()}</span>
      ),
    },
    {
      key: "used_by",
      header: "In Use",
      align: "center" as const,
      render: (value: string[]) => {
        return value.length > 0 ? (
          <Badge className="px-2 py-1 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
            {value.length} container{value.length !== 1 ? "s" : ""}
          </Badge>
        ) : null;
      },
    },
  ];

  // Table columns - Volumes
  const volumeColumns = [
    {
      key: "name",
      header: "Volume Name",
      sortable: true,
      render: (value: string, row: DockerVolume) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
            <HardDrive className="h-5 w-5 text-gray-500" />
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white truncate max-w-[200px]">{value}</p>
            <p className="text-xs text-gray-500">{row.driver} driver</p>
          </div>
        </div>
      ),
    },
    {
      key: "mountpoint",
      header: "Mount Point",
      render: (value: string) => (
        <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded font-mono border-0">
          {value.length > 40 ? `...${value.slice(-37)}` : value}
        </Badge>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      sortable: true,
    },
    {
      key: "used_by",
      header: "In Use",
      align: "center" as const,
      render: (value: string[]) => {
        return value.length > 0 ? (
          <Badge className="px-2 py-1 text-xs bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded border-0">
            {value.length} container{value.length !== 1 ? "s" : ""}
          </Badge>
        ) : (
          <Badge className="px-2 py-1 text-xs bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 rounded border-0">
            Unused
          </Badge>
        );
      },
    },
  ];

  // Table columns - Networks
  const networkColumns = [
    {
      key: "name",
      header: "Name",
      render: (value: string, row: DockerNetwork) => (
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-gray-400" />
          <div>
            <div className="font-medium text-gray-900 dark:text-white">{value}</div>
            <div className="text-xs text-gray-500 font-mono">{row.id.slice(0, 12)}</div>
          </div>
        </div>
      ),
    },
    {
      key: "driver",
      header: "Driver",
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
    },
    {
      key: "containers",
      header: "Containers",
      align: "center" as const,
      render: (value: Record<string, string>) => (
        <span className="text-sm">{Object.keys(value || {}).length}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <Breadcrumb items={[{ label: "Run", href: "/" }, { label: "Docker" }]} />

      <PageHeader
        title="Docker"
        description="Manage containers, images, volumes, and networks"
        action={
          activeAgents.length > 0 && (
            <div className="flex items-center gap-3">
              <select
                value={selectedAgent}
                onChange={(e) => setSelectedAgent(e.target.value)}
                className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
              >
                {activeAgents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} ({agent.hostname || "unknown host"})
                  </option>
                ))}
              </select>
              {activeTab === "images" && (
                <Button variant="primary" size="sm" onClick={() => setShowPullModal(true)}>
                  <Download className="h-4 w-4 mr-1" />
                  Pull Image
                </Button>
              )}
              {activeTab === "volumes" && (
                <Button variant="primary" size="sm" onClick={() => setShowCreateVolumeModal(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Create Volume
                </Button>
              )}
            </div>
          )
        }
      />

      <Tabs tabs={tabs} activeTab={activeTab} onChange={handleTabChange} />

      {!selectedAgent ? (
        <EmptyState icon={Server} title="No agents available" description="Add an agent to manage Docker resources" />
      ) : (
        <>
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              <MetricsGrid columns={4}>
                <StatCard label="Containers" value={containerMetrics.total} icon={ContainerIcon} description={`${containerMetrics.running} running`} iconColor="text-blue-600 dark:text-blue-400" onClick={() => handleTabChange("containers")} />
                <StatCard label="Images" value={imageMetrics.total} icon={ImageIcon} description={formatSize(imageMetrics.totalSize)} iconColor="text-purple-600 dark:text-purple-400" onClick={() => handleTabChange("images")} />
                <StatCard label="Volumes" value={volumeMetrics.total} icon={HardDrive} description={`${volumeMetrics.inUse} in use`} iconColor="text-green-600 dark:text-green-400" onClick={() => handleTabChange("volumes")} />
                <StatCard label="Networks" value={networkMetrics.total} icon={Network} description={`${networkMetrics.bridge} bridge`} iconColor="text-orange-600 dark:text-orange-400" onClick={() => handleTabChange("networks")} />
              </MetricsGrid>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Containers Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Containers</h3>
                    <button onClick={() => handleTabChange("containers")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingContainers ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : containers && containers.length > 0 ? (
                    <Table data={containers.slice(0, 5)} columns={containerColumns.slice(0, -1)} keyExtractor={(row) => row.container_id} onRowClick={(row) => { setSelectedContainer(row); setContainerPanelTab("details"); }} hoverable />
                  ) : (
                    <EmptyState icon={ContainerIcon} title="No containers" description="No containers are running on this agent" />
                  )}
                </div>

                {/* Images Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Images</h3>
                    <button onClick={() => handleTabChange("images")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingImages ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : images && images.length > 0 ? (
                    <Table data={images.slice(0, 5)} columns={imageColumns.slice(1, -1)} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedImage(row)} hoverable />
                  ) : (
                    <EmptyState icon={ImageIcon} title="No images" description="No images are available on this agent" />
                  )}
                </div>

                {/* Volumes Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Volumes</h3>
                    <button onClick={() => handleTabChange("volumes")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingVolumes ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : volumes && volumes.length > 0 ? (
                    <Table data={volumes.slice(0, 5)} columns={volumeColumns.slice(0, 2)} keyExtractor={(row) => row.name} onRowClick={(row) => setSelectedVolume(row)} hoverable />
                  ) : (
                    <EmptyState icon={HardDrive} title="No volumes" description="No volumes are configured on this agent" />
                  )}
                </div>

                {/* Networks Summary */}
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Networks</h3>
                    <button onClick={() => handleTabChange("networks")} className="text-sm text-primary-600 hover:text-primary-700">View all →</button>
                  </div>
                  {loadingNetworks ? (
                    <div className="flex items-center justify-center h-32"><Spinner size="md" /></div>
                  ) : networks && networks.length > 0 ? (
                    <Table data={networks.slice(0, 5)} columns={networkColumns.slice(0, 3)} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedNetwork(row)} hoverable />
                  ) : (
                    <EmptyState icon={Network} title="No networks" description="No networks are configured on this agent" />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Containers Tab */}
          {activeTab === "containers" && (
            <div className="space-y-4">
              <MetricsGrid columns={5}>
                <StatCard label="Total" value={containerMetrics.total} icon={ContainerIcon} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Running" value={containerMetrics.running} icon={Play} iconColor="text-green-600 dark:text-green-400" />
                <StatCard label="Stopped" value={containerMetrics.stopped} icon={Square} iconColor="text-red-600 dark:text-red-400" />
                <StatCard label="CPU Usage" value={`${(containers?.reduce((sum, c) => sum + (c.cpu_percent || 0), 0) || 0).toFixed(1)}%`} icon={Cpu} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Memory Usage" value={`${(containers?.reduce((sum, c) => sum + (c.memory_mb || 0), 0) || 0).toFixed(0)} MB`} icon={MemoryStick} iconColor="text-purple-600 dark:text-purple-400" />
              </MetricsGrid>

              <div className="flex gap-6">
                {/* Filters Sidebar */}
                <div className="w-64 flex-shrink-0">
                  <FilterPanel
                    filters={[
                      {
                        id: "status",
                        label: "Status",
                        type: "radio",
                        options: [
                          { label: "All", value: "all", count: containerMetrics.total },
                          { label: "Running", value: "running", count: containerMetrics.running },
                          { label: "Stopped", value: "exited", count: containerMetrics.stopped },
                        ],
                        value: statusFilter,
                        onChange: (value) => setStatusFilter(value as StatusFilter),
                      },
                      {
                        id: "search",
                        label: "Search",
                        type: "search",
                        value: searchFilter,
                        onChange: (value) => setSearchFilter(value as string),
                      },
                    ]}
                    onReset={() => {
                      setStatusFilter("all");
                      setSearchFilter("");
                    }}
                  />
                </div>

                {/* Containers Table */}
                <div className="flex-1 min-w-0">
                  {loadingContainers ? (
                    <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
                  ) : filteredContainers.length > 0 ? (
                    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                      <Table
                        data={filteredContainers}
                        columns={containerColumns}
                        keyExtractor={(row) => row.container_id}
                        onRowClick={(row) => { setSelectedContainer(row); setContainerPanelTab("details"); }}
                        selectedRows={selectedContainer ? new Set([selectedContainer.container_id]) : undefined}
                        hoverable
                      />
                    </div>
                  ) : (
                    <EmptyState
                      icon={ContainerIcon}
                      title="No containers found"
                      description={containers?.length === 0 ? "Make sure Docker is running and containers are deployed" : "No containers match the current filters"}
                    />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Images Tab */}
          {activeTab === "images" && (
            <div className="space-y-4">
              <MetricsGrid columns={4}>
                <StatCard label="Total Images" value={imageMetrics.total} icon={ImageIcon} iconColor="text-purple-600 dark:text-purple-400" />
                <StatCard label="Total Size" value={formatSize(imageMetrics.totalSize)} icon={Layers} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="In Use" value={imageMetrics.inUse} icon={Tag} iconColor="text-green-600 dark:text-green-400" />
                <StatCard label="Vulnerabilities" value={0} icon={Shield} iconColor="text-orange-600 dark:text-orange-400" />
              </MetricsGrid>

              {/* Selection Action Bar */}
              {images && images.length > 0 && (
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Quick select:</span>
                    <button onClick={selectAllImages} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors">
                      All ({images.length})
                    </button>
                    <button onClick={selectUnusedImages} disabled={unusedImagesCount === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                      Unused ({unusedImagesCount})
                    </button>
                    <button onClick={selectDanglingImages} disabled={danglingImagesCount === 0} className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                      Dangling ({danglingImagesCount})
                    </button>
                    {selectedImageIds.size > 0 && (
                      <button onClick={selectNoImages} className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
                        Clear
                      </button>
                    )}
                  </div>

                  {selectedImageIds.size > 0 && (
                    <div className="flex items-center gap-3">
                      <span className="text-sm text-gray-700 dark:text-gray-300">
                        <strong>{selectedImageIds.size}</strong> selected ({formatSize(selectedImagesSize)})
                      </span>
                      <Button variant="secondary" size="sm" onClick={handleScanSelected}>
                        <Shield className="h-4 w-4 mr-1" />
                        Scan Selected
                      </Button>
                      <Button variant="danger" size="sm" onClick={() => setShowBulkDeleteModal(true)}>
                        <Trash2 className="h-4 w-4 mr-1" />
                        Delete Selected
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {loadingImages ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : images && images.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={images}
                    columns={imageColumns}
                    keyExtractor={(row) => row.id}
                    onRowClick={(row) => setSelectedImage(row)}
                    hoverable
                    rowClassName={(row) =>
                      cn(
                        selectedImage?.id === row.id && "bg-primary-50 dark:bg-primary-900/20",
                        selectedImageIds.has(row.id) && "bg-blue-50 dark:bg-blue-900/10"
                      )
                    }
                  />
                </div>
              ) : (
                <EmptyState
                  icon={ImageIcon}
                  title="No images found"
                  description="Pull a Docker image to get started"
                  action={
                    <Button variant="primary" onClick={() => setShowPullModal(true)}>
                      <Download className="h-4 w-4 mr-1" />
                      Pull Image
                    </Button>
                  }
                />
              )}
            </div>
          )}

          {/* Volumes Tab */}
          {activeTab === "volumes" && (
            <div className="space-y-4">
              <MetricsGrid columns={4}>
                <StatCard label="Total Volumes" value={volumeMetrics.total} icon={HardDrive} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="In Use" value={volumeMetrics.inUse} icon={Database} iconColor="text-green-600 dark:text-green-400" />
                <StatCard label="Total Size" value="N/A" icon={FolderOpen} iconColor="text-purple-600 dark:text-purple-400" />
                <StatCard label="Orphaned" value={volumeMetrics.total - volumeMetrics.inUse} icon={AlertTriangle} iconColor="text-orange-600 dark:text-orange-400" />
              </MetricsGrid>

              {loadingVolumes ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : volumes && volumes.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table
                    data={volumes}
                    columns={volumeColumns}
                    keyExtractor={(row) => row.name}
                    onRowClick={(row) => setSelectedVolume(row)}
                    hoverable
                    rowClassName={(row) => selectedVolume?.name === row.name ? "bg-primary-50 dark:bg-primary-900/20" : ""}
                  />
                </div>
              ) : (
                <EmptyState
                  icon={HardDrive}
                  title="No volumes found"
                  description="Create a Docker volume to persist data"
                  action={
                    <Button variant="primary" onClick={() => setShowCreateVolumeModal(true)}>
                      <Plus className="h-4 w-4 mr-1" />
                      Create Volume
                    </Button>
                  }
                />
              )}
            </div>
          )}

          {/* Networks Tab */}
          {activeTab === "networks" && (
            <div className="space-y-4">
              <MetricsGrid columns={3}>
                <StatCard label="Total Networks" value={networkMetrics.total} icon={Network} iconColor="text-orange-600 dark:text-orange-400" />
                <StatCard label="Bridge" value={networkMetrics.bridge} icon={Network} iconColor="text-blue-600 dark:text-blue-400" />
                <StatCard label="Other" value={networkMetrics.total - networkMetrics.bridge} icon={Network} iconColor="text-purple-600 dark:text-purple-400" />
              </MetricsGrid>

              {loadingNetworks ? (
                <div className="flex items-center justify-center h-64"><Spinner size="lg" /></div>
              ) : networks && networks.length > 0 ? (
                <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
                  <Table data={networks} columns={networkColumns} keyExtractor={(row) => row.id} onRowClick={(row) => setSelectedNetwork(row)} hoverable />
                </div>
              ) : (
                <EmptyState icon={Network} title="No networks" description="No networks are configured on this agent" />
              )}
            </div>
          )}
        </>
      )}

      {/* Container SlideOver */}
      <SlideOver isOpen={!!selectedContainer} onClose={() => setSelectedContainer(null)} size="lg">
        {selectedContainer && (
          <>
            <SlideOver.Header onClose={() => setSelectedContainer(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedContainer.image}</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-2 mb-6 border-b border-gray-200 dark:border-gray-700">
                <button onClick={() => setContainerPanelTab("details")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "details" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Details</button>
                <button onClick={() => setContainerPanelTab("logs")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "logs" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Logs</button>
                {selectedContainer.status === "running" && (
                  <button onClick={() => setContainerPanelTab("terminal")} className={cn("px-4 py-2 text-sm font-medium border-b-2 transition-colors", containerPanelTab === "terminal" ? "border-primary-600 text-primary-600 dark:text-primary-400" : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300")}>Terminal</button>
                )}
              </div>

              {containerPanelTab === "details" && (
                <div className="space-y-6">
                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedContainer.status === "running" ? (
                        <>
                          <button onClick={() => setShowStopModal(true)} disabled={stopMutation.isPending} className="px-3 py-1.5 text-sm bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 rounded-lg hover:bg-yellow-200 dark:hover:bg-yellow-900/50 disabled:opacity-50">
                            <Square className="h-4 w-4 inline mr-1" />Stop
                          </button>
                          <button onClick={() => setShowRestartModal(true)} disabled={restartMutation.isPending} className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50 disabled:opacity-50">
                            <RotateCcw className="h-4 w-4 inline mr-1" />Restart
                          </button>
                        </>
                      ) : (
                        <button onClick={() => startMutation.mutate({ containerId: selectedContainer.container_id })} disabled={startMutation.isPending} className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50 disabled:opacity-50">
                          <Play className="h-4 w-4 inline mr-1" />Start
                        </button>
                      )}
                      <button onClick={() => router.push(`/docker/containers/${selectedAgent}/${selectedContainer.container_id}`)} className="px-3 py-1.5 text-sm bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
                        <ExternalLink className="h-4 w-4 inline mr-1" />Full Details
                      </button>
                      <button onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteContainerModal(true); }} className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50">
                        <Trash2 className="h-4 w-4 inline mr-1" />Delete
                      </button>
                    </div>
                  </div>

                  {/* Container Info */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Container Info</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                        <StatusIndicator status={getStatusLevel(selectedContainer.status)} label={selectedContainer.status} size="sm" />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Container ID</span>
                        <div className="flex items-center gap-1">
                          <code className="text-sm">{selectedContainer.container_id.slice(0, 12)}</code>
                          <button onClick={() => handleCopy(selectedContainer.container_id, "container-id")} className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded">
                            {copied === "container-id" ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400" />}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Stack</span>
                        <span className="text-sm text-gray-900 dark:text-white">{selectedContainer.stack_name || "Standalone"}</span>
                      </div>
                    </div>
                  </div>

                  {/* Resources */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Resources</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <Cpu className="h-3 w-3" />CPU Usage
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.cpu_percent?.toFixed(1) || 0}%</p>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800/50 rounded-lg p-3">
                        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-xs mb-1">
                          <MemoryStick className="h-3 w-3" />Memory
                        </div>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedContainer.memory_mb || 0} MB</p>
                      </div>
                    </div>
                  </div>

                  {/* Networks */}
                  {selectedContainer.networks && selectedContainer.networks.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Networks</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedContainer.networks.map((network) => (
                          <Badge key={network} size="sm">{network}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {containerPanelTab === "logs" && (
                <div className="flex flex-col -mx-6 h-[calc(100vh-300px)]">
                  <div className="flex items-center justify-between px-6 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
                    <select value={logsTail} onChange={(e) => setLogsTail(Number(e.target.value))} className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs text-gray-200">
                      <option value={50}>50 lines</option>
                      <option value={100}>100 lines</option>
                      <option value={500}>500 lines</option>
                      <option value={1000}>1000 lines</option>
                    </select>
                    <button onClick={() => refetchLogs()} className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                      <RefreshCw className={cn("h-3.5 w-3.5 text-gray-400", logsLoading && "animate-spin")} />
                    </button>
                  </div>
                  <div className="flex-1 bg-gray-900 overflow-y-auto min-h-0 px-6">
                    {logsLoading ? (
                      <div className="flex items-center justify-center h-32"><div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-500" /></div>
                    ) : logsData?.logs ? (
                      <div className="font-mono text-xs py-2">
                        {logsData.logs.split("\n").filter((l: string) => l.trim()).map((line: string, idx: number) => (
                          <div key={idx} className="text-gray-300 hover:bg-gray-800/50 py-0.5 px-3 -mx-3">{line}</div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center text-gray-500 py-8 text-sm">No logs available</div>
                    )}
                  </div>
                </div>
              )}

              {containerPanelTab === "terminal" && (
                selectedContainer.status !== "running" ? (
                  <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                    <TerminalIcon className="h-8 w-8 mb-2 opacity-50" />
                    <p className="text-sm">Container must be running to access terminal</p>
                  </div>
                ) : (
                  <div className="h-[500px] bg-gray-900 rounded-lg overflow-hidden -mx-6">
                    <Terminal containerId={selectedContainer.container_id} agentId={selectedAgent} onClose={() => setContainerPanelTab("details")} />
                  </div>
                )
              )}
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Image SlideOver */}
      <SlideOver isOpen={!!selectedImage} onClose={() => setSelectedImage(null)} size="md">
        {selectedImage && (
          <>
            <SlideOver.Header onClose={() => setSelectedImage(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{getImageName(selectedImage)}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">{formatSize(selectedImage.size)}</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Image Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Image Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-900 dark:text-white">{selectedImage.id.slice(0, 12)}</span>
                        <button onClick={() => handleCopy(selectedImage.id, "image-id")} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                          {copied === "image-id" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Size</span>
                      <span className="text-sm text-gray-900 dark:text-white">{formatSize(selectedImage.size)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Created</span>
                      <span className="text-sm text-gray-900 dark:text-white">{new Date(selectedImage.created).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                {/* Tags */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Tags</h3>
                  {selectedImage.tags.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {selectedImage.tags.map((tag) => (
                        <Badge key={tag} className="px-2 py-1 text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded border-0">
                          <Tag className="h-3 w-3 mr-1" />{tag}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">No tags</p>
                  )}
                </div>

                {/* Used By */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Used By</h3>
                  {selectedImage.used_by.length > 0 ? (
                    <div className="space-y-2">
                      {selectedImage.used_by.map((container) => (
                        <div key={container} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                          <Server className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-900 dark:text-white">{container}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">Not used by any containers</p>
                  )}
                </div>

                {/* Security Scan */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Security Scan</h3>
                  <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg space-y-3">
                    <div className="flex items-center gap-2 text-gray-500">
                      <Shield className="h-4 w-4" />
                      <span className="text-sm">Scan for vulnerabilities</span>
                    </div>
                    <Button variant="secondary" size="sm" onClick={() => handleScanSingle(selectedImage)}>
                      <Shield className="h-4 w-4 mr-1" />
                      Scan Image
                    </Button>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="primary" size="sm" onClick={() => handleDeploy(selectedImage)}>
                      <Rocket className="h-4 w-4 mr-1" />Deploy
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteImageModal(true); }}>
                      <Trash2 className="h-4 w-4 mr-1" />Delete Image
                    </Button>
                  </div>
                  {selectedImage.used_by.length > 0 && (
                    <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">Warning: Image is in use. Deletion may require force.</p>
                  )}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Volume SlideOver */}
      <SlideOver isOpen={!!selectedVolume} onClose={() => setSelectedVolume(null)} size="md">
        {selectedVolume && (
          <>
            <SlideOver.Header onClose={() => setSelectedVolume(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white truncate max-w-[300px]">{selectedVolume.name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{selectedVolume.driver} driver</p>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              <div className="space-y-6">
                {/* Volume Info */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Volume Info</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Name</span>
                      <span className="text-sm text-gray-900 dark:text-white font-mono truncate max-w-[200px]">{selectedVolume.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Driver</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.driver}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Mountpoint</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-900 dark:text-white break-all">{selectedVolume.mountpoint}</span>
                        <button onClick={() => handleCopy(selectedVolume.mountpoint, "volume-mountpoint")} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 flex-shrink-0">
                          {copied === "volume-mountpoint" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Scope</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedVolume.scope}</span>
                    </div>
                  </div>
                </div>

                {/* Used By */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Used by Containers</h3>
                  {selectedVolume.used_by.length > 0 ? (
                    <div className="space-y-2">
                      {selectedVolume.used_by.map((containerName, idx) => (
                        <div key={idx} className="text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-3 py-2 rounded">{containerName}</div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">Not in use</span>
                  )}
                </div>

                {/* Actions */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                  <Button variant="danger" size="sm" onClick={() => { setDeleteError(null); setForceDelete(false); setShowDeleteVolumeModal(true); }}>
                    <Trash2 className="h-4 w-4 mr-1" />Delete Volume
                  </Button>
                  {selectedVolume.used_by.length > 0 && <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-2">Warning: Volume is in use. Deletion may require force.</p>}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

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
                  <Button variant="danger" size="sm" onClick={() => { setDeleteError(null); setShowDeleteNetworkModal(true); }} disabled={Object.keys(selectedNetwork.containers || {}).length > 0}>
                    <Trash2 className="h-4 w-4 mr-1" />Delete Network
                  </Button>
                  {Object.keys(selectedNetwork.containers || {}).length > 0 && <p className="text-xs text-gray-500 mt-2">Cannot delete network with connected containers</p>}
                </div>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* Pull Image Modal */}
      {showPullModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowPullModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Pull Image</h3>
              <button onClick={() => setShowPullModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="space-y-4">
              <Input
                label="Image Reference"
                value={pullImageRef}
                onChange={(e) => setPullImageRef(e.target.value)}
                placeholder="nginx:latest or ubuntu:22.04"
              />
              <p className="text-xs text-gray-500">Enter the image name and tag (e.g., nginx:latest, postgres:15)</p>
              {pullError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{pullError}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={() => setShowPullModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={() => pullMutation.mutate()} disabled={!pullImageRef || pullMutation.isPending}>
                {pullMutation.isPending ? "Pulling..." : "Pull Image"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Create Volume Modal */}
      {showCreateVolumeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowCreateVolumeModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Create Volume</h3>
              <button onClick={() => setShowCreateVolumeModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="space-y-4">
              <Input
                label="Volume Name"
                value={newVolumeName}
                onChange={(e) => setNewVolumeName(e.target.value)}
                placeholder="my-volume"
              />
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Driver</label>
                <select
                  value={newVolumeDriver}
                  onChange={(e) => setNewVolumeDriver(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900"
                >
                  <option value="local">local</option>
                </select>
              </div>
              {createVolumeError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-sm text-red-600 dark:text-red-400">{createVolumeError}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={() => setShowCreateVolumeModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={() => createVolumeMutation.mutate()} disabled={!newVolumeName || createVolumeMutation.isPending}>
                {createVolumeMutation.isPending ? "Creating..." : "Create Volume"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Delete Images Modal */}
      {showBulkDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => !bulkDeleteProgress && setShowBulkDeleteModal(false)} />
          <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-lg w-full mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-full">
                <Trash2 className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="text-lg font-semibold">Delete {selectedImageIds.size} Images</h3>
            </div>

            {!bulkDeleteProgress ? (
              <>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  Are you sure you want to delete <strong>{selectedImageIds.size}</strong> selected images?
                  This will free up <strong>{formatSize(selectedImagesSize)}</strong> of disk space.
                </p>
                <div className="max-h-48 overflow-y-auto mb-4 space-y-1">
                  {selectedImagesData.map((img) => (
                    <div key={img.id} className={cn("flex items-center justify-between p-2 rounded text-sm", img.used_by.length > 0 ? "bg-yellow-50 dark:bg-yellow-900/20" : "bg-gray-50 dark:bg-gray-800")}>
                      <span className="font-mono truncate">{img.tags[0] || img.id.slice(0, 12)}</span>
                      <span className="text-gray-500 text-xs">
                        {formatSize(img.size)}
                        {img.used_by.length > 0 && <span className="ml-2 text-yellow-600 dark:text-yellow-400">(in use)</span>}
                      </span>
                    </div>
                  ))}
                </div>
                {selectedImagesData.some((img) => img.used_by.length > 0) && (
                  <div className="mb-4">
                    <label className="flex items-center gap-2">
                      <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300" />
                      <span className="text-sm text-yellow-600 dark:text-yellow-400">Force delete images in use ({selectedImagesData.filter((img) => img.used_by.length > 0).length} images)</span>
                    </label>
                  </div>
                )}
                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => { setShowBulkDeleteModal(false); setForceDelete(false); }}>Cancel</Button>
                  <Button variant="danger" onClick={handleBulkDeleteImages} disabled={selectedImagesData.some((img) => img.used_by.length > 0) && !forceDelete}>
                    Delete {selectedImageIds.size} Images
                  </Button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Deleting images...</span>
                    <span>{bulkDeleteProgress.completed} / {bulkDeleteProgress.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div className="bg-red-600 h-2 rounded-full transition-all duration-300" style={{ width: `${(bulkDeleteProgress.completed / bulkDeleteProgress.total) * 100}%` }} />
                  </div>
                </div>
                {bulkDeleteProgress.failed.length > 0 && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm font-medium text-red-600 dark:text-red-400 mb-2">Failed to delete {bulkDeleteProgress.failed.length} images:</p>
                    <ul className="text-xs text-red-600 dark:text-red-400 space-y-1">
                      {bulkDeleteProgress.failed.map((name, idx) => <li key={idx}>• {name}</li>)}
                    </ul>
                  </div>
                )}
                {bulkDeleteProgress.completed === bulkDeleteProgress.total && (
                  <div className="flex justify-end">
                    <Button variant="secondary" onClick={() => { setShowBulkDeleteModal(false); setSelectedImageIds(new Set()); setBulkDeleteProgress(null); setForceDelete(false); }}>
                      {bulkDeleteProgress.failed.length > 0 ? "Close" : "Done"}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirmation Dialogs */}
      <ConfirmDialog isOpen={showStopModal && !!selectedContainer} onClose={() => setShowStopModal(false)} onConfirm={() => stopMutation.mutate({ containerId: selectedContainer!.container_id })} title="Stop Container" message={`Are you sure you want to stop ${selectedContainer?.name}?`} confirmText="Stop Container" variant="warning" icon="stop" isLoading={stopMutation.isPending} />

      <ConfirmDialog isOpen={showRestartModal && !!selectedContainer} onClose={() => setShowRestartModal(false)} onConfirm={() => restartMutation.mutate({ containerId: selectedContainer!.container_id })} title="Restart Container" message={`Are you sure you want to restart ${selectedContainer?.name}?`} confirmText="Restart Container" variant="default" icon="redeploy" isLoading={restartMutation.isPending} />

      <ConfirmDialog isOpen={showDeleteContainerModal && !!selectedContainer} onClose={() => { setShowDeleteContainerModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteContainerMutation.mutate()} title="Delete Container" message="This action cannot be undone." confirmText="Delete Container" variant="danger" icon="delete" isLoading={deleteContainerMutation.isPending} confirmLevel="name" confirmValue={selectedContainer?.name} error={deleteError} onInputChange={() => {}}>
        {selectedContainer?.status === "running" && (
          <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
            Force delete (stop container first)
          </label>
        )}
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteImageModal && !!selectedImage} onClose={() => { setShowDeleteImageModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteImageMutation.mutate()} title="Delete Image" message={`Are you sure you want to delete this image?`} confirmText="Delete Image" variant="danger" icon="delete" isLoading={deleteImageMutation.isPending} error={deleteError}>
        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
          Force delete (remove even if in use)
        </label>
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteVolumeModal && !!selectedVolume} onClose={() => { setShowDeleteVolumeModal(false); setDeleteError(null); setForceDelete(false); }} onConfirm={() => deleteVolumeMutation.mutate()} title="Delete Volume" message={`Are you sure you want to delete volume "${selectedVolume?.name}"?`} confirmText="Delete Volume" variant="danger" icon="delete" isLoading={deleteVolumeMutation.isPending} error={deleteError}>
        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input type="checkbox" checked={forceDelete} onChange={(e) => setForceDelete(e.target.checked)} className="rounded border-gray-300 dark:border-gray-700 text-red-600 focus:ring-red-500" />
          Force delete
        </label>
      </ConfirmDialog>

      <ConfirmDialog isOpen={showDeleteNetworkModal && !!selectedNetwork} onClose={() => { setShowDeleteNetworkModal(false); setDeleteError(null); }} onConfirm={() => deleteNetworkMutation.mutate()} title="Delete Network" message={`Are you sure you want to delete network "${selectedNetwork?.name}"?`} confirmText="Delete Network" variant="danger" icon="delete" isLoading={deleteNetworkMutation.isPending} error={deleteError} />

      {/* Scan Modal */}
      <ScanModal
        isOpen={showScanModal}
        onClose={() => {
          setShowScanModal(false);
          setScanImages([]);
        }}
        images={scanImages}
        mode="both"
      />

      {/* Deploy Wizard */}
      {deployImageInfo && (
        <DeployWizard
          isOpen={showDeployWizard}
          onClose={() => {
            setShowDeployWizard(false);
            setDeployImageInfo(null);
          }}
          imageRepository={deployImageInfo.repository}
          imageTag={deployImageInfo.tag}
        />
      )}
    </div>
  );
}
