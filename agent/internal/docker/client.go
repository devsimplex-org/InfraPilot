package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

type Client struct {
	cli *client.Client
}

type ContainerInfo struct {
	ID            string
	Name          string
	Image         string
	Status        string
	State         string
	StackName     string
	CPUPercent    float64
	MemoryMB      int64
	MemoryLimitMB int64
	RestartCount  int
}

// NetworkInfo represents Docker network information
type NetworkInfo struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	Containers map[string]string `json:"containers"` // containerID -> containerName
}

// ContainerNetworkInfo represents network membership for a container
type ContainerNetworkInfo struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	IPAddress   string `json:"ip_address"`
}

// NetworkAttachResult contains the result of a network attach operation
type NetworkAttachResult struct {
	Success      bool   `json:"success"`
	NetworkID    string `json:"network_id"`
	NetworkName  string `json:"network_name"`
	Message      string `json:"message,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ============ Extended Network Types ============

// NetworkDetailInfo represents detailed Docker network information
type NetworkDetailInfo struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Driver     string                     `json:"driver"`
	Scope      string                     `json:"scope"`
	Internal   bool                       `json:"internal"`
	Attachable bool                       `json:"attachable"`
	IPAM       NetworkIPAMConfig          `json:"ipam"`
	Containers map[string]NetworkEndpoint `json:"containers"`
	Options    map[string]string          `json:"options"`
	Labels     map[string]string          `json:"labels"`
	CreatedAt  string                     `json:"created_at"`
}

// NetworkIPAMConfig represents IPAM configuration
type NetworkIPAMConfig struct {
	Driver  string           `json:"driver"`
	Configs []IPAMPoolConfig `json:"configs"`
}

// IPAMPoolConfig represents a single IPAM pool configuration
type IPAMPoolConfig struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
	IPRange string `json:"ip_range,omitempty"`
}

// NetworkEndpoint represents a container endpoint on a network
type NetworkEndpoint struct {
	Name        string `json:"name"`
	EndpointID  string `json:"endpoint_id"`
	MacAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// NetworkCreateOptions contains options for creating a network
type NetworkCreateOptions struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable"`
	Labels     map[string]string `json:"labels,omitempty"`
	IPAM       *NetworkIPAMConfig `json:"ipam,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

// ============ Volume Types ============

// VolumeInfo represents Docker volume information
type VolumeInfo struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Scope      string            `json:"scope"`
	Labels     map[string]string `json:"labels"`
	CreatedAt  string            `json:"created_at"`
	UsedBy     []string          `json:"used_by"`
}

// VolumeCreateOptions contains options for creating a volume
type VolumeCreateOptions struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ============ Image Types ============

// ImageInfo represents Docker image information
type ImageInfo struct {
	ID          string   `json:"id"`
	Tags        []string `json:"tags"`
	Size        int64    `json:"size"`
	SizeMB      int64    `json:"size_mb"`
	Created     string   `json:"created"`
	RepoDigests []string `json:"repo_digests"`
	UsedBy      []string `json:"used_by"`
}

// ImagePullProgress represents image pull progress
type ImagePullProgress struct {
	Status   string `json:"status"`
	Progress string `json:"progress,omitempty"`
	ID       string `json:"id,omitempty"`
}

// AuthConfig represents authentication for Docker registry operations
type AuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"server_address,omitempty"`
}

// PullProgressInfo represents progress information during image pull
type PullProgressInfo struct {
	Status   string `json:"status"`   // "pulling", "extracting", "complete", "error"
	Current  int64  `json:"current"`  // bytes downloaded/extracted
	Total    int64  `json:"total"`    // total bytes
	Progress int    `json:"progress"` // 0-100 percentage
	Layer    string `json:"layer,omitempty"`
	Message  string `json:"message,omitempty"`
}

// DockerPullProgress represents a single progress message from Docker's pull API
type DockerPullProgress struct {
	Status         string `json:"status"`
	ID             string `json:"id"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
	Progress string `json:"progress"`
	Error    string `json:"error,omitempty"`
}

func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return &Client{cli: cli}, nil
}

func (c *Client) Close() error {
	return c.cli.Close()
}

// Client returns the underlying Docker client for advanced operations
func (c *Client) Client() *client.Client {
	return c.cli
}

func (c *Client) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	result := make([]ContainerInfo, 0, len(containers))
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}

		// Extract stack name from labels (docker-compose)
		stackName := ""
		if project, ok := cont.Labels["com.docker.compose.project"]; ok {
			stackName = project
		}

		info := ContainerInfo{
			ID:        cont.ID[:12],
			Name:      name,
			Image:     cont.Image,
			Status:    cont.Status,
			State:     cont.State,
			StackName: stackName,
		}

		result = append(result, info)
	}

	return result, nil
}

func (c *Client) InspectContainer(ctx context.Context, containerID string) (*types.ContainerJSON, error) {
	info, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) StartContainer(ctx context.Context, containerID string) error {
	return c.cli.ContainerStart(ctx, containerID, container.StartOptions{})
}

func (c *Client) StopContainer(ctx context.Context, containerID string, timeout *int) error {
	options := container.StopOptions{}
	if timeout != nil {
		options.Timeout = timeout
	}
	return c.cli.ContainerStop(ctx, containerID, options)
}

func (c *Client) RestartContainer(ctx context.Context, containerID string, timeout *int) error {
	options := container.StopOptions{}
	if timeout != nil {
		options.Timeout = timeout
	}
	return c.cli.ContainerRestart(ctx, containerID, options)
}

func (c *Client) GetContainerLogs(ctx context.Context, containerID string, tail string, follow bool) error {
	// Returns io.ReadCloser for streaming
	_, err := c.cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Follow:     follow,
		Timestamps: true,
	})
	return err
}

func (c *Client) GetContainerStats(ctx context.Context, containerID string) (*container.StatsResponse, error) {
	stats, err := c.cli.ContainerStatsOneShot(ctx, containerID)
	if err != nil {
		return nil, err
	}
	defer stats.Body.Close()

	// Parse stats from response body
	// In production, decode JSON stats
	return nil, nil
}

func (c *Client) ExecCreate(ctx context.Context, containerID string, cmd []string) (string, error) {
	resp, err := c.cli.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  false,
		Tty:          false,
	})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// ExecAttach runs an exec and returns the output
func (c *Client) ExecAttach(ctx context.Context, execID string) (string, error) {
	resp, err := c.cli.ContainerExecAttach(ctx, execID, container.ExecStartOptions{
		Tty: false,
	})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	// Read the output
	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		return "", err
	}

	// Check exec result
	inspect, err := c.cli.ContainerExecInspect(ctx, execID)
	if err != nil {
		return "", err
	}

	// Non-zero exit code means the command failed (e.g., file not found)
	if inspect.ExitCode != 0 {
		return "", fmt.Errorf("exec failed with exit code %d", inspect.ExitCode)
	}

	return string(output), nil
}

// ============ Network Operations ============

// ListNetworks returns all Docker networks, filtering out unsafe networks (host, none, overlay)
func (c *Client) ListNetworks(ctx context.Context) ([]NetworkInfo, error) {
	networks, err := c.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	result := make([]NetworkInfo, 0, len(networks))
	for _, net := range networks {
		// Filter out unsafe networks
		if net.Name == "host" || net.Name == "none" {
			continue
		}
		if net.Driver == "overlay" {
			continue
		}

		// Build container map
		containers := make(map[string]string)
		for id, ep := range net.Containers {
			shortID := id
			if len(id) > 12 {
				shortID = id[:12]
			}
			containers[shortID] = ep.Name
		}

		result = append(result, NetworkInfo{
			ID:         net.ID[:12],
			Name:       net.Name,
			Driver:     net.Driver,
			Scope:      net.Scope,
			Internal:   net.Internal,
			Containers: containers,
		})
	}

	return result, nil
}

// InspectNetwork returns detailed info about a specific network
func (c *Client) InspectNetwork(ctx context.Context, networkID string) (*NetworkInfo, error) {
	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	// Build container map
	containers := make(map[string]string)
	for id, ep := range net.Containers {
		shortID := id
		if len(id) > 12 {
			shortID = id[:12]
		}
		containers[shortID] = ep.Name
	}

	return &NetworkInfo{
		ID:         net.ID[:12],
		Name:       net.Name,
		Driver:     net.Driver,
		Scope:      net.Scope,
		Internal:   net.Internal,
		Containers: containers,
	}, nil
}

// GetContainerNetworks returns all networks a container is connected to
func (c *Client) GetContainerNetworks(ctx context.Context, containerID string) ([]ContainerNetworkInfo, error) {
	info, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	if info.NetworkSettings == nil || info.NetworkSettings.Networks == nil {
		return []ContainerNetworkInfo{}, nil
	}

	result := make([]ContainerNetworkInfo, 0, len(info.NetworkSettings.Networks))
	for networkName, netSettings := range info.NetworkSettings.Networks {
		networkID := netSettings.NetworkID
		if len(networkID) > 12 {
			networkID = networkID[:12]
		}

		result = append(result, ContainerNetworkInfo{
			NetworkID:   networkID,
			NetworkName: networkName,
			IPAddress:   netSettings.IPAddress,
		})
	}

	return result, nil
}

// ConnectNetwork attaches a container to a network
func (c *Client) ConnectNetwork(ctx context.Context, networkID, containerID string) error {
	err := c.cli.NetworkConnect(ctx, networkID, containerID, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to network: %w", err)
	}
	return nil
}

// DisconnectNetwork detaches a container from a network
func (c *Client) DisconnectNetwork(ctx context.Context, networkID, containerID string) error {
	err := c.cli.NetworkDisconnect(ctx, networkID, containerID, false)
	if err != nil {
		return fmt.Errorf("failed to disconnect from network: %w", err)
	}
	return nil
}

// IsNetworkSafe validates if a network is safe to attach nginx to
// Returns (true, "") if safe, or (false, reason) if not
func (c *Client) IsNetworkSafe(ctx context.Context, networkID string) (bool, string) {
	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		return false, "network not found"
	}

	// BLOCKED: host network
	if net.Name == "host" {
		return false, "cannot attach to host network"
	}

	// BLOCKED: none network
	if net.Name == "none" {
		return false, "cannot attach to none network"
	}

	// BLOCKED: overlay networks (Swarm mode)
	if net.Driver == "overlay" {
		return false, "overlay networks not supported (requires Swarm mode)"
	}

	// BLOCKED: non-local scope
	if net.Scope != "local" {
		return false, "only local scope networks are supported"
	}

	return true, ""
}

// IsContainerOnNetwork checks if a container is connected to a specific network
func (c *Client) IsContainerOnNetwork(ctx context.Context, containerID, networkID string) (bool, error) {
	networks, err := c.GetContainerNetworks(ctx, containerID)
	if err != nil {
		return false, err
	}

	for _, net := range networks {
		if net.NetworkID == networkID || net.NetworkName == networkID {
			return true, nil
		}
	}

	return false, nil
}

// ============ Extended Network Operations ============

// InspectNetworkDetail returns detailed information about a specific network
func (c *Client) InspectNetworkDetail(ctx context.Context, networkID string) (*NetworkDetailInfo, error) {
	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{Verbose: true})
	if err != nil {
		return nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	// Build container endpoints map
	containers := make(map[string]NetworkEndpoint)
	for id, ep := range net.Containers {
		shortID := id
		if len(id) > 12 {
			shortID = id[:12]
		}
		containers[shortID] = NetworkEndpoint{
			Name:        ep.Name,
			EndpointID:  ep.EndpointID,
			MacAddress:  ep.MacAddress,
			IPv4Address: ep.IPv4Address,
			IPv6Address: ep.IPv6Address,
		}
	}

	// Build IPAM config
	ipamConfigs := make([]IPAMPoolConfig, 0, len(net.IPAM.Config))
	for _, cfg := range net.IPAM.Config {
		ipamConfigs = append(ipamConfigs, IPAMPoolConfig{
			Subnet:  cfg.Subnet,
			Gateway: cfg.Gateway,
			IPRange: cfg.IPRange,
		})
	}

	networkID = net.ID
	if len(networkID) > 12 {
		networkID = networkID[:12]
	}

	return &NetworkDetailInfo{
		ID:         networkID,
		Name:       net.Name,
		Driver:     net.Driver,
		Scope:      net.Scope,
		Internal:   net.Internal,
		Attachable: net.Attachable,
		IPAM: NetworkIPAMConfig{
			Driver:  net.IPAM.Driver,
			Configs: ipamConfigs,
		},
		Containers: containers,
		Options:    net.Options,
		Labels:     net.Labels,
		CreatedAt:  net.Created.Format(time.RFC3339),
	}, nil
}

// CreateNetwork creates a new Docker network
func (c *Client) CreateNetwork(ctx context.Context, opts NetworkCreateOptions) (*NetworkInfo, error) {
	// Validate driver
	if opts.Driver == "" {
		opts.Driver = "bridge"
	}
	if opts.Driver == "overlay" {
		return nil, fmt.Errorf("overlay networks not supported (requires Swarm mode)")
	}

	// Build IPAM config if provided
	var ipamConfig *network.IPAM
	if opts.IPAM != nil && len(opts.IPAM.Configs) > 0 {
		poolConfigs := make([]network.IPAMConfig, 0, len(opts.IPAM.Configs))
		for _, cfg := range opts.IPAM.Configs {
			poolConfigs = append(poolConfigs, network.IPAMConfig{
				Subnet:  cfg.Subnet,
				Gateway: cfg.Gateway,
				IPRange: cfg.IPRange,
			})
		}
		driver := opts.IPAM.Driver
		if driver == "" {
			driver = "default"
		}
		ipamConfig = &network.IPAM{
			Driver: driver,
			Config: poolConfigs,
		}
	}

	resp, err := c.cli.NetworkCreate(ctx, opts.Name, network.CreateOptions{
		Driver:     opts.Driver,
		Internal:   opts.Internal,
		Attachable: opts.Attachable,
		Labels:     opts.Labels,
		Options:    opts.Options,
		IPAM:       ipamConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create network: %w", err)
	}

	networkID := resp.ID
	if len(networkID) > 12 {
		networkID = networkID[:12]
	}

	return &NetworkInfo{
		ID:         networkID,
		Name:       opts.Name,
		Driver:     opts.Driver,
		Scope:      "local",
		Internal:   opts.Internal,
		Containers: make(map[string]string),
	}, nil
}

// DeleteNetwork removes a Docker network
func (c *Client) DeleteNetwork(ctx context.Context, networkID string) error {
	// First check if the network exists and is safe to delete
	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	// Block deletion of system networks
	if net.Name == "bridge" || net.Name == "host" || net.Name == "none" {
		return fmt.Errorf("cannot delete system network: %s", net.Name)
	}

	err = c.cli.NetworkRemove(ctx, networkID)
	if err != nil {
		return fmt.Errorf("failed to delete network: %w", err)
	}

	return nil
}

// IsNetworkInUse checks if a network has any connected containers
func (c *Client) IsNetworkInUse(ctx context.Context, networkID string) (bool, []string, error) {
	net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		return false, nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	containerNames := make([]string, 0, len(net.Containers))
	for _, ep := range net.Containers {
		containerNames = append(containerNames, ep.Name)
	}

	return len(containerNames) > 0, containerNames, nil
}

// ============ Volume Operations ============

// ListVolumes returns all Docker volumes with usage information
func (c *Client) ListVolumes(ctx context.Context) ([]VolumeInfo, error) {
	volumeList, err := c.cli.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Get all containers to find volume usage
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers for volume usage: %w", err)
	}

	// Build a map of volume name -> container names
	volumeUsage := make(map[string][]string)
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}
		for _, mount := range cont.Mounts {
			if mount.Type == "volume" {
				volumeUsage[mount.Name] = append(volumeUsage[mount.Name], name)
			}
		}
	}

	result := make([]VolumeInfo, 0, len(volumeList.Volumes))
	for _, vol := range volumeList.Volumes {
		usedBy := volumeUsage[vol.Name]
		if usedBy == nil {
			usedBy = []string{}
		}

		result = append(result, VolumeInfo{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			Scope:      vol.Scope,
			Labels:     vol.Labels,
			CreatedAt:  vol.CreatedAt,
			UsedBy:     usedBy,
		})
	}

	return result, nil
}

// InspectVolume returns detailed information about a specific volume
func (c *Client) InspectVolume(ctx context.Context, name string) (*VolumeInfo, error) {
	vol, err := c.cli.VolumeInspect(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Get containers using this volume
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	usedBy := []string{}
	for _, cont := range containers {
		contName := ""
		if len(cont.Names) > 0 {
			contName = strings.TrimPrefix(cont.Names[0], "/")
		}
		for _, mount := range cont.Mounts {
			if mount.Type == "volume" && mount.Name == name {
				usedBy = append(usedBy, contName)
				break
			}
		}
	}

	return &VolumeInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Scope:      vol.Scope,
		Labels:     vol.Labels,
		CreatedAt:  vol.CreatedAt,
		UsedBy:     usedBy,
	}, nil
}

// CreateVolume creates a new Docker volume
func (c *Client) CreateVolume(ctx context.Context, opts VolumeCreateOptions) (*VolumeInfo, error) {
	if opts.Driver == "" {
		opts.Driver = "local"
	}

	vol, err := c.cli.VolumeCreate(ctx, volume.CreateOptions{
		Name:       opts.Name,
		Driver:     opts.Driver,
		DriverOpts: opts.DriverOpts,
		Labels:     opts.Labels,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	return &VolumeInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Scope:      vol.Scope,
		Labels:     vol.Labels,
		CreatedAt:  vol.CreatedAt,
		UsedBy:     []string{},
	}, nil
}

// DeleteVolume removes a Docker volume
func (c *Client) DeleteVolume(ctx context.Context, name string, force bool) error {
	err := c.cli.VolumeRemove(ctx, name, force)
	if err != nil {
		return fmt.Errorf("failed to delete volume: %w", err)
	}
	return nil
}

// IsVolumeInUse checks if a volume is being used by any container
func (c *Client) IsVolumeInUse(ctx context.Context, name string) (bool, []string, error) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return false, nil, fmt.Errorf("failed to list containers: %w", err)
	}

	usedBy := []string{}
	for _, cont := range containers {
		contName := ""
		if len(cont.Names) > 0 {
			contName = strings.TrimPrefix(cont.Names[0], "/")
		}
		for _, mount := range cont.Mounts {
			if mount.Type == "volume" && mount.Name == name {
				usedBy = append(usedBy, contName)
				break
			}
		}
	}

	return len(usedBy) > 0, usedBy, nil
}

// ============ Image Operations ============

// ListImages returns all Docker images with usage information
func (c *Client) ListImages(ctx context.Context) ([]ImageInfo, error) {
	images, err := c.cli.ImageList(ctx, image.ListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	// Get all containers to find image usage
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers for image usage: %w", err)
	}

	// Build a map of image ID -> container names
	imageUsage := make(map[string][]string)
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}
		imageID := cont.ImageID
		if len(imageID) > 12 && strings.HasPrefix(imageID, "sha256:") {
			imageID = imageID[7:19] // Get short ID
		}
		imageUsage[imageID] = append(imageUsage[imageID], name)
	}

	result := make([]ImageInfo, 0, len(images))
	for _, img := range images {
		imageID := img.ID
		shortID := imageID
		if strings.HasPrefix(imageID, "sha256:") {
			shortID = imageID[7:19]
		} else if len(imageID) > 12 {
			shortID = imageID[:12]
		}

		usedBy := imageUsage[shortID]
		if usedBy == nil {
			usedBy = []string{}
		}

		tags := img.RepoTags
		if tags == nil {
			tags = []string{}
		}

		digests := img.RepoDigests
		if digests == nil {
			digests = []string{}
		}

		result = append(result, ImageInfo{
			ID:          shortID,
			Tags:        tags,
			Size:        img.Size,
			SizeMB:      img.Size / (1024 * 1024),
			Created:     time.Unix(img.Created, 0).Format(time.RFC3339),
			RepoDigests: digests,
			UsedBy:      usedBy,
		})
	}

	return result, nil
}

// InspectImage returns detailed information about a specific image
func (c *Client) InspectImage(ctx context.Context, imageID string) (*ImageInfo, error) {
	img, _, err := c.cli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Get containers using this image
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	usedBy := []string{}
	for _, cont := range containers {
		if strings.HasPrefix(cont.ImageID, img.ID) || cont.Image == imageID {
			name := ""
			if len(cont.Names) > 0 {
				name = strings.TrimPrefix(cont.Names[0], "/")
			}
			usedBy = append(usedBy, name)
		}
	}

	shortID := img.ID
	if strings.HasPrefix(shortID, "sha256:") {
		shortID = shortID[7:19]
	} else if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	tags := img.RepoTags
	if tags == nil {
		tags = []string{}
	}

	digests := img.RepoDigests
	if digests == nil {
		digests = []string{}
	}

	return &ImageInfo{
		ID:          shortID,
		Tags:        tags,
		Size:        img.Size,
		SizeMB:      img.Size / (1024 * 1024),
		Created:     img.Created,
		RepoDigests: digests,
		UsedBy:      usedBy,
	}, nil
}

// PullImage pulls a Docker image from a registry with optional authentication
func (c *Client) PullImage(ctx context.Context, imageRef string, auth *AuthConfig) error {
	pullOpts := image.PullOptions{}

	// Build registry auth if credentials are provided
	if auth != nil && (auth.Username != "" || auth.Password != "") {
		authConfig := registry.AuthConfig{
			Username:      auth.Username,
			Password:      auth.Password,
			ServerAddress: auth.ServerAddress,
		}
		encodedAuth, err := registry.EncodeAuthConfig(authConfig)
		if err != nil {
			return fmt.Errorf("failed to encode auth config: %w", err)
		}
		pullOpts.RegistryAuth = encodedAuth
	}

	reader, err := c.cli.ImagePull(ctx, imageRef, pullOpts)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// Consume the reader to complete the pull
	decoder := json.NewDecoder(reader)
	for {
		var progress ImagePullProgress
		if err := decoder.Decode(&progress); err != nil {
			if err == io.EOF {
				break
			}
			// Ignore decode errors, just continue
			continue
		}
	}

	return nil
}

// PullImageWithProgress pulls a Docker image and reports progress via callback
func (c *Client) PullImageWithProgress(ctx context.Context, imageRef string, auth *AuthConfig, progressFn func(*PullProgressInfo)) error {
	pullOpts := image.PullOptions{}

	// Build registry auth if credentials are provided
	if auth != nil && (auth.Username != "" || auth.Password != "") {
		authConfig := registry.AuthConfig{
			Username:      auth.Username,
			Password:      auth.Password,
			ServerAddress: auth.ServerAddress,
		}
		encodedAuth, err := registry.EncodeAuthConfig(authConfig)
		if err != nil {
			return fmt.Errorf("failed to encode auth config: %w", err)
		}
		pullOpts.RegistryAuth = encodedAuth
	}

	reader, err := c.cli.ImagePull(ctx, imageRef, pullOpts)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// Send initial progress immediately
	if progressFn != nil {
		progressFn(&PullProgressInfo{
			Status:   "pulling",
			Progress: 0,
			Message:  "Starting download...",
		})
	}

	// Track progress across layers
	layerProgress := make(map[string]*DockerPullProgress)
	var totalBytes, currentBytes int64
	lastReportTime := time.Now().Add(-300 * time.Millisecond) // Allow first progress to send immediately

	decoder := json.NewDecoder(reader)
	for {
		var progress DockerPullProgress
		if err := decoder.Decode(&progress); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		// Handle errors
		if progress.Error != "" {
			if progressFn != nil {
				progressFn(&PullProgressInfo{
					Status:  "error",
					Message: progress.Error,
				})
			}
			return fmt.Errorf("pull error: %s", progress.Error)
		}

		// Track layer progress
		if progress.ID != "" {
			layerProgress[progress.ID] = &progress

			// Calculate total progress across all layers
			totalBytes = 0
			currentBytes = 0
			for _, lp := range layerProgress {
				if lp.ProgressDetail.Total > 0 {
					totalBytes += lp.ProgressDetail.Total
					currentBytes += lp.ProgressDetail.Current
				}
			}
		}

		// Report progress (throttle to avoid flooding)
		if progressFn != nil && time.Since(lastReportTime) > 200*time.Millisecond {
			lastReportTime = time.Now()

			status := "pulling"
			if strings.Contains(strings.ToLower(progress.Status), "extract") {
				status = "extracting"
			} else if strings.Contains(strings.ToLower(progress.Status), "complete") ||
				strings.Contains(strings.ToLower(progress.Status), "already exists") {
				status = "complete"
			}

			progressPercent := 0
			if totalBytes > 0 {
				progressPercent = int(float64(currentBytes) / float64(totalBytes) * 100)
			}

			progressFn(&PullProgressInfo{
				Status:   status,
				Current:  currentBytes,
				Total:    totalBytes,
				Progress: progressPercent,
				Layer:    progress.ID,
				Message:  progress.Status,
			})
		}
	}

	// Send final complete message
	if progressFn != nil {
		progressFn(&PullProgressInfo{
			Status:   "complete",
			Progress: 100,
			Message:  "Pull complete",
		})
	}

	return nil
}

// DeleteImage removes a Docker image
func (c *Client) DeleteImage(ctx context.Context, imageID string, force bool) error {
	_, err := c.cli.ImageRemove(ctx, imageID, image.RemoveOptions{
		Force:         force,
		PruneChildren: true,
	})
	if err != nil {
		return fmt.Errorf("failed to delete image: %w", err)
	}
	return nil
}

// IsImageInUse checks if an image is being used by any container
func (c *Client) IsImageInUse(ctx context.Context, imageID string) (bool, []string, error) {
	// Get image info first
	img, _, err := c.cli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	containers, err := c.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("ancestor", img.ID)),
	})
	if err != nil {
		return false, nil, fmt.Errorf("failed to list containers: %w", err)
	}

	usedBy := make([]string, 0, len(containers))
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}
		usedBy = append(usedBy, name)
	}

	return len(usedBy) > 0, usedBy, nil
}

// ============ Container Run Operations ============

// ContainerRunConfig holds configuration for running a new container
type ContainerRunConfig struct {
	ImageRef      string
	Name          string
	NetworkID     string
	Env           map[string]string
	Ports         map[string]string // container_port -> host_port
	RestartPolicy string
	Labels        map[string]string
}

// ContainerRunResult represents the result of running a container
type ContainerRunResult struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
}

// RunContainer creates and starts a new container
func (c *Client) RunContainer(ctx context.Context, cfg ContainerRunConfig) (*ContainerRunResult, error) {
	// Step 1: Pull the image if it doesn't exist locally
	_, _, err := c.cli.ImageInspectWithRaw(ctx, cfg.ImageRef)
	if err != nil {
		// Image doesn't exist, pull it
		reader, err := c.cli.ImagePull(ctx, cfg.ImageRef, image.PullOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to pull image %s: %w", cfg.ImageRef, err)
		}
		defer reader.Close()
		// Consume the reader to complete the pull
		io.Copy(io.Discard, reader)
	}

	// Step 2: Build container configuration
	envList := make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	containerConfig := &container.Config{
		Image:  cfg.ImageRef,
		Env:    envList,
		Labels: cfg.Labels,
	}

	// Step 3: Build host configuration
	hostConfig := &container.HostConfig{}

	// Set restart policy
	switch cfg.RestartPolicy {
	case "always":
		hostConfig.RestartPolicy = container.RestartPolicy{Name: "always"}
	case "unless-stopped":
		hostConfig.RestartPolicy = container.RestartPolicy{Name: "unless-stopped"}
	case "on-failure":
		hostConfig.RestartPolicy = container.RestartPolicy{Name: "on-failure", MaximumRetryCount: 5}
	default:
		hostConfig.RestartPolicy = container.RestartPolicy{Name: "no"}
	}

	// Configure port bindings if specified
	if len(cfg.Ports) > 0 {
		portBindings := make(map[nat.Port][]nat.PortBinding)
		exposedPorts := make(map[nat.Port]struct{})

		for containerPort, hostPort := range cfg.Ports {
			port := nat.Port(containerPort + "/tcp")
			exposedPorts[port] = struct{}{}
			portBindings[port] = []nat.PortBinding{
				{HostIP: "0.0.0.0", HostPort: hostPort},
			}
		}

		containerConfig.ExposedPorts = exposedPorts
		hostConfig.PortBindings = portBindings
	}

	// Step 4: Build network configuration
	var networkConfig *network.NetworkingConfig
	if cfg.NetworkID != "" {
		networkConfig = &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				cfg.NetworkID: {},
			},
		}
	}

	// Step 5: Create the container
	resp, err := c.cli.ContainerCreate(ctx, containerConfig, hostConfig, networkConfig, nil, cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	containerID := resp.ID
	if len(containerID) > 12 {
		containerID = containerID[:12]
	}

	// Step 6: Start the container
	if err := c.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		// Cleanup: remove the created container if start fails
		c.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	return &ContainerRunResult{
		ContainerID: containerID,
		Name:        cfg.Name,
		Status:      "running",
	}, nil
}

// ============ Secret Management Types ============

// SecretMount represents a secret to be mounted in a container
type SecretMount struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	MountPath string `json:"mount_path"` // e.g., /run/secrets/DB_PASSWORD
}

// SecretMigrationResult contains the result of a secret migration operation
type SecretMigrationResult struct {
	NewContainerID  string        `json:"new_container_id"`
	MountedSecrets  []SecretMount `json:"mounted_secrets"`
	RemovedEnvVars  []string      `json:"removed_env_vars"`
	SecretsBasePath string        `json:"secrets_base_path"`
}

// SecretVerificationResult contains the result of verifying a migration
type SecretVerificationResult struct {
	Success         bool              `json:"success"`
	ContainerID     string            `json:"container_id"`
	ContainerHealth string            `json:"container_health"`
	SecretsFound    map[string]bool   `json:"secrets_found"` // secret name -> exists
	Errors          []string          `json:"errors,omitempty"`
}

// RollbackResult contains the result of a rollback operation
type RollbackResult struct {
	Success             bool   `json:"success"`
	RestoredContainerID string `json:"restored_container_id"`
	CleanedUpSecrets    int    `json:"cleaned_up_secrets"`
	ErrorMessage        string `json:"error_message,omitempty"`
}

// ============ Secret Management Operations ============

// CheckSwarmMode checks if Docker is running in swarm mode
func (c *Client) CheckSwarmMode(ctx context.Context) (bool, error) {
	info, err := c.cli.Info(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get Docker info: %w", err)
	}
	return info.Swarm.LocalNodeState == "active", nil
}

// CreateFileSecret creates a file-based secret on the host filesystem
// Returns the path where the secret file was created
func (c *Client) CreateFileSecret(ctx context.Context, name, value string) (string, error) {
	// We'll exec into a helper container to create the secret file on the host
	// This approach works without requiring direct host filesystem access from the agent

	// Base path for secrets (this will be bind-mounted into containers)
	secretsBasePath := "/var/lib/infrapilot/secrets"
	secretPath := fmt.Sprintf("%s/%s", secretsBasePath, name)

	// Use alpine to create the directory and file with proper permissions
	// The directory is created with 0700 and the file with 0400
	createCmd := fmt.Sprintf(`
		mkdir -p %s && \
		chmod 700 %s && \
		printf '%%s' "$SECRET_VALUE" > %s && \
		chmod 400 %s
	`, secretsBasePath, secretsBasePath, secretPath, secretPath)

	containerConfig := &container.Config{
		Image: "alpine:latest",
		Cmd:   []string{"sh", "-c", createCmd},
		Env:   []string{fmt.Sprintf("SECRET_VALUE=%s", value)},
	}

	hostConfig := &container.HostConfig{
		Binds:      []string{secretsBasePath + ":" + secretsBasePath},
		AutoRemove: true,
	}

	// Pull alpine if not available
	_, _, err := c.cli.ImageInspectWithRaw(ctx, "alpine:latest")
	if err != nil {
		reader, err := c.cli.ImagePull(ctx, "alpine:latest", image.PullOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to pull alpine image: %w", err)
		}
		defer reader.Close()
		io.Copy(io.Discard, reader)
	}

	// Create and run the helper container
	resp, err := c.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("failed to create secret helper container: %w", err)
	}

	if err := c.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		c.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("failed to start secret helper container: %w", err)
	}

	// Wait for completion
	statusCh, errCh := c.cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return "", fmt.Errorf("error waiting for secret creation: %w", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return "", fmt.Errorf("secret creation failed with exit code %d", status.StatusCode)
		}
	}

	return secretPath, nil
}

// RemoveFileSecret removes a file-based secret from the host filesystem
func (c *Client) RemoveFileSecret(ctx context.Context, name string) error {
	secretsBasePath := "/var/lib/infrapilot/secrets"
	secretPath := fmt.Sprintf("%s/%s", secretsBasePath, name)

	removeCmd := fmt.Sprintf("rm -f %s", secretPath)

	containerConfig := &container.Config{
		Image: "alpine:latest",
		Cmd:   []string{"sh", "-c", removeCmd},
	}

	hostConfig := &container.HostConfig{
		Binds:      []string{secretsBasePath + ":" + secretsBasePath},
		AutoRemove: true,
	}

	resp, err := c.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("failed to create cleanup container: %w", err)
	}

	if err := c.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		c.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return fmt.Errorf("failed to start cleanup container: %w", err)
	}

	// Wait for completion
	statusCh, errCh := c.cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("error waiting for secret removal: %w", err)
		}
	case <-statusCh:
		// Success, ignore exit code for rm -f
	}

	return nil
}

// RecreateContainerWithSecrets recreates a container with secrets mounted and env vars removed
func (c *Client) RecreateContainerWithSecrets(ctx context.Context, containerID string, secrets []SecretMount, removeEnvVars []string) (*SecretMigrationResult, error) {
	// Step 1: Inspect the original container to get its config
	originalInfo, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect original container: %w", err)
	}

	// Step 2: Create file secrets on the host
	secretsBasePath := "/var/lib/infrapilot/secrets"
	mountedSecrets := make([]SecretMount, 0, len(secrets))

	for _, secret := range secrets {
		if secret.Value != "" {
			secretPath, err := c.CreateFileSecret(ctx, secret.Name, secret.Value)
			if err != nil {
				// Cleanup any secrets we already created
				for _, ms := range mountedSecrets {
					c.RemoveFileSecret(ctx, ms.Name)
				}
				return nil, fmt.Errorf("failed to create secret %s: %w", secret.Name, err)
			}
			mountedSecrets = append(mountedSecrets, SecretMount{
				Name:      secret.Name,
				MountPath: secretPath,
			})
		}
	}

	// Step 3: Build new container config from original
	newConfig := &container.Config{
		Image:        originalInfo.Config.Image,
		Cmd:          originalInfo.Config.Cmd,
		Entrypoint:   originalInfo.Config.Entrypoint,
		WorkingDir:   originalInfo.Config.WorkingDir,
		ExposedPorts: originalInfo.Config.ExposedPorts,
		Labels:       originalInfo.Config.Labels,
		User:         originalInfo.Config.User,
		Volumes:      originalInfo.Config.Volumes,
		StopSignal:   originalInfo.Config.StopSignal,
		Healthcheck:  originalInfo.Config.Healthcheck,
	}

	// Build env vars, removing the ones we're migrating to secrets
	removeEnvSet := make(map[string]bool)
	for _, envVar := range removeEnvVars {
		removeEnvSet[envVar] = true
	}

	newEnv := make([]string, 0, len(originalInfo.Config.Env))
	removedEnvVars := make([]string, 0)
	for _, env := range originalInfo.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) > 0 && removeEnvSet[parts[0]] {
			removedEnvVars = append(removedEnvVars, parts[0])
			continue
		}
		newEnv = append(newEnv, env)
	}
	newConfig.Env = newEnv

	// Step 4: Build new host config with secrets mount added
	newHostConfig := &container.HostConfig{
		Binds:         originalInfo.HostConfig.Binds,
		NetworkMode:   originalInfo.HostConfig.NetworkMode,
		PortBindings:  originalInfo.HostConfig.PortBindings,
		RestartPolicy: originalInfo.HostConfig.RestartPolicy,
		CapAdd:        originalInfo.HostConfig.CapAdd,
		CapDrop:       originalInfo.HostConfig.CapDrop,
		Privileged:    originalInfo.HostConfig.Privileged,
		PublishAllPorts: originalInfo.HostConfig.PublishAllPorts,
		DNS:           originalInfo.HostConfig.DNS,
		DNSOptions:    originalInfo.HostConfig.DNSOptions,
		DNSSearch:     originalInfo.HostConfig.DNSSearch,
		ExtraHosts:    originalInfo.HostConfig.ExtraHosts,
		Links:         originalInfo.HostConfig.Links,
		LogConfig:     originalInfo.HostConfig.LogConfig,
		SecurityOpt:   originalInfo.HostConfig.SecurityOpt,
		StorageOpt:    originalInfo.HostConfig.StorageOpt,
		Tmpfs:         originalInfo.HostConfig.Tmpfs,
		UTSMode:       originalInfo.HostConfig.UTSMode,
		UsernsMode:    originalInfo.HostConfig.UsernsMode,
		ShmSize:       originalInfo.HostConfig.ShmSize,
		Sysctls:       originalInfo.HostConfig.Sysctls,
		Runtime:       originalInfo.HostConfig.Runtime,
		Resources:     originalInfo.HostConfig.Resources,
		Mounts:        originalInfo.HostConfig.Mounts,
		VolumesFrom:   originalInfo.HostConfig.VolumesFrom,
	}

	// Add the secrets directory bind mount (read-only)
	// Secrets will be available at /run/secrets/<name> in the container
	secretsBindMount := fmt.Sprintf("%s:/run/secrets:ro", secretsBasePath)
	if newHostConfig.Binds == nil {
		newHostConfig.Binds = []string{secretsBindMount}
	} else {
		// Check if already mounted
		hasSecretMount := false
		for _, bind := range newHostConfig.Binds {
			if strings.Contains(bind, "/run/secrets") {
				hasSecretMount = true
				break
			}
		}
		if !hasSecretMount {
			newHostConfig.Binds = append(newHostConfig.Binds, secretsBindMount)
		}
	}

	// Step 5: Build network config from original
	var newNetworkConfig *network.NetworkingConfig
	if originalInfo.NetworkSettings != nil && len(originalInfo.NetworkSettings.Networks) > 0 {
		endpointsConfig := make(map[string]*network.EndpointSettings)
		for netName, netSettings := range originalInfo.NetworkSettings.Networks {
			endpointsConfig[netName] = &network.EndpointSettings{
				Aliases: netSettings.Aliases,
			}
		}
		newNetworkConfig = &network.NetworkingConfig{
			EndpointsConfig: endpointsConfig,
		}
	}

	// Step 6: Stop the original container
	timeout := 30
	if err := c.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		// Cleanup secrets
		for _, ms := range mountedSecrets {
			c.RemoveFileSecret(ctx, ms.Name)
		}
		return nil, fmt.Errorf("failed to stop original container: %w", err)
	}

	// Step 7: Get the original container name for reuse
	originalName := strings.TrimPrefix(originalInfo.Name, "/")

	// Step 8: Remove the original container
	if err := c.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{}); err != nil {
		// Try to restart original container
		c.cli.ContainerStart(ctx, containerID, container.StartOptions{})
		for _, ms := range mountedSecrets {
			c.RemoveFileSecret(ctx, ms.Name)
		}
		return nil, fmt.Errorf("failed to remove original container: %w", err)
	}

	// Step 9: Create the new container with the same name
	newResp, err := c.cli.ContainerCreate(ctx, newConfig, newHostConfig, newNetworkConfig, nil, originalName)
	if err != nil {
		// Cleanup secrets
		for _, ms := range mountedSecrets {
			c.RemoveFileSecret(ctx, ms.Name)
		}
		return nil, fmt.Errorf("failed to create new container: %w", err)
	}

	// Step 10: Start the new container
	if err := c.cli.ContainerStart(ctx, newResp.ID, container.StartOptions{}); err != nil {
		// Remove the failed container
		c.cli.ContainerRemove(ctx, newResp.ID, container.RemoveOptions{Force: true})
		// Cleanup secrets
		for _, ms := range mountedSecrets {
			c.RemoveFileSecret(ctx, ms.Name)
		}
		return nil, fmt.Errorf("failed to start new container: %w", err)
	}

	newContainerID := newResp.ID
	if len(newContainerID) > 12 {
		newContainerID = newContainerID[:12]
	}

	// Update mount paths to use the container's perspective
	for i := range mountedSecrets {
		mountedSecrets[i].MountPath = fmt.Sprintf("/run/secrets/%s", mountedSecrets[i].Name)
	}

	return &SecretMigrationResult{
		NewContainerID:  newContainerID,
		MountedSecrets:  mountedSecrets,
		RemovedEnvVars:  removedEnvVars,
		SecretsBasePath: secretsBasePath,
	}, nil
}

// RecreateContainerWithEnvVars recreates a container with additional environment variables
func (c *Client) RecreateContainerWithEnvVars(ctx context.Context, containerID string, addEnvVars map[string]string) (*SecretMigrationResult, error) {
	// Step 1: Inspect the original container to get its config
	originalInfo, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect original container: %w", err)
	}

	// Step 2: Build new container config from original
	newConfig := &container.Config{
		Image:        originalInfo.Config.Image,
		Cmd:          originalInfo.Config.Cmd,
		Entrypoint:   originalInfo.Config.Entrypoint,
		WorkingDir:   originalInfo.Config.WorkingDir,
		ExposedPorts: originalInfo.Config.ExposedPorts,
		Labels:       originalInfo.Config.Labels,
		User:         originalInfo.Config.User,
		Volumes:      originalInfo.Config.Volumes,
		StopSignal:   originalInfo.Config.StopSignal,
		Healthcheck:  originalInfo.Config.Healthcheck,
	}

	// Build env vars: start with original, then add/override with new ones
	envMap := make(map[string]string)
	for _, env := range originalInfo.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			envMap[parts[0]] = ""
		}
	}

	// Add/override with new env vars
	for k, v := range addEnvVars {
		envMap[k] = v
	}

	// Convert back to slice
	newEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		newEnv = append(newEnv, fmt.Sprintf("%s=%s", k, v))
	}
	newConfig.Env = newEnv

	// Step 3: Build new host config
	newHostConfig := &container.HostConfig{
		Binds:           originalInfo.HostConfig.Binds,
		NetworkMode:     originalInfo.HostConfig.NetworkMode,
		PortBindings:    originalInfo.HostConfig.PortBindings,
		RestartPolicy:   originalInfo.HostConfig.RestartPolicy,
		CapAdd:          originalInfo.HostConfig.CapAdd,
		CapDrop:         originalInfo.HostConfig.CapDrop,
		Privileged:      originalInfo.HostConfig.Privileged,
		PublishAllPorts: originalInfo.HostConfig.PublishAllPorts,
		DNS:             originalInfo.HostConfig.DNS,
		DNSOptions:      originalInfo.HostConfig.DNSOptions,
		DNSSearch:       originalInfo.HostConfig.DNSSearch,
		ExtraHosts:      originalInfo.HostConfig.ExtraHosts,
		Links:           originalInfo.HostConfig.Links,
		LogConfig:       originalInfo.HostConfig.LogConfig,
		SecurityOpt:     originalInfo.HostConfig.SecurityOpt,
		StorageOpt:      originalInfo.HostConfig.StorageOpt,
		Tmpfs:           originalInfo.HostConfig.Tmpfs,
		UTSMode:         originalInfo.HostConfig.UTSMode,
		UsernsMode:      originalInfo.HostConfig.UsernsMode,
		ShmSize:         originalInfo.HostConfig.ShmSize,
		Sysctls:         originalInfo.HostConfig.Sysctls,
		Runtime:         originalInfo.HostConfig.Runtime,
		Resources:       originalInfo.HostConfig.Resources,
		Mounts:          originalInfo.HostConfig.Mounts,
		VolumesFrom:     originalInfo.HostConfig.VolumesFrom,
	}

	// Step 4: Build network config from original
	var newNetworkConfig *network.NetworkingConfig
	if originalInfo.NetworkSettings != nil && len(originalInfo.NetworkSettings.Networks) > 0 {
		endpointsConfig := make(map[string]*network.EndpointSettings)
		for netName, netSettings := range originalInfo.NetworkSettings.Networks {
			endpointsConfig[netName] = &network.EndpointSettings{
				Aliases: netSettings.Aliases,
			}
		}
		newNetworkConfig = &network.NetworkingConfig{
			EndpointsConfig: endpointsConfig,
		}
	}

	// Step 5: Stop the original container
	timeout := 30
	if err := c.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		return nil, fmt.Errorf("failed to stop original container: %w", err)
	}

	// Step 6: Get the original container name for reuse
	originalName := strings.TrimPrefix(originalInfo.Name, "/")

	// Step 7: Remove the original container
	if err := c.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{}); err != nil {
		// Try to restart original container
		c.cli.ContainerStart(ctx, containerID, container.StartOptions{})
		return nil, fmt.Errorf("failed to remove original container: %w", err)
	}

	// Step 8: Create the new container with the same name
	newResp, err := c.cli.ContainerCreate(ctx, newConfig, newHostConfig, newNetworkConfig, nil, originalName)
	if err != nil {
		return nil, fmt.Errorf("failed to create new container: %w", err)
	}

	// Step 9: Start the new container
	if err := c.cli.ContainerStart(ctx, newResp.ID, container.StartOptions{}); err != nil {
		// Remove the failed container
		c.cli.ContainerRemove(ctx, newResp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to start new container: %w", err)
	}

	newContainerID := newResp.ID
	if len(newContainerID) > 12 {
		newContainerID = newContainerID[:12]
	}

	return &SecretMigrationResult{
		NewContainerID: newContainerID,
	}, nil
}

// VerifySecretsMigration verifies that a migrated container has the expected secrets
func (c *Client) VerifySecretsMigration(ctx context.Context, containerID string, expectedSecrets []string) (*SecretVerificationResult, error) {
	result := &SecretVerificationResult{
		Success:      true,
		ContainerID:  containerID,
		SecretsFound: make(map[string]bool),
		Errors:       []string{},
	}

	// Check container is running
	info, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to inspect container: %v", err))
		return result, nil
	}

	result.ContainerHealth = info.State.Status
	if info.State.Status != "running" {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("container is not running (status: %s)", info.State.Status))
	}

	// Check each expected secret file exists
	for _, secretName := range expectedSecrets {
		secretPath := fmt.Sprintf("/run/secrets/%s", secretName)
		checkCmd := []string{"test", "-f", secretPath}

		execID, err := c.ExecCreate(ctx, containerID, checkCmd)
		if err != nil {
			result.SecretsFound[secretName] = false
			result.Errors = append(result.Errors, fmt.Sprintf("failed to check secret %s: %v", secretName, err))
			result.Success = false
			continue
		}

		_, err = c.ExecAttach(ctx, execID)
		if err != nil {
			// Non-zero exit means file doesn't exist
			result.SecretsFound[secretName] = false
			result.Errors = append(result.Errors, fmt.Sprintf("secret %s not found at %s", secretName, secretPath))
			result.Success = false
		} else {
			result.SecretsFound[secretName] = true
		}
	}

	return result, nil
}

// RollbackSecretsMigration restores a container to its original state
func (c *Client) RollbackSecretsMigration(ctx context.Context, containerID string, originalConfig json.RawMessage, createdSecrets []string) (*RollbackResult, error) {
	result := &RollbackResult{
		Success:          false,
		CleanedUpSecrets: 0,
	}

	// Parse original config
	var originalInfo types.ContainerJSON
	if err := json.Unmarshal(originalConfig, &originalInfo); err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to parse original config: %v", err)
		return result, nil
	}

	// Step 1: Stop the migrated container
	timeout := 30
	if err := c.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		// Container might already be stopped, continue
	}

	// Step 2: Remove the migrated container
	if err := c.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to remove migrated container: %v", err)
		return result, nil
	}

	// Step 3: Recreate the original container
	originalName := strings.TrimPrefix(originalInfo.Name, "/")

	// Build network config
	var networkConfig *network.NetworkingConfig
	if originalInfo.NetworkSettings != nil && len(originalInfo.NetworkSettings.Networks) > 0 {
		endpointsConfig := make(map[string]*network.EndpointSettings)
		for netName, netSettings := range originalInfo.NetworkSettings.Networks {
			endpointsConfig[netName] = &network.EndpointSettings{
				Aliases: netSettings.Aliases,
			}
		}
		networkConfig = &network.NetworkingConfig{
			EndpointsConfig: endpointsConfig,
		}
	}

	newResp, err := c.cli.ContainerCreate(ctx, originalInfo.Config, originalInfo.HostConfig, networkConfig, nil, originalName)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to recreate original container: %v", err)
		return result, nil
	}

	// Step 4: Start the restored container
	if err := c.cli.ContainerStart(ctx, newResp.ID, container.StartOptions{}); err != nil {
		c.cli.ContainerRemove(ctx, newResp.ID, container.RemoveOptions{Force: true})
		result.ErrorMessage = fmt.Sprintf("failed to start restored container: %v", err)
		return result, nil
	}

	restoredContainerID := newResp.ID
	if len(restoredContainerID) > 12 {
		restoredContainerID = restoredContainerID[:12]
	}

	// Step 5: Clean up created secrets
	for _, secretName := range createdSecrets {
		if err := c.RemoveFileSecret(ctx, secretName); err == nil {
			result.CleanedUpSecrets++
		}
	}

	result.Success = true
	result.RestoredContainerID = restoredContainerID
	return result, nil
}

// ============ Network Connectivity Testing ============

// GetContainerIP returns the IP address of a container
// It tries to find the container by name or ID and returns its first network IP
func (c *Client) GetContainerIP(ctx context.Context, containerNameOrID string) (string, error) {
	// Try to inspect the container directly
	info, err := c.cli.ContainerInspect(ctx, containerNameOrID)
	if err != nil {
		// Try listing containers and matching by name
		containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
		if err != nil {
			return "", fmt.Errorf("failed to list containers: %w", err)
		}

		for _, cont := range containers {
			name := ""
			if len(cont.Names) > 0 {
				name = strings.TrimPrefix(cont.Names[0], "/")
			}
			if name == containerNameOrID || strings.HasPrefix(cont.ID, containerNameOrID) {
				info, err = c.cli.ContainerInspect(ctx, cont.ID)
				if err != nil {
					return "", fmt.Errorf("failed to inspect container: %w", err)
				}
				break
			}
		}
		if info.ID == "" {
			return "", fmt.Errorf("container not found: %s", containerNameOrID)
		}
	}

	// Get IP from network settings
	if info.NetworkSettings != nil && info.NetworkSettings.Networks != nil {
		for _, netSettings := range info.NetworkSettings.Networks {
			if netSettings.IPAddress != "" {
				return netSettings.IPAddress, nil
			}
		}
	}

	return "", fmt.Errorf("container has no IP address")
}

// TestTCPConnection tests if a TCP connection can be established to host:port
func (c *Client) TestTCPConnection(ctx context.Context, host string, port int, timeout time.Duration) (bool, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Create a context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use a dialer with the context
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		// Connection failed - this is expected for unreachable ports
		return false, nil
	}
	conn.Close()
	return true, nil
}
