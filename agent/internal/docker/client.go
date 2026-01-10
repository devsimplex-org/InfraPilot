package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
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
		AttachStdin:  true,
		Tty:          true,
	})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
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

// PullImage pulls a Docker image from a registry
func (c *Client) PullImage(ctx context.Context, imageRef string) error {
	reader, err := c.cli.ImagePull(ctx, imageRef, image.PullOptions{})
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
