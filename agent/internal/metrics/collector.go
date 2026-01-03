package metrics

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"go.uber.org/zap"
)

type SystemMetrics struct {
	CPUPercent    float64
	MemoryUsedMB  int64
	MemoryTotalMB int64
	DiskUsedMB    int64
	DiskTotalMB   int64
	UptimeSeconds int64
}

type Collector struct {
	logger *zap.Logger
}

func NewCollector(logger *zap.Logger) *Collector {
	return &Collector{
		logger: logger,
	}
}

func (c *Collector) CollectSystemMetrics() *SystemMetrics {
	metrics := &SystemMetrics{}

	// CPU usage
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		metrics.CPUPercent = cpuPercent[0]
	}

	// Memory usage
	vmem, err := mem.VirtualMemory()
	if err == nil {
		metrics.MemoryUsedMB = int64(vmem.Used / 1024 / 1024)
		metrics.MemoryTotalMB = int64(vmem.Total / 1024 / 1024)
	}

	// Disk usage (root partition)
	diskUsage, err := disk.Usage("/")
	if err == nil {
		metrics.DiskUsedMB = int64(diskUsage.Used / 1024 / 1024)
		metrics.DiskTotalMB = int64(diskUsage.Total / 1024 / 1024)
	}

	// Uptime
	hostInfo, err := host.Info()
	if err == nil {
		metrics.UptimeSeconds = int64(hostInfo.Uptime)
	}

	return metrics
}
