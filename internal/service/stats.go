package service

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/yogaagungk/lander/internal/domain"
)

const cpuSampleInterval = 200 * time.Millisecond

// StatsProvider abstracts host telemetry so handlers can be tested.
type StatsProvider interface {
	CPUPercent(ctx context.Context, interval time.Duration) (float64, error)
	MemoryUsedPercent(ctx context.Context) (float64, error)
	Uptime(ctx context.Context) (uint64, error)
}

type systemStats struct{}

func (systemStats) CPUPercent(ctx context.Context, interval time.Duration) (float64, error) {
	values, err := cpu.PercentWithContext(ctx, interval, false)
	if err != nil {
		return 0, err
	}
	if len(values) == 0 {
		return 0, nil
	}
	return values[0], nil
}

func (systemStats) MemoryUsedPercent(ctx context.Context) (float64, error) {
	info, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return info.UsedPercent, nil
}

func (systemStats) Uptime(ctx context.Context) (uint64, error) {
	return host.UptimeWithContext(ctx)
}

// SetStatsProvider overrides host telemetry (used by tests).
func (s *Nginx) SetStatsProvider(provider StatsProvider) {
	if provider != nil {
		s.stats = provider
	}
}

// SystemStatus returns CPU, memory, nginx and uptime telemetry.
func (s *Nginx) SystemStatus(ctx context.Context) (domain.SystemStatus, error) {
	var status domain.SystemStatus

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cpuPercent, err := s.stats.CPUPercent(ctx, cpuSampleInterval)
	if err != nil {
		return status, fmt.Errorf("read cpu stats: %w", err)
	}
	memoryPercent, err := s.stats.MemoryUsedPercent(ctx)
	if err != nil {
		return status, fmt.Errorf("read memory stats: %w", err)
	}
	uptime, err := s.stats.Uptime(ctx)
	if err != nil {
		return status, fmt.Errorf("read uptime: %w", err)
	}

	return domain.SystemStatus{
		CPUUsage:    cpuPercent,
		MemoryUsage: memoryPercent,
		NginxActive: s.NginxActive(ctx),
		Uptime:      uptime,
	}, nil
}
