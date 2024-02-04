package ebpf

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

type Config struct {
	binPath                string
	pid                    int
	uptimeThreshold        time.Duration
	monitorExpiryThreshold time.Duration
	metricsQueue           chan<- pmetric.Metrics
}

func NewConfig(
	binPath string,
	Pid int,
	uptimeThreshold string,
	monitorExpiryThreshold string,
	metricsQueue chan<- pmetric.Metrics,
) (Config, error) {
	durations := make([]time.Duration, 2)
	for i, s := range []string{uptimeThreshold, monitorExpiryThreshold} {
		d, err := time.ParseDuration(s)
		if err != nil {
			return Config{}, err
		}
		durations[i] = d
	}
	return Config{
		binPath:                binPath,
		pid:                    Pid,
		uptimeThreshold:        durations[0],
		monitorExpiryThreshold: durations[1],
		metricsQueue:           metricsQueue,
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d, uptimeThreshold: %s, monitorExpiryThreshold: %s",
		c.binPath,
		c.pid,
		c.uptimeThreshold,
		c.monitorExpiryThreshold,
	)
}
