package ebpf

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

type Config struct {
	binPath                string
	pid                    int
	monitorExpiryThreshold time.Duration
	metricsQueue           chan<- pmetric.Metrics
}

func NewConfig(
	binPath string,
	Pid int,
	monitorExpiryThreshold string,
	metricsQueue chan<- pmetric.Metrics,
) (Config, error) {
	durations := make([]time.Duration, 2)
	for i, s := range []string{monitorExpiryThreshold} {
		d, err := time.ParseDuration(s)
		if err != nil {
			return Config{}, err
		}
		durations[i] = d
	}
	return Config{
		binPath:                binPath,
		pid:                    Pid,
		monitorExpiryThreshold: durations[0],
		metricsQueue:           metricsQueue,
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d, monitorExpiryThreshold: %s",
		c.binPath,
		c.pid,
		c.monitorExpiryThreshold,
	)
}
