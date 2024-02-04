package ebpf

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

type Config struct {
	binPath      string
	pid          int
	metricsQueue chan<- pmetric.Metrics
}

func NewConfig(
	binPath string,
	Pid int,
	metricsQueue chan<- pmetric.Metrics,
) (Config, error) {
	return Config{
		binPath:      binPath,
		pid:          Pid,
		metricsQueue: metricsQueue,
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d",
		c.binPath,
		c.pid,
	)
}
