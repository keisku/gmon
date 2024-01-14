package ebpf

import (
	"fmt"
	"time"
)

type Config struct {
	binPath                string
	pid                    int
	uptimeThreshold        time.Duration
	monitorExpiryThreshold time.Duration
}

func NewConfig(
	binPath string,
	Pid int,
	uptimeThreshold string,
	monitorExpiryThreshold string,
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
