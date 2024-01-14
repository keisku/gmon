package ebpf

import (
	"fmt"
	"time"
)

type Config struct {
	binPath         string
	pid             int
	uptimeThreshold time.Duration
}

func NewConfig(
	binPath string,
	Pid int,
	uptimeThreshold string,
) (Config, error) {
	d, err := time.ParseDuration(uptimeThreshold)
	if err != nil {
		return Config{}, err
	}
	return Config{
		binPath:         binPath,
		pid:             Pid,
		uptimeThreshold: d,
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d, uptimeThreshold: %s",
		c.binPath,
		c.pid,
		c.uptimeThreshold,
	)
}
