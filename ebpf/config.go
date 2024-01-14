package ebpf

import (
	"fmt"
	"time"
)

type Config struct {
	binPath                                          string
	pid                                              int
	uptimeDebug, uptimeInfo, uptimeWarn, uptimeError time.Duration
}

func NewConfig(
	binPath string,
	Pid int,
	uptimeDebug string,
	uptimeInfo string,
	uptimeWarn string,
	uptimeError string,
) (Config, error) {
	uptimes := make([]time.Duration, 4)
	for i, uptime := range []string{uptimeDebug, uptimeInfo, uptimeWarn, uptimeError} {
		d, err := time.ParseDuration(uptime)
		if err != nil {
			return Config{}, err
		}
		uptimes[i] = d
	}
	return Config{
		binPath:     binPath,
		pid:         Pid,
		uptimeDebug: uptimes[0],
		uptimeInfo:  uptimes[1],
		uptimeWarn:  uptimes[2],
		uptimeError: uptimes[3],
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d, uptimeDebug: %s, uptimeInfo: %s, uptimeWarn: %s, uptimeError: %s",
		c.binPath,
		c.pid,
		c.uptimeDebug,
		c.uptimeInfo,
		c.uptimeWarn,
		c.uptimeError,
	)
}
