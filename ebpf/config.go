package ebpf

import (
	"fmt"
)

type Config struct {
	binPath string
	pid     int
}

func NewConfig(
	binPath string,
	Pid int,
) (Config, error) {
	return Config{
		binPath: binPath,
		pid:     Pid,
	}, nil
}

func (c Config) String() string {
	return fmt.Sprintf("binPath: %s, pid: %d",
		c.binPath,
		c.pid,
	)
}
