package kernel

import (
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var releaseFilepath = "/proc/sys/kernel/osrelease" // For testing
var release atomic.Value
var releaseOnce sync.Once

// Release read Linux Kernel release from the proc file system.
// See https://linux.die.net/man/5/proc#:~:text=proc/sys/kernel/-,osrelease,-These%20files%20give
func Release() string {
	if r, ok := release.Load().(string); ok {
		return r
	}
	releaseOnce.Do(func() {
		data, err := os.ReadFile(releaseFilepath)
		if err != nil {
			release.Store("")
			slog.Debug(err.Error())
			return
		}
		release.Store(strings.TrimSpace(string(data)))
	})
	return release.Load().(string)
}
