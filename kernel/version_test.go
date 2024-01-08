package kernel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRelease(t *testing.T) {
	tempDir := t.TempDir()
	f, err := os.Create(filepath.Join(tempDir, "osrelease"))
	releaseFilepath = filepath.Join(tempDir, "osrelease")
	assert.Nilf(t, err, "failed to create temp file in %s", tempDir)
	expectedRelease := "6.2.0-1013-aws"
	_, err = f.Write([]byte(expectedRelease))
	assert.Nilf(t, err, "failed to write dummy release version in %s", releaseFilepath)
	assert.Equal(t, expectedRelease, Release())
	assert.Equalf(t, expectedRelease, release.Load().(string), "%s should be cached", expectedRelease)
}
