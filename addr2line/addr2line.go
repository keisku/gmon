package addr2line

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

type symbols struct {
	mu sync.Mutex
	s  *gosym.Table
}

func (syms *symbols) pcToLine(addr uint64) string {
	syms.mu.Lock()
	defer syms.mu.Unlock()
	if syms.s == nil {
		return ""
	}
	file, line, f := syms.s.PCToLine(addr)
	if f == nil {
		return ""
	}
	if f.Func == nil {
		return fmt.Sprintf("%s:%d", file, line)
	} else {
		return fmt.Sprintf("%s at %s:%d", f.Func.Name, file, line)
	}
}

var initErr error
var initOnce sync.Once
var lineEntries sync.Map
var syms symbols

// Init loads the debug info from the specified binary file and parsing its symbol and line number information.
// This function is intended to be called once, with future calls being no-ops.
func Init(f *elf.File) error {
	initOnce.Do(func() {
		initErr = initialize(f)
	})
	return initErr
}

func initialize(f *elf.File) error {
	gopclntab := f.Section(".gopclntab")
	textSection := f.Section(".text")
	if gopclntab != nil && textSection != nil {
		gopclntabData, err := gopclntab.Data()
		if err != nil {
			return fmt.Errorf("failed to read .gopclntab section: %w", err)
		}
		lineTable := gosym.NewLineTable(gopclntabData, textSection.Addr)
		s, err := gosym.NewTable(nil, lineTable)
		if err != nil {
			return fmt.Errorf("failed to parse symbols: %w", err)
		}
		syms = symbols{
			s: s,
		}
		// If symbols are successfully loaded from `.gopclntab`, skip loading DWARF.
		// `.gopclntab` has enough information.
		slog.Debug("load symbols from .gopclntab")
		return nil
	}

	// Fallback to DWARF when loading `.gopclntab` fails.
	// Reference code: https://github.com/golang/go/blob/go1.21.5/src/debug/dwarf/line_test.go#L181-L255
	d, err := f.DWARF()
	if err != nil {
		return fmt.Errorf("failed to read DWARF: %w", err)
	}
	reader := d.Reader()
	for {
		cu, err := reader.Next()
		if err != nil {
			return err
		}
		if cu == nil {
			break
		}
		lr, err := d.LineReader(cu)
		if err != nil {
			return err
		}
		if lr == nil {
			continue
		}
		var line dwarf.LineEntry
		for {
			if err := lr.Next(&line); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			if line.File != nil {
				lineEntries.Store(line.Address, fmt.Sprintf("%s:%d", line.File.Name, line.Line))
			}
		}
	}
	slog.Debug("load symbols from DWARF")
	return nil
}

// Do converts a program counter address to a file name and line number,
// returning it as a string formatted as "file:line".
// If the symbols table is initialized from .gopclntab, it uses that for the conversion;
// otherwise, it falls back to using the DWARF.
func Do(addr uint64) string {
	if s := syms.pcToLine(addr); s != "" {
		return s
	}
	if line, ok := lineEntries.Load(addr); ok {
		if s, ok := line.(string); ok {
			return s
		}
	}
	return ""
}
