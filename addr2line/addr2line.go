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

func (syms *symbols) pcToLine(addr uint64) Line {
	syms.mu.Lock()
	defer syms.mu.Unlock()
	if syms.s == nil {
		return Line{}
	}
	file, line, f := syms.s.PCToLine(addr)
	if f == nil {
		return Line{}
	}
	if f.Func == nil {
		return Line{
			FileName: file,
			Line:     line,
		}
	} else {
		return Line{
			FileName: file,
			Line:     line,
			Func:     f.Func.Name,
		}
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
				lineEntries.Store(line.Address, Line{
					FileName: line.File.Name,
					Line:     line.Line,
				})
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
func Do(addr uint64) Line {
	if l := syms.pcToLine(addr); !l.IsEmpty() {
		return l
	}
	if line, ok := lineEntries.Load(addr); ok {
		if l, ok := line.(Line); ok {
			return l
		}
	}
	return Line{}
}

type Line struct {
	FileName string
	Line     int
	Func     string
}

func (e Line) IsEmpty() bool {
	return e.FileName == "" && e.Line == 0 && e.Func == ""
}

func (e Line) String() string {
	if e.Func == "" {
		return fmt.Sprintf("%s:%d", e.FileName, e.Line)
	}
	return fmt.Sprintf("%s at %s:%d", e.Func, e.FileName, e.Line)
}
