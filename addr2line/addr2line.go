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

func (syms *symbols) pcToLine(addr uint64) Entry {
	syms.mu.Lock()
	defer syms.mu.Unlock()
	if syms.s == nil {
		return Entry{
			Addr: addr,
		}
	}
	file, line, f := syms.s.PCToLine(addr)
	if f == nil {
		return Entry{
			Addr: addr,
		}
	}
	if f.Func == nil {
		return Entry{
			FileName: file,
			Line:     line,
			Addr:     addr,
		}
	} else {
		return Entry{
			FileName: file,
			Line:     line,
			Func:     f.Func.Name,
			Addr:     addr,
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
				lineEntries.Store(line.Address, Entry{
					FileName: line.File.Name,
					Line:     line.Line,
				})
			}
		}
	}
	slog.Debug("load symbols from DWARF")
	return nil
}

// Do converts a program counter address to Entry.
// If the symbols table is initialized from .gopclntab, it uses that for the conversion;
// otherwise, it falls back to using the DWARF.
func Do(addr uint64) Entry {
	if e := syms.pcToLine(addr); !e.hasAddrOnly() {
		return e
	}
	if entry, ok := lineEntries.Load(addr); ok {
		if e, ok := entry.(Entry); ok {
			return e
		}
	}
	return Entry{
		Addr: addr,
	}
}

// Entry represents a single entry in a stack trace.
type Entry struct {
	FileName string
	Line     int
	Func     string
	Addr     uint64
}

// hasAddrOnly returns true if the entry has only an address.
// It indicates that the entry is not resolved to a file name, line number, or function name.
func (e Entry) hasAddrOnly() bool {
	return e.FileName == "" && e.Line == 0 && e.Func == "" && e.Addr != 0
}

func (e Entry) String() string {
	if e.hasAddrOnly() {
		return fmt.Sprintf("%x", e.Addr)
	}
	if e.Func == "" {
		return fmt.Sprintf("%s:%d", e.FileName, e.Line)
	}
	if e.FileName == "" {
		return e.Func
	}
	return fmt.Sprintf("%s at %s:%d", e.Func, e.FileName, e.Line)
}

type Stack []Entry

func (s Stack) LogAttr() slog.Attr {
	attrs := make([]slog.Attr, len(s))
	for i, e := range s {
		attrs[i] = slog.String(fmt.Sprintf("%d", i), e.String())
	}
	return slog.Attr{
		Key:   "stack",
		Value: slog.GroupValue(attrs...),
	}
}
