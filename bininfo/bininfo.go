package bininfo

import (
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"

	"github.com/go-delve/delve/pkg/proc"
)

// Translator translates information about an executable.
type Translator interface {
	// Address returns the address of the given symbol in the executable.
	Address(symbol string) uint64
	// Stack returns a stack trace from the given stack bytes.
	PCToFunc(pc uint64) *proc.Function
}

// NewTranslator creates a new Translator for the given executable.
func NewTranslator(path string) (Translator, error) {
	bi, err := newBinInfo(path)
	if err == nil {
		slog.Debug("loaded binary info")
		return bi, nil
	} else {
		slog.Debug("failed to load binary info", slog.Any("error", err))
	}
	s, err := newSymbolTable(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load symbol table: %w", err)
	}
	slog.Debug("loaded symbol table")
	return s, nil
}

type binaryInfo struct {
	*proc.BinaryInfo
}

func newBinInfo(path string) (*binaryInfo, error) {
	bininfo := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	if err := bininfo.LoadBinaryInfo(path, 0, nil); err != nil {
		return nil, fmt.Errorf("failed to load binary info: %w", err)
	}
	var bi binaryInfo
	bi.BinaryInfo = bininfo
	return &bi, nil
}

func (bi *binaryInfo) Address(symbol string) uint64 {
	funcs, err := bi.FindFunction(symbol)
	if err != nil {
		return 0
	}
	for _, f := range funcs {
		if f.Name == symbol {
			return f.Entry
		}
	}
	return 0
}

type symbolTable struct {
	addresses map[string]uint64
	functions []*proc.Function
}

// Copy from https://github.com/cilium/ebpf/blob/v0.12.3/link/uprobe.go#L116-L160
func newSymbolTable(path string) (*symbolTable, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	syms = append(syms, dynsyms...)
	if len(syms) == 0 {
		return nil, elf.ErrNoSymbols
	}
	addresses := make(map[string]uint64)
	functions := make([]*proc.Function, 0, len(syms))
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		address := s.Value
		for _, prog := range f.Progs {
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}
			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}
		addresses[s.Name] = address
		index := sort.Search(len(functions), func(i int) bool { return functions[i].Entry >= address })
		functions = append(functions, &proc.Function{})
		copy(functions[index+1:], functions[index:])
		functions[index] = &proc.Function{
			Name:  s.Name,
			Entry: address,
		}
	}
	for i := 0; i < len(functions)-1; i++ {
		functions[i].End = functions[i+1].Entry
	}
	return &symbolTable{
		addresses: addresses,
		functions: functions,
	}, nil
}

func (s *symbolTable) Address(symbol string) uint64 {
	if address, ok := s.addresses[symbol]; ok {
		return address
	}
	return 0
}

func (s *symbolTable) PCToFunc(pc uint64) *proc.Function {
	low := 0
	high := len(s.functions) - 1

	for low <= high {
		mid := low + (high-low)/2
		f := s.functions[mid]

		if pc < f.Entry {
			high = mid - 1
		} else if pc > f.End {
			low = mid + 1
		} else {
			return f
		}
	}
	return nil
}
