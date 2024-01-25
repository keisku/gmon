package bininfo

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"sync"

	"github.com/go-delve/delve/pkg/proc"
)

// BinInfo holds information on the binaries.
type BinInfo struct {
	mu                 sync.Mutex
	internalBinaryInfo *proc.BinaryInfo
}

// NewBinInfo will load and store the information from the binary at 'path'.
func NewBinInfo(path string) (*BinInfo, error) {
	bininfo := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	if err := bininfo.LoadBinaryInfo(path, 0, nil); err != nil {
		return nil, fmt.Errorf("failed to load binary info: %w", err)
	}
	var bi BinInfo
	bi.internalBinaryInfo = bininfo
	return &bi, nil
}

// Stack is a stack trace.
type Stack []*proc.Function

// LogAttr returns a slog.Attr that can be used to log the stack.
func (s Stack) LogAttr() slog.Attr {
	attrs := make([]any, len(s))
	for i, f := range s {
		if f == nil {
			panic("stack must not have nil function")
		}
		attrs[i] = slog.String(fmt.Sprintf("%d", i), f.Name)
	}
	return slog.Group("stack", attrs...)
}

// maxStackDepth is the max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

// Stack returns a stack trace from the given stack bytes.
func (bi *BinInfo) Stack(stackBytes []byte) Stack {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	stack := make(Stack, maxStackDepth)
	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackBytes[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		f := bi.internalBinaryInfo.PCToFunc(stackAddr)
		if f == nil {
			f = &proc.Function{Name: fmt.Sprintf("0x%x", stackAddr)}
		}
		stack[stackCounter] = f
		stackCounter++
	}
	return stack[0:stackCounter]
}
