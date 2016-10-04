package libiptc

import (
	// #cgo LDFLAGS: -lip6tc
	// #include "xtables-lock.h"
	"C"
	"fmt"
	"net"
	"runtime"
	"sync"
)

type XtChainLabel string

const (
	IPTC_LABEL_ACCEPT = "ACCEPT"
	IPTC_LABEL_DROP   = "DROP"
	IPTC_LABEL_QUEUE  = "QUEUE"
	IPTC_LABEL_RETURN = "RETURN"
)

type XtCounters struct {
	Pcnt, Bcnt uint64
}

type Not bool

func (n Not) String() string {
	if n {
		return "!"
	}
	return " "
}

type Rule struct {
	Src    *net.IPNet
	Dest   *net.IPNet
	InDev  string
	OutDev string
	Not    struct {
		Src    Not
		Dest   Not
		InDev  Not
		OutDev Not
	}
	Target string
	XtCounters
}

func (r Rule) String() string {
	return fmt.Sprintf("in: %s%s, out: %s%s, %s%s -> %s%s -> %s: %d packets, %d bytes",
		r.Not.InDev, r.InDev,
		r.Not.OutDev, r.OutDev,
		r.Not.Src, r.Src,
		r.Not.Dest, r.Dest,
		r.Target,
		r.Pcnt, r.Bcnt)
}

// RelayedFunc is a function that returns false if there is an 'errno' to query about.
type RelayedFunc func() bool

type ErrorFunc func() string

type RelayedCall struct {
	Func    RelayedFunc
	Error   ErrorFunc
	Context string
}

var (
	lockOSThread sync.Once
	lastErrors   = make(chan error)
	queueOfCalls = make(chan RelayedCall)
)

func init() {
	// start a main loop that will process (serially) all incoming libiptc/libip6tc calls
	go func() {
		runtime.LockOSThread()
		//defer runtime.UnlockOSThread()

		for call := range queueOfCalls {
			// as extra good measure, reset errno before C-land calls
			C.reset_errno()

			// libiptc logic is called here
			success := call.Func()

			var err error
			if !success {
				err = fmt.Errorf("%s: %s", call.Context, call.Error())
			}

			// this will also signal completion of the call
			lastErrors <- err
		}
	}()
}

// this is used just for the errors set in xtables-lock.c:
// * ENOLCK - lock was not being held at all
// * EALREADY - trying to acquire lock twice
// * any error set by a failed bind() call
// * ETIMEOUT - could not acquire lock in specified timeout
// * any error set by a failed socket() call
func getNativeError() string {
	return C.GoString(C.strerror(C.get_errno()))
}

func XtablesLock(wait bool, maxSeconds uint) (result bool, osErr error) {
	osErr = RelayCall(func() bool {
		r := C.xtables_lock(true, C.uint(maxSeconds))
		if r == 0 {
			result = true
			return result
		} else if r == 1 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "xtables_lock", getNativeError)
	return
}

func XtablesUnlock() (result bool, osErr error) {
	osErr = RelayCall(func() bool {
		r := C.xtables_unlock()
		if r == 0 {
			result = true
			return result
		} else if r == 1 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "xtables_unlock", getNativeError)
	return
}

func GetErrno() int {
	return int(C.get_errno())
}

func RelayCall(f RelayedFunc, context string, e ErrorFunc) error {
	queueOfCalls <- RelayedCall{Func: f, Context: context, Error: e}
	return <-lastErrors
}
