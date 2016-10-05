/*
 * go-libiptc v0.3.1 - libiptc bindings for Go language
 * Copyright (C) 2015~2016 gdm85 - https://github.com/gdm85/go-libiptc/

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package libiptc

import (
	// #cgo LDFLAGS: -liptc
	// #include "xtables-lock.h"
	"C"
	"fmt"
	"net"
	"runtime"
)

// XtChainLabel is a chain label.
type XtChainLabel string

const (
	// the constants are copied from #define declarations in libiptc.h
	IPTC_LABEL_ACCEPT = "ACCEPT"
	IPTC_LABEL_DROP   = "DROP"
	IPTC_LABEL_QUEUE  = "QUEUE"
	IPTC_LABEL_RETURN = "RETURN"
)

// XtCounters contains packet and byte counters.
type XtCounters struct {
	// Pcnt is the packet counter.
	Pcnt uint64
	// Bcnt is the byte counter.
	Bcnt uint64
}

// Not is a shortand for rule negation description.
type Not bool

// String returns '!' for a negated rule.
func (n Not) String() string {
	if n {
		return "!"
	}
	return " "
}

// Rule is a complete iptables rule descriptor.
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

// String returns a human-readable description of a rule.
func (r Rule) String() string {
	return fmt.Sprintf("in: %s%s, out: %s%s, %s%s -> %s%s -> %s: %d packets, %d bytes",
		r.Not.InDev, r.InDev,
		r.Not.OutDev, r.OutDev,
		r.Not.Src, r.Src,
		r.Not.Dest, r.Dest,
		r.Target,
		r.Pcnt, r.Bcnt)
}

// RelayedFunc is a function that returns false if there is an 'errno' to query about. Used internally to perform all lib*iptc calls serially.
type RelayedFunc func() bool

// ErrorFunc generates an error based on a libip*tc_strerror call. Used internally to report about errors.
type ErrorFunc func() string

// RelayedCall
type RelayedCall struct {
	// Context is the C function being called.
	Context string
	// Func is the function that performs the wrapper around the C function call that does the conversion of input/output parameters.
	Func RelayedFunc
	// Error is the specific ErrorFunc needed to extract an error after the C call.
	Error ErrorFunc
}

var (
	callResult   = make(chan error)
	queueOfCalls = make(chan RelayedCall)
)

func init() {
	// start a main loop that will process (serially) all incoming libiptc/libip6tc calls
	go func() {
		runtime.LockOSThread()

		for {
			call := <-queueOfCalls

			// as extra good measure, reset errno before C-land calls
			C.reset_errno()

			// libiptc logic is called here
			success := call.Func()

			var err error
			if !success {
				err = fmt.Errorf("%s: %s", call.Context, call.Error())
			}

			// this will also signal completion of the call
			callResult <- err
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

// XtablesLock acquires the same lock that a call to `iptables --wait` would.
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

// XtablesUnlock releases an iptables lock previously acquired with XtablesLock().
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

// GetErrno returns the OS-level errno value. It is used internally to properly report about errors.
func GetErrno() int {
	return int(C.get_errno())
}

// RelayCall will perform the C call on a OS-locked goroutine, serially.
func RelayCall(f RelayedFunc, context string, e ErrorFunc) error {
	queueOfCalls <- RelayedCall{Func: f, Context: context, Error: e}
	return <-callResult
}
