/*
 * go-libiptc v0.1.0 - libiptc bindings for Go language
 * Copyright (C) 2015 gdm85 - https://github.com/gdm85/go-libiptc/

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

// #cgo CFLAGS: -I iptables/include
// #cgo LDFLAGS: -lip4tc
// #include <stdlib.h>
// #include "libiptc/libiptc.h"
// #include "iptables.h"
// #include "iptc-helper.h"
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type XtChainLabel string

const (
	IPTC_LABEL_ACCEPT = "ACCEPT"
	IPTC_LABEL_DROP   = "DROP"
	IPTC_LABEL_QUEUE  = "QUEUE"
	IPTC_LABEL_RETURN = "RETURN"
)

type XtcHandle struct {
	xtc_handle *_Ctype_struct_xtc_handle
}

type XtCounters struct {
	Pcnt, Bcnt uint64
}

type IptEntry struct {
	ipt_entry_handle *_Ctype_struct_ipt_entry
}

type RelayedCall struct {
	Func    func()
	Context string
}

var (
	lastErrors   = make(chan error)
	queueOfCalls = make(chan RelayedCall)
)

func init() {
	// start a main loop that will process (serially) all incoming libiptc calls
	go func() {
		runtime.LockOSThread()

		for call := range queueOfCalls {
			// process all logic here
			call.Func()

			// get any errno error - this will also signal completion
			//NOTE: will ignore libiptc's errno '0'
			errMsg := C.GoString(C.iptc_last_error())
			if len(errMsg) > 0 {
				lastErrors <- fmt.Errorf("%s: %s", call.Context, errMsg)
			} else {
				lastErrors <- nil
			}
		}
	}()
}

func relayCall(f func(), context string) error {
	queueOfCalls <- RelayedCall{Func: f, Context: context}
	return <-lastErrors
}

func (this XtcHandle) Free() error {
	return relayCall(func() {
		C.iptc_free(this.xtc_handle)
	}, "iptc_free")
}

func TableInit(tableName string) (result XtcHandle, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(tableName)
		defer C.free(unsafe.Pointer(cStr))

		result = XtcHandle{xtc_handle: C.iptc_init(cStr)}
	}, "free")
	return
}

func XtablesLock(wait bool) (result bool, osErr error) {
	osErr = relayCall(func() {
		r := C.xtables_lock(true)
		if r == 0 {
			result = true
		} else if r == 1 {
			result = false
		}
	}, "xtables_lock")
	return
}

func XtablesUnlock() (result bool, osErr error) {
	osErr = relayCall(func() {
		r := C.xtables_unlock()
		if r == 0 {
			result = true
		} else if r == 1 {
			result = false
		}
	}, "xtables_lock")
	return
}

func (this XtcHandle) IsChain(chain string) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_is_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
		panic("invalid return value from iptc_is_chain")
	}, "iptc_is_chain")
	return
}

func (this XtcHandle) IsBuiltin(chain string) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_builtin(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
		panic("invalid return value from iptc_builtin")
	}, "iptc_builtin")
	return
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
func (this XtcHandle) FirstChain() (result string, osErr error) {
	osErr = relayCall(func() {
		cStr := C.iptc_first_chain(this.xtc_handle)
		if cStr == nil {
			result = ""
		} else {
			result = C.GoString(cStr)
		}
	}, "iptc_first_chain")
	return
}

func (this XtcHandle) NextChain() (result string, osErr error) {
	osErr = relayCall(func() {
		cStr := C.iptc_next_chain(this.xtc_handle)
		if cStr == nil {
			result = ""
		} else {
			result = C.GoString(cStr)
		}
	}, "iptc_next_chain")
	return
}

/* Get first rule in the given chain: NULL for empty chain. */
func (this XtcHandle) FirstRule(chain string) (result IptEntry, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		result.ipt_entry_handle = C.iptc_first_rule(cStr, this.xtc_handle)
	}, "iptc_first_rule")
	return
}

/* Returns NULL when rules run out. */
func (this XtcHandle) NextRule(previous IptEntry) (result IptEntry, osErr error) {
	osErr = relayCall(func() {
		result.ipt_entry_handle = C.iptc_next_rule(previous.ipt_entry_handle, this.xtc_handle)
	}, "iptc_next_rule")
	return
}

/* Returns a pointer to the target name of this entry. */
func (this XtcHandle) GetTarget(entry IptEntry) (result string, osErr error) {
	osErr = relayCall(func() {
		cStr := C.iptc_get_target(entry.ipt_entry_handle, this.xtc_handle)
		if cStr == nil {
			result = ""
		} else {
			result = C.GoString(cStr)
		}
	}, "iptc_get_target")
	return
}

/* Get the policy of a given built-in chain */
func (this XtcHandle) GetPolicy(chain string) (policy string, counters XtCounters, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		cStr = C.iptc_get_policy(cStr, &c, this.xtc_handle)
		if cStr == nil {
			// no chains
			policy = ""
		} else {
			policy = C.GoString(cStr)
			counters.Bcnt = uint64(c.bcnt)
			counters.Pcnt = uint64(c.pcnt)
		}
	}, "iptc_get_policy")
	return
}

/* These functions return TRUE for OK or 0 and set errno.  If errno ==
   0, it means there was a version error (ie. upgrade libiptc). */
/* Rule numbers start at 1 for the first rule. */

/* Insert the entry `e' in chain `chain' into position `rulenum'. */
func (this XtcHandle) InsertEntry(chain XtChainLabel, entry IptEntry, ruleNum uint) error {
	osErr := relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_insert_entry(cStr, entry.ipt_entry_handle, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			return
		} else if r == 0 {
			// has error
			return
		}

		panic("invalid return value from iptc_insert_entry")
	}, "iptc_insert_entry")

	return osErr
}

/* Append entry `e' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
func (this XtcHandle) AppendEntry(chain XtChainLabel, entry IptEntry) error {
	osErr := relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_append_entry(cStr, entry.ipt_entry_handle, this.xtc_handle)
		if r == 1 {
			return
		} else if r == 0 {
			// has error
			return
		}

		panic("invalid return value from iptc_insert_entry")
	}, "iptc_append_entry")

	return osErr
}

/* Check whether a matching rule exists */
func (this XtcHandle) CheckEntry(chain XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.iptc_check_entry(cStr, origfw.ipt_entry_handle, cMask, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_check_entry")
	return
}

/* Delete the first rule in `chain' which matches `e', subject to
   matchmask (array of length == origfw) */
func (this XtcHandle) DeleteEntry(chain XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.iptc_delete_entry(cStr, origfw.ipt_entry_handle, cMask, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_delete_entry")
	return
}

/* Delete the rule in position `rulenum' in `chain'. */
func (this XtcHandle) DeleteNumEntry(chain XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_delete_num_entry(cStr, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_delete_num_entry")
	return
}

/* Check the packet `e' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
/*func (this XtcHandle) CheckPacket(chain XtChainLabel, entry IptEntry) error {
	panic("will never be implemented")
}*/

/* Flushes the entries in the given chain (ie. empties chain). */
func (this XtcHandle) FlushEntries(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_flush_entries(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_flush_entries")
	return
}

/* Zeroes the counters in a chain. */
func (this XtcHandle) ZeroEntries(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_zero_entries(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_zero_entries")
	return
}

/* Creates a new chain. */
func (this XtcHandle) CreateChain(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_create_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_create_chain")
	return
}

/* Deletes a chain. */
func (this XtcHandle) DeleteChain(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_delete_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_delete_chain")
	return
}

/* Renames a chain. */
func (this XtcHandle) RenameChain(oldName, newName XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() {
		cOldName := C.CString(string(oldName))
		defer C.free(unsafe.Pointer(cOldName))
		cNewName := C.CString(string(newName))
		defer C.free(unsafe.Pointer(cNewName))

		r := C.iptc_rename_chain(cOldName, cNewName, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_rename_chain")
	return
}

/* Sets the policy and (optionally) counters on a built-in chain. */
func (this XtcHandle) SetPolicy(chain XtChainLabel, policy XtChainLabel, counters *XtCounters) (result bool, osErr error) {
	osErr = relayCall(func() {
		cChain := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cChain))
		cPolicy := C.CString(string(policy))
		defer C.free(unsafe.Pointer(cPolicy))

		var c *_Ctype_struct_xt_counters
		if counters != nil {
			c = &_Ctype_struct_xt_counters{}
			c.bcnt = C.__u64(counters.Bcnt)
			c.pcnt = C.__u64(counters.Pcnt)
		}

		r := C.iptc_set_policy(cChain, cPolicy, c, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_set_policy")
	return
}

/* Get the number of references to this chain */
func (this XtcHandle) GetReferences(chain XtChainLabel) (result uint, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var i C.uint

		r := C.iptc_get_references(&i, cStr, this.xtc_handle)
		if r == 1 {
			// has a valid result
			result = uint(i)
			return
		} else if r == 0 {
			// has an error
			return
		}

		panic("invalid return value from iptc_get_references")
	}, "iptc_get_references")
	return
}

/* read packet and byte counters for a specific rule */
func (this XtcHandle) ReadCounter(chain XtChainLabel, ruleNum uint) (result XtCounters, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		counters_handle := C.iptc_read_counter(cStr, C.uint(ruleNum), this.xtc_handle)
		if counters_handle == nil {
			// has an error
			return
		}
		result.Bcnt = uint64(counters_handle.bcnt)
		result.Pcnt = uint64(counters_handle.pcnt)
	}, "iptc_read_counter")
	return
}

/* zero packet and byte counters for a specific rule */
func (this XtcHandle) ZeroCounter(chain XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_zero_counter(cStr, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_read_counter")
	return
}

/* set packet and byte counters for a specific rule */
func (this XtcHandle) SetCounter(chain XtChainLabel, ruleNum uint, counters XtCounters) (result bool, osErr error) {
	osErr = relayCall(func() {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		c.bcnt = C.__u64(counters.Bcnt)
		c.pcnt = C.__u64(counters.Pcnt)

		r := C.iptc_set_counter(cStr, C.uint(ruleNum), &c, this.xtc_handle)
		if r == 1 {
			result = true
		} else if r == 0 {
			result = false
		}
	}, "iptc_set_counter")
	return
}

/* Makes the actual changes. */
func (this XtcHandle) Commit() (bool, error) {
	var result bool
	var err error

	relayCall(func() {
		r := C.iptc_commit(this.xtc_handle)
		if r == 1 {
			// nothing was changed
			result = false
			return
		} else if r == 0 {
			result = true
			return
		}

		panic("unexpected return value")
	}, "iptc_commit")

	return result, err
}
