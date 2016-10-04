/*
 * go-libip6tc v0.2.1 - libip6tc bindings for Go language
 * Copyright (C) 2015~2016 gdm85 - https://github.com/gdm85/go-libip6tc/

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

// #cgo LDFLAGS: -lip6tc
// #include "xtables-lock.h"
// #include <libiptc/libip6tc.h>
import "C"

import (
	"fmt"
	"net"
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

type Ip6tEntry struct {
	ip6t_entry_handle *_Ctype_struct_ip6t_entry
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

func cin6addr2ip(cAaddr, cMask C.struct_in6_addr) *net.IPNet {
	ip := new(net.IPNet)

	ip.IP = make(net.IP, 16)
	copy(ip.IP, cAaddr.__in6_u[:])
	ip.Mask = make(net.IPMask, 16)
	copy(ip.Mask, cMask.__in6_u[:])

	return ip
}

func (h *XtcHandle) Ip6tEntry2Rule(e *Ip6tEntry) *Rule {
	entry := e.ip6t_entry_handle
	rule := new(Rule)
	rule.Pcnt = uint64(entry.counters.pcnt)
	rule.Bcnt = uint64(entry.counters.bcnt)
	rule.InDev = C.GoString(&entry.ipv6.iniface[0])
	rule.OutDev = C.GoString(&entry.ipv6.outiface[0])
	if entry.ipv6.invflags&C.IP6T_INV_VIA_IN != 0 {
		rule.Not.InDev = true
	}
	if entry.ipv6.invflags&C.IP6T_INV_VIA_OUT != 0 {
		rule.Not.OutDev = true
	}

	rule.Src = cin6addr2ip(entry.ipv6.src, entry.ipv6.smsk)
	if entry.ipv6.invflags&C.IP6T_INV_SRCIP != 0 {
		rule.Not.Src = true
	}

	rule.Dest = cin6addr2ip(entry.ipv6.dst, entry.ipv6.dmsk)
	if entry.ipv6.invflags&C.IP6T_INV_DSTIP != 0 {
		rule.Not.Dest = true
	}

	target := C.ip6tc_get_target(entry, h.xtc_handle)
	if target != nil {
		rule.Target = C.GoString(target)
	}
	return rule
}

// a function that returns false if there is an 'errno' to query about
type RelayedFunc func() bool

type RelayedCall struct {
	Func    func() bool
	Context string
}

var (
	lastErrors   = make(chan error)
	queueOfCalls = make(chan RelayedCall)
)

func init() {
	// start a main loop that will process (serially) all incoming libip6tc calls
	go func() {
		runtime.LockOSThread()
		//defer runtime.UnlockOSThread()

		for call := range queueOfCalls {
			// as extra good measure, reset errno before C-land calls
			C.reset_errno()

			// libip6tc's logic is called here
			success := call.Func()

			var err error
			if !success {
				err = fmt.Errorf("%s: %s", call.Context, C.GoString(C.ip6tc_strerror(C.get_errno())))
			}

			// this will also signal completion of the call
			lastErrors <- err
		}
	}()
}

func relayCall(f RelayedFunc, context string) error {
	queueOfCalls <- RelayedCall{Func: f, Context: context}
	return <-lastErrors
}

func (this XtcHandle) Free() error {
	return relayCall(func() bool {
		C.ip6tc_free(this.xtc_handle)
		return true
	}, "ip6tc_free")
}

func (this Ip6tEntry) IsEmpty() bool {
	return this.ip6t_entry_handle == nil
}

func TableInit(tableName string) (result XtcHandle, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(tableName)
		defer C.free(unsafe.Pointer(cStr))

		h := C.ip6tc_init(cStr)
		result = XtcHandle{xtc_handle: h}

		return h != nil
	}, "free")
	return
}

func XtablesLock(wait bool, maxSeconds uint) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		r := C.xtables_lock(true, C.uint(maxSeconds))
		if r == 0 {
			result = true
			return result
		} else if r == 1 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "xtables_lock")
	return
}

func XtablesUnlock() (result bool, osErr error) {
	osErr = relayCall(func() bool {
		r := C.xtables_unlock()
		if r == 0 {
			result = true
			return result
		} else if r == 1 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "xtables_lock")
	return
}

func (this XtcHandle) IsChain(chain string) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_is_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "ip6tc_is_chain")
	return
}

func (this XtcHandle) IsBuiltin(chain string) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_builtin(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "ip6tc_builtin")
	return
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
func (this XtcHandle) FirstChain() (result string, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.ip6tc_first_chain(this.xtc_handle)
		if cStr == nil {
			result = ""
			return C.get_errno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_first_chain")
	return
}

func (this XtcHandle) NextChain() (result string, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.ip6tc_next_chain(this.xtc_handle)
		if cStr == nil {
			result = ""
			return C.get_errno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_next_chain")
	return
}

/* Get first rule in the given chain: NULL for empty chain. */
func (this XtcHandle) FirstRule(chain string) (result Ip6tEntry, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		result.ip6t_entry_handle = C.ip6tc_first_rule(cStr, this.xtc_handle)

		if result.ip6t_entry_handle == nil && C.get_errno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "ip6tc_first_rule")
	return
}

/* Returns NULL when rules run out. */
func (this XtcHandle) NextRule(previous Ip6tEntry) (result Ip6tEntry, osErr error) {
	osErr = relayCall(func() bool {
		result.ip6t_entry_handle = C.ip6tc_next_rule(previous.ip6t_entry_handle, this.xtc_handle)

		if result.ip6t_entry_handle == nil && C.get_errno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "ip6tc_next_rule")
	return
}

/* Returns a pointer to the target name of this entry. */
func (this XtcHandle) GetTarget(entry Ip6tEntry) (result string, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.ip6tc_get_target(entry.ip6t_entry_handle, this.xtc_handle)
		if cStr == nil {
			result = ""
			return false
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_get_target")
	return
}

/* Get the policy of a given built-in chain */
func (this XtcHandle) GetPolicy(chain string) (policy string, counters XtCounters, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		cStr = C.ip6tc_get_policy(cStr, &c, this.xtc_handle)
		if cStr == nil {
			// no chains
			policy = ""
			return false
		}

		policy = C.GoString(cStr)
		counters.Bcnt = uint64(c.bcnt)
		counters.Pcnt = uint64(c.pcnt)
		return true
	}, "ip6tc_get_policy")
	return
}

/* These functions return TRUE for OK or 0 and set errno.  If errno ==
   0, it means there was a version error (ie. upgrade libiptc). */
/* Rule numbers start at 1 for the first rule. */

/* Insert the entry `e' in chain `chain' into position `rulenum'. */
func (this XtcHandle) InsertEntry(chain XtChainLabel, entry Ip6tEntry, ruleNum uint) error {
	return relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_insert_entry(cStr, entry.ip6t_entry_handle, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_insert_entry")
}

/* Append entry `e' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
func (this XtcHandle) AppendEntry(chain XtChainLabel, entry Ip6tEntry) error {
	return relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_append_entry(cStr, entry.ip6t_entry_handle, this.xtc_handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_append_entry")
}

/* Check whether a matching rule exists */
func (this XtcHandle) CheckEntry(chain XtChainLabel, origfw Ip6tEntry, matchMask []byte) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.ip6tc_check_entry(cStr, origfw.ip6t_entry_handle, cMask, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_check_entry")
	return
}

/* Delete the first rule in `chain' which matches `e', subject to
   matchmask (array of length == origfw) */
func (this XtcHandle) DeleteEntry(chain XtChainLabel, origfw Ip6tEntry, matchMask []byte) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.ip6tc_delete_entry(cStr, origfw.ip6t_entry_handle, cMask, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_entry")
	return
}

/* Delete the rule in position `rulenum' in `chain'. */
func (this XtcHandle) DeleteNumEntry(chain XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_delete_num_entry(cStr, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_num_entry")
	return
}

/* Check the packet `e' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
/*func (this XtcHandle) CheckPacket(chain XtChainLabel, entry Ip6tEntry) error {
	panic("will never be implemented")
}*/

/* Flushes the entries in the given chain (ie. empties chain). */
func (this XtcHandle) FlushEntries(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_flush_entries(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_flush_entries")
	return
}

/* Zeroes the counters in a chain. */
func (this XtcHandle) ZeroEntries(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_zero_entries(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_zero_entries")
	return
}

/* Creates a new chain. */
func (this XtcHandle) CreateChain(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_create_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_create_chain")
	return
}

/* Deletes a chain. */
func (this XtcHandle) DeleteChain(chain XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_delete_chain(cStr, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_chain")
	return
}

/* Renames a chain. */
func (this XtcHandle) RenameChain(oldName, newName XtChainLabel) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cOldName := C.CString(string(oldName))
		defer C.free(unsafe.Pointer(cOldName))
		cNewName := C.CString(string(newName))
		defer C.free(unsafe.Pointer(cNewName))

		r := C.ip6tc_rename_chain(cOldName, cNewName, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_rename_chain")
	return
}

/* Sets the policy and (optionally) counters on a built-in chain. */
func (this XtcHandle) SetPolicy(chain XtChainLabel, policy XtChainLabel, counters *XtCounters) (result bool, osErr error) {
	osErr = relayCall(func() bool {
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

		r := C.ip6tc_set_policy(cChain, cPolicy, c, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_set_policy")
	return
}

/* Get the number of references to this chain */
func (this XtcHandle) GetReferences(chain XtChainLabel) (result uint, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var i C.uint

		r := C.ip6tc_get_references(&i, cStr, this.xtc_handle)
		if r == 1 {
			// has a valid result
			result = uint(i)
			return true
		} else if r == 0 {
			// has an error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_get_references")
	return
}

/* read packet and byte counters for a specific rule */
func (this XtcHandle) ReadCounter(chain XtChainLabel, ruleNum uint) (result XtCounters, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		counters_handle := C.ip6tc_read_counter(cStr, C.uint(ruleNum), this.xtc_handle)
		if counters_handle == nil {
			// has an error
			return false
		}

		result.Bcnt = uint64(counters_handle.bcnt)
		result.Pcnt = uint64(counters_handle.pcnt)
		return true
	}, "ip6tc_read_counter")
	return
}

/* zero packet and byte counters for a specific rule */
func (this XtcHandle) ZeroCounter(chain XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_zero_counter(cStr, C.uint(ruleNum), this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_read_counter")
	return
}

/* set packet and byte counters for a specific rule */
func (this XtcHandle) SetCounter(chain XtChainLabel, ruleNum uint, counters XtCounters) (result bool, osErr error) {
	osErr = relayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		c.bcnt = C.__u64(counters.Bcnt)
		c.pcnt = C.__u64(counters.Pcnt)

		r := C.ip6tc_set_counter(cStr, C.uint(ruleNum), &c, this.xtc_handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_set_counter")
	return
}

/* Makes the actual changes. */
func (this XtcHandle) Commit() error {
	return relayCall(func() bool {
		r := C.ip6tc_commit(this.xtc_handle)
		if r == 1 {
			return true
		} else if r == 0 {
			return false
		}

		panic("unexpected return value")
	}, "ip6tc_commit")
}

func (this XtcHandle) DumpEntries() error {
	return relayCall(func() bool {
		C.dump_entries6(this.xtc_handle)
		return false
	}, "dump_entries6")
}
