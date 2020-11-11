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

package libip6tc

import (
	// #cgo LDFLAGS: -l:libip6tc.so.0
	// #include <libiptc/libip6tc.h>
	// #include <stdlib.h>
	"C"
	"net"
	"runtime"
	"unsafe"

	common "github.com/gdm85/go-libiptc"
)

func cin6addr2ip(cAaddr, cMask C.struct_in6_addr) *net.IPNet {
	ip := new(net.IPNet)

	ip.IP = make(net.IP, 16)
	copy(ip.IP, cAaddr.__in6_u[:])
	ip.Mask = make(net.IPMask, 16)
	copy(ip.Mask, cMask.__in6_u[:])

	return ip
}

type IptEntry struct {
	handle *C.struct_ip6t_entry
}

func (h IptEntry) IsEmpty() bool {
	return h.handle == nil
}

type XtcHandle struct {
	handle *C.struct_xtc_handle
}

func (h XtcHandle) IptEntry2Rule(e *IptEntry) *common.Rule {
	entry := e.handle
	rule := new(common.Rule)
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

	target := C.ip6tc_get_target(entry, h.handle)
	if target != nil {
		rule.Target = C.GoString(target)
	}
	return rule
}

func getNativeError() string {
	return C.GoString(C.ip6tc_strerror(C.int(common.GetErrno())))
}

func (h *XtcHandle) Free() error {
	return common.RelayCall(func() bool {
		if h.handle != nil {
			C.ip6tc_free(h.handle)
			h.handle = nil
		}
		return true
	}, "ip6tc_free", getNativeError)
}

func TableInit(tableName string) (result XtcHandle, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(tableName)
		defer C.free(unsafe.Pointer(cStr))

		h := C.ip6tc_init(cStr)
		result = XtcHandle{h}

		return h != nil
	}, "ip6tc_init", getNativeError)

	// set the finalizer before returning the usable result
	runtime.SetFinalizer(&result, (*XtcHandle).Free)

	return
}

func (h XtcHandle) IsChain(chain string) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_is_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "ip6tc_is_chain", getNativeError)
	return
}

func (h XtcHandle) IsBuiltin(chain string) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_builtin(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "ip6tc_builtin", getNativeError)
	return
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
func (h XtcHandle) FirstChain() (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.ip6tc_first_chain(h.handle)
		if cStr == nil {
			result = ""
			return common.GetErrno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_first_chain", getNativeError)
	return
}

func (h XtcHandle) NextChain() (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.ip6tc_next_chain(h.handle)
		if cStr == nil {
			result = ""
			return common.GetErrno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_next_chain", getNativeError)
	return
}

/* Get first rule in the given chain: NULL for empty chain. */
func (h XtcHandle) FirstRule(chain string) (result IptEntry, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		result.handle = C.ip6tc_first_rule(cStr, h.handle)

		if result.handle == nil && common.GetErrno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "ip6tc_first_rule", getNativeError)
	return
}

/* Returns NULL when rules run out. */
func (h XtcHandle) NextRule(previous IptEntry) (result IptEntry, osErr error) {
	osErr = common.RelayCall(func() bool {
		result.handle = C.ip6tc_next_rule(previous.handle, h.handle)

		if result.handle == nil && common.GetErrno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "ip6tc_next_rule", getNativeError)
	return
}

/* Returns a pointer to the target name of this entry. */
func (h XtcHandle) GetTarget(entry IptEntry) (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.ip6tc_get_target(entry.handle, h.handle)
		if cStr == nil {
			result = ""
			return false
		}

		result = C.GoString(cStr)
		return true
	}, "ip6tc_get_target", getNativeError)
	return
}

// GetPolicy gets the policy of a given built-in chain.
func (h XtcHandle) GetPolicy(chain string) (policy string, counters common.XtCounters, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		var c C.struct_xt_counters
		cStr = C.ip6tc_get_policy(cStr, &c, h.handle)
		if cStr == nil {
			// no chains
			policy = ""
			return false
		}

		policy = C.GoString(cStr)
		counters.Bcnt = uint64(c.bcnt)
		counters.Pcnt = uint64(c.pcnt)
		return true
	}, "ip6tc_get_policy", getNativeError)
	return
}

/* These functions return TRUE for OK or 0 and set errno.  If errno ==
   0, it means there was a version error (ie. upgrade libiptc). */
/* Rule numbers start at 1 for the first rule. */

/* Insert the entry `e' in chain `chain' into position `rulenum'. */
func (h XtcHandle) InsertEntry(chain common.XtChainLabel, entry IptEntry, ruleNum uint) error {
	return common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_insert_entry(cStr, entry.handle, C.uint(ruleNum), h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_insert_entry", getNativeError)
}

/* Append entry `e' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
func (h XtcHandle) AppendEntry(chain common.XtChainLabel, entry IptEntry) error {
	return common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_append_entry(cStr, entry.handle, h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_append_entry", getNativeError)
}

/* Check whether a matching rule exists */
func (h XtcHandle) CheckEntry(chain common.XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.ip6tc_check_entry(cStr, origfw.handle, cMask, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_check_entry", getNativeError)
	return
}

/* Delete the first rule in `chain' which matches `e', subject to
   matchmask (array of length == origfw) */
func (h XtcHandle) DeleteEntry(chain common.XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.ip6tc_delete_entry(cStr, origfw.handle, cMask, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_entry", getNativeError)
	return
}

/* Delete the rule in position `rulenum' in `chain'. */
func (h XtcHandle) DeleteNumEntry(chain common.XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_delete_num_entry(cStr, C.uint(ruleNum), h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_num_entry", getNativeError)
	return
}

/* Flushes the entries in the given chain (ie. empties chain). */
func (h XtcHandle) FlushEntries(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_flush_entries(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_flush_entries", getNativeError)
	return
}

/* Zeroes the counters in a chain. */
func (h XtcHandle) ZeroEntries(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_zero_entries(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_zero_entries", getNativeError)
	return
}

/* Creates a new chain. */
func (h XtcHandle) CreateChain(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_create_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_create_chain", getNativeError)
	return
}

/* Deletes a chain. */
func (h XtcHandle) DeleteChain(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_delete_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_delete_chain", getNativeError)
	return
}

/* Renames a chain. */
func (h XtcHandle) RenameChain(oldName, newName common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cOldName := C.CString(string(oldName))
		defer C.free(unsafe.Pointer(cOldName))
		cNewName := C.CString(string(newName))
		defer C.free(unsafe.Pointer(cNewName))

		r := C.ip6tc_rename_chain(cOldName, cNewName, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_rename_chain", getNativeError)
	return
}

/* Sets the policy and (optionally) counters on a built-in chain. */
func (h XtcHandle) SetPolicy(chain, policy common.XtChainLabel, counters *common.XtCounters) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cChain := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cChain))
		cPolicy := C.CString(string(policy))
		defer C.free(unsafe.Pointer(cPolicy))

		var c *C.struct_xt_counters
		if counters != nil {
			c = &C.struct_xt_counters{}
			c.bcnt = C.__u64(counters.Bcnt)
			c.pcnt = C.__u64(counters.Pcnt)
		}

		r := C.ip6tc_set_policy(cChain, cPolicy, c, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_set_policy", getNativeError)
	return
}

/* Get the number of references to this chain */
func (h XtcHandle) GetReferences(chain common.XtChainLabel) (result uint, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var i C.uint

		r := C.ip6tc_get_references(&i, cStr, h.handle)
		if r == 1 {
			// has a valid result
			result = uint(i)
			return true
		} else if r == 0 {
			// has an error
			return false
		}

		panic("invalid return value")
	}, "ip6tc_get_references", getNativeError)
	return
}

/* read packet and byte counters for a specific rule */
func (h XtcHandle) ReadCounter(chain common.XtChainLabel, ruleNum uint) (result common.XtCounters, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		counters_handle := C.ip6tc_read_counter(cStr, C.uint(ruleNum), h.handle)
		if counters_handle == nil {
			// has an error
			return false
		}

		result.Bcnt = uint64(counters_handle.bcnt)
		result.Pcnt = uint64(counters_handle.pcnt)
		return true
	}, "ip6tc_read_counter", getNativeError)
	return
}

/* zero packet and byte counters for a specific rule */
func (h XtcHandle) ZeroCounter(chain common.XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.ip6tc_zero_counter(cStr, C.uint(ruleNum), h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_read_counter", getNativeError)
	return
}

// SetCounter sets packet and byte counters for a specific rule.
func (h XtcHandle) SetCounter(chain common.XtChainLabel, ruleNum uint, counters common.XtCounters) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var c C.struct_xt_counters
		c.bcnt = C.__u64(counters.Bcnt)
		c.pcnt = C.__u64(counters.Pcnt)

		r := C.ip6tc_set_counter(cStr, C.uint(ruleNum), &c, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "ip6tc_set_counter", getNativeError)
	return
}

// Commit makes the actual changes.
func (h XtcHandle) Commit() error {
	return common.RelayCall(func() bool {
		r := C.ip6tc_commit(h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			return false
		}

		panic("unexpected return value")
	}, "ip6tc_commit", getNativeError)
}

// DumpEntries will use an internal undocumented function to dump all table entries to stdout.
func (h XtcHandle) DumpEntries() error {
	return common.RelayCall(func() bool {
		C.dump_entries6(h.handle)
		return false
	}, "dump_entries6", getNativeError)
}
