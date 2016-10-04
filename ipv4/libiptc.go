/*
 * go-libiptc v0.2.1 - libiptc bindings for Go language
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

// #cgo LDFLAGS: -lip4tc
// #include <libiptc/libiptc.h>
// #include <stdlib.h>
import "C"

import (
	"net"
	"unsafe"

	common "github.com/gdm85/go-libiptc"
)

func cuint2ip(cAaddr, cMask C.in_addr_t) *net.IPNet {
	addr := uint32(cAaddr)
	ip := new(net.IPNet)
	ip.IP = net.IPv4(byte(addr&0xff),
		byte((addr>>8)&0xff),
		byte((addr>>16)&0xff),
		byte((addr>>24)&0xff))
	mask := uint32(cMask)
	ip.Mask = net.IPv4Mask(byte(mask&0xff),
		byte((mask>>8)&0xff),
		byte((mask>>16)&0xff),
		byte((mask>>24)&0xff),
	)
	return ip
}

type IptEntry struct {
	ipt_entry_handle *C.struct_ipt_entry
}

type Xtc4Handle struct {
	handle *C.struct_xtc_handle
}

func (h *Xtc4Handle) IptEntry2Rule(e *IptEntry) *common.Rule {
	entry := e.ipt_entry_handle
	rule := new(common.Rule)
	rule.Pcnt = uint64(entry.counters.pcnt)
	rule.Bcnt = uint64(entry.counters.bcnt)
	rule.InDev = C.GoString(&entry.ip.iniface[0])
	rule.OutDev = C.GoString(&entry.ip.outiface[0])
	if entry.ip.invflags&C.IPT_INV_VIA_IN != 0 {
		rule.Not.InDev = true
	}
	if entry.ip.invflags&C.IPT_INV_VIA_OUT != 0 {
		rule.Not.OutDev = true
	}

	rule.Src = cuint2ip(entry.ip.src.s_addr, entry.ip.smsk.s_addr)
	if entry.ip.invflags&C.IPT_INV_SRCIP != 0 {
		rule.Not.Src = true
	}

	rule.Dest = cuint2ip(entry.ip.dst.s_addr, entry.ip.dmsk.s_addr)
	if entry.ip.invflags&C.IPT_INV_DSTIP != 0 {
		rule.Not.Dest = true
	}

	target := C.iptc_get_target(entry, h.handle)
	if target != nil {
		rule.Target = C.GoString(target)
	}
	return rule
}

func getNativeError() string {
	return C.GoString(C.iptc_strerror(C.int(common.GetErrno())))
}

func (h *Xtc4Handle) Free() error {
	return common.RelayCall(func() bool {
		C.iptc_free(h.handle)
		return true
	}, "iptc_free", getNativeError)
}

func (this IptEntry) IsEmpty() bool {
	return this.ipt_entry_handle == nil
}

func TableInit(tableName string) (result Xtc4Handle, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(tableName)
		defer C.free(unsafe.Pointer(cStr))

		h := C.iptc_init(cStr)
		result = Xtc4Handle{h}

		return h != nil
	}, "iptc_init", getNativeError)
	return
}

func (h Xtc4Handle) IsChain(chain string) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_is_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "iptc_is_chain", getNativeError)
	return
}

func (h Xtc4Handle) IsBuiltin(chain string) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_builtin(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}
		panic("invalid return value")
	}, "iptc_builtin", getNativeError)
	return
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
func (h Xtc4Handle) FirstChain() (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.iptc_first_chain(h.handle)
		if cStr == nil {
			result = ""
			return common.GetErrno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "iptc_first_chain", getNativeError)
	return
}

func (h Xtc4Handle) NextChain() (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.iptc_next_chain(h.handle)
		if cStr == nil {
			result = ""
			return common.GetErrno() == 0
		}

		result = C.GoString(cStr)
		return true
	}, "iptc_next_chain", getNativeError)
	return
}

/* Get first rule in the given chain: NULL for empty chain. */
func (h Xtc4Handle) FirstRule(chain string) (result IptEntry, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		result.ipt_entry_handle = C.iptc_first_rule(cStr, h.handle)

		if result.ipt_entry_handle == nil && common.GetErrno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "iptc_first_rule", getNativeError)
	return
}

/* Returns NULL when rules run out. */
func (h Xtc4Handle) NextRule(previous IptEntry) (result IptEntry, osErr error) {
	osErr = common.RelayCall(func() bool {
		result.ipt_entry_handle = C.iptc_next_rule(previous.ipt_entry_handle, h.handle)

		if result.ipt_entry_handle == nil && common.GetErrno() != 0 {
			// there's some error
			return false
		}

		return true
	}, "iptc_next_rule", getNativeError)
	return
}

/* Returns a pointer to the target name of this entry. */
func (h Xtc4Handle) GetTarget(entry IptEntry) (result string, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.iptc_get_target(entry.ipt_entry_handle, h.handle)
		if cStr == nil {
			result = ""
			return false
		}

		result = C.GoString(cStr)
		return true
	}, "iptc_get_target", getNativeError)
	return
}

/* Get the policy of a given built-in chain */
func (h Xtc4Handle) GetPolicy(chain string) (policy string, counters common.XtCounters, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(chain)
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		cStr = C.iptc_get_policy(cStr, &c, h.handle)
		if cStr == nil {
			// no chains
			policy = ""
			return false
		}

		policy = C.GoString(cStr)
		counters.Bcnt = uint64(c.bcnt)
		counters.Pcnt = uint64(c.pcnt)
		return true
	}, "iptc_get_policy", getNativeError)
	return
}

/* These functions return TRUE for OK or 0 and set errno.  If errno ==
   0, it means there was a version error (ie. upgrade libiptc). */
/* Rule numbers start at 1 for the first rule. */

/* Insert the entry `e' in chain `chain' into position `rulenum'. */
func (h Xtc4Handle) InsertEntry(chain common.XtChainLabel, entry IptEntry, ruleNum uint) error {
	return common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_insert_entry(cStr, entry.ipt_entry_handle, C.uint(ruleNum), h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "iptc_insert_entry", getNativeError)
}

/* Append entry `e' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
func (h Xtc4Handle) AppendEntry(chain common.XtChainLabel, entry IptEntry) error {
	return common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_append_entry(cStr, entry.ipt_entry_handle, h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			// has error
			return false
		}

		panic("invalid return value")
	}, "iptc_append_entry", getNativeError)
}

/* Check whether a matching rule exists */
func (h Xtc4Handle) CheckEntry(chain common.XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.iptc_check_entry(cStr, origfw.ipt_entry_handle, cMask, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_check_entry", getNativeError)
	return
}

/* Delete the first rule in `chain' which matches `e', subject to
   matchmask (array of length == origfw) */
func (h Xtc4Handle) DeleteEntry(chain common.XtChainLabel, origfw IptEntry, matchMask []byte) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))
		cMask := (*C.uchar)(unsafe.Pointer(&matchMask[0]))

		r := C.iptc_delete_entry(cStr, origfw.ipt_entry_handle, cMask, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_delete_entry", getNativeError)
	return
}

/* Delete the rule in position `rulenum' in `chain'. */
func (h Xtc4Handle) DeleteNumEntry(chain common.XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_delete_num_entry(cStr, C.uint(ruleNum), h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_delete_num_entry", getNativeError)
	return
}

/* Check the packet `e' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
/*func (this XtcHandle) CheckPacket(chain XtChainLabel, entry IptEntry) error {
	panic("will never be implemented")
}*/

/* Flushes the entries in the given chain (ie. empties chain). */
func (h Xtc4Handle) FlushEntries(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_flush_entries(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_flush_entries", getNativeError)
	return
}

/* Zeroes the counters in a chain. */
func (h Xtc4Handle) ZeroEntries(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_zero_entries(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_zero_entries", getNativeError)
	return
}

/* Creates a new chain. */
func (h Xtc4Handle) CreateChain(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_create_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_create_chain", getNativeError)
	return
}

/* Deletes a chain. */
func (h Xtc4Handle) DeleteChain(chain common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_delete_chain(cStr, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_delete_chain", getNativeError)
	return
}

/* Renames a chain. */
func (h Xtc4Handle) RenameChain(oldName, newName common.XtChainLabel) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cOldName := C.CString(string(oldName))
		defer C.free(unsafe.Pointer(cOldName))
		cNewName := C.CString(string(newName))
		defer C.free(unsafe.Pointer(cNewName))

		r := C.iptc_rename_chain(cOldName, cNewName, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_rename_chain", getNativeError)
	return
}

/* Sets the policy and (optionally) counters on a built-in chain. */
func (h Xtc4Handle) SetPolicy(chain, policy common.XtChainLabel, counters *common.XtCounters) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
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

		r := C.iptc_set_policy(cChain, cPolicy, c, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_set_policy", getNativeError)
	return
}

/* Get the number of references to this chain */
func (h Xtc4Handle) GetReferences(chain common.XtChainLabel) (result uint, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var i C.uint

		r := C.iptc_get_references(&i, cStr, h.handle)
		if r == 1 {
			// has a valid result
			result = uint(i)
			return true
		} else if r == 0 {
			// has an error
			return false
		}

		panic("invalid return value")
	}, "iptc_get_references", getNativeError)
	return
}

/* read packet and byte counters for a specific rule */
func (h Xtc4Handle) ReadCounter(chain common.XtChainLabel, ruleNum uint) (result common.XtCounters, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		counters_handle := C.iptc_read_counter(cStr, C.uint(ruleNum), h.handle)
		if counters_handle == nil {
			// has an error
			return false
		}

		result.Bcnt = uint64(counters_handle.bcnt)
		result.Pcnt = uint64(counters_handle.pcnt)
		return true
	}, "iptc_read_counter", getNativeError)
	return
}

/* zero packet and byte counters for a specific rule */
func (h Xtc4Handle) ZeroCounter(chain common.XtChainLabel, ruleNum uint) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		r := C.iptc_zero_counter(cStr, C.uint(ruleNum), h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_read_counter", getNativeError)
	return
}

/* set packet and byte counters for a specific rule */
func (h Xtc4Handle) SetCounter(chain common.XtChainLabel, ruleNum uint, counters common.XtCounters) (result bool, osErr error) {
	osErr = common.RelayCall(func() bool {
		cStr := C.CString(string(chain))
		defer C.free(unsafe.Pointer(cStr))

		var c _Ctype_struct_xt_counters
		c.bcnt = C.__u64(counters.Bcnt)
		c.pcnt = C.__u64(counters.Pcnt)

		r := C.iptc_set_counter(cStr, C.uint(ruleNum), &c, h.handle)
		if r == 1 {
			result = true
			return result
		} else if r == 0 {
			result = false
			return result
		}

		panic("invalid return value")
	}, "iptc_set_counter", getNativeError)
	return
}

/* Makes the actual changes. */
func (h Xtc4Handle) Commit() error {
	return common.RelayCall(func() bool {
		r := C.iptc_commit(h.handle)
		if r == 1 {
			return true
		} else if r == 0 {
			return false
		}

		panic("unexpected return value")
	}, "iptc_commit", getNativeError)
}

func (h Xtc4Handle) DumpEntries() error {
	return common.RelayCall(func() bool {
		C.dump_entries(h.handle)
		return false
	}, "dump_entries", getNativeError)
}
