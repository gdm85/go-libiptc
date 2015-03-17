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
	"unsafe"
//	"runtime"
)

type XtChainLabel string

const (
	IPTC_LABEL_ACCEPT = "ACCEPT"
	IPTC_LABEL_DROP = "DROP"
	IPTC_LABEL_QUEUE = "QUEUE"
	IPTC_LABEL_RETURN = "RETURN"
)

type XtcHandle struct {
	xtc_handle	*_Ctype_struct_xtc_handle
}

type XtCounters struct {
	// 2 uint64, as defined in x_tables.h
	counters	_Ctype_struct_xt_counters
}

type IptEntry struct {
	ipt_entry_handle	*_Ctype_struct_ipt_entry
}

func init() {
}

func (this XtcHandle) Free() {
	C.iptc_free(this.xtc_handle)
}

// returns empty string if there is errno is zero
func LastError() string {
	return C.GoString(C.iptc_last_error())
}

func TableInit(tableName string) XtcHandle {
	cStr := C.CString(tableName)
	defer C.free(unsafe.Pointer(cStr))
	
	return XtcHandle{xtc_handle: C.iptc_init(cStr),}
}

func XtablesLock(wait bool) (bool, error) {
	r := C.xtables_lock(true)
	if r == 0 {
		return true, nil
	} else if r == 1 {
		return false, nil
	}
	
	// an error
	return false, fmt.Errorf("%s", C.GoString(C.socket_error()))
}

func (this XtcHandle) IsChain(chain string) bool {
	cStr := C.CString(chain)
	defer C.free(unsafe.Pointer(cStr))
	
	r := C.iptc_is_chain(cStr, this.xtc_handle)
	if r == 1 {
		return true
	} else if r == 0 {
		return false
	}
	panic("invalid return value from iptc_is_chain")
}

func (this XtcHandle) IsBuiltin(chain string) bool {
	cStr := C.CString(chain)
	defer C.free(unsafe.Pointer(cStr))
	
	r := C.iptc_builtin(cStr, this.xtc_handle)
	if r == 1 {
		return true
	} else if r == 0 {
		return false
	}
	panic("invalid return value from iptc_builtin")
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
func (this XtcHandle) FirstChain() string {
	panic("not yet implemented")
}

func (this XtcHandle) NextChain() string {
	panic("not yet implemented")
}

/* Get first rule in the given chain: NULL for empty chain. */
func (this XtcHandle) FirstRule(chain string) IptEntry {
	panic("not yet implemented")
}

/* Returns NULL when rules run out. */
func (this XtcHandle) NextRule(previous IptEntry) IptEntry {
	panic("not yet implemented")
}

/* Returns a pointer to the target name of this entry. */
func (this XtcHandle) GetTarget(entry IptEntry) string {
	panic("not yet implemented")
}

/* Get the policy of a given built-in chain */
func (this XtcHandle) GetPolicy(chain string) (string, XtCounters) {
	cStr := C.CString(chain)
	defer C.free(unsafe.Pointer(cStr))
	
	counters := XtCounters{}
	
	policy := C.iptc_get_policy(cStr, &counters.counters, this.xtc_handle)
	
	return C.GoString(policy), counters
}

/* These functions return TRUE for OK or 0 and set errno.  If errno ==
   0, it means there was a version error (ie. upgrade libiptc). */
/* Rule numbers start at 1 for the first rule. */

/* Insert the entry `e' in chain `chain' into position `rulenum'. */
func (this XtcHandle) InsertEntry(chain XtChainLabel, entry IptEntry, ruleNum uint) error {
	cStr := C.CString(string(chain))
	defer C.free(unsafe.Pointer(cStr))

	r := C.iptc_insert_entry(cStr, entry.ipt_entry_handle, C.uint(ruleNum), this.xtc_handle)
	if r == 1 {
		return nil
	} else if r == 0 {
		return fmt.Errorf("%s", LastError())
	}
	panic("invalid return value from iptc_insert_entry")
}

/* Append entry `e' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
func (this XtcHandle) AppendEntry(chain XtChainLabel, entry IptEntry) error {
	panic("not yet implemented")
}

/* Check whether a matching rule exists */
func (this XtcHandle) CheckEntry(chain XtChainLabel, origfw IptEntry, matchMask string) (bool, error) {
	panic("not yet implemented")
}

/* Delete the first rule in `chain' which matches `e', subject to
   matchmask (array of length == origfw) */
func (this XtcHandle) DeleteEntry(chain XtChainLabel, origfw IptEntry, matchMask string) error {
	panic("not yet implemented")
}

/* Delete the rule in position `rulenum' in `chain'. */
func (this XtcHandle) DeleteNumEntry(chain XtChainLabel, ruleNum uint) error {
	panic("not yet implemented")
}

/* Check the packet `e' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
func (this XtcHandle) CheckPacket(chain XtChainLabel, entry IptEntry) error {
	panic("not yet implemented")
}

/* Flushes the entries in the given chain (ie. empties chain). */
func (this XtcHandle) FlushEntries(chain XtChainLabel) error {
	panic("not yet implemented")
}

/* Zeroes the counters in a chain. */
func (this XtcHandle) ZeroEntries(chain XtChainLabel) error {
	panic("not yet implemented")
}

/* Creates a new chain. */
func (this XtcHandle) CreateChain(chain XtChainLabel) error {
	panic("not yet implemented")
}

/* Deletes a chain. */
func (this XtcHandle) DeleteChain(chain XtChainLabel) error {
	panic("not yet implemented")
}

/* Renames a chain. */
func (this XtcHandle) RenameChain(oldName, newName XtChainLabel) error {
	panic("not yet implemented")
}

/* Sets the policy on a built-in chain. */
func (this XtcHandle) SetPolicy(chain XtChainLabel, policy XtChainLabel, counters XtCounters) error {
	panic("not yet implemented")
}

/* Get the number of references to this chain */
func (this XtcHandle) GetReferences(chain XtChainLabel) (int, error) {
	panic("not yet implemented")
}

/* read packet and byte counters for a specific rule */
func (this XtcHandle) ReadCounter(chain XtChainLabel, ruleNum uint) (XtCounters, error) {
	panic("not yet implemented")
}

/* zero packet and byte counters for a specific rule */
func (this XtcHandle) ZeroCounter(chain XtChainLabel, ruleNum uint) error {
	panic("not yet implemented")
}

/* set packet and byte counters for a specific rule */
func (this XtcHandle) SetCounter(chain XtChainLabel, ruleNum uint, counters XtCounters) error {
	panic("not yet implemented")
}

/* Makes the actual changes. */
func (this XtcHandle) Commit() error {
	panic("not yet implemented")
}

/* Get raw socket. */
//int iptc_get_raw_socket(void);

//extern void dump_entries(struct xtc_handle *const);

//extern const struct xtc_ops iptc_ops;
