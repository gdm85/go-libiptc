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

import (
	"testing"
)

func TestInit(t *testing.T) {
	acquired, err := XtablesLock(false)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !acquired {
		t.FailNow()
	}
	defer XtablesUnlock()

	handle, err := TableInit("filter")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	err = handle.Free()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestXtablesLock(t *testing.T) {
	acquired, err := XtablesLock(false)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !acquired {
		t.FailNow()
	}

	released, err := XtablesUnlock()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	released, err = XtablesUnlock()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// should not succeed at releasing a lock twice
	if released {
		t.FailNow()
	}
}
