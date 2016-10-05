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

package libip4tc

import (
	"testing"

	common "github.com/gdm85/go-libiptc"
)

func TestXtablesLock(t *testing.T) {
	acquired, err := common.XtablesLock(false, 0)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !acquired {
		t.FailNow()
	}

	released, err := common.XtablesUnlock()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	released, err = common.XtablesUnlock()
	if err == nil || released {
		t.Error("unlocking twice succeeded!")
		t.FailNow()
	}
}

func TestInit(t *testing.T) {
	acquired, err := common.XtablesLock(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.FailNow()
	}
	defer func() {
		_, err := common.XtablesUnlock()
		if err != nil {
			panic(err)
		}
	}()

	handle, err := TableInit("filter")
	if err != nil {
		t.Fatal(err)
	}

	err = handle.Free()
	if err != nil {
		t.Fatal(err)
	}
}
