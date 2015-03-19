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

package main

import (
	"../.."
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: dump-chain <table-name>\n")
		os.Exit(1)
	}

	acquired, err := libiptc.XtablesLock(false, 0)
	if err != nil {
		panic(err)
	}
	if !acquired {
		fmt.Fprintf(os.Stderr, "dump-chain: could not acquire xtables lock!\n")
		os.Exit(1)
	}
	defer func() {
		_, err := libiptc.XtablesUnlock()
		if err != nil {
			panic(err)
		}
	}()

	tableName := os.Args[1]

	table, err := libiptc.TableInit(tableName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dump-chain: %s\n", err)
		os.Exit(3)
	}
	defer table.Free()

	// use the native/undocumented DumpEntries() anyways
	table.DumpEntries()
}
