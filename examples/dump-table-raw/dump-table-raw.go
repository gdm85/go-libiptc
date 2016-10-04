/*
 * go-libiptc v0.3.0 - libiptc bindings for Go language
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
	"fmt"
	"os"

	common "github.com/gdm85/go-libiptc"
	libip4tc "github.com/gdm85/go-libiptc/ipv4"
	libip6tc "github.com/gdm85/go-libiptc/ipv6"
)

func showSyntax() {
	fmt.Fprintf(os.Stderr, "Usage: dump-table-raw [-4|-6] <table-name>\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		showSyntax()
	}

	var useIpv6 bool
	switch os.Args[1] {
	case `-4`:
	case `-6`:
		useIpv6 = true
	default:
		showSyntax()
	}

	acquired, err := common.XtablesLock(false, 0)
	if err != nil {
		panic(err)
	}
	if !acquired {
		fmt.Fprintf(os.Stderr, "dump-table-raw: could not acquire xtables lock!\n")
		os.Exit(1)
	}
	defer func() {
		_, err := common.XtablesUnlock()
		if err != nil {
			panic(err)
		}
	}()

	tableName := os.Args[2]

	if !useIpv6 {
		table, err := libip4tc.TableInit(tableName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dump-table-raw: %s\n", err)
			os.Exit(3)
		}
		defer table.Free()

		// use the native/undocumented DumpEntries() anyways
		table.DumpEntries()
	} else {
		table, err := libip6tc.TableInit(tableName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dump-table-raw: %s\n", err)
			os.Exit(3)
		}
		defer table.Free()

		// use the native/undocumented DumpEntries() anyways
		table.DumpEntries()
	}
}
