/*
 * go-libiptc v0.2.1 - libiptc bindings for Go language
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
	"github.com/bstevant/go-libiptc"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: dump-table-rules <table-name>\n")
		os.Exit(1)
	}

	acquired, err := libiptc.XtablesLock(false, 0)
	if err != nil {
		panic(err)
	}
	if !acquired {
		fmt.Fprintf(os.Stderr, "dump-table-rules: could not acquire xtables lock!\n")
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
		fmt.Fprintf(os.Stderr, "dump-table-rules: %s\n", err)
		os.Exit(3)
	}
	defer table.Free()

	// traverse trough chains
	chain, err := table.FirstChain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dump-table-rules: %s\n", err)
		os.Exit(3)
	}
	for chain != "" {
		// use Go-native rules conversion
		e, err := table.FirstRule(chain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dump-table-rules: %s\n", err)
			os.Exit(3)
		}
		for !e.IsEmpty() {
			fmt.Println(chain+":", table.Ip6tEntry2Rule(&e).String())
			e, err = table.NextRule(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "dump-table-rules: %s\n", err)
				os.Exit(3)
			}
		}

		chain, err = table.NextChain()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dump-table-rules: %s\n", err)
			os.Exit(3)
		}
	}
}
