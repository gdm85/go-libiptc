/*
 * go-libiptc v0.3.1 - libiptc bindings for Go language
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
	"time"

	"github.com/gdm85/go-libiptc"
)

func main() {
	fmt.Println("acquiring xtables lock immediately...")
	acquired, err := libiptc.XtablesLock(false, 0)
	if err != nil {
		panic(err)
	}
	if !acquired {
		fmt.Fprintf(os.Stderr, "Could not acquire xtables lock!\n")
		os.Exit(1)
	}
	defer func() {
		_, err := libiptc.XtablesUnlock()
		if err != nil {
			panic(err)
		}
	}()

	fmt.Printf("I have acquired a lock for 5 seconds, try any 'iptables --wait' command\n")
	time.Sleep(5 * time.Second)
}
