/*
 * go-libiptc v0.3.0 - libiptc bindings for Go language
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

#include <libiptc/libiptc.h>
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "xtables-lock.h"

#define XT_SOCKET_NAME "xtables"
#define XT_SOCKET_LEN 8

int xtables_socket = -1;

// it's not possible to read or write errno directly in Go
void reset_errno() {
	errno = 0;
}

// some functions inconsistently report about an erroneous condition through their result,
// thus error checking is peeked with this helper function
// see also: https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=6619179
// NOTE: there is a PR upstream about improving error handling in iptables
int get_errno() {
	return errno;
}

int xtables_unlock() {
	// lock was not being held at all
	if (xtables_socket < 0) {
		errno = ENOLCK;
		return 1;
	}

	if (close(xtables_socket) != 0)
		return 1;

	xtables_socket = -1;
	return 0;
}

// <0 - lock failed, 0 - success, 1 - failure
int xtables_lock(bool wait, uint max_seconds_wait)
{
	// trying to acquire lock twice
	if (xtables_socket >= 0) {
		errno = EALREADY;
		return 1;
	}

	int i = 0, ret;
	struct sockaddr_un xt_addr;

	memset(&xt_addr, 0, sizeof(xt_addr));
	xt_addr.sun_family = AF_UNIX;
	strcpy(xt_addr.sun_path+1, XT_SOCKET_NAME);
	xtables_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	/* If we can't even create a socket, fall back to prior (lockless) behavior */
	if (xtables_socket < 0) {
		// errno is expected to have been set by previous socket() call
		return xtables_socket;
	}

	uint waited_seconds = 0;
	while (waited_seconds <= max_seconds_wait) {
		ret = bind(xtables_socket, (struct sockaddr*)&xt_addr,
			   offsetof(struct sockaddr_un, sun_path)+XT_SOCKET_LEN);

		// successfully acquired lock (via socket)
		// NOTE: the socket is released with xtables_unlock(), or anyway when process exits
		if (ret == 0)
			return 0;

		// fail immediately
		if (wait == false) {
			// errno has been set by the bind() call
			return 1;
		}

		// time to wait
		sleep(1);
		++waited_seconds;
	}

	// timeout
	errno = ETIMEDOUT;
	return 1;
}
