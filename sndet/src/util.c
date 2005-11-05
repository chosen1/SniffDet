/*
 *  sniffdet - A tool for network sniffers detection
 *  Copyright (c) 2002, 2003
 *      Ademar de Souza Reis Jr. <myself@ademar.org>
 *      Milton Soares Filho <eu_mil@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; version 2 dated
 *  June, 1991.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See file COPYING for details.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "util.h"

/* drop root privileges, if they found a way to exploit us, we don't
 * want the exploit to run as root.
 */
int drop_root(int uid, int gid)
{
	if (setuid(uid)) {
		return 2;
	}

	if (setgid(gid)) {
		return 1;
	}

	return 0;
}

/* returns a NULL terminated vector of strings
 * with one hostname/ip in each one
 */
char **parse_targets_file(FILE *f_hosts)
{
#define MAX_HOSTS 1024
	char **hostnames;
	char buffer[1024]; // just a magic number
	int i = 0;

	// + 1 is for NULL termination
	hostnames = malloc(sizeof (char *) * (MAX_HOSTS + 1));

	while (fgets(buffer, sizeof buffer, f_hosts) != NULL) {
		if (i >= MAX_HOSTS) {
			fprintf(stderr, 
					"Warning: Stopped reading hostnames from file after %d entries\n",
					MAX_HOSTS);
			break;
		}
		// skip comments and white lines
		if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == ' ') {
			continue;
		}
		hostnames[i] = malloc(strlen(buffer) + 1);
		strncpy(hostnames[i], buffer, strlen(buffer) + 1);

		// XXX
		// remove '\n'
		hostnames[i][strlen(buffer) - 1] = '\0';
		i++;
	}

	// NULL termination
	hostnames[i] = NULL;

	return hostnames;
}

/* TODO:
 * returns a list with all ips from a network/netmask
 */
char **network_ips(char *netmask, char *network)
{
	return NULL;
}

/*	free_stringlist()
 *		Free a vector of strings, NULL terminated
 */
int free_stringlist(char **list)
{
	char **temp;

	temp = list;
	while(*list) {
		free(*list);
		list++;
	}
	free(*list); // the last arg -- NULL
	free(temp);

	return 0; // OK
}
