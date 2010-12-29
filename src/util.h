/*
 *  sniffdet - A tool for network sniffers detection
 *  Copyright (c) 2002, 2003
 *      Ademar de Souza Reis Jr. <ademar@ademar.org>
 *      Milton Soares Filho <eu_mil@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; version 2 dated
 *  June, 1991.
 *
 * $Id$
 */

/*
 * general use functions
 */

#ifndef __UTIL_H__
#define __UTIL_H__

int drop_root(int uid, int gid);
char **parse_targets_file(FILE *f_hosts);
char **network_ips(char *netmask, char *network);
int free_stringlist(char **list);

#endif
