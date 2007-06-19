/*
 *  sniffdet - A tool for network sniffers detection
 *  Copyright (c) 2002
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
 *  $Id$
 */

#ifndef __SNIFFDET_H__
#define __SNIFFDET_H__

#ifndef __LIBNET_H
#include <libnet.h>
#endif

/* comand line arguments
 * Notice that some comand line arguments are part of
 * global_options structure. The ones here are not
 * configuration options.
 */
struct arguments {
	char *prgname;
	char *configfile;
	char *targetsfile;
	char *target;
};

/* struct with general options
 * They're read from config file or came from comand line
 * arguments
 */
#define MAX_CFG_VAR_SIZE 128
#define MAX_CFG_BIG_VAR_SIZE 1024

/* if you change some type here, remember
 * to also change the handler for the config file..
 * *really* weird things can happen if you forget that because of the
 * variable's size
 *
 * You have been warned :-)
 */
struct config_options {
	// global options
	struct {
		int verbose;
		int silent;
		unsigned int logtype;
		char logfilename[MAX_CFG_VAR_SIZE];
		char plugins_dir[MAX_CFG_VAR_SIZE];
		char plugin[MAX_CFG_VAR_SIZE];
		int UID;
		int GID;
		char iface[MAX_CFG_VAR_SIZE];
		u_char fake_hwaddr[6];
		u_char fake_ipaddr[MAX_CFG_VAR_SIZE];
	} global;

	// icmptest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		u_char fake_hwaddr[6];
	} icmptest;

	// arptest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		u_char fake_hwaddr[6];
	} arptest;

	// dnstest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		unsigned short int dport;
		unsigned short int sport;
		u_char fake_hwaddr[6];
		u_char fake_ipaddr[MAX_CFG_VAR_SIZE];
		unsigned char *payload;
		unsigned short int payload_len;
	} dnstest;

	// latencytest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int probe_interval;
		unsigned int tcpflags;
	} latencytest;

	// plugins options
	struct {
		struct {
			char filename[MAX_CFG_VAR_SIZE];
		} xml;
	} plugins;
};

/* TCP Flags that we use
 * We wrapp the libnet definitions here
 */
#define TCP_FLAG__SYN    TH_SYN
#define TCP_FLAG__FIN    TH_FIN
#define TCP_FLAG__RST    TH_RST
#define TCP_FLAG__PUSH   TH_PUSH
#define TCP_FLAG__ACK    TH_ACK
#define TCP_FLAG__URG    TH_URG

// tests to run
// 1 --> run
// 0 --> don't run :)
struct snd_tests {
	short int dnstest;
	short int icmptest;
	short int arptest;
	short int latencytest;
};

int read_config(char *filename);

#endif // __SNIFFDET_H__
