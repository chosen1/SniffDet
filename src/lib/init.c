/*
 *  libsniffdet - A library for network sniffers detection
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

#include <stdlib.h>

// XXX strndup declaration is inside an ifdef __USE_GNU
// glibc-2.2.4
#define __USE_GNU
#include <string.h>
#undef __USE_GNU

#include <pcap.h>
#include <libnet.h>
#include "libsniffdet.h"

/* initialize an interface
 * Basically, do everything which must be done as root, so
 * the program can drop root uid later.
 * It puts the device in promiscuous mode if signaled and
 * returns an sndet_device struct, which is later used in almost any
 * test
 * - Initializes the sndet_device structure, wich must be freed later
 *   by the application;
 * - Error message is returned in errbuf[];
 */
struct sndet_device * sndet_init_device(char *device, int promisc, char *errbuf)
{
	struct sndet_device *sndet_dev;
	char *temp;

	// error buffer for external calls (libnet + libpcap)
	char ext_errbuf[LIBNET_ERRBUF_SIZE | PCAP_ERRBUF_SIZE];

	sndet_dev = malloc(sizeof(struct sndet_device));

	// find the device to open
	// use a default (from libpcap) if the user didn't supply one
	if (device == NULL) {
		temp = pcap_lookupdev(ext_errbuf);
		if (temp == NULL) {
			snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
					"Could not find a link interface!\n%s", ext_errbuf);
			SNDET_FREE(sndet_dev);
			return NULL;
		}
		sndet_dev->device = strndup(temp, MAX_DEVICE_NAME_LEN);
	}
	else
		sndet_dev->device = strndup(device, MAX_DEVICE_NAME_LEN);

	// open interface
	sndet_dev->pktdesc = pcap_open_live(device, MAX_CAPTURE_BYTES,
			promisc, CAPTURE_READ_TMOUT, ext_errbuf);
	if (!sndet_dev->pktdesc) {
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Could not open link interface!\n%s", ext_errbuf);
		SNDET_FREE(sndet_dev->device);
		SNDET_FREE(sndet_dev);
		return NULL;
	}

	if (pcap_lookupnet(sndet_dev->device, &(sndet_dev->network),
			&(sndet_dev->netmask), ext_errbuf) == -1)
	{
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Could not determine netmask/network of interface %s!\n%s",
				sndet_dev->device, ext_errbuf);
		SNDET_FREE(sndet_dev->device);
		SNDET_FREE(sndet_dev);
		return NULL;
	}

	// see net/bpf.h
	// is the datalink supported? (is that an ethernet device?)
	sndet_dev->datalink = pcap_datalink(sndet_dev->pktdesc);
	switch (sndet_dev->datalink) {
		case DLT_EN10MB:
			sndet_dev->pkt_offset = 14;
			break;
		default:
			snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Device %s is not supported! (not an ethernet device?)\n",
				sndet_dev->device);
			SNDET_FREE(sndet_dev->device);
			SNDET_FREE(sndet_dev);
			return NULL;
	}

	// initialize libnet interface
	sndet_dev->ln_int = libnet_open_link_interface(device, ext_errbuf);
	if (!sndet_dev->ln_int) {
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Could not open link interface!\n%s", ext_errbuf);
		SNDET_FREE(sndet_dev->device);
		SNDET_FREE(sndet_dev);
		return NULL;
	}

	// open a raw socket
	sndet_dev->rawsock = libnet_open_raw_sock(IPPROTO_RAW);
	if (sndet_dev->rawsock == -1) {
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN, "Error opening raw socket\n");
		SNDET_FREE(sndet_dev->device);
		SNDET_FREE(sndet_dev);
		return NULL;
	}

	return sndet_dev;
}


/*
 * close interface channel
 * free structure sndet_device
 * close raw socket
 */
int sndet_finish_device(struct sndet_device *device, char *errbuf)
{
	// assertion
	if (!device) {
		DABORT();
	}

	// TODO: check for errors and fill errbuf
	(void) errbuf;

	// close pcap channel
	pcap_close(device->pktdesc);

	// close libnet channel
	libnet_close_link_interface(device->ln_int);

	// close raw socket
	libnet_close_raw_sock(device->rawsock);

	SNDET_FREE(device->device);
	SNDET_FREE(device);

	return 0;
}
