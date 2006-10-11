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

/* helpers module
 * This file have functions useful for many tests
 */

#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <libnet.h>
#include <pcap.h>
#include "libsniffdet.h"

/* resolve hostname,
 * return IP binary form
 */
u_long sndet_resolve(char *hostname)
{
	struct in_addr inp;
	u_long temp;

	// use inet_aton() just to test if the hostname is
	// in dotted decimal format
	if (inet_aton(hostname, &inp))
		temp = libnet_name_resolve(hostname, 0);
	else
		temp = libnet_name_resolve(hostname, 1);

	/* BOGUS libnet:
	 * it returns -1 on error, but the function returns unsigned long, so
	 * the -1 turns into ULONG_MAX
	 */
	if (temp == ULONG_MAX) {
		return 0;
	} else
		return temp;
}


/* return IP number from an specific interface
 */
u_long sndet_get_iface_ip_addr(struct sndet_device *sndet_dev, char *errbuf)
{
	u_long ip;
	char ext_errbuf[LIBNET_ERRBUF_SIZE | PCAP_ERRBUF_SIZE];

	// assertion
	if (!sndet_dev) {
		DABORT();
	}

	ip = libnet_get_ipaddr(sndet_dev->ln_int,
			sndet_dev->device, ext_errbuf);
	if (!ip) {
		if (errbuf != NULL)
			snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Cannot get IP addres from device \"%s\"\n%s",
				sndet_dev->device, ext_errbuf);
		DABORT();
		return 0;
	}
	return ntohl(ip);

}


/* return mac address from an specific interface
 */
struct ether_addr * sndet_get_iface_mac_addr(struct sndet_device *sndet_dev, char *errbuf)
{
	struct ether_addr *mac;
	struct ether_addr *tmp_mac;
	char ext_errbuf[LIBNET_ERRBUF_SIZE | PCAP_ERRBUF_SIZE];

	// assertion
	if (!sndet_dev) {
		DABORT();
	}

	tmp_mac = libnet_get_hwaddr(sndet_dev->ln_int, sndet_dev->device,
			ext_errbuf);

	if (tmp_mac) {
        mac = (struct ether_addr *) malloc(sizeof(struct ether_addr));
		memcpy(mac, tmp_mac, sizeof(struct ether_addr));
    } else {
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
			"Cannot get HW addres from device \"%s\"\n%s",
			sndet_dev->device, ext_errbuf);
		return NULL;
	}
	return mac;
}


/* pseudo random number generator
 *
 *  TODO: if the host is a linux machine, we could use
 *  the /proc/random interface
 *
 *  Yes, we use a static variable here, but it's not critical and will
 *  not break threaded applications (hopefully) :)
 */
int sndet_random(void)
{
	unsigned int seed;
	static int s_srandom_called = 0;

	if (!s_srandom_called) {
		seed = (unsigned int) time(0) ^ (unsigned int) getpid();
		srandom(seed);
		s_srandom_called = 1;
	}

	srandom((unsigned int) time(NULL));
	return random() % INT_MAX;
}


/* generates a tcp package ready to be inserted in
 * the wire based on custom packet information.
 */
unsigned char *sndet_gen_tcp_pkt(struct custom_info *custom_pkt,
		u_char ctrl_flags, int *pkt_len, char *errbuf)
{
	u_char *pkt;
	int pkt_size;
	ushort urgent_flag = 0;
#ifdef DEBUG
	uint mandatory_fields;

	// assertions
	if (custom_pkt->protocol != SNDET_PROTOCOL_TCP) {
			DABORT();
	}
	mandatory_fields = CUSTOM_DMAC | CUSTOM_SMAC | CUSTOM_PAYLOAD | CUSTOM_ID |
		CUSTOM_TTL | CUSTOM_SRC_IP | CUSTOM_DEST_IP | CUSTOM_SEQ | CUSTOM_ACK |
		CUSTOM_WINSIZE | CUSTOM_DPORT | CUSTOM_SPORT;
	if (!(custom_pkt->values_set & mandatory_fields)) {
		snprintf(errbuf, LIBSNIFFDET_ERR_BUF_LEN,
				"Not all mandantory fields filled\n");
		DABORT();
		return NULL;
	}
#endif

	// init packet
	pkt_size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H +
		custom_pkt->payload_len;
	if (libnet_init_packet(pkt_size, &pkt) < 0) {
		fprintf(stderr, "Memory Allocation error! - libnet_init_packet()");
		DABORT();
	}

	// build full packet
	libnet_build_ethernet(custom_pkt->dmac, custom_pkt->smac, ETHERTYPE_IP,
			NULL, 0, pkt);
	libnet_build_ip(LIBNET_TCP_H + custom_pkt->payload_len, // total len
			0, // tos
			custom_pkt->id,
			0, // frag
			custom_pkt->ttl,
			IPPROTO_TCP,
			custom_pkt->source_ip,
			custom_pkt->dest_ip,
			NULL, // payload
			0, // payload len
			pkt + LIBNET_ETH_H); // buff addr
	libnet_build_tcp(custom_pkt->sport, custom_pkt->dport, custom_pkt->seq,
			custom_pkt->ack, ctrl_flags, custom_pkt->winsize, urgent_flag,
			custom_pkt->payload, custom_pkt->payload_len,
			pkt + LIBNET_IP_H + LIBNET_ETH_H);
	libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
	libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_TCP, LIBNET_TCP_H +
			custom_pkt->payload_len);

	*pkt_len = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H + custom_pkt->payload_len;

	return pkt;
}

/* Portable way for sleeping with subsecond precision
 * Avoids using sleep(), which may be implemented using alarm()
 */
void sndet_sleep(long sec, long usec)
{
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = usec;
	select(1, NULL, NULL, NULL, &tv);
}
