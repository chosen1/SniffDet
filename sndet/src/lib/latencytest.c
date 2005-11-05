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
 *  $Id: latencytests.c,v 1.48 2003/07/04 03:31:06 ademar Exp $
 */

#include <stdlib.h>
#include <limits.h>
#include <libnet.h>
#include <pcap.h>
#include "libsniffdet.h"

#define DEFAULT_PROBE_INTERVAL_TIME 50

// Internal statistics
static unsigned int pkts_sent;
static unsigned int pkts_recvd;
static unsigned int mean_time;
static unsigned int min_time;
static unsigned int max_time;
static unsigned int bytes_sent;
static unsigned int bytes_recvd;

// synchro
static pthread_mutex_t callback_mutex;
static volatile int got_error = 0;
static volatile int finished = 0;
static volatile unsigned int exit_status = 0;

// cancel test flag -- from callback
static volatile int cancel_test;

// threads specific
struct thread_data {
	char *host;
	struct sndet_device *device;
	struct custom_info *bogus_pkt;
	unsigned int tmout;
	unsigned int probe_interval;
	user_callback callback;
};

static struct thread_data tdata;

// prototypes
static void *thread_flooder(void *td);
static void *thread_pinger(void *td);
static inline int bogus_callback(struct test_status *status, int msg_type,
	char *msg);
static int test_bogus_pkt_info(struct custom_info *bogus_pkt);
static struct custom_info *build_default_pkt(struct sndet_device *device);

// Internal Helpers
static void set_status(struct test_status *st);


/* Checks for increase of processing when flooding the wire with packets
 * not related to the suspicious host
 * tmout - time (in seconds) to stay flooding
 * probe_interval - time (in milliseconds) between samples with ping
 * Results are given in usec (max resolution)
 */ 
int sndet_latencytest_pktflood(
		char *host,
		struct sndet_device *device,
		unsigned int tmout, // seconds
		unsigned int probe_interval, // msecs
		user_callback callback,
		struct test_info *info,
		struct custom_info *bogus_pkt)
{
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	struct test_status status = {0, 0, 0};
	struct sndet_ping_result normal_time;
	pthread_t flooder_th, pinger_th;

	// reset cancel flag
	cancel_test = 0;

	/* initialize test status */
	min_time = UINT_MAX;
	max_time = 0;
	mean_time = 0;
	bytes_sent = 0;
	bytes_recvd = 0;
	got_error = 0;
	finished = 0;

	if (info)
		memset(info, 0, sizeof(struct test_info));

	if (info) {
		info->test_name = "Latency test";
        info->code = LATENCY_TEST;
		info->test_short_desc = "Ping response with custom packet flood";
		info->time_start = time(NULL);
	}

	// assertions and like
	if (callback == NULL)
		callback = bogus_callback;
	
	// mandatory
	if (!host || !device) {
		exit_status = errno ? errno : EINVAL;
		callback(&status, ERROR, 
				"Error: invalid args provided to test function [internal error]");

		goto cleanup;
	}

	if (!tmout)
		callback(&status, WARNING, "No timeout set!\n");

	if (!probe_interval)
		probe_interval = DEFAULT_PROBE_INTERVAL_TIME;
	
	/* initialize thread data */
	tdata.host = host;
	tdata.device = device;
	tdata.probe_interval = probe_interval;
	tdata.tmout = tmout;
	tdata.bogus_pkt = bogus_pkt;
	tdata.callback = callback;

	pthread_mutex_init(&callback_mutex, NULL);

	/* calculate normal ping time */
	// TODO set status
	callback(&status, NOTIFICATION, "Checking normal time");
	// FIXME - hardcoded values
	if (sndet_ping_host(host, device, 5, 1000, 1, &normal_time, errbuf)) {
		callback(&status, ERROR, errbuf);
		return -1;
	}

	callback(&status, NOTIFICATION, "Starting network flood");
	/* launch the flooder thread */
	pthread_create(&flooder_th, NULL, thread_flooder, NULL);

	/* launch the periodic ping measurer */
	pthread_create(&pinger_th, NULL, thread_pinger, NULL);
	
	/* wait for execution */
	pthread_join(flooder_th, NULL);
	pthread_cancel(pinger_th);
	pthread_join(pinger_th, NULL);

cleanup:
	if (info) {
		info->valid = exit_status ? 0 : 1;
		info->time_fini = time(NULL);
		info->pkts_sent = pkts_sent;
		info->pkts_recvd = pkts_recvd;
		info->b_sent = bytes_sent;
		info->b_recvd = bytes_recvd;

		// FIXME - include min and max 'normal' time?
		info->test.latency.normal_time = normal_time.avg_time;
		info->test.latency.min_time = min_time;
		info->test.latency.max_time = max_time;
		info->test.latency.mean_time = mean_time;
	}

	status.percent = 100;
	set_status(&status);

	if (got_error) {
		char buff[256];
		snprintf(buff, 256, "Test ended because of an error [%d]",
				exit_status);
		callback(&status, ENDING, buff);
	}
	else 
		callback(&status, ENDING, "Test finished [OK]");

	return exit_status;
}

/* Floods the wire
 */
static void *thread_flooder(void *td)
{
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	unsigned int pktlen;
	struct test_status status = {0, 0, 0};
	u_char *pkt;
	
	// check if a full package was provided
	if (test_bogus_pkt_info(tdata.bogus_pkt)) {
		pkt = sndet_gen_tcp_pkt(tdata.bogus_pkt, 0, &pktlen, errbuf);
	} else {
		pthread_mutex_lock(&callback_mutex);
		// TODO - set status
		tdata.callback(&status, NOTIFICATION, 
				"Using default packet to flood network");
		pthread_mutex_unlock(&callback_mutex);
		tdata.bogus_pkt = build_default_pkt(tdata.device);
		pktlen = LIBNET_TCP_H + LIBNET_IP_H	+ LIBNET_ETH_H +
			tdata.bogus_pkt->payload_len;
		pkt = sndet_gen_tcp_pkt(tdata.bogus_pkt, tdata.bogus_pkt->flags, &pktlen, errbuf);
		
		// no need to keep this
		SNDET_FREE(tdata.bogus_pkt->payload);
		SNDET_FREE(tdata.bogus_pkt);
	}
	
	if (!pkt) {
		pthread_mutex_lock(&callback_mutex);
		// TODO - set status
		tdata.callback(&status, ERROR,
			"Couldn't create packet to flood network [internal]");
		pthread_mutex_unlock(&callback_mutex);
		pthread_exit(0);
	}
		
	// flooding loop
	while (1) {
		bytes_sent += libnet_write_link_layer(tdata.device->ln_int,
			tdata.device->device, pkt, pktlen);
		pkts_sent++;

		if (cancel_test || got_error || finished)
			break;
	}
	
	// free resources
	libnet_destroy_packet(&pkt);

	pthread_exit(0);
}

static void *thread_pinger(void *td)
{
	struct test_status status = {0, 0, 0};
	struct sndet_ping_result ping_result;
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	
	// FIXME - hardcoded args and correct timeout
	if (sndet_ping_host(tdata.host, tdata.device, tdata.tmout, // XXX FIXME
		tdata.probe_interval, 1, &ping_result, errbuf))
	{
		pthread_mutex_lock(&callback_mutex);
		got_error = 1;
		// TODO set status
		tdata.callback(&status, ERROR, errbuf);		
		pthread_mutex_unlock(&callback_mutex);
		pthread_exit(0);
	}

	pkts_recvd += ping_result.pkts_rcvd;
	min_time = ping_result.min_time;
	max_time = ping_result.max_time;

	// notificate
	pthread_mutex_lock(&callback_mutex);
	// TODO set status
	tdata.callback(&status, NOTIFICATION, "Finished icmp echo evaluation");
	pthread_mutex_unlock(&callback_mutex);
	
	mean_time = ping_result.avg_time;

	finished = 1;

	pthread_exit(0);
}

static struct custom_info *build_default_pkt(struct sndet_device *device)
{
	struct custom_info *bogus_pkt;

	// "almost a broadcast" :-)
	u_char fake_hw_addr[6] = {0xff, 0x00, 0x33, 0x67, 0x12, 0x45};

	bogus_pkt = malloc(sizeof(struct custom_info));

	bogus_pkt->values_set = CUSTOM_DMAC | CUSTOM_SMAC | CUSTOM_ID |
		CUSTOM_TTL | CUSTOM_SRC_IP | CUSTOM_DEST_IP | CUSTOM_SEQ |
		CUSTOM_ACK | CUSTOM_FLAGS | CUSTOM_WINSIZE | CUSTOM_DPORT |
		CUSTOM_SPORT | CUSTOM_PAYLOAD;
	
	memcpy(bogus_pkt->dmac, fake_hw_addr, 6);
	memcpy(bogus_pkt->smac, fake_hw_addr, 6);

	bogus_pkt->id = sndet_random();
	bogus_pkt->timestamp = time(NULL);
	bogus_pkt->ttl = 48;
	//bogus_pkt->dest_ip = device->network + (~device->netmask & 0x02020202);
	bogus_pkt->dest_ip = 1611643336; //  200.185.15.96 --> www.yahoo.com.br by now
	bogus_pkt->source_ip = sndet_get_iface_ip_addr(device, NULL);
	//bogus_pkt->source_ip = 2611643336;
	bogus_pkt->protocol = SNDET_PROTOCOL_TCP;
	//bogus_pkt->flags = 0;
	bogus_pkt->flags = TH_SYN;
	bogus_pkt->ack = 0;
	bogus_pkt->winsize = sndet_random() % SHRT_MAX;
	bogus_pkt->dport = 23; // telnet
	bogus_pkt->sport = 23; // telnet
	bogus_pkt->payload = malloc(8);
	bogus_pkt->payload_len = 8;

	return bogus_pkt;
}

static int test_bogus_pkt_info(struct custom_info *bogus_pkt)
{
	int mandatory_fields;

	// sanity check
	if (!bogus_pkt)
		return 0;

	// verify fields integrity
	mandatory_fields = CUSTOM_DMAC | CUSTOM_SMAC | CUSTOM_ID |
	CUSTOM_TTL | CUSTOM_SRC_IP | CUSTOM_DEST_IP | CUSTOM_SEQ |
	CUSTOM_ACK | CUSTOM_FLAGS | CUSTOM_WINSIZE | CUSTOM_DPORT |
	CUSTOM_SPORT | CUSTOM_PAYLOAD;
	
	if (!(bogus_pkt->values_set & mandatory_fields) || 
		(bogus_pkt->protocol != SNDET_PROTOCOL_TCP))
	{
		return 0;
	}

	return 1;
}


// bogus callback
// used if the user didn't supply one (NULL)
static inline int bogus_callback(struct test_status *status, int msg_type,
	char *msg)
{
	// do nothing
	return 0;
}

// just to save some lines of code
static void set_status(struct test_status *st)
{
	st->bytes_sent = bytes_sent;
	st->bytes_recvd = bytes_recvd;
}
