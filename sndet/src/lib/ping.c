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
 *  $Id: ping.c,v 1.30 2003/07/04 03:31:06 ademar Exp $
 */

/* ping module
 * This file contains ping main routine and subroutines
 */

#undef DEBUG

#include <sys/time.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "libsniffdet.h"

#define DEFAULT_TIMEOUT 5
#define DEFAULT_SEND_INTERVAL 2
#define DEFAULT_BURST_SIZE 5
#define MAX_BURST_SIZE 100

#define PKTLEN_HEADER (LIBNET_ICMP_ECHO_H + LIBNET_IP_H)
#define PKTLEN_PAYLOAD sizeof(struct timeval)
#define PKTLEN_SIZE (PKTLEN_HEADER + PKTLEN_PAYLOAD + 48)
// using same size as in real ping application

// statistic variables
static unsigned long pkts_sent;
static unsigned long pkts_rcvd;
static unsigned long time_accum;
static unsigned long max_time;
static unsigned long min_time;

// control flag
static unsigned short inthread_error;
static unsigned short thread_timeout;

struct ping_th_data {
	struct sndet_device *device;
	long timeout_limit;
	long send_interval;
	unsigned int burst_size;
	char *errmsg;
	/*
	u_long ipsaddr;
	u_long ipdaddr;
	*/
	u_char *pkt;
	u_short my_icmp_id;
};

/* returns difference in 0.1 msecs */
static long ping_sub_tv(struct timeval *first, struct timeval *last);

/* general initializers */
static unsigned char * init_ping_packet(unsigned long ipsaddr,
	unsigned long ipdaddr, char *errmsg);
static int init_ping_filter(struct sndet_device *device,
	unsigned short my_id, char *host, char *errmsg);

/* threads prototypes */
static void *ping_thread_sender(void *arg);
static void *ping_thread_catcher(void *arg);

/* calculates time statistics for icmp echo requests (ping)
 * mandatory: host, device
 * returns non zero if failed
 */
int sndet_ping_host(
	char *host,	
	struct sndet_device *device,
	long tmout, // secs
	long send_interval, // msecs
	unsigned int burst_size,
	struct sndet_ping_result *result,
	char *errmsg)
{
	struct ping_th_data thdata;
	struct timeval current;
	pthread_t sender, catcher;
	
	// mandatory
	if (!host || !device) {
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN,
			"Missing mandatory args");
		return EINVAL;
	}
		
	DEBUG_CODE(printf("sndet_ping_host()\n"));
	DEBUG_CODE(printf("Args: host(%s), tmout(%ld)\n", host, tmout));
	
	// set optional values
	if (tmout <= 0)
		tmout = DEFAULT_TIMEOUT;
	if (send_interval <= 0)
		send_interval = DEFAULT_SEND_INTERVAL;
	if (burst_size == 0)
		burst_size = DEFAULT_BURST_SIZE;
	else
		burst_size = burst_size % MAX_BURST_SIZE;
	
	// reset statistics
	pkts_sent = 0;
	pkts_rcvd = 0;
	time_accum = 0;
	max_time = 0;
	min_time = LONG_MAX;

	// group thread data
	thdata.my_icmp_id = sndet_random() % USHRT_MAX;
	thdata.send_interval = send_interval;
	thdata.burst_size = burst_size;
	/*
	thdata.ipdaddr = sndet_resolve(host);
    thdata.ipsaddr = sndet_get_iface_ip_addr(device, errmsg);
	*/
    thdata.errmsg = errmsg;

	// prepare threads
	DEBUG_CODE(printf("Preparing threads\n"));
	
	if (init_ping_filter(device, thdata.my_icmp_id, host, errmsg))
		return 1;
	
	thdata.device = device;

	thdata.pkt = init_ping_packet(sndet_get_iface_ip_addr(device, errmsg),
		sndet_resolve(host), errmsg);
	
	if (thdata.pkt == NULL) {
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN,
			"Couldn't initialize ping packet");
		return 1;
	}
	
	// start threads
	DEBUG_CODE(printf("Starting threads\n"));

	inthread_error = 0;
	thread_timeout = 0;

	gettimeofday(&current, NULL);
	thdata.timeout_limit = current.tv_sec + tmout;
	
	DEBUG_CODE(printf("MAIN THREAD: limit %ld\n", thdata.timeout_limit));

	pthread_create(&catcher, NULL, ping_thread_catcher, (void *)&thdata);
	pthread_create(&sender, NULL, ping_thread_sender, (void *)&thdata);

	// join threads
	pthread_join(sender, NULL);
	DEBUG_CODE(printf("PING SENDER: finished\n"));
	pthread_join(catcher, NULL); // PTHREAD_CANCELED value
	DEBUG_CODE(printf("PING CATCHER: finished\n"));
	
	// clearing
	// free pkt, flush device ??? etc...
	libnet_destroy_packet(&thdata.pkt);
	
	// sanity check
	if (result) {
		result->pkts_sent = pkts_sent;
		DEBUG_CODE(printf("PING: packets sent(%ld)\n", pkts_sent));
		result->pkts_rcvd = pkts_rcvd;
		DEBUG_CODE(printf("PING: packets rcvd(%ld)\n", pkts_rcvd));
		result->max_time = max_time;
		DEBUG_CODE(printf("PING: max time(%ld)\n", max_time));
		if (pkts_rcvd)
			result->avg_time = time_accum / pkts_rcvd;
		else
			result->avg_time = 0;
		DEBUG_CODE(printf("PING: avg time(%ld)\n", result->avg_time));
		result->min_time = min_time;
		DEBUG_CODE(printf("PING: min time(%ld)\n", min_time));
	}

	return 0;
}

/* Returns the difference in 0.1 milliseconds between time values
 */
static long ping_sub_tv(struct timeval *first, struct timeval *last)
{
	if (last->tv_usec < first->tv_usec) {
		return (last->tv_sec - first->tv_sec - 1)*10000 +
			(1000000 - (first->tv_usec - last->tv_usec))/100;
	} else {
		return ((last->tv_sec - first->tv_sec)*10000) +
			((last->tv_usec - first->tv_usec)/100);
	}
	/* ALTERNATIVE
	if ((out->tv_usec -= first->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= first->tv_sec;
	*/
}

/* Sets the frame for a correct icmp request for the target host
 * return NULL if error
 */
static unsigned char * init_ping_packet(unsigned long ipsaddr,
	unsigned long ipdaddr, char *errmsg)
{
	unsigned char *pkt;
	
	// allocate the packet
	if (libnet_init_packet(PKTLEN_SIZE , &pkt) < 0) {
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN,
			"Error allocating memory to create packet [internal]");
		return NULL;
	}
	
	// setting network layer
	if (libnet_build_ip(
		LIBNET_ICMP_ECHO_H,
		0,
		0, // same as in real ping application
		IP_DF, // don't fragment bit
		64,
		IPPROTO_ICMP,
		ipsaddr,
		ipdaddr,
		NULL,
		0,
		pkt) < 0)
	{
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN,
			"Error allocating memory to create packet [internal]");
		return NULL;
	}

	return pkt;
}

/* Prepares the interface to capture icmp replies from target host
 * return non zero if error
 */
static int init_ping_filter(struct sndet_device *device,
	unsigned short my_id, char *host, char *errmsg)
{
	struct bpf_program bpf;
	char filter[PCAP_FILTER_BUFF_SIZE];

	// set the filter
	memset(filter, 0, sizeof(filter));
	snprintf(filter, sizeof(filter), "%s %d %s %s",
		"icmp[0] = 0 and icmp[4:2] =", my_id, "and src host", host);

	if (pcap_compile(device->pktdesc, &bpf, filter, 0,
		device->netmask) < 0)
	{
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN, "pcap_compile() failed (%s)",
			pcap_geterr(device->pktdesc));
		return -1;
	}

	if (pcap_setfilter(device->pktdesc, &bpf) < 0) {
		snprintf(errmsg, LIBSNIFFDET_ERR_BUF_LEN,
			"pcap_setfilter() failed (%s)",	pcap_geterr(device->pktdesc));
		pcap_freecode(&bpf);
		return -1;
	}
	
	// no need to keep it
	pcap_freecode(&bpf);

	return 0;
}

/* Inserts timestamp and sends the icmp requests to the target
 */
static void *ping_thread_sender(void *arg)
{
	struct ping_th_data *thdata;
	struct timeval currenttime;
	unsigned short my_seq = sndet_random() % USHRT_MAX;
	int i;
	
	DEBUG_CODE(printf("PING SENDER ODD: entering thread\n"));

	thdata = (struct ping_th_data *)arg;
	
	// bypass timeout test in first loop
	currenttime.tv_sec = 0;
	
	/* FIXME: there is a possibility of an administrator changing the system
	 * clock while executing this code */
	while (currenttime.tv_sec <= thdata->timeout_limit) {

		DEBUG_CODE(printf("PING SENDER: time %ld, limit %ld.\n",
			currenttime.tv_sec, thdata->timeout_limit));
		
		// insert timestamp
		DEBUG_CODE(printf("PING SENDER: getting current time\n"));
		if (gettimeofday(&currenttime, NULL) < 0) {
			snprintf(thdata->errmsg, LIBSNIFFDET_ERR_BUF_LEN,
				"gettimeofday failed [internal error]: %s",
				strerror(errno));
			inthread_error = 1;
			pthread_exit(0);
		}
		
		DEBUG_CODE(printf("PING SENDER: Sending request time: %ldsec.%ldusec\n",
			currenttime.tv_sec, currenttime.tv_usec));
		
		memcpy((void *)(thdata->pkt + PKTLEN_HEADER),
			(void *)&currenttime, PKTLEN_PAYLOAD);
		
		// loop for burst size
		for (i=0; i < thdata->burst_size; i++, my_seq++) {
			libnet_build_icmp_echo(
				ICMP_ECHO,
				0, // request
				thdata->my_icmp_id,
				my_seq,
				NULL, // payload,
				0, // PKTLEN_PAYLOAD,
				thdata->pkt + LIBNET_IP_H);

			/* don't need for ip cause we're using raw socket
			 */
			if (libnet_do_checksum(thdata->pkt, IPPROTO_ICMP,
				PKTLEN_SIZE - LIBNET_IP_H) < 0)
			{
				snprintf(thdata->errmsg, LIBSNIFFDET_ERR_BUF_LEN,
					"Error calculating checksum [internal]");
				inthread_error = 1;
				pthread_exit(0);
			}

			DEBUG_CODE(printf("PING SENDER: sending burst packet\n"));
			// put it in the wire
			if (libnet_write_ip(thdata->device->rawsock, thdata->pkt,
				PKTLEN_SIZE) < PKTLEN_SIZE)
			{
				snprintf(thdata->errmsg, LIBSNIFFDET_ERR_BUF_LEN,
					"libnet_write_ip() wrote less bytes than ordered\n");
				inthread_error = 1;
				pthread_exit(0);
			}
		} // end burst loop
		
		DEBUG_CODE(printf("PING SENDER: waiting burst interval\n"));
		sndet_sleep(0, thdata->send_interval * 1000);
		pkts_sent++;
	}

	thread_timeout = 1;

	pthread_exit(0);
}

/* Retrieve timestamps from icmp replies and calculate the statistics
 */
static void *ping_thread_catcher(void *arg)
{
	unsigned char *pkt;
	struct pcap_pkthdr pcap_h;
	struct ping_th_data *th;
	struct timeval senttime, read_timeout;
	const int read_timeout_msec = 500;
	fd_set fds;
	int devfd;
	long difference;
	int selret;
	
	DEBUG_CODE(printf("PING CATCHER: entering thread\n"));
	
	th = (struct ping_th_data *)arg;
	
	devfd = pcap_fileno(th->device->pktdesc);
	
	DEBUG_CODE(printf("PING CATCHER: starting loop\n"));
	
	// this thread runs 'til the main thread requests a cancelation
	while (!inthread_error && !thread_timeout) {
		FD_ZERO(&fds);
		FD_SET(devfd, &fds);

		read_timeout.tv_sec = 0;
		read_timeout.tv_usec = read_timeout_msec * 1000;

		// polls the interface
		selret = select(devfd + 1, &fds, NULL, NULL, &read_timeout);
		
		if (selret < 0) {
			// error
			snprintf(th->errmsg, LIBSNIFFDET_ERR_BUF_LEN,
				"Error polling interface descriptor (select()): %s",
				strerror(errno));
			inthread_error = 1;
			pthread_exit(0);
			
		} else if (!selret) {
			// timed out
			DEBUG_CODE(printf("PING CATCHER: timed out polling interface\n")); 
			continue;
		} else {
			// here you can read
			(const u_char *) pkt = pcap_next(th->device->pktdesc, &pcap_h);
		
			// check if it's the filtered packet or another one
			if (!pkt)
				continue;
			
			// extracts senttime
			memcpy((void *)&senttime,
				(void *)(pkt + th->device->pkt_offset + PKTLEN_HEADER),
				PKTLEN_PAYLOAD);
			
			// calculate statistics (max, min, accum and pkts_rcvd)
			difference = ping_sub_tv(&senttime, &pcap_h.ts);

			DEBUG_CODE(printf("PING CATCHER: "
				"sent time(%ldsecs, %ldusecs), recvd time(%ldsecs, %ldusecs),"
				" difference(%ldx.1 msecs)\n", senttime.tv_sec,
				senttime.tv_usec, pcap_h.ts.tv_sec, pcap_h.ts.tv_usec,
				difference));
			
			time_accum += difference;
			pkts_rcvd++;
			
			if (difference < min_time)
				min_time = difference;
			if (difference > max_time)
				max_time = difference;
		}
	} // end of catching main loop

	pthread_exit(0);
}
