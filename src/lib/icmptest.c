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
#include <stdio.h>
#include <limits.h>
#include <libnet.h>
#include <signal.h>
#include <sys/select.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include "libsniffdet.h"

#define DEFAULT_NUMBER_OF_TRIES 10
#define DEFAULT_SEND_INTERVAL 1000
#define DEFAULT_RECEIVER_HOLD_TO_CANCEL 5

//static u_char default_fake_hw_addr[6] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00};
static u_char default_fake_hw_addr[6] = {0xff, 0x66, 0x66, 0x66, 0x66, 0x66};

// avoid 'simultaneous' calls
static pthread_mutex_t callback_mutex;

// threads flow control
static volatile unsigned int timed_out;
static volatile unsigned int got_suspect;
static volatile unsigned int got_error;
static volatile unsigned int exit_status;

// cancel test flag -- from callback
static volatile int cancel_test;

// These are to calculate test_status.percent
static unsigned int sender_percent; // 0 to 100%
static unsigned int bytes_sent;
static unsigned int bytes_recvd;
static unsigned int pkts_sent;
static unsigned int pkts_recvd;


struct icmp_thread_data {
	char *host;
	int tries;
	unsigned short int my_icmp_id;
	u_char *fakehwaddr;
	user_callback callback;
	struct sndet_device *device;
	unsigned int send_interval; // time betwen sending loops
};

// Modules
static void timeout_handler(int signum);

static void *icmptest_sender(void *thread_data);

static void *icmptest_receiver(void *thread_data);

static inline int bogus_callback(struct test_status *status, int msg_type,
	char *msg);

// Internal Helpers
static void set_status(struct test_status *st);

static void handle_in_thread_error(user_callback callback, int my_errno,
	char *msg);

// Main test thread
int sndet_icmptest(
	char *host,
	struct sndet_device *device,
	unsigned int tmout,
	unsigned int tries,
	unsigned int send_interval, // msec
	user_callback callback,
	struct test_info *info,
	u_char *fakehwaddr)
{
	struct sigaction sa;
	pthread_t sender_th, receiver_th;
	struct icmp_thread_data thdata;
	struct bpf_program bpf;
	struct test_status status = {0, 0, 0};
	char filter[PCAP_FILTER_BUFF_SIZE];

	// reset cancel flag
	cancel_test = 0;

	if (info)
		memset(info, 0, sizeof(struct test_info));

	// set basic information
	if (info) {
		info->test_name = "ICMP Test";
		info->code = ICMP_TEST;
		info->test_short_desc =
			"Check if target replies a bogus ICMP request (wrong MAC)";
		info->time_start = time(NULL);
	}

	if (callback)
		thdata.callback = callback;
	else {
		thdata.callback = bogus_callback;
		callback = bogus_callback;
	}

	// mandatory
	if (!host || !device) {
		exit_status = errno ? errno : EINVAL;
		callback(&status, ERROR,
				"Error: invalid args provided to test function [internal error]");

		goto cleanup;
	}

	// init internals
	timed_out = 0;
	got_suspect = 0;
	got_error = 0;
	exit_status = 0;
	sender_percent = 0;
	bytes_sent = 0;
	bytes_recvd = 0;
	pkts_sent = 0;
	pkts_recvd = 0;

	pthread_mutex_init(&callback_mutex, NULL);

	// fill threads argument structure
	thdata.host = host;
	thdata.device = device;

	if (!tmout)
		callback(&status, WARNING, "No timeout set!\n");

	if (!tries)
		thdata.tries = DEFAULT_NUMBER_OF_TRIES;
	else
		thdata.tries = tries;

	if (!send_interval)
		thdata.send_interval = DEFAULT_SEND_INTERVAL;
	else
		thdata.send_interval = send_interval;


	thdata.my_icmp_id = sndet_random() % SHRT_MAX;

	if (fakehwaddr)
		thdata.fakehwaddr = fakehwaddr;
	else
		thdata.fakehwaddr = default_fake_hw_addr;

	// set receiver filter
	memset(filter, 0, sizeof(filter));
	snprintf(filter, sizeof(filter), "%s %d %s %s",
		"icmp[0] = 0 and icmp[4:2] =", thdata.my_icmp_id, "and src host", host);

	if (pcap_compile(device->pktdesc, &bpf, filter, 0,
		device->netmask) < 0)
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;

		set_status(&status);
		callback(&status, ERROR, "Error compiling pcap filter");

		goto cleanup;
	}

	if (pcap_setfilter(device->pktdesc, &bpf) < 0) {
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;

		set_status(&status);
		callback(&status, ERROR, "Error setting pcap filter");

		pcap_freecode(&bpf);
		goto cleanup;
	}

	// we don't need it anymore
	pcap_freecode(&bpf);

	// create sender thread
	if (pthread_create(&sender_th, NULL, icmptest_sender,
		(void*)&thdata))
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;
		got_error = 1;

		callback(&status, ERROR, "Error launching sender thread [internal]");
		goto cleanup;
	}

	// create receiver thread
	if (pthread_create(&receiver_th, NULL, icmptest_receiver,
		(void*)&thdata))
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;

		// signal sender
		got_error = 1;
		pthread_join(sender_th, NULL);

		callback(&status, ERROR, "Error launching receiver thread [internal]");
		goto cleanup;
	}

	// Setting timeout alarm
	if (tmout) {
		// setting interval
		alarm(tmout);

		// setting handler
		sa.sa_handler = timeout_handler;
		sa.sa_flags = SA_RESETHAND;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGALRM, &sa, NULL) < 0) {
			pthread_mutex_lock(&callback_mutex);
			if (!got_error) {
				got_error = 1;
				// check for meaningful value in errno
				exit_status = errno ? errno : EAGAIN;
			}
			pthread_mutex_unlock(&callback_mutex);
			pthread_join(sender_th, NULL);
			pthread_join(receiver_th, NULL);

			callback(&status, ERROR, "Error setting timeout handler [internal]");
			goto cleanup;
		}
	}

	pthread_join(sender_th, NULL);

	// avoid having a receiver running forever if the callback can't
	// stop it
	if (!tmout && !callback) {
		sndet_sleep(DEFAULT_RECEIVER_HOLD_TO_CANCEL, 0);
		pthread_cancel(receiver_th);
	}

	pthread_join(receiver_th, NULL);

cleanup:

	pthread_mutex_destroy(&callback_mutex);

	// calculate final status, result, error code, etc...
	if (info) {
		info->valid = exit_status ? 0 : 1;
		info->time_fini = time(NULL);
		info->b_sent = bytes_sent;
		info->b_recvd = bytes_recvd;
		info->pkts_sent = pkts_sent;
		info->pkts_recvd = pkts_recvd;
		info->test.icmp.positive = got_suspect;
	}

	sender_percent = 100;
	set_status(&status);
	if (timed_out)
		callback(&status, ENDING, "Test finished [TIMED OUT]");
	else if (exit_status) {
		char buff[256];
		snprintf(buff, 256, "Test ended because of an error [%d]",
				exit_status);
		callback(&status, ENDING, buff);
	}
	else
		callback(&status, ENDING, "Test finished [OK]");

	return exit_status;
}

// timeout called when we receive a SIGALRM
static void timeout_handler(__attribute__((unused)) int signum)
{
	timed_out = 1;
	DEBUG_CODE(printf("DEBUG: Time out ALARM - %s \n", __FILE__););
}

static void *icmptest_sender(void *thread_data)
{
	int i;
	unsigned char *pkt;
	unsigned short int my_seq;
	const unsigned int pkt_size = LIBNET_ICMP_ECHO_H + LIBNET_IP_H +
		LIBNET_ETH_H + 56; // using same payload lenght as in a real ping
	struct icmp_thread_data *td;
	struct test_status status = {0, 0, 0};

	td = (struct icmp_thread_data *)thread_data;

	// starts at an aleatory sequency number
	my_seq = sndet_random() % SHRT_MAX;

	// initialize packet
	if (libnet_init_packet(pkt_size, &pkt) < 0) {
		handle_in_thread_error(td->callback, errno,
				"Error allocating package [internal]");
		pthread_exit(0);
	}

	// filling in the packet
	// TODO - check return values and MAC address

	/* int libnet_build_ethernet(u_char *daddr, u_char *saddr, u_short id,
		const u_char *payload, int payload_s, u_char *buf);
	*/
	libnet_build_ethernet(
		td->fakehwaddr,
		(u_char *) sndet_get_iface_mac_addr(td->device, NULL),
		ETHERTYPE_IP,
		NULL,
		0,
		pkt);

	/*int libnet_build_ip(u_short len, u_char tos, u_short id, u_short frag,
		u_char ttl, u_char prot, u_long saddr, u_long daddr, const u_char
		*payload, int payload_s, u_char *buf);
	*/
	libnet_build_ip(
		LIBNET_ICMP_ECHO_H,
		0,
		0, // same as in real ping application
		IP_DF, // don't fragment bit
		64,
		IPPROTO_ICMP,
		sndet_get_iface_ip_addr(td->device, NULL),
		sndet_resolve(td->host),
		NULL,
		0,
		pkt + LIBNET_ETH_H);


	/*int libnet_build_icmp_echo(u_char type, u_char code, u_short id,
		u_short seq, const u_char *payload, int payload_s, u_char *buf);
	*/
	libnet_build_icmp_echo(
			ICMP_ECHO,
			0,
			td->my_icmp_id,
			my_seq,
			NULL,
			0,
			pkt + LIBNET_IP_H + LIBNET_ETH_H);

	if (libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP,
		LIBNET_IP_H) < 0)
	{
		handle_in_thread_error(td->callback, errno,
				"Error calculating checksum");
		goto sender_cleanup;
	}

	if (libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_ICMP,
		pkt_size - LIBNET_ETH_H - LIBNET_IP_H) < 0)
	{
		handle_in_thread_error(td->callback, errno,
				"Error calculating checksum");
		goto sender_cleanup;
	}

	// start sending
	for (i=0; i < td->tries; i++) {

		// at last send the packet
		if (libnet_write_link_layer(td->device->ln_int,
			td->device->device, pkt, pkt_size) < 0)
		{
			handle_in_thread_error(td->callback, errno,
					"Error sending packet");
			break;
		}

		// signs running information
		pthread_mutex_lock(&callback_mutex);
		sender_percent = (i*100)/td->tries;
		bytes_sent += pkt_size;
		pkts_sent++;
		set_status(&status);
		cancel_test = td->callback(&status, RUNNING, "sending packet");
		pthread_mutex_unlock(&callback_mutex);

		// ok to go?
		if (got_suspect || cancel_test || timed_out || got_error)
			break;

		// increment seq
		libnet_build_icmp_echo(ICMP_ECHO, 0, td->my_icmp_id, ++my_seq,
			NULL, 0, pkt + LIBNET_IP_H + LIBNET_ETH_H);

		if (libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP,
			LIBNET_IP_H) < 0)
		{
			handle_in_thread_error(td->callback, errno,
				"Error calculating checksum");
			break;
		}

		if (libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_ICMP,
			LIBNET_ICMP_ECHO_H) < 0)
		{
			handle_in_thread_error(td->callback, errno,
				"Error calculating checksum");
			break;
		}

		// wait til next packet
		sndet_sleep(0, td->send_interval * 1000);
	}

sender_cleanup:
	libnet_destroy_packet(&pkt);

	pthread_exit(0);
}

static void *icmptest_receiver(void *thread_data)
{
	struct icmp_thread_data *td;
	struct test_status status = {0, 0, 0};
	struct pcap_pkthdr header;
	const u_char *pkt;
	// reading poll structures
	struct timeval read_timeout;
	const int read_timeout_msec = 500;
	int devfd;
	fd_set fds;
	int selret;

	td = (struct icmp_thread_data *)thread_data;

	devfd = pcap_fileno(td->device->pktdesc);

	// keep looping 'til find something or timeouts or the callback
	// signals cancelation or forever...
	while (!got_suspect && !cancel_test && !timed_out && !got_error) {

		FD_ZERO(&fds);
		FD_SET(devfd, &fds);

		read_timeout.tv_sec = 0;
		read_timeout.tv_usec = read_timeout_msec * 1000;

		// polls the interface
		selret = select(devfd + 1, &fds, NULL, NULL, &read_timeout);

		if (selret < 0) {
			//handle_in_thread_error(td->callback, errno,
			//	"Error polling interface");
			// FIXME: call strerror_r()
			DEBUG_CODE(perror("select() "));
			break;
		} else if (!selret) {
			// timed out
			pthread_mutex_lock(&callback_mutex);
			cancel_test = td->callback(&status, RUNNING, NULL);
			pthread_mutex_unlock(&callback_mutex);
			continue;
		} else {
			pkt = pcap_next(td->device->pktdesc, &header);

			// check if it's the filtered packet or another one
			if (!pkt)
				continue;

			pthread_mutex_lock(&callback_mutex);

			if (pkt) {
				got_suspect = 1;
				bytes_recvd = header.len;
				pkts_recvd = 1;
				set_status(&status);
				cancel_test = td->callback(&status, NOTIFICATION, "Somebody replied me");
				// never try to put a break in here again!!! (there is an
				// unlock() below) :)
			} else {
				set_status(&status);
				cancel_test = td->callback(&status, RUNNING, "Waiting for reply");
			}

			pthread_mutex_unlock(&callback_mutex);
		}
	}

	pthread_exit(0);
}

// bogus callback
// used if the user didn't supply one (NULL)
static inline int bogus_callback(
		__attribute__((unused)) struct test_status *status,
		__attribute__((unused)) int msg_type,
		__attribute__((unused)) char *msg)
{
	// do nothing
	return 0;
}

// just to save lines of code
static void set_status(struct test_status *st)
{
	st->percent = (ushort)sender_percent;
	st->bytes_sent = bytes_sent;
	st->bytes_recvd = bytes_recvd;
}

// Commom error handling code inside threads
// just to save code space
static void handle_in_thread_error(user_callback callback, int my_errno,
	char *msg)
{
	struct test_status status = {0, 0, 0};

	// locking mutex ensures both threads won't change the value of
	// exit_status and got_error at the same time
	pthread_mutex_lock(&callback_mutex);
	if (!got_error) {
		// another error already happened
		got_error = 1;
		// check for meaningful value in errno
		exit_status = my_errno ? my_errno : EAGAIN;
	}
	set_status(&status);
	callback(&status, ERROR, msg);
	pthread_mutex_unlock(&callback_mutex);
}
