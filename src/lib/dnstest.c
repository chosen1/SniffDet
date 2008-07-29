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
#include <errno.h>
#include <sys/select.h>
#include <pthread.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <netinet/in.h>
#include "libsniffdet.h"

// default values
#define DEFAULT_NUMBER_OF_TRIES 10
#define DEFAULT_SEND_INTERVAL 1000
#define DEFAULT_RECEIVER_HOLD_TO_CANCEL 5
#define DEFAULT_SPORT 23
#define DEFAULT_DPORT 1150 // whatever

// some non meaning values
static u_char default_fake_hwaddr[6] = {0x44, 0x44, 0x44, 0x44, 0x11, 0xff};
static char *default_fake_ipaddr = "10.0.0.21";

// avoid 'simultaneous' calls
pthread_mutex_t callback_mutex;

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

// information passed to threads
struct dns_thread_data {
	char *host;
	struct sndet_device *device;
	int tries;
	unsigned int send_interval; // time betwen sending loops
	user_callback callback;
	u_char *fake_hwaddr;
	u_char *fake_ipaddr;
	ushort sport;
	ushort dport;
	char *payload;
	ushort payload_len;

	u_long iface_ip;
	u_long target_ip;
	u_char *iface_mac;
};

// Modules
static void timeout_handler(int signum);
static void *dnstest_sender(void *thread_data);
static void *dnstest_receiver(void *thread_data);
static inline int bogus_callback(struct test_status *status, int msg_type,
		char *msg);

// Internal Helpers
static void set_status(struct test_status *st);
static void handle_in_thread_error(user_callback callback, int my_errno,
		char *msg);
static int dns_query_search4host(int pkt_offset, const u_char *pkt,
		char *hostdotdecimal, int pkt_len);
static char *string_inversion(char *host);

// Main test thread
int sndet_dnstest(char *host,
		struct sndet_device *device,
		unsigned int tmout,
		unsigned int tries,
		unsigned int send_interval, // msec
		user_callback callback,
		struct test_info *info,

		// bogus pkt information, optional
		u_char *fake_ipaddr, // pkt destination
		u_char *fake_hwaddr, // pkt destination
		ushort dport,
		ushort sport,
		u_char *payload,
		short int payload_len)
{
	struct in_addr temp_in_addr;
	struct sigaction sa;
	pthread_t sender_th, receiver_th;
	struct dns_thread_data thdata;
	struct bpf_program bpf;
	struct test_status status = {0, 0, 0};
	char filter[PCAP_FILTER_BUFF_SIZE];

	// reset cancel flag
	cancel_test = 0;

	if (info)
		memset(info, 0, sizeof(struct test_info));

	// set test_result information if available
	if (info) {
		info->test_name = "DNS Test";
		info->code = DNS_TEST;
		info->test_short_desc =
			"Watch for DNS queries for hostnames who don't exist";
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

	/* optional/default data */

	// timeout
	if (!tmout)
		callback(&status, WARNING, "No timeout set!\n");

	//tries
	if (!tries)
		thdata.tries = DEFAULT_NUMBER_OF_TRIES;
	else
		thdata.tries = tries;

	// send interval
	if (!send_interval)
		thdata.send_interval = DEFAULT_SEND_INTERVAL;
	else
		thdata.send_interval = send_interval;

	// fake_hwaddr
	if (fake_hwaddr)
		thdata.fake_hwaddr = fake_hwaddr;
	else
		thdata.fake_hwaddr = default_fake_hwaddr;

	// fake_ipaddr
	if (fake_ipaddr)
		thdata.fake_ipaddr = fake_ipaddr;
	else
		thdata.fake_ipaddr = default_fake_ipaddr;

	// source port
	if (sport)
		thdata.sport = sport;
	else
		thdata.sport = DEFAULT_SPORT;

	// destination port
	if (dport)
		thdata.dport = dport;
	else
		thdata.dport = DEFAULT_DPORT;

	// tcp payload
	if (payload && payload_len) {
		thdata.payload = payload;
		thdata.payload_len = payload_len;
	}
	else {
		thdata.payload = NULL;
		thdata.payload_len = 0;
	}

	// get mac address from interface
	thdata.iface_mac = (u_char *) sndet_get_iface_mac_addr(device, NULL);

	// get ip address from interface
	temp_in_addr.s_addr = sndet_get_iface_ip_addr(device, NULL);
	thdata.iface_ip = temp_in_addr.s_addr;

	// discover target ip
	if ((thdata.target_ip = sndet_resolve(host)) == 0) {
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;

		set_status(&status);
		callback(&status, ERROR, "Error resolving target hostname");

		goto cleanup;
	}

	// set receiver filter (DNS packet from target host)
	memset(filter, 0, sizeof(filter));
	snprintf(filter, sizeof(filter),
			"udp dst port 53");

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
		callback(&status, ERROR, "Error setting pcap filter [internal]");

		pcap_freecode(&bpf);
		goto cleanup;
	}

	// we don't need it anymore
	pcap_freecode(&bpf);

	// create sender thread
	if (pthread_create(&sender_th, NULL, dnstest_sender,
		(void*) &thdata))
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;
		got_error = 1;

		callback(&status, ERROR, "Error launching sender thread [internal]");
		goto cleanup;
	}

	// create receiver thread
	if (pthread_create(&receiver_th, NULL, dnstest_receiver,
		(void*) &thdata))
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
		info->test.dns.positive = got_suspect;
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

static void *dnstest_sender(void *thread_data)
{
	int i, j;
	struct custom_info bogus_pkt;
	u_char *pkt[DNS_TEST_PKTS_PER_BURST];
	unsigned int pkt_size[DNS_TEST_PKTS_PER_BURST];
	struct dns_thread_data *td;
	struct test_status status = {0, 0, 0};
	unsigned short tcp_id_seq;
	unsigned short tcp_id_ack;
	u_long aux_source_ip;
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];

	td = (struct dns_thread_data *) thread_data;

	/*
	 * simulate a burst with a tcp handshaking
	 */

	/* pkt information */
	tcp_id_seq = (unsigned short) sndet_random() % SHRT_MAX;
	tcp_id_ack = (unsigned short) sndet_random() % SHRT_MAX;

	bogus_pkt.protocol = SNDET_PROTOCOL_TCP;
	memcpy(bogus_pkt.dmac, td->fake_hwaddr, 6);
	memcpy(bogus_pkt.smac, td->iface_mac, 6);

	bogus_pkt.id = (unsigned short) sndet_random() % SHRT_MAX;
	bogus_pkt.ttl = 64;
	bogus_pkt.dest_ip = inet_addr(td->fake_ipaddr);
	bogus_pkt.source_ip = td->iface_ip;

	bogus_pkt.sport = td->sport;
	bogus_pkt.dport = td->dport;
	bogus_pkt.winsize = 0;

	bogus_pkt.payload = td->payload;
	bogus_pkt.payload_len = td->payload_len;

	bogus_pkt.values_set = CUSTOM_PROTOCOL | CUSTOM_DMAC | CUSTOM_SMAC |
		CUSTOM_PAYLOAD | CUSTOM_ID | CUSTOM_TTL | CUSTOM_SRC_IP |
		CUSTOM_DEST_IP | CUSTOM_WINSIZE | CUSTOM_DPORT | CUSTOM_SPORT;

	// build packets

	// SYN
	bogus_pkt.seq = tcp_id_seq;
	bogus_pkt.ack = 0;
	bogus_pkt.values_set += CUSTOM_SEQ | CUSTOM_ACK;
	pkt[0] = sndet_gen_tcp_pkt(&bogus_pkt, TH_SYN,
			&pkt_size[0], errbuf);

	// SYN + ACK
	aux_source_ip = bogus_pkt.source_ip; // temp holding
	bogus_pkt.source_ip = td->iface_ip;
	bogus_pkt.seq = tcp_id_ack;
	bogus_pkt.ack = tcp_id_seq + 1;
	pkt[1] = sndet_gen_tcp_pkt(&bogus_pkt, TH_SYN|TH_ACK,
			&pkt_size[1], errbuf);

	// ACK (connection stablished)
	bogus_pkt.source_ip = aux_source_ip; // return original value
	bogus_pkt.seq = tcp_id_seq + 1;
	bogus_pkt.ack = tcp_id_ack + 1;
	pkt[2] = sndet_gen_tcp_pkt(&bogus_pkt, TH_ACK,
			&pkt_size[2], errbuf);
	bogus_pkt.seq = tcp_id_seq + 1;
	bogus_pkt.ack = tcp_id_ack + 1;
	pkt[3] = sndet_gen_tcp_pkt(&bogus_pkt, TH_ACK,
			&pkt_size[3], errbuf);

	// RESET connection
	bogus_pkt.seq = tcp_id_seq + 1;
	bogus_pkt.ack = tcp_id_ack + 1;
	bogus_pkt.payload = NULL;
	bogus_pkt.payload_len = 0;
	pkt[4] = sndet_gen_tcp_pkt(&bogus_pkt, TH_RST,
			&pkt_size[4], errbuf);

	// start sending
	for (i = 0; i < td->tries; i++) {

		// send a busrt (connection simulation)
		for (j = 0; j < DNS_TEST_PKTS_PER_BURST; j++) {
			if (libnet_write_link_layer(td->device->ln_int,
				td->device->device, pkt[j], pkt_size[j]) < 0)
			{
				handle_in_thread_error(td->callback, errno,
						"Error writing packet to link layer");
				break;
			}

			bytes_sent += pkt_size[j];
			pkts_sent++;
		}

		// signs running information
		pthread_mutex_lock(&callback_mutex);
		sender_percent = (i * 100) / td->tries;
		set_status(&status);
		cancel_test = td->callback(&status, RUNNING, "Sending a packet");
		pthread_mutex_unlock(&callback_mutex);

		// ok to go?
		if (got_suspect || cancel_test || timed_out || got_error)
			break;

		// delay before next burst
		sndet_sleep(0, td->send_interval * 1000);
	}

	// free resources
	for (i = 0; i < DNS_TEST_PKTS_PER_BURST; i++) {
		libnet_destroy_packet(&pkt[i]);
	}

	pthread_exit(0);
}

static void *dnstest_receiver(void *thread_data)
{
	struct dns_thread_data *td;
	struct test_status status = {0, 0, 0};
	struct pcap_pkthdr header;
	const u_char *pkt;
	// reading poll structures
	struct timeval read_timeout;
	const int read_timeout_msec = 500;
	int devfd;
	fd_set fds;
	int selret;

	td = (struct dns_thread_data *) thread_data;

	devfd = pcap_fileno(td->device->pktdesc);

	// keep looping 'til find something or timeouts or the callback
	// signals cancelation (or work forever)
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
				// is that a query for our bogus host?
				if (dns_query_search4host(td->device->pkt_offset, pkt,
							td->fake_ipaddr, header.len)) {
					got_suspect = 1;
					cancel_test = td->callback(&status, NOTIFICATION,
						"Got a response from target");
				} else {
					cancel_test = td->callback(&status, RUNNING,
						"Got a DNS query from target, but it wasn't ours");
				}
				bytes_recvd = header.len;
				pkts_recvd = 1;
				set_status(&status);
			}
			else {
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
	// do nothing :)
	return 0;
}

// just to save lines of code
static void set_status(struct test_status *st)
{
	st->percent = (ushort) sender_percent;
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

// search for a host query inside a dns query packet
static int dns_query_search4host(int pkt_offset, const u_char *pkt,
		char *host_dotdecimal, int pkt_len)
{
	const struct libnet_ip_hdr *ip;
	const struct libnet_udp_hdr *udp;
	const struct libnet_dns_hdr *dns;
	const char *data;
	char names[512];
	char *inverted_host;
	char buffer[MAX_HOSTNAME_LEN];
	int left_bytes = pkt_len;
	int cnt;

	ip  = (const struct libnet_ip_hdr *) (pkt + pkt_offset);
	udp = (const struct libnet_udp_hdr *) (pkt + pkt_offset + LIBNET_IP_H);
	dns = (const struct libnet_dns_hdr *) (pkt + pkt_offset + LIBNET_IP_H +
			LIBNET_UDP_H);
	data = (const char *) (pkt + pkt_offset + LIBNET_IP_H + LIBNET_UDP_H +
			LIBNET_DNS_H);
	left_bytes -= (pkt_offset + LIBNET_IP_H + LIBNET_UDP_H + LIBNET_DNS_H);

	if (!dns->num_q)
		return 0;

	// query domain name size
	// comer, pg476
	cnt = (char) *data;

	if (cnt >= left_bytes) {
		DEBUG_CODE(printf("invalid packet received... ");)
		DEBUG_CODE(printf("%s:%d\n", __FILE__, __LINE__);)
		return 0;
	}

	while (cnt) {
		data++;
		strncat(names, data, cnt);
		data += cnt;
		cnt = (char) *data;
		strncat(names, ".", sizeof(names) - strlen(names));
	}

	names[strlen(names) - 1] = 0x0;

	inverted_host = string_inversion(host_dotdecimal);
	snprintf(buffer, MAX_HOSTNAME_LEN, "%s.in-addr.arpa", inverted_host);
	SNDET_FREE(inverted_host);
	if (strstr(names, buffer)) {
		// found it!
		return 1;
	}
	return 0;
}

// just invert a string
static char *string_inversion(char *string)
{
	char *temp = malloc(sizeof(char) * (strlen(string) + 1));
	int i;
	int j = 0;

	for (i = strlen(string); i >= 0; i--)
		temp[j++] = string[i];
	temp[j] = '\0';

	return temp;
}
