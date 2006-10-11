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

#include <libnet1.h>
#include <pcap.h>
#include <netinet/in.h>
#include "libsniffdet.h"

#define DEFAULT_NUMBER_OF_TRIES 10
#define DEFAULT_SEND_INTERVAL 1000
#define DEFAULT_RECEIVER_HOLD_TO_CANCEL 5

static u_char default_dest_fake_hw_addr[6] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
 * ok, I just don't know what address to use, so, I'm getting the first one
 * ever possible assigned. :)
 * See http://standards.ieee.org/regauth/oui/index.shtml for assigned MAC
 * numbers.
 */
static u_char default_source_fake_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

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


struct arp_thread_data {
	char *host;
	int tries;
	u_char *fakehwaddr;
	user_callback callback;
	struct sndet_device *device;
	unsigned int send_interval; // time betwen sending loops

	u_long iface_ip;
	u_long target_ip;
	u_char *iface_mac;
};

// Modules
static void timeout_handler(int signum);
static void *arptest_sender(void *thread_data);
static void *arptest_receiver(void *thread_data);
static inline int bogus_callback(struct test_status *status, int msg_type,
	char *msg);

// Internal Helpers
static void set_status(struct test_status *st);
static void handle_in_thread_error(user_callback callback, int my_errno,
	char *msg);
	
// Main test thread
int sndet_arptest(char *host,
		struct sndet_device *device,
		unsigned int tmout,
		unsigned int tries,
		unsigned int send_interval, // msec
		user_callback callback,
		struct test_info *info,
		u_char *fakehwaddr)
{
	struct in_addr temp_in_addr;
	struct sigaction sa;
	pthread_t sender_th, receiver_th;
	struct arp_thread_data thdata;
	struct bpf_program bpf;
	struct test_status status = {0, 0, 0};
	char filter[PCAP_FILTER_BUFF_SIZE];

	// reset cancel flag
	cancel_test = 0;

	if (info)
		memset(info, 0, sizeof(struct test_info));

	// set test result information if available
    if (info) {
        info->test_name = "ARP Test (single host)";
        info->code = ARP_TEST;
        info->test_short_desc =
			"Check if target replies a bogus ARP request (with wrong MAC)";
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
	
	if (!tries)
		thdata.tries = DEFAULT_NUMBER_OF_TRIES;
	else
	    thdata.tries = tries;

	if (!send_interval)
		thdata.send_interval = DEFAULT_SEND_INTERVAL;
	else
		thdata.send_interval = send_interval; 


	if (!fakehwaddr)
		thdata.fakehwaddr = default_dest_fake_hw_addr;
	else
		thdata.fakehwaddr = fakehwaddr;

	if (!tmout)
		callback(&status, WARNING, "No timeout set!\n");

#if 0
	// get mac address from interface
	thdata.iface_mac = (u_char *) sndet_get_iface_mac_addr(device, NULL);
#endif
	// I'm using a different approach. If I use my real mac addres, there's
	// a chance that a valid ARP response (due to a valid request generated
	// by the system) triggers my test. So I use a false request MAC address
	// and check a specific response to this packet.
	// Note this is possible because a ARP response is a copy of the request
	// packet with the sender/target fields swaped.
	thdata.iface_mac = default_source_fake_hw_addr;
	
	// get ip address from interface
	temp_in_addr.s_addr = sndet_get_iface_ip_addr(device, NULL);
	thdata.iface_ip = temp_in_addr.s_addr;

	// discover target ip
	thdata.target_ip = sndet_resolve(host);

	// set receiver filter (arp reply from target to us)
	memset(filter, 0, sizeof(filter));

	snprintf(filter, sizeof(filter),
			"arp[6:2] = 2 \
			and arp[18]=%hu and arp[19]=%hu and arp[20]=%hu \
			and arp[21]=%hu and arp[22]=%hu and arp[23]=%hu \
			and src host %s and dst host %s",
			default_source_fake_hw_addr[0],
			default_source_fake_hw_addr[1],
			default_source_fake_hw_addr[2],
			default_source_fake_hw_addr[3],
			default_source_fake_hw_addr[4],
			default_source_fake_hw_addr[5],
			host, inet_ntoa(temp_in_addr));

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
	if (pthread_create(&sender_th, NULL, arptest_sender,
		(void*)&thdata))
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;
		got_error = 1;

		callback(&status, ERROR, "Error launching sender thread");
		goto cleanup;
	}

	// create receiver thread
	if (pthread_create(&receiver_th, NULL, arptest_receiver,
		(void*)&thdata))
	{
		// check for meaningful value in errno
		exit_status = errno ? errno : EAGAIN;

		// signal sender
		got_error = 1;
		pthread_join(sender_th, NULL);
		
		callback(&status, ERROR, "Error launching receiver thread");
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
			
			callback(&status, ERROR, "Error setting timeout handler");
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
		info->test.arp.positive = got_suspect;
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

static void *arptest_sender(void *thread_data)
{
	int i;
	unsigned char *pkt;
	const unsigned int pkt_size = LIBNET_ARP_H + LIBNET_ETH_H;
	struct arp_thread_data *td;
	struct test_status status = {0, 0, 0};

	td = (struct arp_thread_data *) thread_data;

	// initialize packet
	if (libnet_init_packet(pkt_size, &pkt) < 0) {
		handle_in_thread_error(td->callback, errno,
				"Error allocating package [internal]");
		pthread_exit(0);
	}

	// build ethernet frame
	libnet_build_ethernet(
		td->fakehwaddr,  // dest address
		td->iface_mac,   // source address
		ETHERTYPE_ARP,
		NULL, // no payload
		0,    // payload len
		pkt);

	// build arp packet
	libnet_build_arp(
			ARPHRD_ETHER,
			ETHERTYPE_IP,
			6, // HLN - hardware address lenght
			4, // PLN - Protocol address lenght
			ARPOP_REQUEST,
			td->iface_mac,
			(u_char *) &td->iface_ip,
			td->fakehwaddr,
			(u_char *) &td->target_ip,
			NULL,
			0,
			pkt + ETH_H);

	// start sending
	for (i = 0; i < td->tries; i++) {

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

		// wait til next packet
		sndet_sleep(0, td->send_interval * 1000);
	}

	// free resources, close interface
	libnet_destroy_packet(&pkt);

	pthread_exit(0);
}

static void *arptest_receiver(void *thread_data)
{
	struct arp_thread_data *td;
	struct test_status status = {0, 0, 0};
	struct pcap_pkthdr header;
	const u_char *pkt;
	// reading poll structures
	struct timeval read_timeout;
	const int read_timeout_msec = 500;
	int devfd;
	fd_set fds;
	int selret;

	td = (struct arp_thread_data *) thread_data;

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
				cancel_test = td->callback(&status, NOTIFICATION,
						"Somebody replied me");
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
// just to save some lines of code
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
