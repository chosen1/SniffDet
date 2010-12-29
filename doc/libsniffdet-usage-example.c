/*
 *  libsniffdet usage example
 *  Copyright (c) 2002-2003
 *      Ademar de Souza Reis Jr. <ademar@ademar.org>
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
 * $Id: libsniffdet-usage-example.c,v 1.1 2003/07/04 04:21:11 ademar Exp $
 */

/* compile with:
 * gcc libsniffdet-usage-example.c -o example `libnet-config \
 *     --defines --libs` -lsniffdet -lpcap -lpthread -g
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <libsniffdet.h>

static int cancel_test_flag;


static int tests_msg_callback(struct test_status *status, 
		const int msg_type, char *msg);
void sighandler(void);
int print_test_result(char *target, struct test_info *info);

int main(int argc, char **argv)
{
	char *iface;
	char *target;
	struct test_info t_info;
	struct sndet_device *device;
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	int status;

	/* blah... use a better scan_args(), this is just an example! :) */
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <interface> <host>\n", argv[0]);
		exit(1);
	}
	iface = argv[1]; /* something like eth0 */
	target = argv[2]; /* something like "localhost.localdomain" or "192.168.1.1" */

	if ((device = sndet_init_device(iface, 1, errbuf)) == NULL) {
		fprintf(stderr, "Error initializing interface %s\n", iface);
		exit(1);
	}

	if (!sndet_resolve(target)) {
		fprintf(stderr, "Cannot resolve target hostname \"%s\"\n", target);
		exit(1);
	}

	/* Could be any signal... SIGINT is just an example! */
	signal(SIGINT, (void *) sighandler);

	/* now we start calling the tests...
	 *
	 * Notice that we call them in sequence using the same t_info structure,
	 * the same print_* function and the same error treatment. Of course
	 * this can be improved, but it's just an example :)
	 */

	/* ICMP TEST */
	/* most of the arguments have default values, so use '0' or 'NULL' */
	status = sndet_icmptest(target,
			device,
			20,  // timeout (secs) -- mandatory (0 means 'until interrupted')
			0,  // tries -- optional
			0, // interval (msecs) -- optional
			tests_msg_callback,
			&t_info,
			NULL); // fake mac address -- optional

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running ICMP test\n");

	cancel_test_flag = 0;

	/* ARP TEST */
	/* most of the arguments have default values, so use '0' or 'NULL' */
	status = sndet_arptest(target,
			device,
			20,  // timeout (secs) -- mandatory (0 means 'until interrupted')
			0,  // tries
			0, // interval (msecs)
			tests_msg_callback,
			&t_info,
			NULL); // fake mac address

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running ARP test\n");

	cancel_test_flag = 0;

	/* DNS TEST */
	status = sndet_dnstest(target,
			device,
			20,  // timeout (secs) -- mandatory (0 means 'until interrupted')
			0,  // tries
			0, // interval (msecs)
			tests_msg_callback,
			&t_info,
			// optional data (packet data)
			NULL, // fake ip
			NULL, // fake mac
			0, // destination port
			0, // source port
			NULL, // payload
			0); // payload len

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running DNS test\n");

	cancel_test_flag = 0;

	/* LATENCY Test */
	status = sndet_latencytest_pktflood(target,
			device,
			300,  // timeout (secs) -- mandatory (0 means 'until interrupted')
			0, // interval between measures (msec)
			tests_msg_callback,
			&t_info,
			NULL); // bogus_pkt

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running Latency test\n");

	if (sndet_finish_device(device, errbuf))
		fprintf(stderr, "Error: %s", errbuf);

	exit(0);
}

static int tests_msg_callback(struct test_status *status, 
		const int msg_type, char *msg)
{
	switch (msg_type) {
		case RUNNING:
			break;
		case NOTIFICATION:
			if (msg != NULL)
				printf("Notification: %s\n", msg);
			break;
		case ERROR:
			if (msg != NULL)
				fprintf(stderr, "Error: %s\n", msg);
			break;
		case WARNING:
			if (msg != NULL)
				fprintf(stderr, "Warning: %s\n", msg);
			break;
		case DETECTION:
			break;
		case ENDING:
			break;
	}

	/* could be a progressbar */
	printf("Percentage: %d%%\n", status->percent);
	printf("Bytes Sent: %d\n", status->bytes_sent);
	printf("Bytes Recvd: %d\n", status->bytes_recvd);

	if (cancel_test_flag) {
		printf("Canceling test\n");
		return 1;
	}
	else
		return 0;
}

/* Signal handler to
 * set the flag "cancel_test_flag" to 1
 */
void sighandler(void)
{
	cancel_test_flag = 1;
}

/* 
 * TEXT INTERFACE 
 * 
 * Based on the stdout plugin from sniffdet 0.8
 *
 */

static int print_icmptest_results(struct test_info *info);
static int print_arptest_results(struct test_info *info);
static int print_dnstest_results(struct test_info *info);
static int print_latencytest_results(struct test_info *info);
static char *timeString(time_t t);

// pointers to print result functions
static int (*print_test_result_table[MAX_TESTS + 1]) (
		struct test_info *info) = {
			print_icmptest_results,
			print_arptest_results,
			print_dnstest_results,
			print_latencytest_results,
			NULL };

int print_test_result(char *target, struct test_info *info)
{
	int result;

	printf("\n");
	printf("------------------------------------------------------------\n");
	printf("Test: %s\n", info->test_name);
	printf("      %s\n", info->test_short_desc);
	printf("------------------------------------------------------------\n");
	printf("Validation: %s\n", info->valid ? "OK" : "INVALID");
	printf("Started on: %s\n", timeString(info->time_start));
	printf("Finished on: %s\n", timeString(info->time_fini)); 
	printf("Bytes Sent: %d\n", info->b_sent);
	printf("Bytes Received: %d\n", info->b_recvd);
	printf("Packets Sent: %d\n", info->pkts_sent);
	printf("Packets Received: %d\n", info->pkts_recvd);
	printf("------------------------------------------------------------\n");
	result = print_test_result_table[info->code](info);
	printf("------------------------------------------------------------\n");
	printf("\n");

	return result;
}


static int print_icmptest_results(struct test_info *info)
{
	printf("RESULT: %s\n",
			info->test.icmp.positive ? "POSITIVE" : "NEGATIVE");
	return info->test.icmp.positive;
}

static int print_arptest_results(struct test_info *info)
{
	printf("RESULT: %s\n",
			info->test.arp.positive ? "POSITIVE" : "NEGATIVE");
	return info->test.icmp.positive;
}

static int print_dnstest_results(struct test_info *info)
{
	printf("RESULT: %s\n",
			info->test.dns.positive ? "POSITIVE" : "NEGATIVE");
	return info->test.icmp.positive;
}

static int print_latencytest_results(struct test_info *info)
{
	printf("RESULT:\n");
	printf("Normal time: %u.%u\n",
			info->test.latency.normal_time / 10,
			info->test.latency.normal_time % 10);
	printf("Flood round-trip min/avg/max: %u.%u/%u.%u/%u.%u ms\n",
				info->test.latency.min_time / 10,
				info->test.latency.min_time % 10,
				info->test.latency.mean_time / 10,
				info->test.latency.mean_time % 10,
				info->test.latency.max_time / 10,
				info->test.latency.max_time % 10
				);

	// this function is non-deterministic
	return 0;
}


/* 
 * timeString()
 * converts a time to a particular representation:
 * "The preferred date and time representation for the current locale"
 */
static char *timeString(time_t t)
{
	static char buffer[64];
	static char timestr[64]; 
    struct tm *local;

    local = localtime(&t);
    strftime(buffer, 64, "%c", local);

	strncpy(timestr, buffer, 64);

    return timestr;
}
