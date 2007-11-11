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
 * $Id$
 */

#include <stdlib.h>
#include <unistd.h>
#include <lib/libsniffdet.h>
#include "../sniffdet.h"
#include "plugins.h"

static int print_icmptest_results(struct test_info info, int verbose);
static int print_arptest_results(struct test_info info, int verbose);
static int print_dnstest_results(struct test_info info, int verbose);
static int print_latencytest_results(struct test_info info, int verbose);
static char *timeString(time_t t);

// pointer to result functions
static int (*print_tests_results[MAX_TESTS + 1]) (
		struct test_info info, int verbose) = {
			print_icmptest_results,
			print_arptest_results,
			print_dnstest_results,
			print_latencytest_results,
			NULL };

int test_output(char *target, struct test_info info[],
		struct config_options config, char *errbuf)
{
	int i = 0;
	int positives = 0;
	int valids = 0;

	// avoid warnings
	(void) errbuf;

	printf("------------------------------------------------------------\n");
	printf("Sniffdet Report\n");
	printf("Generated on: %s\n", timeString(time(NULL)));
	printf("------------------------------------------------------------\n");
	printf("Tests Results for target %s\n", target);
	printf("------------------------------------------------------------\n");
	while (info[i].code != MAX_TESTS) {
		printf("Test: %s\n", info[i].test_name);
		printf("      %s\n", info[i].test_short_desc);
		printf("Validation: %s\n", info[i].valid ? "OK" : "INVALID");
		if (info[i].valid)
			valids++;
		printf("Started on: %s\n", timeString(info[i].time_start));
		printf("Finished on: %s\n", timeString(info[i].time_fini));
		printf("Bytes Sent: %d\n", info[i].b_sent);
		printf("Bytes Received: %d\n", info[i].b_recvd);
		printf("Packets Sent: %d\n", info[i].pkts_sent);
		printf("Packets Received: %d\n", info[i].pkts_recvd);
		printf("------------------------------------------------------------\n");
		positives += print_tests_results[info[i].code]
			(info[i], config.global.verbose);
		printf("------------------------------------------------------------\n");
		printf("\n");

		i++;
	}

	printf("------------------------------------------------------------\n");
	printf("Number of valid tests: #%d\n", valids);
	printf("Number of tests with positive result: #%d\n", positives);
	printf("------------------------------------------------------------\n");
	printf("\n");
	return 0;
}

static int print_icmptest_results(struct test_info info, int verbose)
{
	// avoid warnings
	(void) verbose;

	printf("RESULT: %s\n",
			info.test.icmp.positive ? "POSITIVE" : "NEGATIVE");
	return info.test.icmp.positive;
}

static int print_arptest_results(struct test_info info, int verbose)
{
	// avoid warnings
	(void) verbose;

	printf("RESULT: %s\n",
			info.test.arp.positive ? "POSITIVE" : "NEGATIVE");
	return info.test.icmp.positive;
}

static int print_dnstest_results(struct test_info info, int verbose)
{
	// avoid warnings
	(void) verbose;

	printf("RESULT: %s\n",
			info.test.dns.positive ? "POSITIVE" : "NEGATIVE");
	return info.test.icmp.positive;
}

static int print_latencytest_results(struct test_info info, int verbose)
{
	// avoid warnings
	(void) verbose;

	printf("RESULT:\n");
	printf("Normal time: %u.%u\n",
			info.test.latency.normal_time / 10,
			info.test.latency.normal_time % 10);
	printf("Flood round-trip min/avg/max: %u.%u/%u.%u/%u.%u ms\n",
				info.test.latency.min_time / 10,
				info.test.latency.min_time % 10,
				info.test.latency.mean_time / 10,
				info.test.latency.mean_time % 10,
				info.test.latency.max_time / 10,
				info.test.latency.max_time % 10
				);

	// this functions is non-deterministic
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
