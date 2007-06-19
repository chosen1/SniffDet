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
#include <lib/libsniffdet.h>
#include "../sniffdet.h"
#include "plugins.h"

static int xml_output(char *target, char *file, struct test_info info[],
		int verbose, char *errbuf);
static int print_icmptest_results(struct test_info info, int verbose);
static int print_arptest_results(struct test_info info, int verbose);
static int print_dnstest_results(struct test_info info, int verbose);
static int print_latencytest_results(struct test_info info, int verbose);
static int print_info_header(struct test_info info, char *errbuf);
static int print_info_result(struct test_info info, char *errbuf);
static char *timeString(time_t t);

// XML file
static FILE *xmlfile;

// pointer to result functions
static int (*print_tests_results[MAX_TESTS + 1]) (struct test_info info,
		int verbose) = {
			print_icmptest_results,
			print_arptest_results,
			print_dnstest_results,
			print_latencytest_results,
			NULL
		};

int test_output(char *target, struct test_info info[],
		struct config_options config, char *errbuf)
{
	return xml_output(target, config.plugins.xml.filename, info,
			config.global.verbose, errbuf);
}

static int xml_output(char *target, char *filename,
		struct test_info info[], int verbose, char *errbuf)
{

	int i = 0;

	xmlfile = fopen(filename, "w+");
	if (xmlfile == NULL) {
		fprintf(stderr, "XML Plugin error\n");
		fprintf(stderr, "Error opening xml output file: %s\n",
				filename);
		perror("");
		return -1;
	}

	fprintf(xmlfile, "<?xml version=\"1.0\"?>\n\n");
	fprintf(xmlfile, "<SNIFFDET-SESSION>\n");
	for (i=0; info[i].code < MAX_TESTS; i++) {
		fprintf(xmlfile, "<info>\n");
		print_info_header(info[i], errbuf);
		print_info_result(info[i], errbuf);
		fprintf(xmlfile, "</info>\n");
	}
	fprintf(xmlfile, "</SNIFFDET-SESSION>");

	return 0;
}

static int print_info_header(struct test_info info, char *errbuf)
{
	fprintf(xmlfile, "\t<name>%s</name>\n", info.test_name);
	fprintf(xmlfile, "\t<description>%s</description>\n",
		info.test_short_desc);
	fprintf(xmlfile, "\t<validation>%s</validation>\n",
		info.valid ? "VALID" : "INVALID");
	fprintf(xmlfile, "\t<start-time>%s</start-time>\n",
		timeString(info.time_start));
	fprintf(xmlfile, "\t<finish-time>%s</finish-time>\n",
		timeString(info.time_fini));
	fprintf(xmlfile, "\t<bytes-sent>%d</bytes-sent>\n", info.b_sent);
	fprintf(xmlfile, "\t<bytes-received>%d</bytes-received>\n",
			info.b_recvd);
	fprintf(xmlfile, "\t<pkts-sent>%d</pkts-sent>\n", info.pkts_sent);
	fprintf(xmlfile, "\t<pkts-received>%d</pkts-received>\n",
		info.pkts_recvd);
	return 0;
}

static int print_info_result(struct test_info info, char *errbuf)
{
	return print_tests_results[info.code](info, 0);
}

static int print_icmptest_results(struct test_info info, int verbose)
{
	fprintf(xmlfile, "\t<result>%s</result>\n",
			info.test.icmp.positive ? "POSITIVE" : "NEGATIVE");

	return info.test.icmp.positive;
}

static int print_arptest_results(struct test_info info, int verbose)
{
	fprintf(xmlfile, "\t<result>%s</result>\n",
			info.test.arp.positive ? "POSITIVE" : "NEGATIVE");
	return info.test.icmp.positive;
}

static int print_dnstest_results(struct test_info info, int verbose)
{
	fprintf(xmlfile, "\t<result>%s</result>\n",
			info.test.dns.positive ? "POSITIVE" : "NEGATIVE");
	return info.test.icmp.positive;
}

static int print_latencytest_results(struct test_info info, int verbose)
{
	// this functions is non-deterministic
	fprintf(xmlfile, "\t<results unit=\"msecs\">\n");
	fprintf(xmlfile, "\t\t<normal>%d.%d</normal>\n",
		info.test.latency.normal_time / 10,
		info.test.latency.normal_time % 10);
	fprintf(xmlfile, "\t\t<minimal>%d.%d</minimal>\n",
		info.test.latency.min_time / 10,
		info.test.latency.min_time % 10);
	fprintf(xmlfile, "\t\t<maximal>%d.%d</maximal>\n",
		info.test.latency.max_time / 10,
		info.test.latency.max_time % 10);
	fprintf(xmlfile, "\t\t<mean>%d.%d</mean>\n",
		info.test.latency.mean_time / 10,
		info.test.latency.mean_time % 10);
	fprintf(xmlfile, "\t</results>\n");
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
