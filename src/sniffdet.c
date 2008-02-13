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
 *  $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <string.h>

#include "config.h"
#include "libsniffdet.h"
#include "sniffdet.h"
#include "log.h"
#include "util.h"

// function prototypes
static int tests_msg_callback(struct test_status *status,
		const int msg_type, char *msg);
static void set_global_defaults(void);
static void scan_args(int argc, char **argv);
static int parse_testnames(char *names);
void sighandler_sigint(void);
static void show_version(void);
static void show_usage(void);
static void show_help(void);

/* static data */
// XXX: use a global structure to hold that?
// XXX: I don't think it's a good idea
static struct arguments args;
static struct snd_tests run_tests;
static int logfd;
struct config_options config;

// global switch used when we want to cancel a test
static int cancel_tests = 0;


/* This is our callback. It receives status notifications from the tests. It
 * can be used to avoid the freezing sensation that we get when running a
 * test for a long time.
 *
 * TODO:
 * - Implement it in a clean, simple and eyecandy way... :-)
 */

static int tests_msg_callback(struct test_status *status,
		const int msg_type, char *msg)
{
#ifdef DEBUG_CALLBACK
	static char *msgs[7] = {
		"RUNNING",
		"NOTIFICATION",
		"ERROR",
		"WARNING",
		"DETECTION",
		"ENDING",
		NULL
	};

	printf("-CB- MSG TYPE: %s\n", msgs[msg_type]);
	if (msg != NULL)
		printf("-CB- Message: %s\n", msg);
	printf("-CB- Percentage: %d%%\n", status->percent);
	printf("-CB- Bytes Sent: %d\n", status->bytes_sent);
	printf("-CB- Bytes Recvd: %d\n", status->bytes_recvd);
#endif

	// avoid warning
	(void) status;

	// just return if we're not using a log
	if (config.global.logtype == LOG_NOLOG)
		return cancel_tests ? 1 : 0;

	// do we have a message?
	if (msg == NULL)
		return cancel_tests ? 1 : 0;

	switch (msg_type) {
		case RUNNING:
			if (config.global.verbose)
				mylog(config.global.logtype, logfd, "%s", msg);
			break;
		case NOTIFICATION:
		case ENDING:
			mylog(config.global.logtype, logfd, "%s", msg);
			break;
		case ERROR:
			mylog(config.global.logtype, logfd, "Error: %s", msg);
			break;
		case WARNING:
			mylog(config.global.logtype, logfd, "Warning: %s", msg);
			break;
	}

	return cancel_tests ? 1 : 0;
}

/* TODO:
 * Our main function is big... We could split it in several little
 * static functions and call them (like the handling of config file,
 * plugins, etc).
 */
int main(int argc, char **argv)
{
	struct test_info t_info[5]; // 4 tests + ending
	struct sndet_device *device;
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	char plugin_path[PATH_MAX];
	int test = 0;
	int i;
	int status;
	char **targets = NULL;
	FILE *f_hosts;

	// output plugin
	void *o_plugin;
	int (*test_output)(char *, struct test_info *, struct config_options, char *);

	// set everything in config struct to NULL (zero)
	memset(&config, 0, sizeof(struct config_options));

	// set default options and general info
	set_global_defaults();

	// scan command line arguments
	scan_args(argc, argv);

	// read/parse config file
	if (read_config(args.configfile)) {
		fprintf(stderr, "Error reading config file %s\n",
				args.configfile);
		fprintf(stderr, "Exiting...\n");
		return 1;
	}

	// scan command line arguments (again to override config file options)
	// TODO: use a better approach
	scan_args(argc, argv);

	// open log file
	if ((config.global.logfilename[0] != '\0') &&
			(config.global.logtype & LOG_USE_FILE)) {
		logfd = open(config.global.logfilename, O_APPEND|O_WRONLY|O_CREAT, 0644);
		if (logfd == -1) {
			fprintf(stderr, "Error opening log file: %s\n",
					config.global.logfilename);
			perror("");
			fprintf(stderr, "Log disabled\n");
			config.global.logfilename[0] = '\0';
		}
	}

	/* TODO:
	 * check geteuid() and warn the user if the file is suid,
	 * since I think it's not a good idea to have sniffdet suid in the
	 * system
	 */
	// running as root?
	//
	if (getuid() != 0) {
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"This program needs root privileges to run!");
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"Exiting...");
		return 1;
	}

	// initialize device(s)
	// (must be root to do that)
	if ((device = sndet_init_device(config.global.iface, 1, errbuf)) == NULL) {
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"Error initializing interface %s", config.global.iface);
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"%s", errbuf);
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"Exiting...");
		return 1;
	}

	mylog(config.global.logtype, logfd,
			"%s", "--- sniffdet session started ---");

	// bump some network info to the log
	{
	struct in_addr net[2];
	char temp_buf[256];

	net[0].s_addr = device->network;
	net[1].s_addr = device->netmask;
	// inet_ntoa() returns a statically buffer, which
	// is overwrited at every call - see manpage
	snprintf(temp_buf, 256, "%s", inet_ntoa(net[1]));

	mylog(config.global.logtype, logfd,
			"NETWORK INFO: device: %s; network: %s (0x%X); netmask: %s (0x%X)",
			device->device, inet_ntoa(net[0]), net[0].s_addr,
			temp_buf, net[1].s_addr);
	}

	// read targets file
	if (args.targetsfile != NULL) {
		f_hosts = fopen(args.targetsfile, "r");
		if (f_hosts == NULL) {
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Error opening targets file: %s", args.targetsfile);
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					strerror(errno));
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Exiting...");
			return 1;
		}
		targets = parse_targets_file(f_hosts);
		if (targets == NULL)
			DABORT();

		fclose(f_hosts);
	}
	else {
		targets = malloc(sizeof (char *) * 2);
		targets[0] = args.target;
		targets[1] = NULL;
	}

	// now we run as some unprivileged user
	if (config.global.UID == 0) {
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"WARNING: Running as root user!");
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"         Check your configuration!");
	}
	else {
		if (config.global.verbose) {
			mylog(config.global.logtype, logfd,
					"Dropping root privileges UID: %d, GID: %d",
					config.global.UID, config.global.GID);
		}
		if (!drop_root(config.global.UID, config.global.GID)) {
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Error dropping privileges");
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Exiting...");
			return 1;
		}
	}

	// open output plugin
	snprintf(plugin_path, PATH_MAX, "%s/%s", config.global.plugins_dir, config.global.plugin);
	if (config.global.verbose) {
		mylog(config.global.logtype, logfd,
			"Opening plugin: %s\n", plugin_path);
	}
	o_plugin = dlopen(plugin_path, RTLD_LAZY);
	if (!o_plugin) {
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Error loading plugin: %s", plugin_path);
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"%s", dlerror());
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Exiting...");
			return 1;
	}
	test_output = dlsym(o_plugin, "test_output");
	if (!o_plugin) {
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Invalid plugin - %s", plugin_path);
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"%s", dlerror());
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Exiting...");
			return 1;
	}

	/* loop to test every target */
	for (i = 0; targets[i] != NULL; i++) {

		/* call tests */
		test = 0;

		if (!sndet_resolve(targets[i])) {
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Warning: Cannot resolve hostname \"%s\" [ignoring host]",
					targets[i]);
			continue;
		}

		// ICMP test
		if (run_tests.icmptest && !cancel_tests) {
			mylog(config.global.logtype, logfd,
					"Calling ICMP Test for %s on %s",
					targets[i], device->device);
			status = sndet_icmptest(targets[i],
					device,
					config.icmptest.timeout, // timeout (secs)
					config.icmptest.tries, // tries
					config.icmptest.interval, // interval (msecs)
					tests_msg_callback,
					&t_info[test++],
					config.icmptest.fake_hwaddr); // fake mac address
			mylog(config.global.logtype, logfd,
					"%s: %s (%d)", "ICMP Test done",
					(status ? "failure" : "sucess"), status);
		}

		// DNS
		if (run_tests.dnstest && !cancel_tests) {
			mylog(config.global.logtype, logfd,
					"Calling DNS Test for %s on %s",
					targets[i], device->device);
			status = sndet_dnstest(targets[i],
					device,
					config.dnstest.timeout, // timeout (secs)
					config.dnstest.tries, // tries
					config.dnstest.interval, // interval (msecs)
					tests_msg_callback,
					&t_info[test++],
					// optional data (packet data)
					config.dnstest.fake_ipaddr, // fake ip
					config.dnstest.fake_hwaddr, // fake mac
					config.dnstest.dport, // destination port
					config.dnstest.sport, // source port
					config.dnstest.payload, // payload
					config.dnstest.payload_len); // payload len
			mylog(config.global.logtype, logfd,
					"%s: %s (%d)", "DNS Test done",
					(status ? "failure" : "sucess"), status);
		}

		// ARP
		if (run_tests.arptest && !cancel_tests) {
			mylog(config.global.logtype, logfd,
					"Calling ARP Test for %s on %s",
					targets[i], device->device);
			status = sndet_arptest(targets[i],
					device,
					config.arptest.timeout, // timeout (secs)
					config.arptest.tries, // tries
					config.arptest.interval, // interval (msecs)
					tests_msg_callback,
					&t_info[test++],
					config.arptest.fake_hwaddr); // fake mac address
			mylog(config.global.logtype, logfd,
					"%s: %s (%d)", "ARP Test done",
					(status ? "failure" : "sucess"), status);
		}

		// LATENCY
		if (run_tests.latencytest && !cancel_tests) {

			mylog(config.global.logtype, logfd,
					"Calling Latency Test for %s on %s",
					targets[i], device->device);

			// TODO/FIXME:
			// build bogus_pkt with defaults
			// (and use as much options as possible from the config file)
			status = sndet_latencytest_pktflood(
					targets[i],
					device,
					config.latencytest.timeout, // timeout (sec)
					// interval between measures (msec)
					config.latencytest.probe_interval,
					tests_msg_callback,
					&t_info[test++],
					NULL); // bogus_pkt

			mylog(config.global.logtype, logfd,
					"%s: %s (%d)", "Latency Test done",
					(status ? "failure" : "sucess"), status);
		}

		// mark the end of tests info structure vector
		t_info[test].code = MAX_TESTS;

		// output tests info/result
		// this comes from a plugin
		if ((*test_output)(targets[i], t_info, config, errbuf))
			mylog(config.global.logtype | LOG_USE_STDERR, logfd,
					"Error: %s", errbuf);

	} // end targets loop

	// close plugin
	dlclose(o_plugin);

	// finish/close our device(s)
	mylog(config.global.logtype, logfd,
			"Closing device %s", device->device);

	if (sndet_finish_device(device, errbuf))
		mylog(config.global.logtype | LOG_USE_STDERR, logfd,
				"Error: %s", errbuf);

	mylog(config.global.logtype, logfd,
			"%s", "--- sniffdet session ended ---\n");

	// close log file
	if (config.global.logfilename[0] != '\0')
		close(logfd);

	// free targets string list
	if (targets != NULL) {
		free_stringlist(targets);
	}

	return 0;
}

/* fill some defaults in the args and global structures */
static void set_global_defaults(void)
{
	snprintf(config.global.iface, MAX_CFG_VAR_SIZE, "%s", "eth0");
	config.global.UID = SNDET_DEFAULT_UID; // just a non meaning number
	config.global.GID = SNDET_DEFAULT_GID; // just a non meaning number
	config.global.verbose = 0;
	config.global.silent = 0;
	config.global.logtype = LOG_NOLOG;
	config.global.logfilename[0] = '\0';
	snprintf(config.global.plugins_dir, MAX_CFG_VAR_SIZE, "%s", SNDET_PLUGINSDIR);
	snprintf(config.global.plugin, MAX_CFG_VAR_SIZE, "%s", "stdout.so");

	snprintf(config.plugins.xml.filename, MAX_CFG_VAR_SIZE, "%s", "tests_result.xml");

	args.target = NULL;
	args.targetsfile = NULL;
	args.configfile = SNDET_CONFIG;

	// no tests by default
	run_tests.dnstest = 0;
	run_tests.icmptest = 0;
	run_tests.arptest = 0;
	run_tests.latencytest = 0;

	// no log by default
	logfd = -1;

	return;
}


/* scan_args()
 * call getopt*() to process the command line arguments
 * passed. Fills a global struct with some info.
 *
 * Notice we call this function a second time after we read the config file
 * (yes, I agree, this is nasty, but it is used to override config options
 * with command line arguments...)
 * TODO: Use a better approach :-)
 */
static void scan_args(int argc, char **argv)
{
	static int pass = 0; // 1 if this function was already called
	int i;
	int mandatory_testname_option = 0;
	int option_index;
	static struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 1000},
		{"verbose", 0, NULL, 'v'},
		{"silent", 0, NULL, 's'},
		{"log", 1, NULL, 'l'},
		{"configfile", 1, NULL, 'c'},
		{"targetsfile", 1, NULL, 'f'},
		{"pluginsdir", 1, NULL, 1001},
		{"plugin", 1, NULL, 'p'},
		{"iface", 1, NULL, 'i'},
		{"test", 1, NULL, 't'},
		{"uid", 1, NULL, 'u'},
		{"gid", 1, NULL, 'g'},
		{0, 0, 0, 0}
	};

	// since we call this function more than once, we
	// have to reset the global variables it has
	if (pass)
		optind = opterr = optopt = 0;

	// set program name
	args.prgname = argv[0];

	while ((i = getopt_long(argc, argv, "hsvl:p:c:f:i:t:u:g:", long_options,
					&option_index)) != EOF) {
		switch (i) {
			case 'h':
				show_help();
				exit(0);
				break;
			case 'v':
				config.global.verbose = 1;
				break;
			case 's':
				config.global.silent = 1;
				break;
			case 'l':
				config.global.logtype |= LOG_USE_FILE;
				snprintf(config.global.logfilename, MAX_CFG_VAR_SIZE, "%s", optarg);
				break;
			case 1001:
				snprintf(config.global.plugins_dir, MAX_CFG_VAR_SIZE, "%s", optarg);
				break;
			case 'p':
				snprintf(config.global.plugin, MAX_CFG_VAR_SIZE, "%s", optarg);
				break;
			case 'i':
				snprintf(config.global.iface, MAX_CFG_VAR_SIZE, "%s", optarg);
				break;
			case 'u':
				config.global.UID = atoi(optarg);
				break;
			case 'g':
				config.global.GID = atoi(optarg);
				break;
			case 'c':
				if (pass)
					break;
				args.configfile = strdup(optarg);
				break;
			case 'f':
				if (pass)
					break;
				args.targetsfile = strdup(optarg);
				break;
			case 't':
				if (pass)
					break;
				mandatory_testname_option = 1;
				if (parse_testnames(optarg) == 0) {
					fprintf(stderr, "Error: Invalid test required!\n");
					show_usage();
					exit(-1);
				}
				break;
			case 1000:
				show_version();
				exit(0);
				break;
			case '?': /* invalid argument */
				show_usage();
				exit(-1);
		}
	}

	if (pass)
		return;

	if (!mandatory_testname_option) {
		fprintf(stderr, "Error: No tests to perform!\n");
		show_usage();
		exit(-1);
	}

	/* get target */
	if (optind < argc) {
		args.target = strdup(argv[optind]);
	}
	else {
		if (args.targetsfile == NULL) { // not using a targetsfile destination
			fprintf(stderr, "Error: No destination target!\n");
			show_usage();
			exit(-1);
		}
	}

	// set pass to 1 (to inform we already called this function)
	pass = 1;
}


/* look for tests to perform in a string
 * and set the run_tests flag
 *
 * TODO:
 * Use an approach like the one in the config_file module, where we have a
 * structure with all strings and handlers for them. It would be easier to
 * add new tests using that approach.
 */
static int parse_testnames(char *names)
{
	int count = 0;

	if (strstr(names, "dns")) {
		run_tests.dnstest = 1;
		count++;
	}
	if (strstr(names, "icmp")) {
		run_tests.icmptest = 1;
		count++;
	}
	if (strstr(names, "arp")) {
		run_tests.arptest = 1;
		count++;
	}
	if (strstr(names, "latency")) {
		run_tests.latencytest = 1;
		count++;
	}

	return count;
}

/* Copyrigth notice and release
 */
static void show_version(void)
{
	printf("sniffdet %s\n", PACKAGE_VERSION);
	printf("A Remote Sniffer Detection Tool\n");
	printf("Copyright (c) 2002\n");
	printf("   Ademar de Souza Reis Jr. <myself@ademar.org>\n");
	printf("   Milton Soares Filho <eu_mil@yahoo.com>\n");
}


/* Helps the user about the syntax of calling this program
 */
static void show_usage(void)
{
	fprintf(stderr, "Usage: %s [options] TARGET\n", args.prgname);
	fprintf(stderr, "try '%s --help' for more information\n", args.prgname);
}


/* Helps the user about how to call this program
 */
static void show_help(void)
{
	show_version();
	printf("Usage: %s [options] TARGET\n", args.prgname);
	printf("  Where:\n");
	printf("  TARGET is a canonical hostname or a dotted decimal IPv4 address\n");
	printf("\n");
	printf("  -i  --iface=DEVICE     Use network DEVICE interface for tests\n");
	printf("  -c  --configfile=FILE  Use FILE as configuration file\n");
	printf("  -l  --log=FILE         Use FILE for tests log\n");
	printf("  -f  --targetsfile=FILE Use FILE for tests target\n");
	printf("      --pluginsdir=DIR   Search for plugins in DIR\n");
	printf("  -p  --plugin=FILE      Use FILE plugin\n");
	printf("  -u  --uid=UID          Run program with UID (after dropping root)\n");
	printf("  -g  --gid=GID          Run program with GID (after dropping root)\n");
	printf("\n");
	printf("  -t  --test=[testname]  Perform specific test\n");
	printf("      Where [testname] is a list composed by:\n");
	printf("        dns         DNS test\n");
	printf("        arp         ARP response test\n");
	printf("        icmp        ICMP ping response test\n");
	printf("        latency     ICMP ping latency test\n");
	printf("\n");
	printf("  -s  --silent           Run in silent mode (no output, only call plugin with results)\n");
	printf("  -v  --verbose          Run in verbose mode (extended output)\n");
	printf("  -h, --help             Show this help screen and exit\n");
	printf("      --version          Show version info and exit\n");
	printf("\n");
	printf("Defaults:\n");
	printf("    Interface: \"eth0\"\n");
	printf("    Log file: \"sniffdet.log\"\n");
	printf("    Config file: \"%s\"\n", SNDET_CONFIG);
	printf("    Plugins Directory: \"%s\"\n", SNDET_PLUGINSDIR);
	printf("    Plugin: \"stdout.so\"\n");
	printf("\n");
	printf("You have to inform at least one test to perform\n");
}
