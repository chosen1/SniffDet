/*
 *  libsniffdet - A library for network sniffers detection
 *  Copyright (c) 2002
 *      Ademar de Souza Reis Jr. <ademar@ademar.org>
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

#ifndef __LIBSNIFFDET_H__
#define __LIBSNIFFDET_H__

#include <stdio.h>
#include <time.h>
#include <netdb.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>

// DEBUG HELPERS
#ifdef DEBUG
#define DEBUG_CODE(p) p
#define DABORT() \
	{ \
		fprintf(stderr, "Aborting at line %d in source file %s\n",\
				__LINE__, __FILE__);\
		abort();\
	}
#else
// no debug ==> empty macros
#define DEBUG_CODE(p)
#define DABORT() \
	{ \
		fprintf(stderr, "There's a bug at line %d in source file %s\n",\
				__LINE__, __FILE__);\
		fprintf(stderr, "Please report it to sniffdet-devel@lists.sourceforge.net\n");\
		abort();\
	}
#endif

#define SNDET_FREE(BUFFER) \
	if (BUFFER != NULL) { \
		free(BUFFER); \
		BUFFER = NULL; \
	} \
	else { \
		DABORT() \
	}


/*
 * CALLBACK DEFINITIONS
 */

struct test_status {
	unsigned short int percent; // 0% to 100%
	unsigned int bytes_sent;
	unsigned int bytes_recvd;
};

// Message type codes
#define RUNNING			0
#define NOTIFICATION	1
#define ERROR			2
#define WARNING			3
#define DETECTION		4
#define ENDING			5

/* TEST CALLBACK
 * It's responsible for messages, warnings, errors and is a mecanism used to
 * cancel the test. If it returns anything != 0, we cancel the test
 */
typedef int (*user_callback)(struct test_status *status,
	int msg_type, char *msg);


/*
 * MODULES GENERAL DEFINITIONS
 */

#define LIBSNIFFDET_MSG_BUF_LEN 2048
#define LIBSNIFFDET_ERR_BUF_LEN 4096
#define PCAP_FILTER_BUFF_SIZE   1024
#define MAX_DEVICE_NAME_LEN      256
#define MAX_CAPTURE_BYTES       2048
// FIXME: is there a RFC for that?
#define MAX_HOSTNAME_LEN         512
#define CAPTURE_READ_TMOUT      1024

/*
 * struct custom_info fields
 */

// - They're ORed inside values_set field when set
//   in the custom_info structure
#define CUSTOM_DMAC           0x1 << 0
#define CUSTOM_SMAC           0x1 << 1
#define CUSTOM_ID             0x1 << 2
#define CUSTOM_TIMESTAMP      0x1 << 3
#define CUSTOM_TTL            0x1 << 4
#define CUSTOM_DEST_IP        0x1 << 5
#define CUSTOM_SRC_IP         0x1 << 6
#define CUSTOM_PROTOCOL	      0x1 << 7
#define CUSTOM_FLAGS          0x1 << 8
#define CUSTOM_SEQ            0x1 << 9
#define CUSTOM_ACK            0x1 << 10
#define CUSTOM_WINSIZE        0x1 << 11
#define CUSTOM_DPORT          0x1 << 12
#define CUSTOM_SPORT          0x1 << 13
#define CUSTOM_PAYLOAD        0x1 << 14

// Packet flags
// These must include TCP/UPD/ICMP flags when needed
#define SNDET_FLAG_SYN        0x1
#define SNDET_FLAG_FIN        0x1 << 1
#define SNDET_FLAG_RST        0x1 << 2

// Protocol definition
#define SNDET_PROTOCOL_TCP    0x1
#define SNDET_PROTOCOL_UDP    0x1 << 1
#define SNDET_PROTOCOL_ICMP   0x1 << 2

struct custom_info {
	int values_set; // defined values ORed

	// ETH
	u_char dmac[6];
	u_char smac[6];

	// IP
	uint id;
	uint timestamp;
	u_char ttl;
	ulong dest_ip;
	ulong source_ip;

	// TCP/UDP
	short protocol; // udp/tcp/icmp
	int flags; // header flags
	uint seq;
	uint ack;
	ushort winsize;
	short dport;
	short sport;
	char *payload;
	short int payload_len; // mandatory if payload is used
};


/* device structure
 */

struct sndet_device {
	char *device;
	int datalink; // datalink type
	int pkt_offset;
	struct libnet_link_int *ln_int;

	pcap_t *pktdesc;
	bpf_u_int32 network;
	bpf_u_int32 netmask;

	// XXX:
	// well... it's not part of the interface, but...
	int rawsock;
};

/* initialize/open device
 * Must be done as root user
 */
struct sndet_device * sndet_init_device(char *device, int promisc, char *errbuf);

/* finish/close device */
int sndet_finish_device(struct sndet_device *device, char *errbuf);


/*
 * STRUCTURES AND DEFINITIONS FOR TESTS
 */

/*
 * Tests enum
 */
enum test_code {
	ICMP_TEST = 0,
	ARP_TEST,
	DNS_TEST,
	LATENCY_TEST,
	MAX_TESTS
};

/*
 * individual strucutes
 */

struct icmptest_result {
	int positive;
};

struct arptest_result {
	int positive;
};

struct dnstest_result {
	int positive;
};

struct latencytest_result {
	// time is expressed in msec/10
	u_int normal_time;
	u_int min_time;
	u_int max_time;
	u_int mean_time;
};

/*
 * Main test structure
 * all test info came here
 */
struct test_info {
	enum test_code code;
	int valid;
	char *test_name;
	char *test_short_desc;
	time_t time_start;
	time_t time_fini;
	unsigned int b_sent;
	unsigned int b_recvd;
	unsigned int pkts_sent;
	unsigned int pkts_recvd;
	union {
		struct icmptest_result icmp;
		struct arptest_result arp;
		struct dnstest_result dns;
		struct latencytest_result latency;
	} test;
};



/*
 * ICMPTEST:
 * tests whether a suspicious host (probably in promiscuous mode)
 * answers an ICMP request that is not addressed (invalid MAC
 * address) to its
 */

/*
 * mandatory:
 *     host, device
 */
int sndet_icmptest(char *host,
		struct sndet_device *device,
		unsigned int tmout, //secs
		unsigned int tries,
		unsigned int send_interval, // msec
		user_callback callback,
		struct test_info *result,
		u_char *fakehwaddr // optional
		);


/*
 * ARPTEST:
 * tests wheter a suspicious host answers an ARP request with a bogus
 * MAC address
 */

/*
 * Mandatory:
 *     host, device
 */
int sndet_arptest(char *host,
		struct sndet_device *device,
		unsigned int tmout, // secs
		unsigned int tries,
		unsigned int send_interval, // msec
		user_callback callback,
		struct test_info *result,
		u_char *fakehwaddr // optional
		);


/*
 * DNSTEST:
 * tests whether a suspicious host tries to resolve an
 * abnormal name.
 */

#define DNS_TEST_PKTS_PER_BURST 5

/*
 * Mandatory:
 *     host, device
 */
int sndet_dnstest(char *host,
		struct sndet_device *device,
		unsigned int tmout, // secs
		unsigned int tries,
		unsigned int send_interval, // msec
		user_callback callback,
		struct test_info *info,

		// bogus pkt information, optional
		u_char *fake_ipaddr, // pkt destination
		u_char *fake_hwaddr, // pkt destination
		ushort dport, ushort sport,
		u_char *payload,
		short int payload_len
		);


/*
 * LATENCY TESTS
 * Measure ICMP response time (ping) in:
 *    - normal situation
 *    - network flooded with bogus packets (invalid MAC address)
 * A host in promiscuous mode will capture the bogus flood and
 * will delay the response because of the higher load.
 */

// single packet flood
int sndet_latencytest_pktflood(char *host,
		struct sndet_device *device,
		unsigned int tmout, // secs
		unsigned int probe_interval, // x10 msec
		user_callback callback,
		struct test_info *info,
		//optional
		struct custom_info *bogus_pkt
		);

// POP session simulation flood
int sndet_latencytest_popflood(char *host,
		struct sndet_device *device,
		unsigned int tmout, // secs
		unsigned int num_bursts,
		unsigned int probe_interval, // msec
		user_callback callback,
		struct test_info *info,

		// optional
		struct custom_info *pop_client_pkt,
		struct custom_info *pop_server_pkt
		);

// Telnet session simulation flood
int sndet_latencytest_telnetflood(char *host,
		struct sndet_device *device,
		unsigned int tmout, // secs
		unsigned int num_bursts,
		unsigned int probe_interval, // msec
		user_callback callback,
		struct test_info *info,

		// optional
		struct custom_info *telnet_client_pkt,
		struct custom_info *telnet_server_pkt
		);

/*
 * HELPER FUNCTIONS
 */


/* resolve hostname, returns binary representation
 * in network-ordered represenation. Hostname is
 * an ASCII string representing an IPv4 address (canonical
 * hostname or doted decimal representation).
 */
u_long sndet_resolve(char *hostname);


/* returns a pseudo random integer
 */
int sndet_random(void);


/* "ping" function
 */
struct sndet_ping_result {
	long pkts_sent;
	long pkts_rcvd;
	long max_time;
	long avg_time;
	long min_time;
};

int sndet_ping_host(
	char *host,
	struct sndet_device *device,
	long tmout, // secs
	long send_interval, // x 0.1 msecs
	unsigned int burst_size,
	struct sndet_ping_result *result,
	char *errmsg);

/* returns interface ip address in binary notation
 * (host-ordered)
 */
u_long sndet_get_iface_ip_addr(struct sndet_device *sndet_dev,
		char *errbuf);

/* return interface MAC address
 */
struct ether_addr * sndet_get_iface_mac_addr(struct sndet_device *sndet_dev,
		char *errbuf);

/* generates a TCP packet based on information supplied in custom_pkt
 * information
 */
unsigned char *sndet_gen_tcp_pkt(struct custom_info *custom_pkt,
		u_char ctrl_flags, int *pkt_len, char *errbuf);

/* independent and portable way for sleeping
 */
void sndet_sleep(long sec, long usec);

#endif // __LIBSNIFFDET_H__
