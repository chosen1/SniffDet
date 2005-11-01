/*
 * $Id: test-config.c,v 1.4 2003/01/22 18:42:12 ademar Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include "sniffdet.h"

struct config_options config;

int main(int argc, char **argv)
{
	// read/parse config file
	if (read_config("../sniffdet.conf")) {
		fprintf(stderr, "Error reading config file %s\n",
				"../sniffdet.conf");
		fprintf(stderr, "Exiting...\n");
		exit(1);
	}

	printf("global:\n");
	printf("iface: %s\n", config.global.iface);

	return 0;
}

