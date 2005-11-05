/*
 * $Id$
 */
#include <stdlib.h>
#include <stdio.h>
#include "sniffdet.h"

struct config_options config;

int main(int argc, char **argv)
{
	if (argc != 2)
		fprintf(stderr, "usage: %s <config_file>\n", argv[0]);

	// read/parse config file
	if (read_config(argv[1])) {
		fprintf(stderr, "Error reading config file %s\n",
				argv[1]);
		fprintf(stderr, "Exiting...\n");
		exit(1);
	}

	printf("global:\n");
	printf("iface: %s\n", config.global.iface);

	return 0;
}
