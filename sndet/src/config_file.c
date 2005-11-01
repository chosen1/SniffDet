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
 *  $Id: config_file.c,v 1.15 2003/04/27 19:19:46 mil Exp $
 */

/* HOW IT WORKS:
 *
 * We first create a structure with all section names. This structe will be
 * used inside a loop after a section name is get from the config file.
 * Every section name also needs a "state" or a "ID" value, which is inside
 * an enum.
 *
 * Then we create a big structure with all possible variable names inside
 * all sections. In this structure, we have pointers to functions
 * responsible to get that kind of value (int, string, mac address, etc). It
 * also has a pointer to the config file structure, which is the place
 * where we hold the configuration (it's visible by the application).
 *
 * If a section cannot have such a varname, then its pointer to the
 * config file structure is set to NULL. When we find a variable name, we
 * call it's handler, which then checks if the config structure pointer is
 * not NULL. If it is, then we found a syntax error.
 *
 * Both structures are NULL terminated (or -1 in case of an int).
 *
 * With that approach, you don't have to worry about modifying the
 * algorithms to add new sections or variable names. You just have to add
 * new variables to the structures.
 */

/* TODO:
 * - There are some variables to parse, like payload and tcpflags
 * - We should check for error and treat them in all places. The way it is
 *   now, if we find a syntax error, we eventually return, but not imediately.
 * - We could change the application to accept individual interfaces in a
 *   per test basis. The way it works now, we can use only one interface for
 *   all tests.
 */

#ifdef DEBUG
#warning "************************************************"
#warning "Disabling DEBUG for config_file module mannually"
#warning "************************************************"
#undef DEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>

#include "lib/libsniffdet.h"
#include "sniffdet.h"
#include "log.h"

#define BUFF_SIZE 1024

// sections
#define CFG_NUMBER_OF_SECTIONS 6 // Remember to increase that if you add a section!
#define CFG_SECTION_GLOBAL "global"
#define CFG_SECTION_ICMPTEST "icmptest"
#define CFG_SECTION_ARPTEST "arptest"
#define CFG_SECTION_DNSTEST "dnstest"
#define CFG_SECTION_LATENCYTEST "latencytest"
#define CFG_SECTION_PLUGINS "plugins"

/* state / ID
 */
enum section_state {
	READING_GLOBAL = 0,
	READING_ICMPTEST,
	READING_ARPTEST,
	READING_DNSTEST,
	READING_LATENCYTEST,
	READING_PLUGINS
};

/* variable names
 */
#define CFG_VAR_VERBOSE "verbose"
#define CFG_VAR_LOGTYPE "logtype"
#define CFG_VAR_LOGFILENAME "logfilename"
#define CFG_VAR_PLUGINS_DIR "plugins_dir"
#define CFG_VAR_PLUGIN "plugin"
#define CFG_VAR_UID "UID"
#define CFG_VAR_GID "GID"
#define CFG_VAR_IFACE "iface"

#define CFG_VAR_TIMEOUT "timeout"
#define CFG_VAR_TRIES "tries"
#define CFG_VAR_INTERVAL "interval"
#define CFG_VAR_FAKE_HWADDR "fake_hwaddr"
#define CFG_VAR_FAKE_IPADDR "fake_ipaddr"
#define CFG_VAR_DPORT "dport"
#define CFG_VAR_SPORT "sport"
#define CFG_VAR_FAKE_SRC_IPADDR "fake_src_ipaddr"
#define CFG_VAR_FAKE_DST_IPADDR "fake_dst_ipaddr"
#define CFG_VAR_TCPFLAGS "tcpflags"
#define CFG_VAR_PAYLOAD "payload"

#define CFG_VAR_XMLPLUGIN_FILENAME "xmlplugin_filename"

// structure to handle sections
struct config_section_t {
	char *section_name;
	enum section_state section_id;
};

// structure to handle sections variables
struct config_variables_t {
	char *var_name;
	int (*var_handler)(struct config_variables_t *self, 
			enum section_state state);
	void *var[CFG_NUMBER_OF_SECTIONS];
};


// parser variables
extern struct config_options config;
static char *f_name;
static FILE *conf_file;
static char line_buffer[BUFF_SIZE];
static int line;
static int eof;
static int error_syntax;

/* TODO:
 * these two functions could be merged */
static int parse_section(void);
static int read_section(enum section_state section_id);

/* general use functions */
static void syntax_error(const char *format, ...);
static void get_line(void);

/* these functions return a name of a variable or a section */
static char *get_var_name(void);
static char *get_section(void);

/*
 * get functions are used to retrieve a value for a variable
 */

static int get_string(struct config_variables_t *self,
		enum section_state state);

static int get_logtype(struct config_variables_t *self,
		enum section_state state);

static int get_int(struct config_variables_t *self,
		enum section_state state);

static int get_ushort_int(struct config_variables_t *self,
		enum section_state state);

static int get_mac(struct config_variables_t *self,
		enum section_state state);

static int get_ip(struct config_variables_t *self,
		enum section_state state);

static int get_tcpflags(struct config_variables_t *self,
		enum section_state state);

static int get_payload(struct config_variables_t *self,
		enum section_state state);

/* this is the structure with section names */
const static struct config_section_t config_section[] = {
	{ CFG_SECTION_GLOBAL,		READING_GLOBAL },
	{ CFG_SECTION_ICMPTEST,		READING_ICMPTEST },
	{ CFG_SECTION_ARPTEST,		READING_ARPTEST },
	{ CFG_SECTION_DNSTEST,		READING_DNSTEST },
	{ CFG_SECTION_LATENCYTEST,	READING_LATENCYTEST },
	{ CFG_SECTION_PLUGINS,		READING_PLUGINS },
	{ NULL,						-1 },
};

/* Here it comes... That structure has pointers to the config file structure
 * field and for the variable handlers. The field pointer is set to NULL if
 * a respective section doesn't allow such a varname.
 */

/* WARNING:
 * BE CAREFUL!!!
 * Specially about the handler... It's not very smart and will destroy your
 * memory arrangement if trying to read something bigger or smaller than what
 * it really is.
 */
const static struct config_variables_t config_vars[] = {
	{ CFG_VAR_VERBOSE,			get_int,
		{ &(config.global.verbose),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL 
		}
	},
	{ CFG_VAR_LOGTYPE, 			get_logtype,
		{ &(config.global.logtype),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_LOGFILENAME, 		get_string,
		{ &(config.global.logfilename),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_PLUGINS_DIR,		get_string,
		{ &(config.global.plugins_dir),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL 
		}
	},
	{ CFG_VAR_PLUGIN,			get_string,
		{ &(config.global.plugin),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}	
	},
	{ CFG_VAR_UID,				get_int,
		{ &(config.global.UID),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_GID,				get_int,
		{ &(config.global.GID),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_IFACE, 			get_string,
		{ &(config.global.iface),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
// TODO
#if 0
			&(config.icmptest.iface),
			&(config.arptest.iface),
			&(config.dnstest.iface),
			&(config.latencytest.iface)
#endif
		}
	},
	{ CFG_VAR_TIMEOUT, 			get_int,
		{ NULL,
			&(config.icmptest.timeout),
			&(config.arptest.timeout),
			&(config.dnstest.timeout),
			&(config.latencytest.timeout),
			NULL
		}
	},

	{ CFG_VAR_TRIES, 			get_int,
		{ NULL,
			&(config.icmptest.tries),
			&(config.arptest.tries),
			&(config.dnstest.tries),
			NULL,
			NULL
		}
	},
	{ CFG_VAR_INTERVAL, 		get_int,
		{ NULL,
			&(config.icmptest.interval),
			&(config.arptest.interval),
			&(config.dnstest.interval),
			&(config.latencytest.probe_interval),
			NULL
		}
	},
	{ CFG_VAR_FAKE_HWADDR, 		get_mac,
		{ &(config.global.fake_hwaddr),
			&(config.icmptest.fake_hwaddr),
			&(config.arptest.fake_hwaddr),
			&(config.dnstest.fake_hwaddr),
			NULL,
			NULL
		}
	},
	{ CFG_VAR_FAKE_IPADDR, 		get_ip,
		{ &(config.global.fake_ipaddr),
			NULL,
			NULL,
			&(config.dnstest.fake_ipaddr),
			NULL,
			NULL
		}
	},
	{ CFG_VAR_DPORT, 			get_ushort_int,
		{ NULL,
			NULL,
			NULL,
			&(config.dnstest.dport),
			NULL,
			NULL
		}
	},
	{ CFG_VAR_SPORT, 			get_ushort_int,
		{ NULL,
			NULL,
			NULL,
			&(config.dnstest.sport),
			NULL,
			NULL
		}
	},
	{ CFG_VAR_FAKE_SRC_IPADDR,	get_ip,
		{ NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_FAKE_DST_IPADDR,	get_ip,
		{ NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_TCPFLAGS,			get_tcpflags,
		{ NULL,
			NULL,
			NULL,
			NULL,
			&(config.latencytest.tcpflags),
			NULL
		}
	},
	{ CFG_VAR_PAYLOAD,			get_payload,
		{ NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
	{ CFG_VAR_XMLPLUGIN_FILENAME,	get_string,
		{ NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			&(config.plugins.xml.filename)
		}
	},
	{ NULL,						NULL,
		{ NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		}
	},
};

int read_config(char *filename)
{
	int status;
	f_name = filename;

	conf_file = fopen(filename, "r");
	if (conf_file == NULL) {
		return 0;
	}

	line = 0;
	eof = 0;
	error_syntax = 0;

	DEBUG_CODE(printf("***\n");)
	DEBUG_CODE(printf("*** config_options struct size: %d\n",
				sizeof(struct config_options));)
	DEBUG_CODE(printf("***\n");)

	status = parse_section();

	return (error_syntax || status);
}

/*
 * Parse a section of the config file
 * sections must be a word and the values are inside brackets {}
 */
static int parse_section(void)
{
	char *section;
	int i = 0;

	while ((section = get_section()) != NULL) {

		i = 0;
		while ((config_section[i].section_name) != NULL) {
			if (!strcmp(section, config_section[i].section_name)) {
				DEBUG_CODE(printf("reading %s\n", section);)
				read_section(config_section[i].section_id);
				break;
			}
			i++;
		}

		if ((config_section[i].section_name) == NULL) {
			syntax_error("invalid section name: \"%s\"\n", section);
			return 1;
		}
	}

	return 0;
}

static char *get_section(void)
{
	int i = 0;
	static char section[MAX_CFG_VAR_SIZE];

	(void) get_line();

	if (eof)
		return NULL;

	while (line_buffer[i] != ' ' && line_buffer[i] != '\t' &&
			line_buffer[i] != '{' && line_buffer[i] != '\0' &&
			line_buffer[i] != '#') {
		section[i] = line_buffer[i];
		i++;
	}

	if (i == 0) {
		syntax_error("expecting section name, found \"%s\"\n",
				&(line_buffer[i]));
		return NULL;
	}

	section[i] = '\0';

	return section;
}

static int read_section(enum section_state section_id)
{
	int i;
	char *var_name;

	(void) get_line();

	while (line_buffer[0] != '}') {

		if ((var_name = get_var_name()) == NULL) {
			return 1;
		}

		i = 0;
		while ((config_vars[i].var_name) != NULL) {
			if (!strcmp(var_name, config_vars[i].var_name)) {
				DEBUG_CODE(printf("\treading %s\n", var_name);)
				// it generates a warning... ignore it?
				config_vars[i].var_handler(&(config_vars[i]), section_id);
				break;
			}
			i++;
		}

		if ((config_vars[i].var_name) == NULL) {
			syntax_error(
					"variable name not recognized in this section: \"%s\"\n",
					var_name);
			return 1;
		}

		(void) get_line();
		if (eof) {
			syntax_error("found EOF while searching variable name\n");
			return 1;
		}
	}

	// OK
	return 0;
}

static char *get_var_name(void)
{
	int i = 0;
	int j = 0;
	static char var_name[MAX_CFG_VAR_SIZE];

	// skip initial blank spaces
	while ((line_buffer[i] == ' ') || (line_buffer[i] == '\t'))
		i++;

	// copy name until a space or a '='
	while ((line_buffer[i] != ' ') && (line_buffer[i] != '=')) {
		var_name[j] = line_buffer[i];
		i++;
		j++;
	}
	
	var_name[j] = '\0';

	return var_name;
}



/*
 * FIXME/TODO:
 * Support string with escape chars:
 * Format: "xxx". Uses '\' as escape character:
 *  \" --> "
 *  \\ --> \
 */
static int get_string(struct config_variables_t *self, enum section_state state)
{
	int i = 0;
	int j = 0;
	char *string_value = (char *) self->var[state];

	if (string_value == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}


	// skip initial blank spaces and the name of the var itself
	while (line_buffer[i++] != '"')
		;

	// copy name until a '"' 
	while (line_buffer[i] != '"') {
		string_value[j] = line_buffer[i];
		i++;
		j++;
		// we reached the end of the buffer... Ops
		if (i - 2 == MAX_CFG_VAR_SIZE) {
			syntax_error("variable value to big to fit in buffer\n"); 
			return -1;
		}
	}

	string_value[j] = '\0';
	DEBUG_CODE(printf("\t\tvalue: %s\n", string_value);)

	return 0;
}

static int get_int(struct config_variables_t *self, enum section_state state)
{
	int *var = (int *) self->var[state];
	int i = 0;

	if (var == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}

	// skip initial blank spaces and the name of the var itself
	while (line_buffer[i++] != '=')
		;

	sscanf((&line_buffer[i]), "%d", var);
	DEBUG_CODE(printf("\t\tvalue: %d\n", *var);)

	return 0;
}

static int get_ushort_int(struct config_variables_t *self,
		enum section_state state)
{
	unsigned short int *var = (unsigned short int *) self->var[state];
	int i = 0;

	if (var == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}

	// skip initial blank spaces and the name of the var itself
	while (line_buffer[i++] != '=')
		;

	sscanf(&(line_buffer[i]), "%hu", var);
	DEBUG_CODE(printf("\t\tvalue: %hu\n", *var);)

	return 0;
}


/*
 * MAC Address
 * Format: {0xff, 0x00, 0x00, 0x00, 0x00, 0x00}
 */
static int get_mac(struct config_variables_t *self, enum section_state state)
{
	int i = 0;
	int j;
	unsigned char *var = (unsigned char *) self->var[state];
	char *buf_ptr, *end_ptr;


	if (var == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}

	while (line_buffer[i++] != '{')
		;

	DEBUG_CODE(printf("\t\tvalue: { ");)

	buf_ptr = line_buffer + i;
	end_ptr = buf_ptr;

	for (j = 0; j < 6; j++) {
		var[j] = (unsigned char) strtoul(buf_ptr, &end_ptr, 16);

		if (*end_ptr != ',' && j < 5)
			syntax_error("Expected ',' instead of %c.\n", *end_ptr);
		else
			buf_ptr = end_ptr + 1;
	}
	
	if(*end_ptr != '}')
	  syntax_error("Expected '}' instead of %c.\n", *end_ptr);

	DEBUG_CODE(printf("}\n");)

	return 0;
}

// TODO: 
// We may improve that in the future...
static int get_ip(struct config_variables_t *self, enum section_state state)
{
	return get_string(self, state);
}

/*
 * Accept logtype (FILE, STDOUT, STDERR, SYSLOG)...
 * They're defined in log.h
 */
static int get_logtype(struct config_variables_t *self, enum section_state state)
{
	unsigned int *type = (unsigned int *) self->var[state];
	int found = 0;

	if (type == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}

	if (strstr(line_buffer, "FILE")) {
		*type |= LOG_USE_FILE;
		found++;
	}

	if (strstr(line_buffer, "STDOUT")) {
		*type |= LOG_USE_STDOUT;
		found++;
	}

	if (strstr(line_buffer, "STDERR")) {
		*type |= LOG_USE_STDERR;
		found++;
	}

	if (strstr(line_buffer, "SYSLOG")) {
		*type |= LOG_USE_SYSLOG;
		found++;
	}

	if (!found) {
		syntax_error("Invalid or empty value for logtype\n");
		return -1;
	}

	return 0;
}

/*
 * Accept flags like SYN, RST, PUSH, etc...
 * See the definitions in sniffdet.h
 */
static int get_tcpflags(struct config_variables_t *self, enum section_state state)
{
	unsigned int *type = (unsigned int *) self->var[state];
	int found = 0;

	if (type == NULL) {
		syntax_error("Ooops... something bad happened while reading your config file... :-(\n");
		return -1;
	}

	if (strstr(line_buffer, "SYN")) {
		*type |= TCP_FLAG__SYN;
		found++;
	}

	if (strstr(line_buffer, "FIN")) {
		*type |= TCP_FLAG__FIN;
		found++;
	}


	if (strstr(line_buffer, "RST")) {
		*type |= TCP_FLAG__RST;
		found++;
	}

	if (strstr(line_buffer, "PUSH")) {
		*type |= TCP_FLAG__PUSH;
		found++;
	}

	if (strstr(line_buffer, "ACK")) {
		*type |= TCP_FLAG__ACK;
		found++;
	}

	if (strstr(line_buffer, "URG")) {
		*type |= TCP_FLAG__URG;
		found++;
	}

	if (!found) {
		syntax_error("Invalid or empty value for tcpflags\n");
		return -1;
	}

	return 0;
}

/*
 * TODO:
 * This one would be interesting to have. We could allow a config file with
 * a payload to be pointed, or just a string.
 */
static int get_payload(struct config_variables_t *self, enum section_state state)
{
	fprintf(stderr,
			"** WARNING The parser for \"payload\" is not implemented yet\n");
	fprintf(stderr,
			"** WARNING \t%s:%d\n", f_name, line);
	return -1;
}

static void syntax_error(const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	fprintf(stderr, "*** Syntax error in \"%s\" at line %d:\n", f_name, line);
	fprintf(stderr, "    ");
	vfprintf(stderr, format, ap);

	error_syntax++;
}

/* Get a line, ignoring comments and blank ones
 */
static void get_line(void)
{
	int i;
	char *s;
	while ((s = fgets(line_buffer, sizeof line_buffer, conf_file)) != NULL) {
		i = 0;
		line++;

		// skip initial comments and empty lines
		if (line_buffer[0] == '#' || line_buffer[0] == '\n') {
			continue;
		}

		// skip initial blank spaces to check if a line is a comment...
		// ... then skip it if it's a comment
		while (line_buffer[i] == ' ' || line_buffer[i] == '\t') {
			i++;
		}
		if (line_buffer[i] == '#')
			continue;

		// found something
		if (line_buffer[i] != '\n')
			break;
	}

	if (s == NULL)
		eof = 1;
}
