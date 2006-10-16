/*
 *  sniffdet - A tool for network sniffers detection
 *  Copyright (c) 2002, 2003
 *      Ademar de Souza Reis Jr. <myself@ademar.org>
 *      Milton Soares Filho <eu_mil@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; version 2 dated
 *  June, 1991.
 *
 *  $Id$
 */

/* log.h
 * Simple log system definitions
 */


#ifndef __LOG_H__
#define __LOG_H__

/*
 * Multiple outputs can be used
 * by ORing these values
 */
#define LOG_NOLOG        0x00
#define LOG_USE_SYSLOG   0x01 << 0
#define LOG_USE_FILE     0x01 << 1
#define LOG_USE_STDOUT   0x01 << 2
#define LOG_USE_STDERR   0x01 << 3

#define MAX_LOG_MSG_LEN 512
int mylog(unsigned int ltype, int fd, const char *format, ...);

#endif
