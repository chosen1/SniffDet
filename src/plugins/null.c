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

#include <lib/libsniffdet.h>
#include "../sniffdet.h"
#include "../sniffdet.h" // XXX
#include "plugins.h"

int test_output(__attribute__((unused)) char *target,
		__attribute__((unused)) struct test_info info[],
		__attribute__((unused)) struct config_options config,
		__attribute__((unused)) char *errbuf)
{
	return 0;
}
