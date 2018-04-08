/*
 * Copyright (c) 2018 Chen Jingpiao <chenjingpiao@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void error_msg_and_die(const char *fmt, ...)
{
	va_list p;

	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	exit(EXIT_FAILURE);
}

void perror_msg_and_die(const char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}
