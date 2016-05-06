/*
 * Copyright 2016 (c) Yousong Zhou
 *
 * This is free software, licensed under the GNU General Public License v2.
 * See /LICENSE for more information.
 */

#ifndef __VERSION_H__
#define __VERSION_H__

#include <stdint.h>

#define AESC_SIG "M9_"
#define AESC_PROGNAME "mkmzupdate"
#define AESC_PROGVERS "0.1"

struct model_data {
	char		*model;
	uint8_t		key[0x400];
	int         keylen;
};

extern struct model_data *meizu_models[];

#endif
