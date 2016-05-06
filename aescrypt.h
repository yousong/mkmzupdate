/*
 * aescrypt.h
 *
 * Copyright (C) 2007, 2008, 2009, 2013
 *
 * This software is licensed as "freeware."  Permission to distribute
 * this software in source and binary forms is hereby granted without a
 * fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
 * THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
 * BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
 *
 * Copyright 2016 (c) Yousong Zhou
 *
 * This is free software, licensed under the GNU General Public License v2.
 * See /LICENSE for more information.
 *
 * This file was modified from aescrypt-3.10
 *
 */

#ifndef __AESCRYPT_H__
#define __AESCRYPT_H__

#include "aes.h"
#include "sha256.h"

typedef struct {
    char aes[3];
    unsigned char version;
    unsigned char last_block_size;
} aescrypt_hdr;

typedef unsigned char sha256_t[32];

extern int encrypt_stream(FILE *infp, FILE *outfp, unsigned char* passwd, int passlen);
extern int decrypt_stream(FILE *infp, FILE *outfp, unsigned char* passwd, int passlen);

#endif // __AESCRYPT_H__
