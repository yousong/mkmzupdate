/*
 * Copyright 2016 (c) Yousong Zhou
 *
 * This is free software, licensed under the GNU General Public License v2.
 * See /LICENSE for more information.
 */

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aescrypt.h"
#include "mkmzupdate.h"

static struct model_data *find_model_data(const char *model)
{
	int i;
	struct model_data *p;

	if (!model) {
		return NULL;
	}

	for (i = 0; meizu_models[i]; i++) {
		p = meizu_models[i];
		if (!strncmp(p->model, model, strlen(p->model))) {
			return p;
		}
	}

	return NULL;
}

static void show_usage(const char *arg0)
{
	int i;
	struct model_data *p;

#define OPT_INDENT	"    "
	fprintf(stderr, "Usage: %s -m <model> -e|-d [-i FILE] [-o FILE]\n", arg0);
	fprintf(stderr, "Encrypt or decrypt firmware for use with MEIZU devices.\n\n");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-m, --model", "model name, e.g. mx3, etc.");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-i, --input", "input file (defaults to stdin)");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-o, --output", "output file (defaults to stdout)");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-e, --encrypt", "encrypt image");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-d, --decrypt", "decrypt image");
	fprintf(stderr, OPT_INDENT "%-15s %s\n", "-h, --help", "show this help text");

	fprintf(stderr, "\nCurrently supported models:");
	for (i = 0; meizu_models[i]; i++) {
		p = meizu_models[i];
		fprintf(stderr, " %s", p->model);
	}
	fprintf(stderr, "\n");
}

static struct option long_options[] = {
	{"model",   required_argument, 0, 'm'},
	{"input",   required_argument, 0, 'i'},
	{"output",  required_argument, 0, 'o'},
	{"encrypt", no_argument,       0, 'e'},
	{"decrypt", no_argument,       0, 'd'},
	{"help",    no_argument,       0, 'h'},
	{0,         0,                 0, 0  }
};
#define short_options "m:i:o:edh"

int main(int argc, char **argv)
{
	int opt_encrypt = 0;
	int opt_decrypt = 0;
	char *input_filename = NULL;
	char *output_filename = NULL;
	char *model_string = NULL;

	struct model_data *md = NULL;
	FILE *fin, *fout;
	int ret = EXIT_FAILURE;

	while (1) {
        int c = getopt_long(argc, argv, short_options,
		                long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'm':
			model_string = optarg;
			break;
		case 'i':
			if (strcmp("-", optarg) != 0) {
				input_filename = optarg;
			}
			break;
		case 'o':
			if (strcmp("-", optarg) != 0) {
				output_filename = optarg;
			}
			break;
		case 'e':
			opt_encrypt = 1;
			break;
		case 'd':
			opt_decrypt = 1;
			break;
		case 'h':
		default:
			show_usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	if (model_string == NULL) {
		show_usage(argv[0]);
		exit(EXIT_SUCCESS);
	}
	md = find_model_data(model_string);
	if (!md) {
		fprintf(stderr, "%s: cannot find model data for: %s\n",
		        argv[0], model_string);
		show_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (input_filename) {
		fin = fopen(input_filename, "rb");
		if (fin == NULL) {
			fprintf(stderr, "Can't open %s for reading: %s\n", input_filename,
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		fin = stdin;
	}

	if (output_filename) {
		fout = fopen(output_filename, "wb");
		if (fout == NULL) {
			fprintf(stderr, "Can't open %s for writing: %s\n", output_filename,
				strerror(errno));
			goto quit_close;
		}
	} else {
		exit(EXIT_FAILURE);
		fout = stdout;
	}

	if (opt_decrypt) {
		ret = decrypt_stream(fin, fout, md->key, md->keylen);
	} else if (opt_encrypt) {
		ret = encrypt_stream(fin, fout, md->key, md->keylen);
	}

quit_close:
	fclose(fin);
	fclose(fout);

	return ret;
}
