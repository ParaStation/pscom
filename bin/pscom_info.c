/*
 * ParaStation
 *
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pscom_priv.h"

typedef struct optargs {
	int config;
	int documentation;
	int help;
	int version;
	int expert;
	char *progname;
} optargs_t;

optargs_t opts = {
        .config        = 0,
        .documentation = 0,
        .help          = 0,
        .version       = 0,
        .expert        = 0,
};


static
void print_usage(void)
{
	printf("USAGE:\n");
	printf("    %s [OPTIONS]\n\n", opts.progname);
	printf("OPTIONS:\n");
	printf("    -v, --version       Show pscom version information\n");
	printf("    -c, --config        Show pscom environment configuration\n");
	printf("    -d, --documentation Display documentation to the environment configuration (requires -c)\n");
	printf("    -h, --help          Show this help message\n");
}

static
void parse_opt(int argc, char **argv)
{
	int c;

	opts.progname = argv[0];

	while (1) {
		static struct option long_options[] = {
			{"config"        , no_argument      , &opts.config        ,  1 },
			{"documentation" , no_argument      , &opts.documentation ,  1 },
			{"help"          , no_argument      , &opts.help          ,  1 },
			{"version"       , no_argument      , &opts.version       ,  1 },
			{0, 0, 0, 0}
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "hvcdx", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 0:
				break;
			case 'c':
				opts.config = 1;
				break;
			case 'd':
				opts.documentation = 1;
				break;
			case 'v':
				opts.version = 1;
				break;
			case 'x':
				opts.expert = 1;
				break;
			case '?':
				break;
			case 'h':
			default:
				print_usage();
				exit(EXIT_FAILURE);
		}
	}

        if (opts.help) {
                print_usage();
                exit(EXIT_FAILURE);
        }
}


int main(int argc, char **argv)
{
        parse_opt(argc, argv);

        pscom_env_print_flags_t print_flags = 0;

        if (opts.config) {
                print_flags |= (PSCOM_ENV_PRINT_CONFIG |
                                PSCOM_ENV_PRINT_DEFAULT_VALUE);

                /* documentation requires the config to be printed */
                if (opts.documentation) {
                        print_flags |= PSCOM_ENV_PRINT_DOC;
                }

                /* hidden config is only shown if the config is printed */
                if (opts.expert) {
                        print_flags |= PSCOM_ENV_PRINT_HIDDEN;
                }
        }

        if (opts.version) {
                setenv("PSP_DEBUG_VERSION", "1", 1);
        }

        /* print usage if no options are provided */
        if ((print_flags == 0) && !opts.version) {
                print_usage();
                exit(EXIT_FAILURE);
        }

        pscom_init(PSCOM_VERSION);

	/* we have to open a socket to trigger the loading of plugins */
	pscom_socket_t *dummy_socket __attribute__((unused));
	dummy_socket = pscom_open_socket(0, 0);

        pscom_env_table_list_print(print_flags);
        return 0;
}
