/*
 * Portable getopt_long implementation for systems without <getopt.h>.
 * Based on public domain implementations.
 * Used on Windows with MSVC (MinGW provides its own getopt).
 */

#include "getopt.h"

#include <string.h>
#include <stdio.h>

char *optarg;
int optind = 1;
int opterr = 1;
int optopt = '?';

static int optwhere = 1;

static void permute(char *const argv[], int from, int to)
{
	char *tmp = argv[from];
	int i;

	for (i = from; i > to; i--)
		((char **)argv)[i] = argv[i - 1];
	((char **)argv)[to] = tmp;
}

int getopt(int argc, char *const argv[], const char *optstring)
{
	char *cp;
	int c;

	optarg = NULL;

	if (optind >= argc || argv[optind] == NULL)
		return -1;

	if (argv[optind][0] != '-' || argv[optind][1] == '\0')
		return -1;

	if (strcmp(argv[optind], "--") == 0) {
		optind++;
		return -1;
	}

	c = argv[optind][optwhere++];

	cp = strchr(optstring, c);
	if (c == ':' || cp == NULL) {
		optopt = c;
		if (opterr)
			fprintf(stderr, "%s: invalid option -- '%c'\n",
			        argv[0], c);
		if (argv[optind][optwhere] == '\0') {
			optind++;
			optwhere = 1;
		}
		return '?';
	}

	if (cp[1] == ':') {
		if (argv[optind][optwhere] != '\0') {
			optarg = &argv[optind][optwhere];
			optind++;
			optwhere = 1;
		} else if (cp[2] != ':') {
			/* Required argument */
			optind++;
			if (optind >= argc) {
				optopt = c;
				if (opterr)
					fprintf(stderr,
					        "%s: option requires an argument -- '%c'\n",
					        argv[0], c);
				return optstring[0] == ':' ? ':' : '?';
			}
			optarg = argv[optind];
			optind++;
			optwhere = 1;
		} else {
			/* Optional argument not present */
			optind++;
			optwhere = 1;
		}
	} else {
		if (argv[optind][optwhere] == '\0') {
			optind++;
			optwhere = 1;
		}
	}

	return c;
}

int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex)
{
	int i;
	int match = -1;
	int num_matches = 0;
	size_t len;

	optarg = NULL;

	if (optind >= argc)
		return -1;

	/* GNU-style permutation: skip non-option arguments */
	if (argv[optind] == NULL || argv[optind][0] != '-') {
		int j;

		for (j = optind; j < argc; j++) {
			if (argv[j] && argv[j][0] == '-' && argv[j][1] != '\0')
				break;
		}
		if (j >= argc)
			return -1;
		/* Move the non-option args after the option we found */
		while (j > optind)
			permute(argv, j--, optind);
		if (argv[optind] == NULL || argv[optind][0] != '-')
			return -1;
	}

	/* Check for "--" */
	if (strcmp(argv[optind], "--") == 0) {
		optind++;
		return -1;
	}

	/* Check for long option */
	if (argv[optind][1] == '-') {
		const char *opt = &argv[optind][2];
		const char *eq = strchr(opt, '=');

		len = eq ? (size_t)(eq - opt) : strlen(opt);

		for (i = 0; longopts[i].name; i++) {
			if (strncmp(longopts[i].name, opt, len) == 0 &&
			    strlen(longopts[i].name) == len) {
				match = i;
				num_matches = 1;
				break;
			}
		}

		/* Try prefix matching if exact match not found */
		if (match == -1) {
			for (i = 0; longopts[i].name; i++) {
				if (strncmp(longopts[i].name, opt, len) == 0) {
					match = i;
					num_matches++;
				}
			}
		}

		if (num_matches != 1) {
			if (opterr) {
				if (num_matches > 1)
					fprintf(stderr,
					        "%s: option '--%.*s' is ambiguous\n",
					        argv[0], (int)len, opt);
				else
					fprintf(stderr,
					        "%s: unrecognized option '--%.*s'\n",
					        argv[0], (int)len, opt);
			}
			optind++;
			return '?';
		}

		if (longindex)
			*longindex = match;

		optind++;

		if (longopts[match].has_arg == required_argument ||
		    longopts[match].has_arg == optional_argument) {
			if (eq) {
				optarg = (char *)(eq + 1);
			} else if (longopts[match].has_arg == required_argument) {
				if (optind >= argc) {
					if (opterr)
						fprintf(stderr,
						        "%s: option '--%s' requires an argument\n",
						        argv[0], longopts[match].name);
					return '?';
				}
				optarg = argv[optind++];
			}
		}

		if (longopts[match].flag) {
			*longopts[match].flag = longopts[match].val;
			return 0;
		}
		return longopts[match].val;
	}

	/* Short option */
	return getopt(argc, argv, optstring);
}
