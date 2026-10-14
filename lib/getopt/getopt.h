/*
 * Portable getopt_long implementation for systems without <getopt.h>.
 * Based on public domain getopt implementations.
 * Used on Windows with MSVC (MinGW provides its own getopt).
 */

#ifndef PORTABLE_GETOPT_H
#define PORTABLE_GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

#define no_argument       0
#define required_argument 1
#define optional_argument 2

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

int getopt(int argc, char *const argv[], const char *optstring);

int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_GETOPT_H */
