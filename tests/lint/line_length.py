#!/usr/bin/env python3
# Copyright (c) 2015 Adrien Vergé

"""Enforce maximum line length in openfortivpn C source code.

Example
-------
   Pass the list of files to check as arguments to the script::

    $ line_length.py file1.c file2.c file3.c

Notes
-----
This script has been working so far for openfortivpn.
It has not been widely tested. It may not work on any C source file.

"""

import sys

# Guidelines say 80, let's tolerate a bit more
MAX = 90


def endswithstring(line):
    """Detect lines from C source code ending with a string.

    This function has not been widely tested.

    Parameters
    ----------
    line : str
        Line of C source code.

    Returns
    -------
    bool
        True if line ends with string, False otherwise.

    """
    return any(line.endswith(end) for end in ('"', '",', '");', '";', '" \\', "];"))


def main():
    """Check each file provided as a command line parameter.

    Returns
    -------
    int
        1 if a line in one of the files exceeds the expected length, else 0.

    """
    exit_status = 0

    for arg in sys.argv[1:]:
        with open(arg, "r") as source_file:
            for i, line in enumerate(source_file, start=1):
                line = line.rstrip()
                # Lines that end with a string are exempted
                if endswithstring(line):
                    continue
                # Replace tabs with 8 spaces
                line = line.replace("\t", "        ")
                # Lines longer than MAX are reported as an error
                if len(line) > MAX:
                    print(
                        f"{arg}: {i}: line too long ({len(line)} characters)",
                        file=sys.stderr,
                    )
                    exit_status = 1

    sys.exit(exit_status)


if __name__ == "__main__":
    main()
