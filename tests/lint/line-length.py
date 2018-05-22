#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (C) 2015 Adrien Vergé

import sys

# Guidelines say 80, let's tolerate a bit more
MAX = 90


def endswithstring(line):
    """Detect lines from C source code ending with a string.

    Parameters
    ----------
    line : str
        Line of C source code.

    Returns
    -------
    bool
        True if line ends with string, False otherwise.

    """
    for end in ('"', '",', '");', '" \\'):
        if line.endswith(end):
            return True
    return False


def main():
    exit_status = 0

    for arg in sys.argv[1:]:
        with open(arg, 'r') as source_file:
            for i, line in enumerate(source_file):
                line = line.rstrip()
                # Lines that end with a string are exempted
                if endswithstring(line):
                    continue
                # Replace tabs with 8 spaces
                line = line.replace('\t', '        ')
                # Lines longer than MAX are reported as an error
                if len(line) > MAX:
                    print('{}: {}: line too long ({} characters)'
                          .format(arg, i, len(line)))
                    exit_status = 1

    sys.exit(exit_status)


if __name__ == '__main__':
    main()
