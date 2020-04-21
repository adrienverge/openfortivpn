/*
 *  Copyright (C) 2015 Lubomir Rintel
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "xml.h"
#include "config.h"
#include "log.h"

#include <string.h>

/*
 * Poor man's XML parser. Looks for given tag or attribute. Assumes
 * there's no CDATA or text content and does not recognize strings:
 * it would mess up the parsing if they contain '<' or '/'.
 *
 * @t		'<' if we're looking for a tag, ' ' if we're looking
 *              for an attribute.
 * @needle	name of a tag or attribute (end and attribute with a
 *              '=' to swallow	it).
 * @buf		a NUL terminated buffer to look in.
 * @nest	do not escape more than @nest levels of nesting
 *              (1 == look for kids, 2 == look for siblings).
 * @return	a string immediately following the needle if found,
 *              %NULL otherwise.
 */
const char *xml_find(char t, const char *needle, const char *buf, int nest)
{
	int i;

	if (!buf)
		return NULL;
	for (i = 0; buf[i]; i++) {
		if (buf[i] == '<' && buf[i + 1] != '/')
			nest++;
		if (buf[i] == '/')
			nest--;
		if (!nest)
			return NULL;
		if (&buf[i+1] == strstr(&buf[i], needle) &&
		    buf[i] == t) {
			return &buf[i + 1 + strlen(needle)];
		}
	}
	return NULL;
}

/*
 * Poor man's XML attribute parser. Takes the first string as a quoting
 * character and consumes characters until the next occurrence or an end
 * of the buffer. Doesn't return more than 15 characters (enough for an
 * IPv4 address textural form).
 *
 * @buf		a NUL terminated buffer to look in.
 * @return	%NULL in case of an error, a character string with
 *              ownership passed upon success
 */
char *xml_get(const char *buf)
{
	char val[MAX_DOMAIN_LENGTH]; // just enough to hold a domain search string
	char quote;
	int i;

	if (!buf)
		return NULL;
	quote = buf[0];
	if (!quote) {
		log_warn("Short read while getting value in config XML\n");
		return NULL;
	}
	for (i = 1; buf[i]; i++) {
		if (buf[i] == quote)
			break;
		if (i == MAX_DOMAIN_LENGTH) {
			log_warn("Value too long in config XML\n");
			break;
		}
		val[i - 1] = buf[i];
	}
	if (buf[i] != quote) {
		log_warn("Could not read out an attribute value in config XML\n");
		return NULL;
	}
	val[i - 1] = '\0';

	return strdup(val);
}
