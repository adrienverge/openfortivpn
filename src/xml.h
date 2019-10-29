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

#ifndef _OPENFORTIVPN_XML_H
#define _OPENFORTIVPN_XML_H

#define MAX_DOMAIN_LENGTH 256
// see https://unix.stackexchange.com/questions/245849
// ... /resolv-conf-limited-to-six-domains-with-a-total-of-256-characters

const char *xml_find(char t, const char *tag, const char *buf, int nest);
char *xml_get(const char *buf);

#endif
