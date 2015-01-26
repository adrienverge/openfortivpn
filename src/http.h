/*
 *  Copyright (C) 2015 Adrien Vergé
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

#ifndef _AUTH_H
#define _AUTH_H

#include "tunnel.h"

int http_send(struct tunnel *tunnel, const char *request, ...);
int http_receive(struct tunnel *tunnel, char **response);

int auth_log_in(struct tunnel *tunnel);
int auth_log_out(struct tunnel *tunnel);
int auth_request_vpn_allocation(struct tunnel *tunnel);

#endif
