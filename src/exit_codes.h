/*
 *  Copyright (c) 2015 Adrien Vergé
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

#ifndef OPENFORTIVPN_EXIT_CODES_H
#define OPENFORTIVPN_EXIT_CODES_H

enum ofv_exit_code {
	OFV_EXIT_OK             = 0,
	OFV_EXIT_GENERIC        = 1,   /* legacy fallback */
	OFV_EXIT_DNS_FAILED     = 10,
	OFV_EXIT_TCP_FAILED     = 11,
	OFV_EXIT_TLS_FAILED     = 12,
	OFV_EXIT_CERT_FAILED    = 13,
	OFV_EXIT_AUTH_FAILED    = 20,
	OFV_EXIT_OTP_MISSING    = 21,
	OFV_EXIT_SAML_FAILED    = 22,
	OFV_EXIT_ALLOC_DENIED   = 23,
	OFV_EXIT_CONFIG_FAILED  = 30,
	OFV_EXIT_ADAPTER_FAILED = 40,
	OFV_EXIT_TUNNEL_FAILED  = 41,
	OFV_EXIT_PERMISSION     = 50,
	OFV_EXIT_SIGNAL         = 60
};

#endif /* OPENFORTIVPN_EXIT_CODES_H */
