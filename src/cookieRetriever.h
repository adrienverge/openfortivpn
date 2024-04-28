/*
 * cookieRetriever.h
 *
 *  Created on: 28 apr 2024
 *      Author: filippor
 */

#ifndef SRC_COOKIERETRIEVER_H_
#define SRC_COOKIERETRIEVER_H_
#include <stddef.h>
#include "config.h"

char *retrieve_cookie_with_external_browser(struct vpn_config *cfg );

char *retrieve_cookie_from_id(struct vpn_config *cfg );

#endif /* SRC_COOKIERETRIEVER_H_ */
