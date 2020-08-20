/** 
 * This file is part of igd2-for-linux project
 * Copyright © 2011-2016 France Telecom / Orange.
 * Contact: fabrice.fontaine@orange.com
 * Developer(s): fabrice.fontaine@orange.com, rmenard.ext@orange-ftgroup.com
 *  
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 2 of the License, or 
 * (at your option) any later version. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details. 
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program, see the /doc directory of this program. If 
 * not, see http://www.gnu.org/licenses/. 
 * 
 */

#ifndef PINHOLEV6_H_
#define PINHOLEV6_H_

#include <netinet/in.h>

struct pinholev6 {
    struct in6_addr * internal_client;
    struct in6_addr * remote_host;
    uint16_t internal_port;
    uint16_t remote_port;
    uint8_t protocol;
    uint32_t lease_time;
    uint32_t unique_id;
    int event_id;

    struct pinholev6 *next;

};

struct phv6_expirationEvent
{
    int event_id;
    struct pinholev6 *pinhole;
};

int phv6_init(void);

int phv6_close(void);

int phv6_findPinhole(uint32_t id, struct pinholev6 ** pinhole);

int phv6_existingPinhole(char *internal_client,
        char *remote_host,
        char *internal_port,
        char *remote_port,
        char *protocol,
        uint32_t *uniqueID);

int phv6_addPinhole(char *internalclient,
        char *remote_host,
        char *internal_port,
        char *remote_port,
        char *protocol,
        uint32_t lease_time,
        uint32_t *uniqueId);

int phv6_deletePinhole(uint32_t id);

int phv6_updatePinhole(uint32_t id, uint32_t lease_time);

int phv6_ip6table_addRule(struct in6_addr * internal_client,
        struct in6_addr * remote_host,
        uint16_t internal_port,
        uint16_t remote_port,
        uint16_t protocol);

int phv6_ip6table_deleteRule(struct in6_addr * internal_client,
        struct in6_addr * remote_host,
        uint16_t internal_port,
        uint16_t remote_port,
        uint16_t protocol);



int phv6_checkPinholeWorking(int unique_id);

#endif /* PINHOLEV6_H_ */
