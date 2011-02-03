/** 
 * This file is part of igd2-for-linux project
 * Copyright © 2011 France Telecom.
 * Contact: fabrice.fontaine@orange-ftgroup.com
 * Developer(s): fabrice.fontaine@orange-ftgroup.com, rmenard.ext@orange-ftgroup.com
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

#ifndef _WANIPV6FW_H
#define _WANIPV6FW_H

#ifdef __cplusplus
extern "C" {
#endif


#include <upnp/upnp.h>

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

//error definitions
#define ERR_ACTION_NOT_AUTHORIZED   606
#define ERR_PINHOLE_SPACE_EXHAUSTED 701
#define ERR_FIREWALL_DISABLED       702
#define ERR_INBOUND_PINHOLE_NOT_ALLOWED 703
#define ERR_NO_SUCH_ENTRY           704
#define ERR_PROTOCOL_NOT_SUPPORTED  705
#define ERR_INTERNAL_PORT_WILDCARD  706
#define ERR_PROTOCOL_WILDCARD       707
#define ERR_SRC_ADD_WILDCARD        708
#define ERR_NO_TRAFFIC              709

char FirewallEnabled[2];
char InboundPinholeAllowed[2];

//-----------------------------------------------------------------------------

int InitFirewallv6(void);

int CloseFirewallv6(void);

int upnp_wanipv6_getFirewallStatus(struct Upnp_Action_Request *ca_event);

int upnp_wanipv6_getOutboundPinholeTimeOut
    (struct Upnp_Action_Request *ca_event);

int upnp_wanipv6_addPinhole(struct Upnp_Action_Request *ca_event);

int upnp_wanipv6_updatePinhole(struct Upnp_Action_Request *ca_event);

int upnp_wanipv6_deletePinhole(struct Upnp_Action_Request *ca_event);

int phv6_getPinholePackets(uint32_t id, int * packets);

int upnp_wanipv6_checkPinholeWorking(struct Upnp_Action_Request *ca_event);

int upnp_wanipv6_getPinholePackets(struct Upnp_Action_Request *ca_event);


#ifdef __cplusplus
}
#endif


#endif //_WANIPV6_H
