/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 * 
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU (Lesser) General Public License as 
 * published by the Free Software Foundation, version 2 of the License. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU (Lesser) General Public License for more details. 
 * 
 * You should have received a copy of the GNU (Lesser) General Public 
 * License along with this program. If not, see http://www.gnu.org/licenses/. 
 * 
 */

#ifndef _LAN_HOST_CONFIG_H_
#define _LAN_HOST_CONFIG_H_

#include <upnp/upnp.h>

#define SERVICE_START   "start"
#define SERVICE_STOP    "stop"
#define SERVICE_RESTART "restart"

#define COMMAND_LEN 64
#define LINE_LEN 256
#define DEFAULT_GATEWAY_IP "0.0.0.0"

#define MAX_RESERVED_ADDRESS 256

// max size of last ip part
static const int MAX_IP_LAST_PART = 5;

// regex to identify valid nameserver lines in resolv.conf
static const char REGEX_NAMESERVER[] = "nameserver[[:blank:]]*([[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3})";


int SetDHCPServerConfigurable(UpnpActionRequest *ca_event);
int GetDHCPServerConfigurable(UpnpActionRequest *ca_event);
int SetDHCPRelay(UpnpActionRequest *ca_event);
int GetDHCPRelay(UpnpActionRequest *ca_event);
int SetSubnetMask(UpnpActionRequest *ca_event);
int GetSubnetMask(UpnpActionRequest *ca_event);
int SetIPRouter(UpnpActionRequest *ca_event);
int DeleteIPRouter(UpnpActionRequest *ca_event);
int GetIPRoutersList(UpnpActionRequest *ca_event);
int SetDomainName(UpnpActionRequest *ca_event);
int GetDomainName(UpnpActionRequest *ca_event);
int SetAddressRange(UpnpActionRequest *ca_event);
int GetAddressRange(UpnpActionRequest *ca_event);
int SetReservedAddress(UpnpActionRequest *ca_event);
int DeleteReservedAddress(UpnpActionRequest *ca_event);
int GetReservedAddresses(UpnpActionRequest *ca_event);
int SetDNSServer(UpnpActionRequest *ca_event);
int DeleteDNSServer(UpnpActionRequest *ca_event);
int GetDNSServers(UpnpActionRequest *ca_event);

int CheckLanHostConfigFiles();
int InitLanHostConfig();
void FreeLanHostConfig();

#endif // _LAN_HOST_CONFIG_H_
