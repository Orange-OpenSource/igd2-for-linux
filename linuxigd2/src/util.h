/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 *  
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
 
#ifndef _UTIL_H_
#define _UTIL_H_

#include <upnp/upnp.h>

static const char REGEX_IP_LASTBYTE[] = "^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$";
static const char REGEX_DOMAIN_NAME[] = "^([a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,6}$";

/* interface statistics */
typedef enum
{
    STATS_TX_BYTES,
    STATS_RX_BYTES,
    STATS_TX_PACKETS,
    STATS_RX_PACKETS,
    STATS_LIMIT
} stats_t;

// ACL error codes
typedef enum {
    ACL_SUCCESS           = 0,

    ACL_COMMON_ERROR      = -1,
    ACL_USER_ERROR        = -2,  //user either exist if it shouldn't or doesn't exist even if should
    ACL_ROLE_ERROR        = -3,  //role either exist if it shouldn't or doesn't exist even if should
} ACL_ERRORCODE;

char* createUnion(const char *str1, const char *str2);
int readStats(unsigned long stats[STATS_LIMIT]);
char* escapeXMLString(char *xml);
char* unescapeXMLString(char *escXML);
char *toUpperCase(const char * str);
int caseInsesitive_strcmp(const char *str1, const char *str2);
int GetIpAddressStr(char *address, char *ifname);
int GetMACAddressStr(unsigned char *address, int addressSize, char *ifname);
int GetConnectionStatus(char *conStatus, char *ifname);
int IsIpOrDomain(char *address);
int ControlPointIP_equals_InternalClientIP(char *ICAddress, struct sockaddr_storage *);
int checkForWildCard(const char *str);
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message);
void trace(int debuglevel, const char *format, ...);
int setEthernetLinkStatus(char *ethLinStatus, char *iface);
int resolveBoolean(char *);
int releaseIP(char *iface);
int killDHCPClient(char *iface);
int startDHCPClient(char *iface);
int readIntFromFile(char *file);

char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );
char* GetDocumentItem(IXML_Document * doc, const char *item, int index);
int GetNbSoapParameters(IN IXML_Document * doc);
int isStringInteger(char * string);

void ParseXMLResponse(struct Upnp_Action_Request *ca_event, const char *result);
void ParseResult( struct Upnp_Action_Request *ca_event, const char *str, ... );

#endif //_UTIL_H_
