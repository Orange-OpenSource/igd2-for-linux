/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
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
 * along with this program. If not, see http://www.gnu.org/licenses/. 
 * 
 */
 
#ifndef _UTIL_H_
#define _UTIL_H_

#include <upnp/upnp.h>

// ACL error codes
typedef enum {
    ACL_SUCCESS           = 0,

    ACL_COMMON_ERROR      = -1,
    ACL_USER_ERROR        = -2,  //user either exist if it shouldn't or doesn't exist even if should
    ACL_ROLE_ERROR        = -3,  //role either exist if it shouldn't or doesn't exist even if should
} ACL_ERRORCODE;


char *toUpperCase(const char * str);
int GetIpAddressStr(char *address, char *ifname);
int GetMACAddressStr(unsigned char *address, int addressSize, char *ifname);
int GetConnectionStatus(char *conStatus, char *ifname);
int ControlPointIP_equals_InternalClientIP(char *ICAddress, struct in_addr *);
int checkForWildCard(const char *str);
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message);
void trace(int debuglevel, const char *format, ...);
int setEthernetLinkStatus(char *ethLinStatus, char *iface);
int resolveBoolean(char *);
int releaseIP(char *iface);
int killDHCPClient(char *iface);
int startDHCPClient(char *iface);
int readIntFromFile(char *file);

int tokenizeAndSearch(const char *constList, const char *separator, const char *searchItem);

char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );
char* GetDocumentItem(IXML_Document * doc, const char *item, int index);
int writeDocumentToFile(IXML_Document *doc, const char *file);

void ParseXMLResponse(struct Upnp_Action_Request *ca_event, const char *result);


// access level handling and parsing stuff
int initActionAccessLevels(const char *pathToFile);
void deinitActionAccessLevels();
char* getAccessLevel(const char *actionName, int manage);

// ACL handling stuff
int ACL_doesIdentityHasRole(IXML_Document *doc, const char *identity, const char *targetRole);
char *ACL_getRolesOfUser(IXML_Document *doc, const char *username);
char *ACL_getRolesOfCP(IXML_Document *doc, const char *hash);
char *ACL_createRoleListXML(const char *csv_roles);
int ACL_addCP(IXML_Document *doc, const char *name, const char *alias, const char *hash, const char *roles, int introduced);
int ACL_updateCPAlias(IXML_Document *doc, const char *hash, const char *alias, int forceChange);
int ACL_addUser(IXML_Document *doc, const char *name, const char *roles);
int ACL_removeUser(IXML_Document *doc, const char *name);
int ACL_removeCP(IXML_Document *doc, const char *hash);
int ACL_addRolesForUser(IXML_Document *doc, const char *name, const char *roles);
int ACL_addRolesForCP(IXML_Document *doc, const char *hash, const char *roles);
int ACL_removeRolesFromUser(IXML_Document *doc, const char *name, const char *roles);
int ACL_removeRolesFromCP(IXML_Document *doc, const char *hash, const char *roles);
int ACL_validateListAndUpdateACL(IXML_Document *ACLdoc, IXML_Document *identitiesDoc, int admin);
int ACL_validateAndRemoveIdentity(IXML_Document *ACLdoc, IXML_Document *identityDoc);
int ACL_validateAndUpdateCPAlias(IXML_Document *ACLdoc, IXML_Document *identityDoc);

// SIR handling stuff
IXML_Document *SIR_init();
int SIR_addSession(IXML_Document *doc, const char *id, int active, const char *identity, const char *role, int *attempts, const char *loginName, const char *loginChallenge);
int SIR_updateSession(IXML_Document *doc, const char *id, int *active, const char *identity, const char *role, int *attempts, const char *loginName, const char *loginChallenge);
int SIR_removeSession(IXML_Document *doc, const char *id);
char *SIR_getIdentityOfSession(IXML_Document *doc, const char *id, int *active, char **role);
int SIR_getLoginDataOfSession(IXML_Document *doc, const char *id, int *loginattempts, char **loginName, char **loginChallenge);
int SIR_removeLoginDataOfSession(IXML_Document *doc, const char *id);

#endif //_UTIL_H_
