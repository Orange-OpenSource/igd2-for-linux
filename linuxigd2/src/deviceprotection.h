/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
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

#ifndef _DEVICEPROTECTION_H_
#define _DEVICEPROTECTION_H_

#include <upnp/upnp.h>


#define DP_SERVICE_TYPE "urn:schemas-upnp-org:service:DeviceProtection:1"
// for use with GetUserLoginChallenge action
#define DP_PRF_ROUNDS    5000
#define DP_SALT_BYTES    16
#define DP_STORED_BYTES  16
#define DP_NONCE_BYTES   16
#define DP_AUTH_BYTES    16

#define DP_MAX_LOGIN_ATTEMPTS 5

#define DP_MAX_WPS_SETUP_TIME 60

// DeviceProtection state variables
int SetupReady;
char SupportedProtocols[500];

int InitDP();
void FreeDP();
void DPStateTableInit();
void DP_loadDocuments();
void DP_finishDocuments();
int checkCPPrivileges(struct Upnp_Action_Request *ca_event, const char *targetRole);
void createUuidFromData(char **uuid_str, unsigned char **uuid_bin, size_t *uuid_size, unsigned char *hash, int hashLen);


// deviceprotection actions
int SendSetupMessage(struct Upnp_Action_Request *ca_event);
int GetSupportedProtocols(struct Upnp_Action_Request *ca_event);
int GetUserLoginChallenge(struct Upnp_Action_Request *ca_event);
int UserLogin(struct Upnp_Action_Request *ca_event);
int UserLogout(struct Upnp_Action_Request *ca_event);
int GetACLData(struct Upnp_Action_Request *ca_event);
int AddRolesForIdentity(struct Upnp_Action_Request *ca_event);
int RemoveRolesForIdentity(struct Upnp_Action_Request *ca_event);
int GetAssignedRoles(struct Upnp_Action_Request *ca_event);
int GetRolesForAction(struct Upnp_Action_Request *ca_event);
int SetUserLoginPassword(struct Upnp_Action_Request *ca_event);
int AddIdentityList(struct Upnp_Action_Request *ca_event);
int RemoveIdentity(struct Upnp_Action_Request *ca_event);

#endif /*_DEVICEPROTECTION_H_*/
