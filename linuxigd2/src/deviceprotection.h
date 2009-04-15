#ifndef _DEVICEPROTECTION_H_
#define _DEVICEPROTECTION_H_

#include <upnp/upnp.h>

// DeviceProtection state variables
int SetupReady;
char SupportedProtocols[150];


void DPStateTableInit();

// deviceprotection actions
int SendSetupMessage(struct Upnp_Action_Request *ca_event);
int GetSupportedProtocols(struct Upnp_Action_Request *ca_event);
int GetSessionLoginChallenge(struct Upnp_Action_Request *ca_event);
int SessionLogin(struct Upnp_Action_Request *ca_event);
int SessionLogout(struct Upnp_Action_Request *ca_event);
int GetACLData(struct Upnp_Action_Request *ca_event);
int AddRolesForIdentity(struct Upnp_Action_Request *ca_event);
int RemoveRolesForIdentity(struct Upnp_Action_Request *ca_event);
int AddLoginData(struct Upnp_Action_Request *ca_event);
int RemoveLoginData(struct Upnp_Action_Request *ca_event);
int AddIdentityData(struct Upnp_Action_Request *ca_event);
int RemoveIdentityData(struct Upnp_Action_Request *ca_event);

#endif /*_DEVICEPROTECTION_H_*/
