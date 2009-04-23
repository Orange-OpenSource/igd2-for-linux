#ifndef _DEVICEPROTECTION_H_
#define _DEVICEPROTECTION_H_

#include <upnp/upnp.h>

#define DP_SERVICE_TYPE "urn:schemas-upnp-org:service:DeviceProtection:1"
// for use with GetUserLoginChallenge action
#define DP_PRF_ROUNDS    5000
#define DP_SALT_BYTES    16
#define DP_STORED_BYTES  20
#define DP_NONCE_BYTES   16

// DeviceProtection state variables
int SetupReady;
char SupportedProtocols[150];


void DPStateTableInit();

// deviceprotection actions
int SendSetupMessage(struct Upnp_Action_Request *ca_event);
int GetSupportedProtocols(struct Upnp_Action_Request *ca_event);
int GetUserLoginChallenge(struct Upnp_Action_Request *ca_event);
int UserLogin(struct Upnp_Action_Request *ca_event);
int UserLogout(struct Upnp_Action_Request *ca_event);
int GetACLData(struct Upnp_Action_Request *ca_event);
int SetRoleForIdentity(struct Upnp_Action_Request *ca_event);
int GetCurrentRole(struct Upnp_Action_Request *ca_event);
int AddLoginData(struct Upnp_Action_Request *ca_event);
int RemoveLoginData(struct Upnp_Action_Request *ca_event);
int AddIdentityData(struct Upnp_Action_Request *ca_event);
int RemoveIdentityData(struct Upnp_Action_Request *ca_event);

#endif /*_DEVICEPROTECTION_H_*/
