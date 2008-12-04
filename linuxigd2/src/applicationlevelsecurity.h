#ifndef APPLICATIONLEVELSECURITY_H_
#define APPLICATIONLEVELSECURITY_H_

int InitALS();
void FreeALS();
int message_received(int error, unsigned char *data, int len, void* control);

int GetDeviceInfo(struct Upnp_Action_Request *ca_event);
int PutMessage(struct Upnp_Action_Request *ca_event);
int RequestCert(struct Upnp_Action_Request *ca_event);
int GetRoles(struct Upnp_Action_Request *ca_event);
int GetCACert(struct Upnp_Action_Request *ca_event);
int GetKnownCAs(struct Upnp_Action_Request *ca_event);
int AddACLEntry(struct Upnp_Action_Request *ca_event);
int AddCACertHash(struct Upnp_Action_Request *ca_event);

#endif /*APPLICATIONLEVELSECURITY_H_*/
