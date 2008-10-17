#ifndef _LAN_HOST_CONFIG_H_
#define _LAN_HOST_CONFIG_H_

#include <upnp/upnp.h>

int SetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event);
int GetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event);
int SetDHCPRelay(struct Upnp_Action_Request *ca_event);
int GetDHCPRelay(struct Upnp_Action_Request *ca_event);
int SetSubnetMask(struct Upnp_Action_Request *ca_event);
int GetSubnetMask(struct Upnp_Action_Request *ca_event);
int SetIPRouter(struct Upnp_Action_Request *ca_event);
int DeleteIPRouter(struct Upnp_Action_Request *ca_event);
int GetIPRoutersList(struct Upnp_Action_Request *ca_event);
int SetDomainName(struct Upnp_Action_Request *ca_event);
int GetDomainName(struct Upnp_Action_Request *ca_event);
int SetAddressRange(struct Upnp_Action_Request *ca_event);
int GetAddressRange(struct Upnp_Action_Request *ca_event);
int SetReservedAddress(struct Upnp_Action_Request *ca_event);
int DeleteReservedAddress(struct Upnp_Action_Request *ca_event);
int GetReservedAddresses(struct Upnp_Action_Request *ca_event);
int SetDNSServer(struct Upnp_Action_Request *ca_event);
int DeleteDNSServer(struct Upnp_Action_Request *ca_event);
int GetDNSServers(struct Upnp_Action_Request *ca_event);

int InitLanHostConfig();
void FreeLanHostConfig();

#endif // _LAN_HOST_CONFIG_H_
