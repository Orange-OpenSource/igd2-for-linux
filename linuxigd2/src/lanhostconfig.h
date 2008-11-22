#ifndef _LAN_HOST_CONFIG_H_
#define _LAN_HOST_CONFIG_H_

#include <upnp/upnp.h>

#define SERVICE_START "start"
#define SERVICE_STOP "stop"

#define COMMAND_LEN 64
#define LINE_LEN 256
#define DEFAULT_GATEWAY_IP "0.0.0.0"

#define MAX_RESERVED_ADDRESS 256

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
