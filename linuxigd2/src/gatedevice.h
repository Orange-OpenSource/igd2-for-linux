/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 *  
 * This file is part of igd2-for-linux project
 * Copyright © 2011-2012 France Telecom.
 * Contact: fabrice.fontaine@orange.com
 * Developer(s): fabrice.fontaine@orange.com, rmenard.ext@orange.com
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
 
#ifndef _GATEDEVICE_H_
#define _GATEDEVICE_H_ 1

#include <upnp/upnp.h>
#include <upnp/TimerThread.h>
#include "util.h"

// Thread which contains all kind of timers and threads used in gatedevice.c and deviceprotection.c
TimerThread gExpirationTimerThread;

// IGD Device Globals
UpnpDevice_Handle deviceHandle;
UpnpDevice_Handle deviceHandleIPv6;
UpnpDevice_Handle deviceHandleIPv6UlaGua;
char *gateUDN;
char *wanUDN;
char *wanConnectionUDN;
char *lanUDN;
long int startup_time;
unsigned long connection_stats[STATS_LIMIT]; // this is used for defining if connection is in idling
long int idle_time;

// State Variables
char ConnectionType[50];
char PossibleConnectionTypes[50];
char ConnectionStatus[20];
char LastConnectionError[35];
long int AutoDisconnectTime;
long int IdleDisconnectTime;
long int WarnDisconnectDelay;
int RSIPAvailable;
int NATEnabled;
char ExternalIPAddress[INET6_ADDRSTRLEN];
int PortMappingNumberOfEntries;
int PortMappingEnabled;
char RemoteHost[INET6_ADDRSTRLEN];    // updated IPv6 addrss length 16 -> 46
long int SystemUpdateID;

// WANEthLinkConfig state variables
char EthernetLinkStatus[12];

// Linked list for portmapping entries
struct portMap *pmlist_Head;
struct portMap *pmlist_Current;

// WanIPConnection Actions
int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie);
int StateTableInit(char *descDocUrl);
void AcceptSubscriptionExtForIPv4andIPv6(const char *DevID, const char *ServID,
                                        IXML_Document *PropSet, Upnp_SID SubsId);
void NotifyExtForIPv4AndIPv6(const char *DevID, const char *ServID,
                            IXML_Document *PropSet);
int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event);
int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_event);
int HandleActionRequest(struct Upnp_Action_Request *ca_event);

int GetConnectionTypeInfo(struct Upnp_Action_Request *ca_event);
int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event);
int SetConnectionType(struct Upnp_Action_Request *ca_event);
int SetAutoDisconnectTime(struct Upnp_Action_Request *ca_event);
int SetIdleDisconnectTime(struct Upnp_Action_Request *ca_event);
int SetWarnDisconnectDelay(struct Upnp_Action_Request *ca_event);
int GetAutoDisconnectTime(struct Upnp_Action_Request *ca_event);
int GetIdleDisconnectTime(struct Upnp_Action_Request *ca_event);
int GetWarnDisconnectDelay(struct Upnp_Action_Request *ca_event);
int RequestConnection(struct Upnp_Action_Request *ca_event);
int GetTotal(struct Upnp_Action_Request *ca_event, stats_t stat);
int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event);
int InvalidAction(struct Upnp_Action_Request *ca_event);
int GetStatusInfo(struct Upnp_Action_Request *ca_event);
int AddPortMapping(struct Upnp_Action_Request *ca_event);
int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetExternalIPAddress(struct Upnp_Action_Request *ca_event);
int DeletePortMapping(struct Upnp_Action_Request *ca_event);
int DeletePortMappingRange(struct Upnp_Action_Request *ca_event);
int AddAnyPortMapping(struct Upnp_Action_Request *ca_event);
int GetListOfPortmappings(struct Upnp_Action_Request *ca_event);
int ForceTermination(struct Upnp_Action_Request *ca_event);
int RequestTermination(struct Upnp_Action_Request *ca_event);

// WANEthernetLinkConfig Actions
int GetEthernetLinkStatus (struct Upnp_Action_Request *ca_event);

// Definitions for mapping expiration timer thread
#define THREAD_IDLE_TIME 5000
#define JOBS_PER_THREAD 10
#define MIN_THREADS 2
#define MAX_THREADS 12

int ExpirationTimerThreadInit(void);
int ExpirationTimerThreadShutdown(void);
int ScheduleMappingExpiration(struct portMap *mapping, char *DevUDN, char *ServiceID);
int CancelMappingExpiration(int eventId);
void DeleteAllPortMappings(void);
int AddNewPortMapping(struct Upnp_Action_Request *ca_event, char* new_enabled, long int leaseDuration,
                     char* new_remote_host, char* new_external_port, char* new_internal_port,
                     char* new_protocol, char* new_internal_client, char* new_port_mapping_description,
                     int is_update);
int createAutoDisconnectTimer(void);
void DisconnectWAN(void *input);
int createEventUpdateTimer(void);
void UpdateEvents(void *input);
int EthernetLinkStatusEventing(IXML_Document *propSet);
int ExternalIPAddressEventing(IXML_Document *propSet);
int ConnectionStatusEventing(IXML_Document *propSet);
int ConnectionTermination(struct Upnp_Action_Request *ca_event, long int disconnectDelay);
int AuthorizeControlPoint(struct Upnp_Action_Request *ca_event, int managed, int addError);

int WANIPv6FirewallStatusEventing(IXML_Document *propSet);

// Definition for authorizing control point
typedef enum
{
    CONTROL_POINT_AUTHORIZED,
    CONTROL_POINT_HALF_AUTHORIZED,
    CONTROL_POINT_NOT_AUTHORIZED
} authorization_levels;

#endif //_GATEDEVICE_H
