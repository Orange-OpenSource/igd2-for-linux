/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 *  
 * This file is part of igd2-for-linux project
 * Copyright © 2011-2016 France Telecom / Orange.
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

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <upnp/ixml.h>
#include <string.h>
#include <time.h>
#include <upnp/upnp.h>
#include <upnp/upnptools.h>
#include <arpa/inet.h>
#include "globals.h"
#include "gatedevice.h"
#include "pmlist.h"
#include "lanhostconfig.h"
#include "wanipv6fw.h"
#include "config.h"

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

char FirewallEnabled[2];
char InboundPinholeAllowed[2];

//Definitions for mapping expiration timer thread
static ThreadPool gExpirationThreadPool;
static ThreadPoolJob gEventUpdateJob;

static int gAutoDisconnectJobId = -1;

// MUTEX for locking shared state variables whenver they are changed
ithread_mutex_t DevMutex = PTHREAD_MUTEX_INITIALIZER;

// XML string definitions
static const char xml_portmapEntry[] =
        "<p:PortMappingEntry>"
        "<p:NewRemoteHost>%s</p:NewRemoteHost>"
        "<p:NewExternalPort>%s</p:NewExternalPort>"
        "<p:NewProtocol>%s</p:NewProtocol>"
        "<p:NewInternalPort>%s</p:NewInternalPort>"
        "<p:NewInternalClient>%s</p:NewInternalClient>"
        "<p:NewEnabled>%d</p:NewEnabled>"
        "<p:NewDescription>%s</p:NewDescription>"
        "<p:NewLeaseTime>%li</p:NewLeaseTime>"
        "</p:PortMappingEntry>\n";
static const char xml_portmapListingHeader[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<p:PortMappingList xmlns:p=\"urn:schemas-upnp-org:gw:WANIPConnection\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xsi:schemaLocation=\"urn:schemas-upnp-org:gw:WANIPConnection http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd\">\n";
static const char xml_portmapListingFooter[] = "</p:PortMappingList>";


/**
 * Main event handler for callbacks from the SDK.  Determine type of event
 * and dispatch to the appropriate handler (Note: Get Var Request deprecated)
 *  
 * @param EventType Type of event (UPNP_EVENT_SUBSCRIPTION_REQUEST, UPNP_CONTROL_GET_VAR_REQUEST, UPNP_CONTROL_ACTION_REQUEST).
 * @param Event Upnp event struct.
 * @param Cookie This parameter is not used.
 * @return 0
 */
int EventHandler(Upnp_EventType EventType, const void *Event, void *Cookie)
{
    switch (EventType)
    {
    case UPNP_EVENT_SUBSCRIPTION_REQUEST:
        HandleSubscriptionRequest((UpnpSubscriptionRequest *) Event);
        break;
        // -- Deprecated --
    case UPNP_CONTROL_GET_VAR_REQUEST:
        HandleGetVarRequest((UpnpStateVarRequest *) Event);
        break;
    case UPNP_CONTROL_ACTION_REQUEST:
        HandleActionRequest((UpnpActionRequest *) Event);
        break;
    default:
        trace(1, "Error in EventHandler: Unknown event type %d", EventType);
    }
    return (0);
}

/**
 * Initialize state variables and parse device UDN's for InternetGatewayDevice, 
 * WANDevice and WANConnectionDevice.
 * Also read access level xml into memory.
 *  
 * @param descDocUrl Url of device description document.
 * @return Upnp error code.
 */
int StateTableInit(char *descDocUrl)
{
    IXML_Document *ixmlDescDoc;
    int ret;

    if ((ret = UpnpDownloadXmlDoc(descDocUrl, &ixmlDescDoc)) != UPNP_E_SUCCESS)
    {
        syslog(LOG_ERR, "Could not parse description document. Exiting ...");
        UpnpFinish();
        exit(0);
    }

    // Get the UDN from the description document, then free the DescDoc's memory
    // Assumes that order of devices in file is IGD, WAN, WANConn, LAN
    gateUDN = GetDocumentItem(ixmlDescDoc, "UDN", 0);
    wanUDN = GetDocumentItem(ixmlDescDoc, "UDN", 1);
    wanConnectionUDN = GetDocumentItem(ixmlDescDoc, "UDN", 2);
    lanUDN = GetDocumentItem(ixmlDescDoc, "UDN", 3);
    ixmlDocument_free(ixmlDescDoc);

    trace(3, "UDN's: %s\n%s\n%s\n%s\n", gateUDN, wanUDN, wanConnectionUDN,
        lanUDN);

    if (gateUDN == NULL || wanUDN == NULL || wanConnectionUDN == NULL ||
        lanUDN == NULL)
    {
        syslog(LOG_ERR, "Failed to get device UDN's from description document.  Exiting ...");
        UpnpFinish();
        exit(1);
    }

    // Initialize our linked list of port mappings.
    pmlist_Head = pmlist_Current = NULL;

    AutoDisconnectTime = 0;
    IdleDisconnectTime = 0;
    WarnDisconnectDelay = 0;
    PortMappingNumberOfEntries = 0;
    SystemUpdateID = 0;
    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);
    GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);

    if (!readStats(connection_stats))
    {
        syslog(LOG_ERR, "Failed get connection stats from /proc. Exiting ...");
        UpnpFinish();
        exit(1);
    }
    idle_time = 0;

    // only supported type at the moment
    strcpy(ConnectionType,"IP_Routed");

    // Record the startup time, for uptime
    startup_time = time(NULL);

    return (ret);
}

void AcceptSubscriptionExtForIPv4AndIPv6(const char *DevID, const char *ServID,
                                        IXML_Document *PropSet, const Upnp_SID SubsId)
{
    if(deviceHandle)
        UpnpAcceptSubscriptionExt(deviceHandle, DevID, ServID, PropSet, SubsId);
    if(deviceHandleIPv6)
        UpnpAcceptSubscriptionExt(deviceHandleIPv6, DevID, ServID, PropSet,
                SubsId); 
    if(deviceHandleIPv6UlaGua)
        UpnpAcceptSubscriptionExt(deviceHandleIPv6UlaGua, DevID, ServID,
                PropSet, SubsId); 
}

void NotifyExtForIPv4AndIPv6(const char *DevID, const char *ServID,
                            IXML_Document *PropSet)
{
    if(deviceHandle)
        UpnpNotifyExt(deviceHandle, DevID, ServID, PropSet);
    if(deviceHandleIPv6)
        UpnpNotifyExt(deviceHandleIPv6, DevID, ServID, PropSet);
    if(deviceHandleIPv6UlaGua)
        UpnpNotifyExt(deviceHandleIPv6UlaGua, DevID, ServID, PropSet);
}

/**
 * Handles subscription request for state variable notifications.
 *  
 * @param sr_event Upnp Subscription Request struct
 * @return 1
 */
int HandleSubscriptionRequest(UpnpSubscriptionRequest *sr_event)
{
    IXML_Document *propSet = NULL;
    const char *serviceId = NULL;
    const char *udn = NULL;
    const char *sid = NULL;

    ithread_mutex_lock(&DevMutex);

    serviceId = UpnpSubscriptionRequest_get_ServiceId_cstr(sr_event);
    udn = UpnpSubscriptionRequest_get_UDN_cstr(sr_event);
    sid = UpnpSubscriptionRequest_get_SID_cstr(sr_event);

    if (wanUDN != NULL && strcmp(udn, wanUDN) == 0)
    {
        // WAN Common Interface Config Device Notifications
        if (strcmp(serviceId, "urn:upnp-org:serviceId:WANCommonIFC1") == 0)
        {
            trace(3, "Received request to subscribe to WANCommonIFC1");
            UpnpAddToPropertySet(&propSet, "PhysicalLinkStatus", "Up");
            AcceptSubscriptionExtForIPv4AndIPv6(udn, serviceId, propSet, sid);
            ixmlDocument_free(propSet);
        }
    }
    else if (wanConnectionUDN != NULL && strcmp(udn, wanConnectionUDN) == 0)
    {
        // WAN IP Connection Device Notifications
        if (strcmp(serviceId, "urn:upnp-org:serviceId:WANIPConn1") == 0)
        {
            GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
            GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
            trace(3, "Received request to subscribe to WANIPConn1");
            UpnpAddToPropertySet(&propSet, "PossibleConnectionTypes","IP_Routed");
            UpnpAddToPropertySet(&propSet, "ExternalIPAddress", ExternalIPAddress);
            UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);

            char tmp[11];
            snprintf(tmp,11,"%ld",SystemUpdateID);
            UpnpAddToPropertySet(&propSet, "SystemUpdateID",tmp);
            snprintf(tmp,11,"%d",PortMappingNumberOfEntries);
            UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries",tmp);

            AcceptSubscriptionExtForIPv4AndIPv6(udn, serviceId, propSet, sid);
            ixmlDocument_free(propSet);
        }
        else if (strcmp(serviceId, "urn:upnp-org:serviceId:WANEthLinkC1") == 0)
        {
            trace(3, "Received request to subscribe to WANEthLinkC1");
            setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);
            UpnpAddToPropertySet(&propSet, "EthernetLinkStatus", EthernetLinkStatus);
            AcceptSubscriptionExtForIPv4AndIPv6(udn, serviceId, propSet, sid);
            ixmlDocument_free(propSet);
        }
        else if (strcmp(serviceId, "urn:upnp-org:serviceId:WANIPv6FwCtrl1") == 0)
        {
            trace(3, "Received request to subscribe to WANIPv6FwCtrl1 UDN : %s, SID : %s", udn, sid);
            snprintf(FirewallEnabled,2,"%i",g_vars.ipv6firewallEnabled);
            snprintf(InboundPinholeAllowed,2,"%i",g_vars.ipv6inboundPinholeAllowed);
            UpnpAddToPropertySet(&propSet, "FirewallEnabled", FirewallEnabled);
            UpnpAddToPropertySet(&propSet, "InboundPinholeAllowed", InboundPinholeAllowed);
            AcceptSubscriptionExtForIPv4AndIPv6(udn, serviceId, propSet, sid);
            ixmlDocument_free(propSet);
        }
    }
    ithread_mutex_unlock(&DevMutex);
    return(1);
}

/**
 * Handles GetVar request for state variables.
 * GET VAR REQUEST DEPRECATED FROM UPnP SPECIFICATIONS!
 * Report this in debug and ignore requests.
 *  
 * @param sr_event Upnp GetVar Request struct
 * @return 1
 */
int HandleGetVarRequest(UpnpStateVarRequest *gv_request)
{
    //If anyone experiences problems please let us know.
    trace(3, "Deprecated Get Variable Request received. Ignoring.");
    return 1;
}

/**
 * Handles action requests for WANCommonIFC1, WANIPConn1, LANHostConfig1 and
 * WANEthLinkC1 services.
 *  
 * @param sr_event Upnp Action Request struct
 * @return Upnp error code.
 */
int HandleActionRequest(UpnpActionRequest *ca_event)
{
    int result = 0;
    const char *devUDN = NULL;
    const char *serviceID = NULL;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    ithread_mutex_lock(&DevMutex);
    devUDN = UpnpActionRequest_get_DevUDN_cstr(ca_event);
    serviceID = UpnpActionRequest_get_ServiceID_cstr(ca_event);
    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);
    trace(3, "ActionName = %s", actionName);

    // check if CP is authorized to use this action.
    // checking managed flag is left to action itself
    if ( AuthorizeControlPoint(ca_event, 0, 1) == CONTROL_POINT_NOT_AUTHORIZED )
    {
        ithread_mutex_unlock(&DevMutex);
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    if (wanUDN != NULL && strcmp(devUDN, wanUDN) == 0)
    {
        if (strcmp(serviceID,"urn:upnp-org:serviceId:WANCommonIFC1") == 0)
        {
            if (strcmp(actionName,"GetTotalBytesSent") == 0)
            {
                if(GetNbSoapParameters(actionRequest) == 0)
		    result = GetTotal(ca_event, STATS_TX_BYTES);
                else
                    addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
            }
            else if (strcmp(actionName,"GetTotalBytesReceived") == 0)
            {
                if(GetNbSoapParameters(actionRequest) == 0)
                    result = GetTotal(ca_event, STATS_RX_BYTES);
                else
                    addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
            }
            else if (strcmp(actionName,"GetTotalPacketsSent") == 0)
            {
                if(GetNbSoapParameters(actionRequest) == 0)
                    result = GetTotal(ca_event, STATS_TX_PACKETS);
                else
                    addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args"); 
            }
            else if (strcmp(actionName,"GetTotalPacketsReceived") == 0)
            {
                if(GetNbSoapParameters(actionRequest) == 0)
                    result = GetTotal(ca_event, STATS_RX_PACKETS);
                else
                    addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
            }
            else if (strcmp(actionName,"GetCommonLinkProperties") == 0)
                result = GetCommonLinkProperties(ca_event);
            else
            {
                trace(1, "Invalid Action Request : %s",actionName);
                result = InvalidAction(ca_event);
            }
        }
    }
    else if (wanConnectionUDN !=NULL && strcmp(devUDN, wanConnectionUDN) == 0)
    {
        if (strcmp(serviceID, "urn:upnp-org:serviceId:WANIPConn1") == 0)
        {
            if (strcmp(actionName,"GetConnectionTypeInfo") == 0)
                result = GetConnectionTypeInfo(ca_event);
            else if (strcmp(actionName,"GetNATRSIPStatus") == 0)
                result = GetNATRSIPStatus(ca_event);
            else if (strcmp(actionName,"SetConnectionType") == 0)
                result = SetConnectionType(ca_event);
            else if (strcmp(actionName,"RequestConnection") == 0)
                result = RequestConnection(ca_event);
            else if (strcmp(actionName,"AddPortMapping") == 0)
                result = AddPortMapping(ca_event);
            else if (strcmp(actionName,"GetGenericPortMappingEntry") == 0)
                result = GetGenericPortMappingEntry(ca_event);
            else if (strcmp(actionName,"GetSpecificPortMappingEntry") == 0)
                result = GetSpecificPortMappingEntry(ca_event);
            else if (strcmp(actionName,"GetExternalIPAddress") == 0)
                result = GetExternalIPAddress(ca_event);
            else if (strcmp(actionName,"DeletePortMapping") == 0)
                result = DeletePortMapping(ca_event);
            else if (strcmp(actionName,"GetStatusInfo") == 0)
                result = GetStatusInfo(ca_event);
            else if (strcmp(actionName,"DeletePortMappingRange") == 0)
                result = DeletePortMappingRange(ca_event);
            else if (strcmp(actionName,"AddAnyPortMapping") == 0)
                result = AddAnyPortMapping(ca_event);
            else if (strcmp(actionName,"GetListOfPortMappings") == 0)
                result = GetListOfPortmappings(ca_event);
            else if (strcmp(actionName,"ForceTermination") == 0)
                result = ForceTermination(ca_event);
            else if (strcmp(actionName,"RequestTermination") == 0)
                result = RequestTermination(ca_event);
            else if (strcmp(actionName,"SetAutoDisconnectTime") == 0)
                result = SetAutoDisconnectTime(ca_event);
            else if (strcmp(actionName,"SetIdleDisconnectTime") == 0)
                result = SetIdleDisconnectTime(ca_event);
            else if (strcmp(actionName,"SetWarnDisconnectDelay") == 0)
                result = SetWarnDisconnectDelay(ca_event);
            else if (strcmp(actionName,"GetAutoDisconnectTime") == 0)
                result = GetAutoDisconnectTime(ca_event);
            else if (strcmp(actionName,"GetIdleDisconnectTime") == 0)
                result = GetIdleDisconnectTime(ca_event);
            else if (strcmp(actionName,"GetWarnDisconnectDelay") == 0)
                result = GetWarnDisconnectDelay(ca_event);
            else result = InvalidAction(ca_event);
        }
        else if (strcmp(serviceID,"urn:upnp-org:serviceId:WANEthLinkC1") == 0)
        {
            if (strcmp(actionName,"GetEthernetLinkStatus") == 0)
                result = GetEthernetLinkStatus(ca_event);
            else
            {
                trace(1, "Invalid Action Request : %s",actionName);
                result = InvalidAction(ca_event);
            }
        }
        /**
         * Added for WANIPv6FirewallControl
         */
        else if (strcmp(serviceID,"urn:upnp-org:serviceId:WANIPv6FwCtrl1") == 0)
        {
            if (strcmp(actionName,"GetFirewallStatus") == 0)
                result = upnp_wanipv6_getFirewallStatus(ca_event);
            else if (strcmp(actionName,"GetOutboundPinholeTimeout") == 0)
                result = upnp_wanipv6_getOutboundPinholeTimeOut(ca_event);
            else if (strcmp(actionName,"AddPinhole") == 0)
                result = upnp_wanipv6_addPinhole(ca_event);
            else if (strcmp(actionName,"UpdatePinhole") == 0)
                result = upnp_wanipv6_updatePinhole(ca_event);
            else if (strcmp(actionName,"DeletePinhole") == 0)
                result = upnp_wanipv6_deletePinhole(ca_event);
            else if (strcmp(actionName,"GetPinholePackets") == 0)
                result = upnp_wanipv6_getPinholePackets(ca_event);
            else if (strcmp(actionName,"CheckPinholeWorking") == 0)
                result = upnp_wanipv6_checkPinholeWorking(ca_event);
            else
            {
                trace(1, "Invalid Action Request : %s",actionName);
                result = InvalidAction(ca_event);
            }
        }
    }
    else if (lanUDN !=NULL && strcmp(devUDN, lanUDN) == 0)
    {
        if (strcmp(serviceID,"urn:upnp-org:serviceId:LANHostConfig1") == 0)
        {
            if (strcmp(actionName,"SetDHCPServerConfigurable") == 0)
                result = SetDHCPServerConfigurable(ca_event);
            else if (strcmp(actionName,"GetDHCPServerConfigurable") == 0)
                result = GetDHCPServerConfigurable(ca_event);
            else if (strcmp(actionName,"SetDHCPRelay") == 0)
                result = SetDHCPRelay(ca_event);
            else if (strcmp(actionName,"GetDHCPRelay") == 0)
                result = GetDHCPRelay(ca_event);
            else if (strcmp(actionName,"SetSubnetMask") == 0)
                result = SetSubnetMask(ca_event);
            else if (strcmp(actionName,"GetSubnetMask") == 0)
                result = GetSubnetMask(ca_event);
            else if (strcmp(actionName,"SetIPRouter") == 0)
                result = SetIPRouter(ca_event);
            else if (strcmp(actionName,"DeleteIPRouter") == 0)
                result = DeleteIPRouter(ca_event);
            else if (strcmp(actionName,"GetIPRoutersList") == 0)
                result = GetIPRoutersList(ca_event);
            else if (strcmp(actionName,"SetDomainName") == 0)
                result = SetDomainName(ca_event);
            else if (strcmp(actionName,"GetDomainName") == 0)
                result = GetDomainName(ca_event);
            else if (strcmp(actionName,"SetAddressRange") == 0)
                result = SetAddressRange(ca_event);
            else if (strcmp(actionName,"GetAddressRange") == 0)
                result = GetAddressRange(ca_event);
            else if (strcmp(actionName,"SetReservedAddress") == 0)
                result = SetReservedAddress(ca_event);
            else if (strcmp(actionName,"DeleteReservedAddress") == 0)
                result = DeleteReservedAddress(ca_event);
            else if (strcmp(actionName,"GetReservedAddresses") == 0)
                result = GetReservedAddresses(ca_event);
            else if (strcmp(actionName,"SetDNSServer") == 0)
                result = SetDNSServer(ca_event);
            else if (strcmp(actionName,"DeleteDNSServer") == 0)
                result = DeleteDNSServer(ca_event);
            else if (strcmp(actionName,"GetDNSServers") == 0)
                result = GetDNSServers(ca_event);
            else
            {
                trace(1, "Action not supported: %s",actionName);
                result = InvalidAction(ca_event);
            }
        }
    }

    ithread_mutex_unlock(&DevMutex);

    return (result);
}

/**
 * Default Action when we receive unknown Action Requests
 *  
 * @param sr_event Upnp Action Request struct
 * @return Upnp error code 401.
 */
int InvalidAction(UpnpActionRequest *ca_event)
{
    UpnpActionRequest_set_ErrCode(ca_event, 401);
    UpnpActionRequest_strcpy_ErrStr(ca_event, "Invalid Action");
    UpnpActionRequest_set_ActionResult(ca_event, NULL);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

//-----------------------------------------------------------------------------
//
//                      WANCommonInterfaceConfig:1 Service Actions
//
//-----------------------------------------------------------------------------
/**
 * WANCommonInterfaceConfig:1 Action: GetCommonLinkProperties
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetCommonLinkProperties(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetCommonLinkProperties invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult (ca_event, "<NewWANAccessType>Cable</NewWANAccessType>\n"
        "<NewLayer1UpstreamMaxBitRate>%s</NewLayer1UpstreamMaxBitRate>\n"
        "<NewLayer1DownstreamMaxBitRate>%s</NewLayer1DownstreamMaxBitRate>\n"
        "<NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>\n",
        g_vars.upstreamBitrate, g_vars.downstreamBitrate);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANCommonInterfaceConfig:1 Actions: GetTotalBytesSent
 *                                     GetTotalBytesReceived
 *                                     GetTotalPacketsSent
 *                                     GetTotalPacketsReceived
 * 
 * Get specified statistic from /proc/net/dev.
 * 
 * @param ca_event Upnp event struct.
 * @param stat Which value is read from /proc
 * @return Upnp error code.
 */
int GetTotal(UpnpActionRequest *ca_event, stats_t stat)
{
    const char *methods[STATS_LIMIT] =
        { "BytesSent", "BytesReceived", "PacketsSent", "PacketsReceived" };
    unsigned long stats[STATS_LIMIT];

    if (!readStats(stats))
    {
        trace(1, "Error reading stats for GetTotal");
        UpnpActionRequest_set_ActionResult(ca_event, NULL);
        UpnpActionRequest_set_ErrCode(ca_event, 501);
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event, "<NewTotal%s>%lu</NewTotal%s>\n",
        methods[stat], stats[stat], methods[stat]);

    return UpnpActionRequest_get_ErrCode(ca_event);
}


//-----------------------------------------------------------------------------
//
//                      WANIPConnection:2 Service Actions
//
//-----------------------------------------------------------------------------

/**
 * WANIPConnection:2 Action: GetStatusInfo
 * 
 * Returns connection status related information to the control points.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetStatusInfo(UpnpActionRequest *ca_event)
{
    long int uptime;

    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetStatusInfo invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    // If connection is not connected, uptime value is 0
    if (strcmp(ConnectionStatus, "Connected") == 0)
        uptime = (time(NULL) - startup_time);
    else
        uptime = 0;

    ParseResult(ca_event, "<NewConnectionStatus>%s</NewConnectionStatus>\n"
        "<NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\n"
        "<NewUptime>%ld</NewUptime>\n",
        ConnectionStatus, uptime);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetConnectionTypeInfo
 * 
 * As IP_Routed is the only relevant Connection Type for Linux-IGD
 * we respond with IP_Routed as both current type and only type
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetConnectionTypeInfo (UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0) {
        trace(1, "GetConnectionTypeInfo invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event, "<NewConnectionType>IP_Routed</NewConnectionType>\n"
         "<NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>");

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetNATRSIPStatus
 * 
 * Linux-IGD does not support RSIP.  However NAT is of course so respond with NewNATEnabled = 1
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetNATRSIPStatus(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0) {
        trace(1, "GetNATRSIPStatus invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event, "<NewRSIPAvailable>0</NewRSIPAvailable>\n"
         "<NewNATEnabled>1</NewNATEnabled>\n");

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: SetConnectionType
 * 
 * Connection Type is a Read Only Variable as linux-igd is only
 * a device that supports a NATing IP router (not an Ethernet
 * bridge).  Possible other uses may be explored.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetConnectionType(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 1)
    {
        trace(1, "SetConnectionType invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    UpnpActionRequest_set_ErrCode(ca_event, 731);
    UpnpActionRequest_strcpy_ErrStr(ca_event, "ReadOnly");
    UpnpActionRequest_set_ActionResult(ca_event, NULL);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: SetAutoDisconnectTime
 * 
 * This action sets value of the AutoDisconnectTime state variable.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetAutoDisconnectTime(UpnpActionRequest *ca_event)
{
    char *delay_str = NULL;
    long int delay;
    int result = 0;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((delay_str = GetFirstDocumentItem(actionRequest, "NewAutoDisconnectTime")) &&
            (GetNbSoapParameters(actionRequest)==1))
    {
        delay = atol(delay_str);
        if (delay < 0)
        {
            trace(1, "%s: Argument value out of range",actionName);
            result = 601;
            addErrorData(ca_event, 601, "Argument Value Out of Range");
        }
        else
        {
            AutoDisconnectTime = delay;
            trace(2, "%s: WAN connection AutoDisconnectTime set to %ld seconds.",actionName, AutoDisconnectTime);
        }

        if (result == 0)
        {
            if (createAutoDisconnectTimer() == 0)
            {
                // create response SOAP message
                ParseResult(ca_event, ""); 
            }
            else
            {
                trace(1, "%s: Failed to create AutoDisconnect timer",actionName);
                addErrorData(ca_event, 501, "Action Failed");
            }
        }
    }
    else
    {
        trace(1, "%s: Invalid Args",actionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }
    free (delay_str);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: SetIdleDisconnectTime
 * 
 * This action sets value of the IdleDisconnectTime state variable.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetIdleDisconnectTime(UpnpActionRequest *ca_event)
{
    char *delay_str = NULL;
    long int delay;
    int result = 0;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((delay_str = GetFirstDocumentItem(actionRequest, "NewIdleDisconnectTime")) &&
            (GetNbSoapParameters(actionRequest)==1))
    {
        delay = atol(delay_str);
        if (delay < 0)
        {
            trace(1, "%s: Argument value out of range",actionName);
            result = 601;
            addErrorData(ca_event, 601, "Argument Value Out of Range");
        }
        else
        {
            IdleDisconnectTime = delay;
            trace(2, "%s: WAN connection IdleDisconnectTime set to %ld seconds.",actionName, IdleDisconnectTime);
        }

        if (result == 0)
        {
            // create response SOAP message
            ParseResult(ca_event, "");            
        }
    }
    else
    {
        trace(1, "%s: Invalid Args",actionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }
    free (delay_str);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: SetWarnDisconnectDelay
 * 
 * This action sets value of the WarnDisconnectDelay state variable.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetWarnDisconnectDelay(UpnpActionRequest *ca_event)
{
    char *delay_str = NULL;
    long int delay;
    int result = 0;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((delay_str = GetFirstDocumentItem(actionRequest, "NewWarnDisconnectDelay")) &&
           (GetNbSoapParameters(actionRequest)==1))
    {
        delay = atol(delay_str);
        if (delay < 0)
        {
            trace(1, "%s: Argument value out of range",actionName);
            result = 601;
            addErrorData(ca_event, 601, "Argument Value Out of Range");
        }
        else
        {
            WarnDisconnectDelay = delay;
            trace(2, "%s: WAN connection WarnDisconnectDelay set to %ld seconds.",actionName, WarnDisconnectDelay);
        }

        if (result == 0)
        {
            // create response SOAP message
            ParseResult(ca_event, "");
        }

    }
    else
    {
        trace(1, "%s: Invalid Args",actionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }
    free (delay_str);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: GetAutoDisconnectTime
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetAutoDisconnectTime(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetAutoDisconnectTime invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event,
        "<NewAutoDisconnectTime>%ld</NewAutoDisconnectTime>\n",
        AutoDisconnectTime);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: GetIdleDisconnectTime
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetIdleDisconnectTime(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetIdleDisconnectTime invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event, 
        "<NewIdleDisconnectTime>%ld</NewIdleDisconnectTime>\n", 
        IdleDisconnectTime);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: GetWarnDisconnectDelay
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetWarnDisconnectDelay(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetWarnDisconnectDelay invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    ParseResult(ca_event,
        "<NewWarnDisconnectDelay>%ld</NewWarnDisconnectDelay>\n",    
        WarnDisconnectDelay);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: RequestConnection
 * 
 * Start DHCP Client and try to acquire IP-address.
 * If external interface has IP, assume that status is Connected, else Disconnected.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int RequestConnection(UpnpActionRequest *ca_event)
{
    IXML_Document *propSet = NULL;
    int result = 0;
    const char *devUDN = NULL;
    const char *serviceID = NULL;
    const char *actionName = NULL;

    devUDN = UpnpActionRequest_get_DevUDN_cstr(ca_event);
    serviceID = UpnpActionRequest_get_ServiceID_cstr(ca_event);
    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);

    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "RequestConnection invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    // create result document for succesfull cases. addErrorData overwrites this if no success
    ParseResult(ca_event, "");

    trace(2, "RequestConnection received ... Checking status...");

    //Immediatley Set lastconnectionerror to none. We don't now care about errors.
    strcpy(LastConnectionError, "ERROR_NONE");

    // connection already up. Nothing to do. Return success
    if (strcmp(ConnectionStatus,"Connected") == 0)
    {
        trace(2, "%s: Connection is already connected",actionName);
        return UpnpActionRequest_get_ErrCode(ca_event);
    }
    else if (strcmp(ConnectionType,"IP_Routed") != 0)
    {
        trace(1, "%s: ConnectionType must be IP_Routed. Type: %s",actionName, ConnectionType);
        result = 710;
        addErrorData(ca_event, result, "InvalidConnectionType");
    }
    else if (strcmp(ConnectionStatus,"Disconnecting") == 0)
    {
        trace(1, "%s: Connection of %s is disconnecting",actionName, g_vars.extInterfaceName);
        result = 707;
        addErrorData(ca_event, result, "DisconnectInProgress");
    }
    else if (strcmp(ConnectionStatus,"Connecting") == 0)
    {
        trace(1, "%s: Connection of %s is connecting",actionName, g_vars.extInterfaceName);
        result = 705;
        addErrorData(ca_event, result, "ConnectionSetupInProgress");
    }
    else if (strcmp(ConnectionStatus,"PendingDisconnect") == 0)
    {
        trace(1, "%s: Connection of %s is pending disconnect. Setting state back to Connected.",actionName, g_vars.extInterfaceName);
        strcpy(ConnectionStatus, "Connected");
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);
        ixmlDocument_free(propSet);
        propSet = NULL;

        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    if (result == 0)
    {
        strcpy(ConnectionStatus, "Connecting");
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);
        ixmlDocument_free(propSet);
        propSet = NULL;
        trace(2, "RequestConnection received ... Connecting..");

        if (startDHCPClient(g_vars.extInterfaceName))
            UpnpActionRequest_set_ErrCode(ca_event, UPNP_E_SUCCESS);
        else
        {
            trace(1, "%s: Connection set up failed",actionName, g_vars.extInterfaceName);
            result = 704;
            addErrorData(ca_event, result, "ConnectionSetupFailed");
        }

        GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
        // Build DOM Document with state variable connectionstatus and event it
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        // Send off notifications of state change
        NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);

        // if new status is connected, we create autodisconnecttimer and set startup time for Uptime statevariable
        if (strcmp(ConnectionStatus, "Connected") == 0)
        {
            createAutoDisconnectTimer();
            // Record the startup time, for uptime
            startup_time = time(NULL);
        }
    }

    ixmlDocument_free(propSet);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: ForceTermination
 * 
 * Force termination of WAN-connection immediatedly. (i.e. try to release IP of external interface 
 * by killing DHCP-client).
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int ForceTermination(UpnpActionRequest *ca_event)
{
    int result = 0;
    const char *actionName = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);

    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "ForceTermination invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    if (strcmp(ConnectionStatus,"Disconnecting") == 0)
    {
        trace(1, "%s: Connection of %s already disconnecting", actionName, g_vars.extInterfaceName);
        result = 707;
        addErrorData(ca_event, result, "DisconnectInProgress");
    }

    // if ok to continue termination
    if (result == 0)
    {
        return ConnectionTermination(ca_event, 0);
    }

    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: RequestTermination
 * 
 * Terminate WAN connection after WarnDisconnectDelay.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int RequestTermination(UpnpActionRequest *ca_event)
{
    int result = 0;
    long int delay = WarnDisconnectDelay;
    const char *actionName = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);

    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "RequestTermination invalid number of parameters");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    if (strcmp(ConnectionStatus,"Disconnecting") == 0 || strcmp(ConnectionStatus,"PendingDisconnect") == 0) 
    {
        trace(1, "%s: Connection of %s already disconnecting", actionName, g_vars.extInterfaceName);
        result = 707;
        addErrorData(ca_event, result, "DisconnectInProgress");
    }
    else if (strcmp(ConnectionStatus,"Connecting") == 0) 
    {
        trace(3, "%s: Connection of %s Connecting. WarnDisconnectDelay is now ignored", actionName, g_vars.extInterfaceName);
        delay = 0;
    }

    // if ok to continue termination
    if (result == 0)
    {
        return ConnectionTermination(ca_event, delay);
    }

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: AddPortMapping
 * 
 * Add New Port Map to the IGD
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int AddPortMapping(UpnpActionRequest *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    char *int_port=NULL;
    char *int_client=NULL;
    char *long_duration=NULL;
    char *bool_enabled=NULL;
    char *desc=NULL;
    struct portMap *ret;
    int result = 0;
    int update_portmap = 0;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ( (remote_host = GetFirstDocumentItem(actionRequest, "NewRemoteHost") )
            && (ext_port = GetFirstDocumentItem(actionRequest, "NewExternalPort") )
            && (proto = GetFirstDocumentItem(actionRequest, "NewProtocol") )
            && (int_port = GetFirstDocumentItem(actionRequest, "NewInternalPort") )
            && (int_client = GetFirstDocumentItem(actionRequest, "NewInternalClient") )
            && (long_duration = GetFirstDocumentItem(actionRequest, "NewLeaseDuration") )
            && (bool_enabled = GetFirstDocumentItem(actionRequest, "NewEnabled") )
            && (isStringInteger(ext_port) )
            && (isStringInteger(int_port) )
            && (isStringInteger(long_duration) )
            && (GetNbSoapParameters(actionRequest) == 8 )
            && (desc = GetFirstDocumentItem(actionRequest, "NewPortMappingDescription") ) )
    {
        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0))
            || (atoi(ext_port) < 0)
            || (atoi(int_port) < 1 || atoi(int_port) > 65535)
            || (atol(long_duration) < 0 || atol(long_duration) > 604800))
        {
            trace(1, "%s: Argument value out of range:  ExtPort: %s RemHost: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
                    actionName, ext_port, remote_host, proto, int_port, int_client, long_duration, bool_enabled, desc);
            result = 601;
            addErrorData(ca_event, result, "Argument Value Out of Range");
        }
        else if ( ((strcmp(remote_host, "") != 0) && !IsIpOrDomain(remote_host)) || !IsIpOrDomain(int_client) )
        {
            trace(1, "%s: RemoteHost or InternalClient Argument Value Invalid:  ExtPort: %s RemHost: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
                    actionName, ext_port, remote_host, proto, int_port, int_client, long_duration, bool_enabled, desc);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        // If ext_port or int_port is <1024 control point needs to be authorized
        else if ((atoi(ext_port) < 1024 || atoi(int_port) < 1024 || !ControlPointIP_equals_InternalClientIP(int_client, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)))
             && AuthorizeControlPoint(ca_event, 1, 0) != CONTROL_POINT_AUTHORIZED)
        {
            trace(1, "Port numbers must be greater than 1023 and NewInternalClient must be same as IP of Control point \
unless control port is authorized. external_port:%s, internal_port:%s internal_client:%s",
                  ext_port, int_port, int_client);
            result = 606;
            addErrorData(ca_event, result, "Action not authorized");
        }

        // Check RemoteHost and InternalPort parameters
        else if (checkForWildCard(int_client)) 
        {
            trace(1, "Wild cards not permitted in internal_client:%s", int_client);
            result = 715;
            addErrorData(ca_event, result, "WildCardNotPermittedInSrcIp");
        }
        else if (checkForWildCard(ext_port)) // Not sure if this is really needed
        {
            trace(1, "Wild cards not permitted in external_port:%s", ext_port);
            result = 716;
            addErrorData(ca_event, result, "WildCardNotPermittedInExtPort");
        }
        else if (checkForWildCard(int_port)) 
        {
            trace(1, "Wild cards not permitted in internal_port:%s", int_port);
            result = 732;
            addErrorData(ca_event, result, "WildCardNotPermittedInIntPort");
        }

        // parameters are OK
        if (result == 0)
        {
            // If port map with the same External Port, Protocol, Internal Client and remoteHost exists
            // then, as per spec, we overwrite it (for simplicity, we delete and re-add at end of list)
            // Note: This may cause problems with GetGernericPortMappingEntry if a CP expects the overwritten
            // to be in the same place.
            if ((ret = pmlist_Find(remote_host, ext_port, proto, int_client)) != NULL)
            {
                trace(3, "Found port map to already exist for this client.  Replacing");
                pmlist_Delete(ret);
                update_portmap = 1;
            }

            // If the ExternalPort and PortMappingProtocol pair is already mapped to another 
            // internal client, an error is returned.
            else if ((ret = pmlist_FindBy_extPort_proto(ext_port, proto)) != NULL && 
                    strcmp(ret->m_InternalClient, int_client) != 0)
            {
                trace(1, "Portmapping with same external port '%s' and protocol '%s' are mapped to another client already.\n",ext_port,proto);
                result = 718;
                addErrorData(ca_event, result, "ConflictInMappingEntry");
            }

            // if still no errors happened, add new portmapping
            if (result == 0)
                result = AddNewPortMapping(ca_event,bool_enabled,atol(long_duration),remote_host,ext_port,int_port,proto,int_client,desc,update_portmap);

            // create response message if success, AddNewPortMapping adds error to response if it fails
            if (result == 1)
            {
                // create response SOAP message
                ParseResult(ca_event, "");
            }
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceAddPortMapping: Invalid Arguments!");
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(ext_port);
    free(int_port);
    free(proto);
    free(int_client);
    free(bool_enabled);
    free(desc);
    free(remote_host);
    free(long_duration);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

 /**
 * WANIPConnection:2 Action: AddAnyPortMapping
 * 
 * Like AddPortMapping() action, AddAnyPortMapping() action also creates a port mapping 
 * specified with the same arguments. The behaviour differs only on the case where the 
 * specified port is not free, because in that case the gateway reserves any free 
 * NewExternalPort and NewProtocol pair and returns the NewReservedPort.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int AddAnyPortMapping(UpnpActionRequest *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    char *int_port = NULL;
    char *int_client=NULL;
    char *bool_enabled=NULL;
    char *desc=NULL;
    char *long_duration=NULL;
    int next_free_port = 0;
    struct portMap *ret;
    int result = 0;
    char freePort[5];
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ( (remote_host = GetFirstDocumentItem(actionRequest, "NewRemoteHost") )
            && (ext_port = GetFirstDocumentItem(actionRequest, "NewExternalPort") )
            && (proto = GetFirstDocumentItem(actionRequest, "NewProtocol") )
            && (int_port = GetFirstDocumentItem(actionRequest, "NewInternalPort") )
            && (int_client = GetFirstDocumentItem(actionRequest, "NewInternalClient") )
            && (bool_enabled = GetFirstDocumentItem(actionRequest, "NewEnabled") )
            && (desc = GetFirstDocumentItem(actionRequest, "NewPortMappingDescription") )
            && (long_duration = GetFirstDocumentItem(actionRequest, "NewLeaseDuration") )
            && (isStringInteger(ext_port) )
            && (isStringInteger(int_port) )
            && (isStringInteger(long_duration) )
            && (GetNbSoapParameters(actionRequest) == 8) )
    {
        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0))
            || (atoi(ext_port) < 0)
            || (atoi(int_port) < 1 && atoi(int_port) > 65535)
            || (atol(long_duration) < 0 && atol(long_duration) > 604800) )
        {
            trace(1, "%s: Argument value out of range:  ExtPort: %s RemHost: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
                    actionName, ext_port, remote_host, proto, int_port, int_client, long_duration, bool_enabled, desc);
            result = 601;
            addErrorData(ca_event, result, "Argument Value Out of Range");
        }
        else if ( ((strcmp(remote_host, "") != 0) && !IsIpOrDomain(remote_host)) || !IsIpOrDomain(int_client) )
        {
            trace(1, "%s: RemoteHost or InternalClient Argument Value Invalid:  ExtPort: %s RemHost: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
                    actionName, ext_port, remote_host, proto, int_port, int_client, long_duration, bool_enabled, desc);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        // If ext_port or int_port is <1024 control point needs to be authorized
        else if ((atoi(ext_port) < 1024 || atoi(int_port) < 1024 || !ControlPointIP_equals_InternalClientIP(int_client, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)))
             && AuthorizeControlPoint(ca_event, 1, 0) != CONTROL_POINT_AUTHORIZED)
        {
            trace(1, "Port numbers must be greater than 1023 and NewInternalClient must be same as IP of Control point \
unless control port is authorized. external_port:%s, internal_port:%s internal_client:%s",
                  ext_port, int_port, int_client);
            result = 606;
            addErrorData(ca_event, result, "Action not authorized");
        }

        // Check Internal client and Port parameters
        else if (checkForWildCard(int_client)) 
        {
            trace(1, "Wild cards not permitted in internal_client:%s", int_client);
            result = 715;
            addErrorData(ca_event, result, "WildCardNotPermittedInSrcIp");
        }
        else if (checkForWildCard(ext_port))
        {
            trace(1, "Wild cards not permitted in external_port:%s", ext_port);
            result = 716;
            addErrorData(ca_event, result, "WildCardNotPermittedInExtPort");
        }
        else if (checkForWildCard(int_port)) 
        {
            trace(1, "Wild cards not permitted in internal_port:%s", int_port);
            result = 732;
            addErrorData(ca_event, result, "WildCardNotPermittedInIntPort");
        }

        // Parameters OK... proceed with adding port map
        if (result == 0)
            {
                // If port map with the same External Port, Protocol, Internal Client and RemoteHost exists
                // we should just update it, NOT create new
                if ((ret = pmlist_Find(remote_host, ext_port, proto, int_client)) != NULL)
                {
                    trace(3, "Port map with same ExternalPort, Protocol, InternalClient and RemoteHost exists. Updating existing.");
                    // update existing (Remove old one and after that create new one with new values)
                    // TODO: Create functions which really updates existing portmappings found from iptables
                    //       Or at least find out if it is even possible.
                    pmlist_Delete(ret);

                    result = AddNewPortMapping(ca_event, bool_enabled, atol(long_duration), remote_host,
                                                ext_port, int_port, proto,
                                                int_client, desc, 1);
                }
                // Else if port mapping using same external port and protocol,
                // get new external port and create new port mapping
                else if (!checkForWildCard(ext_port) && (ret = pmlist_FindBy_extPort_proto(ext_port, proto)) != NULL)
                {
                    // Find searches free external port...
                    trace(3, "Port map with same ExternalPort and protocol exists. Finding next free ExternalPort...");
                    next_free_port = pmlist_FindNextFreePort(proto);
                    if (next_free_port > 0)
                    {
                        trace(3, "Found free port:%d", next_free_port);
                        sprintf(freePort, "%d", next_free_port);
                        result = AddNewPortMapping(ca_event, bool_enabled, atol(long_duration), remote_host,
                                                    freePort, int_port, proto,
                                                    int_client, desc, 0);
                    }
                    else 
                    {
                        result = 728; /* no free port found... use NoPortMapsAvailable error code */
                    }
                }
                else 
                {
                    // Otherwise just add the port map
                    result = AddNewPortMapping(ca_event, bool_enabled, atol(long_duration), remote_host,
                                                ext_port, int_port, proto,
                                                int_client, desc, 0);
                }
        }
        if (result==728)
        {
            trace(1,"Failure in GateDeviceAddAnyPortMapping: RemoteHost: %s Protocol:%s ExternalPort: %s InternalClient: %s.%s\n",
                    remote_host, proto, ext_port, int_client, int_port);

            addErrorData(ca_event, 728, "NoPortMapsAvailable");
        }

    }
    else
    {
        trace(1, "Failure in GateDeviceAddAnyPortMapping: Invalid Arguments!");
        trace(1, "  RemoteHost: %s ExternalPort: %s Protocol: %s InternalClient: %s Enabled: %s PortMappingDesc: %s LeaseDuration: %s",
                remote_host, ext_port, proto, int_client, bool_enabled, desc, long_duration);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    if (result == 1)
    {
        UpnpActionRequest_set_ErrCode(ca_event, UPNP_E_SUCCESS);
        // Port mapping has been done for external port that control point wanted
        if (next_free_port == 0) next_free_port = atoi(ext_port);

        ParseResult(ca_event, "<NewReservedPort>%d</NewReservedPort>\n",
            next_free_port);
    }

    free(remote_host);
    free(ext_port);
    free(proto);
    free(int_port);
    free(int_client);
    free(bool_enabled);
    free(desc);
    free(long_duration);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetGenericPortMappingEntry
 * 
 * This action retrieves NAT port mappings one entry at a time.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetGenericPortMappingEntry(UpnpActionRequest *ca_event)
{
    char *mapindex = NULL;
    struct portMap *temp;
    char result_param[RESULT_LEN];
    int action_succeeded = 0;
    IXML_Document *actionRequest = NULL;

    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((mapindex = GetFirstDocumentItem(actionRequest, "NewPortMappingIndex"))
            && (GetNbSoapParameters(actionRequest) == 1)
            && (isStringInteger(mapindex)) )
    {
        temp = pmlist_FindByIndex(atoi(mapindex));
        // if portmapping is found, we must check if CP is authorized OR if internalclient value of portmapping matches IP of CP
        // Also if CP is not authorized NewInternalPort and NewExternalPort values of the port mapping entry must be greater than or equal to 1024,
        // else empty values are returned 
        if (temp && (AuthorizeControlPoint(ca_event, 1, 0) == CONTROL_POINT_AUTHORIZED || 
                        (ControlPointIP_equals_InternalClientIP(temp->m_InternalClient, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)) && 
                         atoi(temp->m_ExternalPort) > 1023 && atoi(temp->m_InternalPort) > 1023)
                     )
            )
        {
            snprintf(result_param, RESULT_LEN, "<NewRemoteHost>%s</NewRemoteHost>\n"
                "<NewExternalPort>%s</NewExternalPort>\n"
                "<NewProtocol>%s</NewProtocol>\n"
                "<NewInternalPort>%s</NewInternalPort>\n"
                "<NewInternalClient>%s</NewInternalClient>\n"
                "<NewEnabled>%d</NewEnabled>\n"
                "<NewPortMappingDescription>%s</NewPortMappingDescription>\n"
                "<NewLeaseDuration>%li</NewLeaseDuration>\n",
                temp->m_RemoteHost,
                temp->m_ExternalPort,
                temp->m_PortMappingProtocol,
                temp->m_InternalPort,
                temp->m_InternalClient,
                temp->m_PortMappingEnabled,
                temp->m_PortMappingDescription,
                (temp->m_IsStatic == 1)?0:(temp->expirationTime-time(NULL)));
            action_succeeded = 1;
        }
        else if (!temp) // nothing in that index
        {
            trace(1, "GetGenericPortMappingEntry: SpecifiedArrayIndexInvalid");
            addErrorData(ca_event, 713, "SpecifiedArrayIndexInvalid");
        }
        else // not authorized and IP's doesn't match or too small portnumbers
        {
            trace(1, "GetGenericPortMappingEntry: Not authorized user and Control point IP and portmapping internal client doesn't mach or portnumbers of portmapping are under 1024");
            addErrorData(ca_event, 606, "Action not authorized");
        }

        if (action_succeeded)
        {
            ParseResult(ca_event, result_param);
        }

    }
    else
    {
        trace(1, "Failure in GetGenericPortMappingEntry: Invalid Args");
        addErrorData(ca_event, 402, "Invalid Args");
    }
    free (mapindex);
    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetSpecificPortMappingEntry
 * 
 * This action reports the port mapping specified by the unique tuple of RemoteHost, 
 * ExternalPort and PortMappingProtocol.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetSpecificPortMappingEntry(UpnpActionRequest *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    char result_param[RESULT_LEN];
    int action_succeeded = 0;
    struct portMap *temp;
    int authorized = 0;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((remote_host = GetFirstDocumentItem(actionRequest, "NewRemoteHost")) &&
            (ext_port = GetFirstDocumentItem(actionRequest, "NewExternalPort")) &&
            (GetNbSoapParameters(actionRequest)==3) &&
            (isStringInteger(ext_port)) &&
            (proto = GetFirstDocumentItem(actionRequest,"NewProtocol")) )
    {
        //check if authorized
        if (AuthorizeControlPoint(ca_event, 1, 0) == CONTROL_POINT_AUTHORIZED)
        {
            authorized = 1;
        }

        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0)) || 
            (atoi(ext_port) < 0) )
        {
            trace(1, "%s: Argument value out of range",actionName);
            addErrorData(ca_event, 601, "Argument Value Out of Range");
        }
        else if ((strcmp(remote_host, "") != 0) && !IsIpOrDomain(remote_host))
        {
            trace(1, "%s: Argument Value Invalid");
            addErrorData(ca_event, 600, "Argument Value Invalid");
        }
        else if (!authorized && (atoi(ext_port) < 1024))
        {
            trace(1, "Failure in GetSpecificPortMappingEntry: Action not authorized\n");
            addErrorData(ca_event, 606, "Action not authorized");
        }
        // if portmapping is found, we must check if CP is authorized OR if internalclient value of portmapping matches IP of CP
        // Also if CP is not authorized NewInternalPort and NewExternalPort values of the port mapping entry must be greater than or equal to 1024,
        // else error is returned 
        else if ((temp = pmlist_FindSpecific (remote_host, ext_port, proto)) && (authorized || 
                        (ControlPointIP_equals_InternalClientIP(temp->m_InternalClient, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)) && 
                         atoi(temp->m_ExternalPort) > 1023 && atoi(temp->m_InternalPort) > 1023)
                     )
            )
        {
            snprintf(result_param, RESULT_LEN, "<NewInternalPort>%s</NewInternalPort>\n"
                "<NewInternalClient>%s</NewInternalClient>\n"
                "<NewEnabled>%d</NewEnabled>\n"
                "<NewPortMappingDescription>%s</NewPortMappingDescription>\n"
                "<NewLeaseDuration>%li</NewLeaseDuration>\n",
                temp->m_InternalPort,
                temp->m_InternalClient,
                temp->m_PortMappingEnabled,
                temp->m_PortMappingDescription,
                (temp->m_IsStatic == 1)?0:(temp->expirationTime-time(NULL)));
            action_succeeded = 1;
        }
        else if (!temp)
        {
            trace(2, "GateDeviceGetSpecificPortMappingEntry: PortMapping Doesn't Exist...");
            addErrorData(ca_event, 714, "NoSuchEntryInArray");
        }
        else
        {
            trace(1, "Failure in GetSpecificPortMappingEntry: Action not authorized\n");
            addErrorData(ca_event, 606, "Action not authorized");
        }

        if (action_succeeded)
        {
            ParseResult(ca_event, result_param);
        }
    }
    else
    {
        trace(1, "Failure in GetSpecificPortMappingEntry: Invalid Args %s", remote_host);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(remote_host);
    free(ext_port);
    free(proto);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetExternalIPAddress
 * 
 * This action retrieves the value of the external IP address on this connection instance.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetExternalIPAddress(UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "Failure in GetExternalIPAddress: Invalid Args");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event);
    }

    GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
    ParseResult(ca_event, "<NewExternalIPAddress>%s</NewExternalIPAddress>\n",
        ExternalIPAddress);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: DeletePortMapping
 * 
 * This action deletes a previously instantiated port mapping. 
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int DeletePortMapping(UpnpActionRequest *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    int result=0;
    char num[5];
    IXML_Document *propSet= NULL;
    int action_succeeded = 0;
    struct portMap *temp;
    char tmp[11];
    int authorized = 0;
    const char *devUDN = NULL;
    const char *serviceID = NULL;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    devUDN = UpnpActionRequest_get_DevUDN_cstr(ca_event);
    serviceID = UpnpActionRequest_get_ServiceID_cstr(ca_event);
    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ((remote_host = GetFirstDocumentItem(actionRequest, "NewRemoteHost")) &&
            (ext_port = GetFirstDocumentItem(actionRequest, "NewExternalPort")) &&
            (GetNbSoapParameters(actionRequest)==3) &&
            (isStringInteger(ext_port)) &&
            (proto = GetFirstDocumentItem(actionRequest, "NewProtocol")) )
    {
        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0)) || 
            (atoi(ext_port) < 0) )
        {
            trace(1, "%s: Argument value out of range",actionName);
            result = 601;
            addErrorData(ca_event, result, "Argument Value Out of Range");
        }
        else if ((strcmp(remote_host, "") != 0) && !IsIpOrDomain(remote_host))
        {
            trace(1, "%s: Argument Value Invalid");
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        //check if authorized
        if (AuthorizeControlPoint(ca_event, 1, 0) == CONTROL_POINT_AUTHORIZED)
        {
            authorized = 1;
        }

        // check that external port value is greater than or equal to 1024 if CP is not authorized
        if (result == 0 && !authorized && atoi(ext_port) < 1024)
        {
            trace(1, "Failure 'Action not authorized' in DeletePortMapping: Remote Host:%s Proto:%s Port:%s. Port value is under 1024 and CP is not authorized\n",remote_host, proto, ext_port);
            addErrorData(ca_event, 606, "Action not authorized");
        }
        // if portmapping is found, we must check if CP is authorized OR if internalclient value of portmapping matches IP of CP
        // Also if CP is not authorized NewInternalPort and NewExternalPort values of the port mapping entry must be greater than or equal to 1024,
        // else error is returned 
        else if ((temp = pmlist_FindSpecific(remote_host, ext_port, proto)) != NULL && 
                     (authorized || 
                        (ControlPointIP_equals_InternalClientIP(temp->m_InternalClient, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)) && 
                         atoi(temp->m_ExternalPort) > 1023 && atoi(temp->m_InternalPort) > 1023))
            )
        {
            result = pmlist_Delete(temp);

            if (result==1)
            {
                trace(2, "DeletePortMap: Remote Host: %s Proto:%s Port:%s\n", remote_host, proto, ext_port);
                PortMappingNumberOfEntries = pmlist_Size();
                sprintf(num,"%d",PortMappingNumberOfEntries);
                UpnpAddToPropertySet(&propSet,"PortMappingNumberOfEntries", num);
                snprintf(tmp,11,"%ld",++SystemUpdateID);
                UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
                NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);
                ixmlDocument_free(propSet);
                action_succeeded = 1;
            }
            else
            {
                trace(2, "%s: Failed to remove portmapping.", actionName);
                // add error to ca_event
                addErrorData(ca_event, 501, "Action Failed");
            }
        }
        else if (!temp)
        {
            trace(1, "Failure 'NoSuchEntryInArray' in DeletePortMapping: Remote Host:%s Proto:%s Port:%s\n",remote_host, proto, ext_port);
            addErrorData(ca_event, 714, "NoSuchEntryInArray");
        }
        else
        {
            trace(1, "Failure 'Action not authorized' in DeletePortMapping: Remote Host:%s Proto:%s Port:%s\n",remote_host, proto, ext_port);
            addErrorData(ca_event, 606, "Action not authorized");
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceDeletePortMapping: Invalid Arguments!");
        addErrorData(ca_event, 402, "Invalid Args");
    }

    if (action_succeeded)
    {
        ParseResult(ca_event, "");
    }

    free(remote_host);
    free(ext_port);
    free(proto);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: DeletePortMappingRange
 * 
 * This action deletes port mapping entries defined by a range.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int DeletePortMappingRange(UpnpActionRequest *ca_event)
{
    char *start_port=NULL;
    char *end_port=NULL;
    char *proto=NULL;
    char *bool_manage=NULL;
    int start=0;
    int end=0;
    int ext_port=0;
    int result=0;
    int str_len = 6;
    char del_port[str_len];
    char tmp[11];
    IXML_Document *propSet= NULL;
    int action_succeeded = 0;
    struct portMap *temp;
    int authorized = 0;
    int managed = 0;
    int index = 0;
    int foundPortmapCount = 0;
    const char *devUDN = NULL;
    const char *serviceID = NULL;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    devUDN = UpnpActionRequest_get_DevUDN_cstr(ca_event);
    serviceID = UpnpActionRequest_get_ServiceID_cstr(ca_event);
    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    UpnpActionRequest_set_ErrCode(ca_event, UPNP_E_SUCCESS);

    if ((start_port = GetFirstDocumentItem(actionRequest, "NewStartPort")) &&
            (end_port = GetFirstDocumentItem(actionRequest, "NewEndPort")) &&
            (proto = GetFirstDocumentItem(actionRequest, "NewProtocol")) &&
            (GetNbSoapParameters(actionRequest) == 4) &&
            (isStringInteger(start_port)) &&
            (isStringInteger(end_port)) &&
            (bool_manage = GetFirstDocumentItem(actionRequest, "NewManage")) )
    {
        //check if authorized
        if (AuthorizeControlPoint(ca_event, 1, 0) == CONTROL_POINT_AUTHORIZED)
        {
            authorized = 1;
        }

        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0)) || 
            (atoi(start_port) < 0) ||
            (atoi(end_port) < 0) )
        {
            trace(1, "%s: Argument value out of range",actionName);
            result = 601;
            addErrorData(ca_event, result, "Argument Value Out of Range");
        }
        // check that port values are greater than or equal to 1024 if CP is not authorized
        else if (!authorized && (atoi(start_port) < 1024 || atoi(end_port) < 1024))
        {
            trace(1, "Failure in DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s. Port values under 1024 and CP is not authorized\n",start_port,end_port,proto,bool_manage);
            addErrorData(ca_event, 606, "Action not authorized");
        }
        else if ((end = atoi(end_port)) < (start = atoi(start_port)))
        {
            trace(1, "Failure in DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s InconsistentParameters!\n", start_port,end_port,proto,bool_manage);
            addErrorData(ca_event, 733, "InconsistentParameters");
        }

        // parameters OK, lets continue
        if (UpnpActionRequest_get_ErrCode(ca_event) == UPNP_E_SUCCESS) 
        {
            managed = resolveBoolean(bool_manage);

            //loop ports from start to end
            for (ext_port = start; ext_port <= end; ext_port++)
            {
                snprintf(del_port,str_len,"%d",ext_port);
                index = 0;
                // remove all instances with externalPort, actually there can ony be one, byt let's be sure
                while ( (temp = pmlist_FindBy_extPort_proto_afterIndex(del_port, proto, index)) != NULL )
                {
                    foundPortmapCount++;
                    // portmapping can be deleted if control point IP is same as internal client of portmapping,
                    // or if user is authorized and managed flag is up
                    if ((authorized && managed) || ControlPointIP_equals_InternalClientIP(temp->m_InternalClient, UpnpActionRequest_get_CtrlPtIPAddr(ca_event)))
                    {
                        // delete portmapping
                        result = pmlist_Delete(temp);

                        if (result==1)
                        {
                            trace(2, "DeletePortMappingRange: DeletedPort:%s StartPort:%s EndPort:%s  Proto:%s Manage:%s\n", del_port, start_port, end_port, proto, bool_manage);
                            action_succeeded = 1;
                        }
                    }
                    else // if portmap is deleted, index of following port mappings decreases, that is why we increase our index only when nothing is removed
                        index++;
                }
            }

            // if action has succeeded and something has been deleted, send event and update SystemUpdateId 
            if (action_succeeded)
            {
                SystemUpdateID++;
                PortMappingNumberOfEntries = pmlist_Size();
                sprintf(tmp,"%d",PortMappingNumberOfEntries);
                UpnpAddToPropertySet(&propSet,"PortMappingNumberOfEntries", tmp);
                snprintf(tmp,11,"%ld",SystemUpdateID);
                UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
                NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);
            }

            // portmappings which are in area of deletion exists, but none has been deleted -> Action is not authorized
            else if (foundPortmapCount > 0 && !action_succeeded)
            {
                trace(1, "Failure in DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s Action not authorized!\n", start_port,end_port,proto,bool_manage);
                addErrorData(ca_event, 606, "Action not authorized");
            }
            else if (!action_succeeded) // there just is not any portmaps to match given parameters
            {
                trace(1, "Failure in DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s NoSuchEntryInArray!\n", start_port,end_port,proto,bool_manage);
                addErrorData(ca_event, 730, "PortMappingNotFound"); 
            }
        }
    }
    else
    {
        trace(1, "Failure in DeletePortMappingRange: Invalid Arguments!");
        addErrorData(ca_event, 402, "Invalid Args");
    }

    if (action_succeeded)
    {
        ParseResult(ca_event, "");
    }

    ixmlDocument_free(propSet);
    free(start_port);
    free(end_port);
    free(proto);
    free(bool_manage);

    return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * WANIPConnection:2 Action: GetListOfPortmappings
 * 
 * This action returns a list of port mappings matching the arguments. 
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetListOfPortmappings(UpnpActionRequest *ca_event)
{
    char *start_port = NULL;
    char *end_port = NULL;
    char *manage = NULL;
    char *proto = NULL;
    char *number_of_ports = NULL;
    char cp_ip[INET_ADDRSTRLEN] = "";
    char result_str[RESULT_LEN_LONG]; // TODO: dynamically allocated result_str

    int start, end;
    int max_entries, chars_wrote;
    int action_succeeded = 0, action_fail_exit = 0;
    int result_place = 0;
    int authorized = 0;
    struct portMap *pm = NULL;
    const char *actionName = NULL;
    IXML_Document *actionRequest = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);
    actionRequest = UpnpActionRequest_get_ActionRequest(ca_event);

    if ( (start_port = GetFirstDocumentItem(actionRequest, "NewStartPort") )
            && (end_port = GetFirstDocumentItem(actionRequest, "NewEndPort") )
            && (manage = GetFirstDocumentItem(actionRequest, "NewManage") )
            && (number_of_ports = GetFirstDocumentItem(actionRequest, "NewNumberOfPorts") )
            && (GetNbSoapParameters(actionRequest) == 5 )
            && (isStringInteger(start_port) )
            && (isStringInteger(end_port) )
            && (isStringInteger(number_of_ports) )
            && (proto = GetFirstDocumentItem(actionRequest, "NewProtocol") ) )
    {
        //check if authorized
        if (AuthorizeControlPoint(ca_event, 1, 0) == CONTROL_POINT_AUTHORIZED)
        {
            authorized = 1;
        }
        if (((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0)) || 
            (atoi(start_port) < 0) ||
            (atoi(end_port) < 0) )
        {
            trace(1, "%s: Argument value out of range",actionName);
            addErrorData(ca_event, 601, "Argument Value Out of Range");
        }
        // check that port values are greater than or equal to 1024 if CP is not authorized
        else if (!authorized && (atoi(start_port) < 1024 || atoi(end_port) < 1024))
        {
            trace(1, "Failure in GetListOfPortmappings: StartPort:%s EndPort:%s Proto:%s Manage:%s. Port values under 1024 and CP is not authorized\n",start_port,end_port,proto,manage);
            addErrorData(ca_event, 606, "Action not authorized");
        }
        else if ((end = atoi(end_port)) < (start = atoi(start_port)))
        {
            trace(1, "Failure in GetListOfPortmappings: StartPort:%s EndPort:%s Proto:%s Manage:%s InconsistentParameters!\n", start_port,end_port,proto,manage);
            addErrorData(ca_event, 733, "InconsistentParameters");
        }
        else
        {
            max_entries = atoi(number_of_ports);
            if (max_entries == 0)
                max_entries = INT_MAX;

            // If manage is not true or CP is not authorized, list only CP's port mappings
            if ( !resolveBoolean(manage) || !authorized )
                inet_ntop(AF_INET, UpnpActionRequest_get_CtrlPtIPAddr(ca_event), cp_ip, INET_ADDRSTRLEN);

            // Write XML header
            result_place += snprintf(result_str, RESULT_LEN_LONG, xml_portmapListingHeader);
            if (result_place > RESULT_LEN_LONG)
            {
                // if buffer runs out of space, return error
                action_fail_exit = 1;
            }

            // Loop through port mappings until we run out or max_entries reaches 0
            while (!action_fail_exit && (pm = pmlist_FindRangeAfter(start, end, proto, cp_ip, pm)) != NULL && max_entries--)
            {
                chars_wrote = snprintf(&result_str[result_place], RESULT_LEN_LONG-result_place, xml_portmapEntry,
                                       pm->m_RemoteHost, pm->m_ExternalPort, pm->m_PortMappingProtocol,
                                       pm->m_InternalPort, pm->m_InternalClient, pm->m_PortMappingEnabled,
                                       pm->m_PortMappingDescription, (pm->m_IsStatic == 1)?0:(pm->expirationTime-time(NULL)));

                // if buffer runs out of space, return error
                if (chars_wrote > RESULT_LEN_LONG-result_place)
                {
                    action_succeeded = 0;
                    action_fail_exit = 1;
                    break;
                }

                result_place += chars_wrote;
                action_succeeded = 1;
            }

            if (action_succeeded)
            {
                chars_wrote = snprintf(&result_str[result_place], RESULT_LEN_LONG-result_place, xml_portmapListingFooter);
                if (chars_wrote > RESULT_LEN_LONG-result_place)
                {
                    // if buffer runs out of space, return error
                    trace(2, "GetListOfPortmappings: Failure while creating result string");
                    addErrorData(ca_event, 501, "Action Failed");
                }
                else
                {
                    // this will automatically escape value of NewPortListing
                    ParseResult(ca_event, "<NewPortListing>%s</NewPortListing>\n",
                        escapeXMLString(result_str));
                    trace(3, "[This is un-escaped value of response]\n%s",result_str);
                }
            }
            else if (action_fail_exit)
            {
                trace(2, "GetListOfPortmappings: Failure while creating result string");
                addErrorData(ca_event, 501, "Action Failed");
            }
            else
            {
                trace(2, "GetListOfPortmappings: Portmapping does not exist");
                addErrorData(ca_event, 730, "PortMappingNotFound");
            }
        }
    }
    else
    {
        trace(1, "GetListOfPortmappings: Invalid Arguments\n\tStartPort: %s EndPort: %s Proto: %s NumberOfPorts: %s Manage: %s",
              start_port, end_port, proto, number_of_ports, manage);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(start_port);
    free(end_port);
    free(proto);
    free(manage);
    free(number_of_ports);

    return UpnpActionRequest_get_ErrCode(ca_event);
}


//-----------------------------------------------------------------------------
//
//                      WANEthernetLinkConfig:1 Service Actions
//
//-----------------------------------------------------------------------------

/**
 * WANEthernetLinkConfig:1 Action: GetEthernetLinkStatus
 * 
 * This action retrieves the link status of the external Ethernet connection.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetEthernetLinkStatus (UpnpActionRequest *ca_event)
{
    if(GetNbSoapParameters(UpnpActionRequest_get_ActionRequest(ca_event)) != 0)
    {
        trace(1, "GetEthernetLinkStatus invalid args");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args");
        return UpnpActionRequest_get_ErrCode(ca_event); 
    } 

    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);

    ParseResult(ca_event,
        "<NewEthernetLinkStatus>%s</NewEthernetLinkStatus>\n",
        EthernetLinkStatus);

    return UpnpActionRequest_get_ErrCode(ca_event);
}


//-----------------------------------------------------------------------------
//
//                      Internal functionalities
//
//-----------------------------------------------------------------------------

/**
 * Initialize expiration timer thread, which maintains expirations of portmappings.
 * 
 * @return Upnp error code.
 */
int ExpirationTimerThreadInit(void)
{
    int retVal;
    ThreadPoolAttr attr;
    TPAttrInit( &attr );
    TPAttrSetMaxThreads( &attr, MAX_THREADS );
    TPAttrSetMinThreads( &attr, MIN_THREADS );
    TPAttrSetStackSize( &attr, ITHREAD_STACK_MIN ); 
    TPAttrSetJobsPerThread( &attr, JOBS_PER_THREAD );
    TPAttrSetIdleTime( &attr, THREAD_IDLE_TIME );

    if ( ThreadPoolInit( &gExpirationThreadPool, &attr ) != UPNP_E_SUCCESS )
    {
        return UPNP_E_INIT_FAILED;
    }

    if ( ( retVal = TimerThreadInit( &gExpirationTimerThread,
                                     &gExpirationThreadPool ) ) !=
            UPNP_E_SUCCESS )
    {
        return retVal;
    }

    createEventUpdateTimer();

    return 0;
}

/**
 * Quit expiration timer thread.
 * 
 * @return Upnp error code.
 */
int ExpirationTimerThreadShutdown(void)
{
    TimerThreadShutdown(&gExpirationTimerThread);
    return ThreadPoolShutdown(&gExpirationThreadPool);
}

/**
 * Set expiration event free.
 * 
 * @param event Expiration event.
 */
void free_expiration_event(expiration_event *event)
{
    if (event!=NULL && event->mapping!=NULL)
        event->mapping->expirationEventId = -1;
    free(event);
}

/**
 * Create timer for disconnecting WAN connection automatically after time defined by 
 * AutoDisconnectTime state variable has elapsed from the connection status changing
 * to Connected status.
 * 
 * Every time the state of connection changes to "Connected", this timer must be updated!
 * See ConnectionStatusEventing().
 * 
 * @return Upnp error code.
 */
int createAutoDisconnectTimer(void)
{
    int result = 0;
    // cancel possible previous autodisconnect job
    if (gAutoDisconnectJobId != -1)
    {
        trace(3,"Remove previous AutoDisconnect timer");
        TimerThreadRemove(&gExpirationTimerThread, gAutoDisconnectJobId, NULL);
    }

    if (AutoDisconnectTime > 0)
    {
        trace(3,"Create new AutoDisconnect timer to be executed after %ld seconds",AutoDisconnectTime);
        long int *pointer_to_delay = (long int *)malloc(sizeof(long int));
        *pointer_to_delay = WarnDisconnectDelay;
        // schedule new autodisconnect job
        ThreadPoolJob job;
        // Add disconnect job
        TPJobInit( &job, ( start_routine ) DisconnectWAN, pointer_to_delay );
        result = TimerThreadSchedule( &gExpirationTimerThread,
                                        AutoDisconnectTime,
                                        REL_SEC, &job, SHORT_TERM,
                                        &gAutoDisconnectJobId );
    }
    return result;
}

/**
 * Disconnects WAN connection. Does the needed eventing.
 * 
 * @param input Pointer to long int which contains possible WarnDisconnectDelay. Must be pointer that is possible to free. Or NULL.
 */
void DisconnectWAN(void *input)
{
    IXML_Document *propSet = NULL;
    long int *delay = (long int *)input;
    trace(2, "Request for WAN connection termination received. Start disconnecting... ");
    if (strcmp(ConnectionStatus, "Disconnected") == 0 || strcmp(ConnectionStatus, "Disconnecting") == 0)
    {
        trace(2, "Disconnecting has been already started from somewhere else. Cancel this one. Status of connection: %s",ConnectionStatus);
        free(input);
        return;
    }

    //TODO: Some really good way to get serviceids and UDNs from descdoc!!
    if (input && *delay > 0)
    {
        trace(3, "Pending WAN connection termination for %ld seconds...", *delay);
        strcpy(ConnectionStatus, "PendingDisconnect");
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
        ixmlDocument_free(propSet);
        propSet = NULL;

        /* Sleep one second at a time and check if connection status has changed to Connected.
         * This way we don't block the next possible disconnect job initiated from DisconnectWAN()
         */
        long int slept;
        for (slept = 0; slept <= *delay; slept++)
        {
            if (strcmp(ConnectionStatus, "Connected") == 0)
            {
                /* so somebody called RequestConnection while we were sleeping. Don't terminate then. */
                trace(3, "WAN connection termination has been canceled.");
                free(input);
                return;
            }
            sleep(1);
        }
    }

    strcpy(ConnectionStatus, "Disconnecting");
    UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
    NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
    ixmlDocument_free(propSet);
    propSet = NULL;

    // terminate
    if (releaseIP(g_vars.extInterfaceName))
    {
        trace(3, "WAN connection Disconnected!");
    }
    else
    {
        trace(3, "Failed to disconnect WAN connection!");
    }

    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
    // Event ConnectionStatus
    UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
    NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
    ixmlDocument_free(propSet);

    if (strcmp(ConnectionStatus, "Disconnected") == 0)
    {
        trace(2, "Disconnecting WAN connection succeeded. State of connection: '%s'",ConnectionStatus);
    }
    else
    {
        trace(2, "Disconnecting WAN connection failed. State of connection: '%s'",ConnectionStatus);
    }
    free(input);
}

/**
 * This timer is used to check periodically if values of some state variables have changed.
 * If some has chandeg then event is sent to control points which has subscribed those events.
 * 
 * @return Upnp error code.
 */
int createEventUpdateTimer(void)
{
    expiration_event *event;
    event = ( expiration_event * ) malloc( sizeof( expiration_event ) );
    if ( event == NULL )
    {
        return 0;
    }
    event->mapping=NULL;

    // Add event update job
    TPJobInit( &gEventUpdateJob, ( start_routine ) UpdateEvents, event );
    TPJobSetFreeFunction( &gEventUpdateJob, ( free_routine ) free_expiration_event );
    TimerThreadSchedule( &gExpirationTimerThread,
                         g_vars.eventUpdateInterval,
                         REL_SEC, &gEventUpdateJob, SHORT_TERM,
                         &( event->eventId ) );
    return  event->eventId;
}

/**
 * Updates global variable idle_time which tells how long the WAN connection has been unused.
 * If idle_time is equal or greater than IdleDisconnectTime, then the WAN connection is terminated.
 */
static void updateIdleTime()
{
    if (IdleDisconnectTime <= 0 || strcmp(ConnectionStatus, "Connected") != 0)
        return;

    unsigned long stats[STATS_LIMIT];
    if (!readStats(stats))
    {
        return;
    }

    if (stats[STATS_RX_PACKETS] != connection_stats[STATS_RX_PACKETS] ||
         stats[STATS_TX_PACKETS] != connection_stats[STATS_TX_PACKETS])
        idle_time = 0;
    else 
        idle_time += g_vars.eventUpdateInterval; // this function is executed every g_vars.eventUpdateInterval seconds

    // if we have idled long enough lets terminate WAN connection
    if (idle_time >= IdleDisconnectTime)
    {
        trace(2,"WAN connection has been idling for IdleDisconnectTime %ld seconds. Terminate connection.",IdleDisconnectTime);
        long int *pointer_to_delay = (long int *)malloc(sizeof(long int));
        *pointer_to_delay = WarnDisconnectDelay;
        DisconnectWAN((void *)pointer_to_delay);
        idle_time = 0;
    }
    else
    {
        connection_stats[STATS_RX_BYTES] = stats[STATS_RX_BYTES];
        connection_stats[STATS_RX_PACKETS] = stats[STATS_RX_PACKETS];
        connection_stats[STATS_TX_BYTES] = stats[STATS_TX_BYTES];
        connection_stats[STATS_TX_PACKETS] = stats[STATS_TX_PACKETS];
    }
}

/**
 * UpdateEventTimer calls this to check if state variables, which may change on they own,
 * have changed. These variables are EthernetLinkStatus, ExternalIPAddress and ConnectionStatus.
 * 
 * @param input This parameter not used.
 */
void UpdateEvents(void *input)
{
    IXML_Document *propSet = NULL;
    expiration_event *event = ( expiration_event * ) input;

    ithread_mutex_lock(&DevMutex);

    EthernetLinkStatusEventing(propSet);
    ExternalIPAddressEventing(propSet);
    ConnectionStatusEventing(propSet);
    WANIPv6FirewallStatusEventing(propSet);

    // this is not anything to do with eventing, but because this function is regularly executed this is here also.
    updateIdleTime();

    ithread_mutex_unlock(&DevMutex);

    ixmlDocument_free(propSet);

    free_expiration_event(event);

    // create update event again
    createEventUpdateTimer();
}

/**
 * Check if EthernetLinkStatus state variable has changed since last check.
 * Update value and send notification for control points if it has changed.
 * 
 * @param propSet IXML_Document used for notification.
 * @return 1 if EthernetLinkStatus has changed, 0 if not.
 */
int EthernetLinkStatusEventing(IXML_Document *propSet)
{
    char prevStatus[12];

    strcpy(prevStatus,EthernetLinkStatus);
    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);

    // has status changed?
    if (strcmp(prevStatus,EthernetLinkStatus) != 0)
    {
        UpnpAddToPropertySet(&propSet, "EthernetLinkStatus", EthernetLinkStatus);
        NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANEthLinkC1", propSet);

        trace(2, "EthernetLinkStatus changed: From %s to %s",prevStatus,EthernetLinkStatus);
        ixmlDocument_free(propSet);
        propSet = NULL;
        return 1;
    }
    return 0;
}

/**
 * Check if ExternalIPAddress state variable has changed since last check.
 * Update value and send notification for control points if it has changed.
 * 
 * @param propSet IXML_Document used for notification.
 * @return 1 if ExternalIPAddress has changed, 0 if not.
 */
int ExternalIPAddressEventing(IXML_Document *propSet)
{
    char prevStatus[INET6_ADDRSTRLEN];

    strcpy(prevStatus,ExternalIPAddress);
    GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);

    // has status changed?
    if (strcmp(prevStatus,ExternalIPAddress) != 0)
    {
        UpnpAddToPropertySet(&propSet, "ExternalIPAddress", ExternalIPAddress);
        NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
        trace(2, "ExternalIPAddress changed: From %s to %s",prevStatus,ExternalIPAddress);
        ixmlDocument_free(propSet);
        propSet = NULL;
        return 1;
    }
    return 0;
}

/**
 * Check if ConnectionStatus state variable has changed since last check.
 * Update value and send notification for control points if it has changed.
 * 
 * If state has changed and the new state of connection is "Connected", reset
 * AutoDisconnectTimer.
 * 
 * @param propSet IXML_Document used for notification.
 * @return 1 if ConnectionStatus has changed, 0 if not.
 */
int ConnectionStatusEventing(IXML_Document *propSet)
{
    /* this is done only if previous state of connection is either "Connected" or "Disconnected"
     * Other states are caused by DisconnectWAN or RequestConnection and they will take care of 
     * eventing of those states. 
     */
    if (strcmp(ConnectionStatus, "Connected") == 0 || strcmp(ConnectionStatus, "Disconnected") == 0)
    {
        char prevStatus[20];

        strcpy(prevStatus,ConnectionStatus);
        GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);

        // has status changed?
        if (strcmp(prevStatus,ConnectionStatus) != 0)
        {
            // if new status is connected, we create autodisconnecttimer and set startup time for Uptime statevariable
            if (strcmp(ConnectionStatus, "Connected") == 0)
            {
                createAutoDisconnectTimer();
                // Record the startup time, for uptime
                startup_time = time(NULL);
            }

            UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
            NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
            trace(2, "ConnectionStatus changed: From %s to %s",prevStatus,ConnectionStatus);
            ixmlDocument_free(propSet);
            propSet = NULL;
            return 1;
        }
    }
    return 0;
}

/**
 * Check the state variables of the WANIPv6FirewallControl service
 * Those variables are only changed in the /etc/upnpd.conf file
 * A web service should be developped for that
 * The only purpose of thisfunction is to test the GENA events
 */
int WANIPv6FirewallStatusEventing(IXML_Document *propSet)
{
    int ipv6firewall_enabled = g_vars.ipv6firewallEnabled;
    int ipv6inbound_pinhole_allowed = g_vars.ipv6inboundPinholeAllowed;

    char FirewallEnabled[2] = {'\0'};
    char InboundPinholeAllowed[2] = {'\0'};

    if(parseConfigFile(&g_vars))
    {
        perror("Error parsing config file");
        return 0;
    }
    // has status changed?
    if (g_vars.ipv6firewallEnabled != ipv6firewall_enabled
            || g_vars.ipv6inboundPinholeAllowed != ipv6inbound_pinhole_allowed)
    {
        if(g_vars.ipv6firewallEnabled != ipv6firewall_enabled)
        {
            snprintf(FirewallEnabled,2,"%i", g_vars.ipv6firewallEnabled);
            UpnpAddToPropertySet(&propSet, "FirewallEnabled", FirewallEnabled);
            trace(2, "IPv6 FirewallEnabled changed to %i", g_vars.ipv6firewallEnabled);
        }
        if(g_vars.ipv6inboundPinholeAllowed != ipv6inbound_pinhole_allowed)
        {
            snprintf(InboundPinholeAllowed,2,"%i", g_vars.ipv6inboundPinholeAllowed);
            UpnpAddToPropertySet(&propSet, "InboundPinholeAllowed", InboundPinholeAllowed);
            trace(2, "IPv6 InboundPinholeAllowed changed to %i", g_vars.intInterfaceName);
        }

        NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPv6FwCtrl1", propSet);

        ixmlDocument_free(propSet);
        propSet = NULL;
        return 1;
    }
    return 0;
}

/**
 * Expire portmapping when expiration time of portmapping has expired.
 * Delete portmapping and send notifications.
 * 
 * @param input Expiration event struct.
 */
void ExpireMapping(void *input)
{
    char num[5]; // Maximum number of port mapping entries 9999
    IXML_Document *propSet = NULL;
    expiration_event *event = ( expiration_event * ) input;
    char tmp[11];

    ithread_mutex_lock(&DevMutex);

    trace(2, "ExpireMapping: Proto:%s Port:%s\n",
          event->mapping->m_PortMappingProtocol, event->mapping->m_ExternalPort);

    //reset the event id before deleting the mapping so that pmlist_Delete
    //will not call CancelMappingExpiration
    if(event != NULL && event->mapping != NULL) {
        event->mapping->expirationEventId = -1;
        pmlist_Delete(event->mapping);
    }

    PortMappingNumberOfEntries = pmlist_Size();
    sprintf(num,"%d",PortMappingNumberOfEntries);
    UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);
    snprintf(tmp,11,"%ld",++SystemUpdateID);
    UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
    NotifyExtForIPv4AndIPv6(event->DevUDN, event->ServiceID, propSet);
    ixmlDocument_free(propSet);
    trace(3, "ExpireMapping: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
          event->DevUDN, event->ServiceID, num);

    free_expiration_event(event);

    ithread_mutex_unlock(&DevMutex);
}

/**
 * Schedule expiration event for new portmapping into ExpirationTimer
 * 
 * @param mapping portMap struct of new portmapping.
 * @param DevUDN Device UDN.
 * @param ServiceID ID of service.
 * @return eventID if success, 0 else.
 */
int ScheduleMappingExpiration(struct portMap *mapping, const char *DevUDN, const char *ServiceID)
{
    int retVal = 0;
    ThreadPoolJob job;
    expiration_event *event;
    time_t curtime = time(NULL);

    // set expiration time for portmapping
    if (mapping->m_PortMappingLeaseDuration == 0 || mapping->m_PortMappingLeaseDuration > MAXIMUM_DURATION)
    {
        mapping->m_PortMappingLeaseDuration = MAXIMUM_DURATION;
        mapping->expirationTime = curtime + mapping->m_PortMappingLeaseDuration;
    }
    else if (mapping->m_PortMappingLeaseDuration > 0)
    {
        mapping->expirationTime = curtime + mapping->m_PortMappingLeaseDuration;
    }
    else // mapping->m_PortMappingLeaseDuration < 0
    {
        //client did not provide a duration, so use the default duration
        if (g_vars.duration==0 || g_vars.duration>MAXIMUM_DURATION)
        {
            mapping->expirationTime = curtime+MAXIMUM_DURATION;
        }
        else if (g_vars.duration>0)
        {
            //relative duration
            mapping->expirationTime = curtime+g_vars.duration;
        }
        else   //g_vars.duration < 0
        {
            //absolute daily expiration time
            long int expclock = -1*g_vars.duration;
            struct tm *loctime = localtime(&curtime);
            long int curclock = loctime->tm_hour*3600 + loctime->tm_min*60 + loctime->tm_sec;
            long int diff = expclock-curclock;
            if (diff<60) //if exptime is in less than a minute (or in the past), schedule it in 24 hours instead
                diff += 24*60*60;
            if (diff > MAXIMUM_DURATION)
                diff = MAXIMUM_DURATION;
            mapping->expirationTime = curtime+diff;
        }
    }
    event = ( expiration_event * ) malloc( sizeof( expiration_event ) );
    if ( event == NULL )
    {
        return 0;
    }

    event->mapping = mapping;

    if (strlen(DevUDN) < sizeof(event->DevUDN)) strcpy(event->DevUDN, DevUDN);
    else strcpy(event->DevUDN, "");
    if (strlen(ServiceID) < sizeof(event->ServiceID)) strcpy(event->ServiceID, ServiceID);
    else strcpy(event->ServiceID, "");

    TPJobInit( &job, ( start_routine ) ExpireMapping, event );
    TPJobSetFreeFunction( &job, ( free_routine ) free_expiration_event );

    if ( ( retVal = TimerThreadSchedule( &gExpirationTimerThread,
                                         mapping->expirationTime,
                                         ABS_SEC, &job, SHORT_TERM,
                                         &( event->eventId ) ) )
            != UPNP_E_SUCCESS )
    {
        free( event );
        mapping->expirationEventId = -1;
        return 0;
    }

    mapping->expirationEventId = event->eventId;

    trace(3,"ScheduleMappingExpiration: DevUDN: %s ServiceID: %s Proto: %s ExtPort: %s Int: %s.%s at: %s eventId: %d",event->DevUDN,event->ServiceID,mapping->m_PortMappingProtocol, mapping->m_ExternalPort, mapping->m_InternalClient, mapping->m_InternalPort, ctime(&(mapping->expirationTime)), event->eventId);

    return event->eventId;
}

/**
 * Cancel given expiration event.
 * 
 * @param expirationEventId ID of mappingExpiration.
 * @return 1
 */
int CancelMappingExpiration(int expirationEventId)
{
    ThreadPoolJob job;
    if (expirationEventId<0)
        return 1;
    trace(3,"CancelMappingExpiration: eventId: %d",expirationEventId);
    if (TimerThreadRemove(&gExpirationTimerThread,expirationEventId,&job)==0)
    {
        free_expiration_event((expiration_event *)job.arg);
    }
    else
    {
        trace(1,"  TimerThreadRemove failed!");
    }
    return 1;
}

/**
 * Delete all portmappings.
 */
void DeleteAllPortMappings(void)
{
    IXML_Document *propSet = NULL;
    char tmp[11];

    ithread_mutex_lock(&DevMutex);

    pmlist_FreeList();

    PortMappingNumberOfEntries = pmlist_Size();
    sprintf(tmp,"%d",PortMappingNumberOfEntries);
    UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", tmp);
    snprintf(tmp,11,"%ld",++SystemUpdateID);
    UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
    NotifyExtForIPv4AndIPv6(wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
    ixmlDocument_free(propSet);
    trace(2, "DeleteAllPortMappings: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
          wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", "0");

    ithread_mutex_unlock(&DevMutex);
}

/**
 * Create new portmapping.
 * AddPortMapping and AddAnyPortMapping actions use this function.
 * 
 * Because it is possible to "update" port mappings, meaning that old one is first 
 * removed and after that new one is created with new values, with is_update flag it 
 * is possible to control if PortMappingNumberOfEntries is evented. 
 * PortMappingNumberOfEntries should be evented only if number of portmappings is changed and 
 * when updating it really isn't changing, even if port mapping is first removed and then added new.
 * 
 * 
 * @param ca_event UpnpActionRequest.
 * @param bool_enabled Is rule enabled. Rule is added only if it is enabled (1).
 * @param leaseDuration Lease duration of portmapping. Value between 0 and 604800.
 * @param remote_host WAN IP address (destination) of connections initiated by a client in the local network.
 * @param ext_port TCP or UDP port number of the Client as seen by the remote host.
 * @param int_port The local TCP or UDP port number of the client.
 * @param proto Portmapping protocol, either TCP or UDP.
 * @param int_client The local IP address of the client.
 * @param desc Textual description of portmapping.
 * @param is_update With this value it is controlled if PortMappingNumberOfEntries is evented. 0 is no eventing.
 * @return 1 if addition succeeded, 0 if failed.
 */
int AddNewPortMapping(UpnpActionRequest *ca_event, char* bool_enabled, long int leaseDuration,
                      char* remote_host, char* ext_port, char* int_port,
                      char* proto, char* int_client, char* desc,
                      int is_update)
{
    int result;
    char num[5]; // Maximum number of port mapping entries 9999
    IXML_Document *propSet = NULL;
    struct portMap *new;
    char tmp[11];
    int isStatic = 0;
    const char *devUDN = NULL;
    const char *serviceID = NULL;
    const char *actionName = NULL;

    devUDN = UpnpActionRequest_get_DevUDN_cstr(ca_event);
    serviceID = UpnpActionRequest_get_ServiceID_cstr(ca_event);
    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);

    // if duration is 0, it must be interpreted as 604800
    if (leaseDuration == 0)
    {
        leaseDuration = 604800;
        isStatic = 1;
    }

    new = pmlist_NewNode(atoi(bool_enabled), leaseDuration, remote_host,
                  ext_port, int_port, proto,
                  int_client, desc, isStatic);

    result = pmlist_PushBack(new);

    if (result==1)
    {
        ScheduleMappingExpiration(new,devUDN,serviceID);
        PortMappingNumberOfEntries = pmlist_Size();
        // no enventing on PortMappingNumberOfEntries if updating
        if (!is_update)
        {
            sprintf(num,"%d",PortMappingNumberOfEntries);
            trace(3, "PortMappingNumberOfEntries: %d", pmlist_Size());
            UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);
        }
        snprintf(tmp,11,"%ld",++SystemUpdateID);
        UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
        NotifyExtForIPv4AndIPv6(devUDN, serviceID, propSet);

        ixmlDocument_free(propSet);
        trace(2, "%s: DevUDN: %s ServiceID: %s RemoteHost: %s Protocol: %s ExternalPort: %s InternalClient: %s.%s",
                    actionName,devUDN,serviceID,remote_host, proto, ext_port,
                    int_client, int_port);
    }
    else
    {
        trace(2, "%s: Failed to add new portmapping. DevUDN: %s ServiceID: %s RemoteHost: %s Protocol: %s ExternalPort: %s InternalClient: %s.%s",
                    actionName,devUDN,serviceID,remote_host, proto, ext_port,
                    int_client, int_port);
        // add error to ca_event
        addErrorData(ca_event, 501, "Action Failed");
    }

    return result;
}

/**
 * THIS DOES NOT ACTUALLY DO ANYTHING. WAIT LATER RELEASES FOR ACTUAL USAGE.
 * Checks if control point is authorized
 * If not, inserts error data in UpnpActionRequest if addError is != 0.
 * 
 * @param ca_event Upnp_Action_Request struct.
 * @param managed Is accessLevelManage or accessLevel used from accesslevel.xml
 * @param addError Is error data added to ca_event if control point is not authorized.
 * @return UPnP error code or 0 if CP is authorized
 */
int AuthorizeControlPoint(UpnpActionRequest *ca_event, int managed, int addError)
{
	return CONTROL_POINT_AUTHORIZED;
}

/**
 * Creates new job for terminating WAN connection. Checks also common errors for RequestTermination
 * and ForceTermination.
 * 
 * @param ca_event UpnpActionRequest.
 * @param disconnectDelay How long is waited before really terminates connection. If greater than 0, sends PendingDisconnect event.
 * @return UPnP error code or 0 if CP is authorized
 */
int ConnectionTermination(UpnpActionRequest *ca_event, long int disconnectDelay)
{
    int result = 0;
    const char *actionName = NULL;

    actionName = UpnpActionRequest_get_ActionName_cstr(ca_event);

    if (strcmp(ConnectionType,"IP_Routed") != 0)
    {
        trace(1, "%s: ConnectionType must be IP_Routed. Type: %s", actionName, ConnectionType);
        result = 710;
        addErrorData(ca_event, result, "InvalidConnectionType");
    }
    else if (strcmp(ConnectionStatus,"Disconnected") == 0)
    {
        trace(1, "%s: Connection of %s already terminated", actionName, g_vars.extInterfaceName);
        result = 711;
        addErrorData(ca_event, result, "ConnectionAlreadyTerminated");
    }

    // if ok to continue termination
    if (result == 0)
    {
        long int *pointer_to_delay = (long int *)malloc(sizeof(long int));
        *pointer_to_delay = disconnectDelay;
        // create new job that will disconnect and send events, we can return success to CP
        int jobId;
        ThreadPoolJob job;
        TPJobInit( &job, ( start_routine ) DisconnectWAN, pointer_to_delay );
        result = ThreadPoolAdd(&gExpirationThreadPool, &job, &jobId);

        if (result == 0)
        {
            // create response SOAP message
            ParseResult(ca_event, "");
        }
        else
        {
            trace(1, "%s: Failed to create job for WAN connection termination", actionName);
            addErrorData(ca_event, 501, "Action Failed");
        }
    }

    return UpnpActionRequest_get_ErrCode(ca_event);
}
