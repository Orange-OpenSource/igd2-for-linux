#include <syslog.h>
#include <stdlib.h>
#include <upnp/ixml.h>
#include <string.h>
#include <time.h>
#include <upnp/upnp.h>
#include <upnp/upnptools.h>
#include <upnp/TimerThread.h>
#include <arpa/inet.h>
#include "globals.h"
#include "gatedevice.h"
#include "pmlist.h"
#include "util.h"
#include "lanhostconfig.h"

//Definitions for mapping expiration timer thread
static TimerThread gExpirationTimerThread;
static ThreadPool gExpirationThreadPool;
static ThreadPoolJob gEventUpdateJob;

// MUTEX for locking shared state variables whenver they are changed
static ithread_mutex_t DevMutex = PTHREAD_MUTEX_INITIALIZER;

// XML string definitions
static const char xml_portmapEntry[] = "<p:PortmapEntry NewRemoteHost=\"%s\" NewExternalPort=\"%s\" NewProtocol=\"%s\" NewInternalPort=\"%s\" NewInternalClient=\"%s\" NewEnabled=\"%d\" NewDescription=\"%s\" NewLeaseTime=\"%ld\"></p:PortmapEntry>\n";
static const char xml_portmapListingHeader[] = "<u:%sResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><p:PortMappingList xmlns:p=\"http://www.upnp.org/schemas/GWPortMappingList.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.upnp.org/schemas/GWPortMappingList.xsd GwPortMappingList-V0.5.xsd\">\n";
static const char xml_portmapListingFooter[] = "</p:PortMappingList></u:%sResponse>";

// Main event handler for callbacks from the SDK.  Determine type of event
// and dispatch to the appropriate handler (Note: Get Var Request deprecated
int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie)
{
    switch (EventType)
    {
    case UPNP_EVENT_SUBSCRIPTION_REQUEST:
        HandleSubscriptionRequest((struct Upnp_Subscription_Request *) Event);
        break;
        // -- Deprecated --
    case UPNP_CONTROL_GET_VAR_REQUEST:
        HandleGetVarRequest((struct Upnp_State_Var_Request *) Event);
        break;
    case UPNP_CONTROL_ACTION_REQUEST:
        HandleActionRequest((struct Upnp_Action_Request *) Event);
        break;
    default:
        trace(1, "Error in EventHandler: Unknown event type %d", EventType);
    }
    return (0);
}

// Grab our UDN from the Description Document.  This may not be needed,
// the UDN comes with the request, but we leave this for other device initializations
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
    gateUDN = GetDocumentItem(ixmlDescDoc, "UDN", 0);
    wanUDN = GetDocumentItem(ixmlDescDoc, "UDN", 1);
    wanConnectionUDN = GetDocumentItem(ixmlDescDoc, "UDN", 2);
    ixmlDocument_free(ixmlDescDoc);

    trace(3, "UDN's: %s\n%s\n%s\n",gateUDN,wanUDN,wanConnectionUDN);

    if (gateUDN == NULL || wanUDN == NULL || wanConnectionUDN == NULL)
    {
        syslog(LOG_ERR, "Failed to get device UDN's from description document.  Exiting ...");
        UpnpFinish();
        exit(1);
    }

    // Initialize our linked list of port mappings.
    pmlist_Head = pmlist_Current = NULL;
    PortMappingNumberOfEntries = 0;
    SystemUpdateID = 0;
    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);
    
    // only supported type at the moment
    strcpy(ConnectionType,"IP_Routed");
    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);

    return (ret);
}

// Handles subscription request for state variable notifications
int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event)
{
    IXML_Document *propSet = NULL;

    ithread_mutex_lock(&DevMutex);

    if (strcmp(sr_event->UDN, wanUDN) == 0)
    {
        // WAN Common Interface Config Device Notifications
        if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:WANCommonIFC1") == 0)
        {
            trace(3, "Received request to subscribe to WANCommonIFC1");
            UpnpAddToPropertySet(&propSet, "PhysicalLinkStatus", "Up");
            UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
                                      propSet, sr_event->Sid);
            ixmlDocument_free(propSet);
        }
    }
    else if (strcmp(sr_event->UDN, wanConnectionUDN) == 0)
    {
        // WAN IP Connection Device Notifications
        if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:WANIPConn1") == 0)
        {
            char tmp[11];
            snprintf(tmp,11,"%ld",SystemUpdateID);
                   
            GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
            GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
            trace(3, "Received request to subscribe to WANIPConn1");
            UpnpAddToPropertySet(&propSet, "PossibleConnectionTypes","IP_Routed");
            UpnpAddToPropertySet(&propSet, "ExternalIPAddress", ExternalIPAddress);
            UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries","0");
            UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
            UpnpAddToPropertySet(&propSet, "SystemUpdateID",tmp);
            UpnpAddToPropertySet(&propSet, "ChangedPortMapping","");

            UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
                                      propSet, sr_event->Sid);
            ixmlDocument_free(propSet);
        }
        // LAN Host Config Management Notifications
        else if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:LANHostConfig1") == 0)
        {
            trace(3, "Received request to subscribe to LANHostConfig1");
            // No state variable requires eventing, is next step needed?
            UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
                                      propSet, sr_event->Sid);
            ixmlDocument_free(propSet);
        }
        else if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:WANEthLinkC1") == 0)
        {
            trace(3, "Received request to subscribe to WANEthLinkC1");
            setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);
            UpnpAddToPropertySet(&propSet, "EthernetLinkStatus", EthernetLinkStatus);
            UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
                                      propSet, sr_event->Sid);
            ixmlDocument_free(propSet);
        }
    }
    ithread_mutex_unlock(&DevMutex);
    return(1);
}

int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_request)
{
    // GET VAR REQUEST DEPRECATED FROM UPnP SPECIFICATIONS
    // Report this in debug and ignore requests.  If anyone experiences problems
    // please let us know.
    trace(3, "Deprecated Get Variable Request received. Ignoring.");
    return 1;
}

int HandleActionRequest(struct Upnp_Action_Request *ca_event)
{
    int result = 0;

    ithread_mutex_lock(&DevMutex);


    if (strcmp(ca_event->DevUDN, wanUDN) == 0)
    {
        if (strcmp(ca_event->ServiceID,"urn:upnp-org:serviceId:WANCommonIFC1") == 0)
        {
            if (strcmp(ca_event->ActionName,"GetTotalBytesSent") == 0)
                result = GetTotal(ca_event, STATS_TX_BYTES);
            else if (strcmp(ca_event->ActionName,"GetTotalBytesReceived") == 0)
                result = GetTotal(ca_event, STATS_RX_BYTES);
            else if (strcmp(ca_event->ActionName,"GetTotalPacketsSent") == 0)
                result = GetTotal(ca_event, STATS_TX_PACKETS);
            else if (strcmp(ca_event->ActionName,"GetTotalPacketsReceived") == 0)
                result = GetTotal(ca_event, STATS_RX_PACKETS);
            else if (strcmp(ca_event->ActionName,"GetCommonLinkProperties") == 0)
                result = GetCommonLinkProperties(ca_event);
            else
            {
                trace(1, "Invalid Action Request : %s",ca_event->ActionName);
                result = InvalidAction(ca_event);
            }
        }
    }
    else if (strcmp(ca_event->DevUDN, wanConnectionUDN) == 0)
    {
        // Common debugging info, hopefully gets removed soon.
        trace(3, "ActionName = %s", ca_event->ActionName);

        if (strcmp(ca_event->ServiceID, "urn:upnp-org:serviceId:WANIPConn1") == 0)
        {
            if (strcmp(ca_event->ActionName,"GetConnectionTypeInfo") == 0)
                result = GetConnectionTypeInfo(ca_event);
            else if (strcmp(ca_event->ActionName,"GetNATRSIPStatus") == 0)
                result = GetNATRSIPStatus(ca_event);
            else if (strcmp(ca_event->ActionName,"SetConnectionType") == 0)
                result = SetConnectionType(ca_event);
            else if (strcmp(ca_event->ActionName,"RequestConnection") == 0)
                result = RequestConnection(ca_event);
            else if (strcmp(ca_event->ActionName,"AddPortMapping") == 0)
                result = AddPortMapping(ca_event);
            else if (strcmp(ca_event->ActionName,"GetGenericPortMappingEntry") == 0)
                result = GetGenericPortMappingEntry(ca_event);
            else if (strcmp(ca_event->ActionName,"GetSpecificPortMappingEntry") == 0)
                result = GetSpecificPortMappingEntry(ca_event);
            else if (strcmp(ca_event->ActionName,"GetExternalIPAddress") == 0)
                result = GetExternalIPAddress(ca_event);
            else if (strcmp(ca_event->ActionName,"DeletePortMapping") == 0)
                result = DeletePortMapping(ca_event);
            else if (strcmp(ca_event->ActionName,"GetStatusInfo") == 0)
                result = GetStatusInfo(ca_event);
            else if (strcmp(ca_event->ActionName,"DeletePortMappingRange") == 0)
                result = DeletePortMappingRange(ca_event);
            else if (strcmp(ca_event->ActionName,"AddAnyPortMapping") == 0)
                result = AddAnyPortMapping(ca_event);
            else if (strcmp(ca_event->ActionName,"RetrieveListOfPortmappings") == 0)
                result = RetrieveListOfPortmappings(ca_event);
            else if (strcmp(ca_event->ActionName,"ForceTermination") == 0)
                result = ForceTermination(ca_event);
                
            // Intentionally Non-Implemented Functions -- To be added later
            /*else if (strcmp(ca_event->ActionName,"RequestTermination") == 0)
                result = RequestTermination(ca_event);
            else if (strcmp(ca_event->ActionName,"SetAutoDisconnectTime") == 0)
                result = SetAutoDisconnectTime(ca_event);
            else if (strcmp(ca_event->ActionName,"SetIdleDisconnectTime") == 0)
                result = SetIdleDisconnectTime(ca_event);
            else if (strcmp(ca_event->ActionName,"SetWarnDisconnectDelay") == 0)
                result = SetWarnDisconnectDelay(ca_event);
            else if (strcmp(ca_event->ActionName,"GetAutoDisconnectTime") == 0)
                result = GetAutoDisconnectTime(ca_event);
            else if (strcmp(ca_event->ActionName,"GetIdleDisconnectTime") == 0)
                result = GetIdleDisconnectTime(ca_event);
            else if (strcmp(ca_event->ActionName,"GetWarnDisconnectDelay") == 0)
                result = GetWarnDisconnectDelay(ca_event);*/
            else result = InvalidAction(ca_event);
        }
        else if (strcmp(ca_event->ServiceID,"urn:upnp-org:serviceId:LANHostConfig1") == 0)
        {
            if (strcmp(ca_event->ActionName,"SetDHCPServerConfigurable") == 0)
                result = SetDHCPServerConfigurable(ca_event);
            else if (strcmp(ca_event->ActionName,"GetDHCPServerConfigurable") == 0)
                result = GetDHCPServerConfigurable(ca_event);
            else if (strcmp(ca_event->ActionName,"SetDHCPRelay") == 0)
                result = SetDHCPRelay(ca_event);
            else if (strcmp(ca_event->ActionName,"GetDHCPRelay") == 0)
                result = GetDHCPRelay(ca_event);
            else if (strcmp(ca_event->ActionName,"SetSubnetMask") == 0)
                result = SetSubnetMask(ca_event);
            else if (strcmp(ca_event->ActionName,"GetSubnetMask") == 0)
                result = GetSubnetMask(ca_event);
            else if (strcmp(ca_event->ActionName,"SetIPRouter") == 0)
                result = SetIPRouter(ca_event);
            else if (strcmp(ca_event->ActionName,"DeleteIPRouter") == 0)
                result = DeleteIPRouter(ca_event);
            else if (strcmp(ca_event->ActionName,"GetIPRoutersList") == 0)
                result = GetIPRoutersList(ca_event);
            else if (strcmp(ca_event->ActionName,"SetDomainName") == 0)
                result = SetDomainName(ca_event);
            else if (strcmp(ca_event->ActionName,"GetDomainName") == 0)
                result = GetDomainName(ca_event);
            else if (strcmp(ca_event->ActionName,"SetAddressRange") == 0)
                result = SetAddressRange(ca_event);
            else if (strcmp(ca_event->ActionName,"GetAddressRange") == 0)
                result = GetAddressRange(ca_event);
            else if (strcmp(ca_event->ActionName,"SetReservedAddress") == 0)
                result = SetReservedAddress(ca_event);
            else if (strcmp(ca_event->ActionName,"DeleteReservedAddress") == 0)
                result = DeleteReservedAddress(ca_event);
            else if (strcmp(ca_event->ActionName,"GetReservedAddresses") == 0)
                result = GetReservedAddresses(ca_event);
            else if (strcmp(ca_event->ActionName,"SetDNSServer") == 0)
                result = SetDNSServer(ca_event);
            else if (strcmp(ca_event->ActionName,"DeleteDNSServer") == 0)
                result = DeleteDNSServer(ca_event);
            else if (strcmp(ca_event->ActionName,"GetDNSServers") == 0)
                result = GetDNSServers(ca_event);
            else
            {
                trace(1, "Action not supported: %s",ca_event->ActionName);
                result = InvalidAction(ca_event);
            }
        }
        else if (strcmp(ca_event->ServiceID,"urn:upnp-org:serviceId:WANEthLinkC1") == 0)
        {
            if (strcmp(ca_event->ActionName,"GetEthernetLinkStatus") == 0)
                result = GetEthernetLinkStatus(ca_event);
            else
            {
                trace(1, "Invalid Action Request : %s",ca_event->ActionName);
                result = InvalidAction(ca_event);
            }
        }
    }

    ithread_mutex_unlock(&DevMutex);

    return (result);
}

// Default Action when we receive unknown Action Requests
int InvalidAction(struct Upnp_Action_Request *ca_event)
{
    ca_event->ErrCode = 401;
    strcpy(ca_event->ErrStr, "Invalid Action");
    ca_event->ActionResult = NULL;
    return (ca_event->ErrCode);
}

// As IP_Routed is the only relevant Connection Type for Linux-IGD
// we respond with IP_Routed as both current type and only type
int GetConnectionTypeInfo (struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    IXML_Document *result;

    snprintf(resultStr, RESULT_LEN,
             "<u:GetConnectionTypeInfoResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
             "<NewConnectionType>IP_Routed</NewConnectionType>\n"
             "<NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>"
             "</u:GetConnectionTypeInfoResponse>");

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetConnectionTypeinfo: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return(ca_event->ErrCode);
}

// Linux-IGD does not support RSIP.  However NAT is of course
// so respond with NewNATEnabled = 1
int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    IXML_Document *result;

    snprintf(resultStr, RESULT_LEN, "<u:GetNATRSIPStatusResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
             "<NewRSIPAvailable>0</NewRSIPAvailable>\n"
             "<NewNATEnabled>1</NewNATEnabled>\n"
             "</u:GetNATRSIPStatusResponse>");

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetNATRSIPStatus: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return(ca_event->ErrCode);
}


// Connection Type is a Read Only Variable as linux-igd is only
// a device that supports a NATing IP router (not an Ethernet
// bridge).  Possible other uses may be explored.
int SetConnectionType(struct Upnp_Action_Request *ca_event)
{
    // Ignore requests
    ca_event->ActionResult = NULL;
    ca_event->ErrCode = UPNP_E_SUCCESS;
    return ca_event->ErrCode;
}

// This function should set the state variable ConnectionStatus to
// connecting, and then return synchronously, firing off a thread
// asynchronously to actually change the status to connected.
//
// v2.0: If external interface has IP, assume that status is Connected, else Disconnected
int RequestConnection(struct Upnp_Action_Request *ca_event)
{ 
    IXML_Document *propSet = NULL;
    int result = 0;
    char resultStr[RESULT_LEN];
    IXML_Document *ixml_result = NULL;

    // create result document for succesfull cases. addErrorData overwrites this if no success
    snprintf(resultStr, RESULT_LEN, "<u:RequestConnectionResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
             "</u:RequestConnectionResponse>");

    // Create a IXML_Document from resultStr and return with ca_event
    if ((ixml_result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = ixml_result;
    } 
    
    ca_event->ErrCode = UPNP_E_SUCCESS;
    
    trace(2, "RequestConnection received ... Checking status...");
    
    //Immediatley Set lastconnectionerror to none. We don't now think about errors.
    strcpy(LastConnectionError, "ERROR_NONE");
    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
    
    // connection already up. Nothing to do.
    if (strcmp(ConnectionStatus,"Connected") == 0)
    {
        trace(2, "RequestConnection: Connection is already connected");
       
        return ca_event->ErrCode;
    }
    else if (strcmp(ConnectionType,"IP_Routed") != 0)
    {
        trace(1, "RequestConnection: ConnectionType must be IP_Routed. Type: %s", ConnectionType);
        result = 710;
        addErrorData(ca_event, result, "InvalidConnectionType");
    }
    else if (strcmp(ConnectionStatus,"Disconnecting") == 0)
    {
        trace(1, "RequestConnection: Connection of %s is disconnecting", g_vars.extInterfaceName);
        result = 707;
        addErrorData(ca_event, result, "DisconnectInProgress");
    }
    else if (strcmp(ConnectionStatus,"Connecting") == 0)
    {
        trace(1, "RequestConnection: Connection of %s is connecting", g_vars.extInterfaceName);
        result = 705;
        addErrorData(ca_event, result, "ConnectionSetupInProgress");
    }

    if (result == 0)
    {
        strcpy(ConnectionStatus, "Connecting");
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);
        
        trace(2, "RequestConnection received ... Connecting..");
        
        if (startDHCPClient(g_vars.extInterfaceName))
            ca_event->ErrCode = UPNP_E_SUCCESS;
        else
        {
            trace(1, "RequestConnection: Connection set up failed", g_vars.extInterfaceName);
            result = 704;
            addErrorData(ca_event, result, "ConnectionSetupFailed");
        }     

        GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
        // Build DOM Document with state variable connectionstatus and event it
        propSet = NULL;
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        // Send off notifications of state change
        UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);
    }
    
    return ca_event->ErrCode;
}

/**
 * Force termination of WAN-connection immediatedly. (i.e. try to release IP of external interface)
 */
int ForceTermination(struct Upnp_Action_Request *ca_event)
{
    IXML_Document *propSet = NULL;
    int result = 0;

    char resultStr[RESULT_LEN];
    IXML_Document *ixml_result = NULL;
    
    // create result document for succesfull cases. addErrorData overwrites this if no success
    snprintf(resultStr, RESULT_LEN, "<u:ForceTerminationResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
             "</u:ForceTerminationResponse>");

    // Create a IXML_Document from resultStr and return with ca_event
    if ((ixml_result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = ixml_result;
    }


    ca_event->ErrCode = UPNP_E_SUCCESS;

    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
    
    if (strcmp(ConnectionType,"IP_Routed") != 0)
    {
        trace(1, "ForceTermination: ConnectionType must be IP_Routed. Type: %s", ConnectionType);
        result = 710;
        addErrorData(ca_event, result, "InvalidConnectionType");
    }    
    else if (strcmp(ConnectionStatus,"Disconnected") == 0)
    {
        trace(1, "ForceTermination: Connection of %s already terminated", g_vars.extInterfaceName);
        result = 711;
        addErrorData(ca_event, result, "ConnectionAlreadyTerminated");
    }
    else if (strcmp(ConnectionStatus,"Disconnecting") == 0)
    {
        trace(1, "ForceTermination: Connection of %s already disconnecting", g_vars.extInterfaceName);
        result = 707;
        addErrorData(ca_event, result, "DisconnectInProgress");
    }

    // if ok to continue termination
    if (result == 0)
    {
        trace(2, "ForceTermination received ... Disconnecting.");

        strcpy(ConnectionStatus, "Disconnecting");
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);
        
        // terminate    
        if (releaseIP(g_vars.extInterfaceName))
        {       
            trace(3, "Disconnected...");   
            ca_event->ErrCode = UPNP_E_SUCCESS;   
        }
        else
            ca_event->ErrCode = UPNP_SOAP_E_ACTION_FAILED;
        
            
        GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);
        // Event ConnectionStatus
        propSet = NULL;
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);     
    }
    
    return ca_event->ErrCode;
}

int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    IXML_Document *result;

    ca_event->ErrCode = UPNP_E_SUCCESS;
    snprintf(resultStr, RESULT_LEN,
             "<u:GetCommonLinkPropertiesResponse xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">\n"
             "<NewWANAccessType>Cable</NewWANAccessType>\n"
             "<NewLayer1UpstreamMaxBitRate>%s</NewLayer1UpstreamMaxBitRate>\n"
             "<NewLayer1DownstreamMaxBitRate>%s</NewLayer1DownstreamMaxBitRate>\n"
             "<NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>\n"
             "</u:GetCommonLinkPropertiesResponse>",g_vars.upstreamBitrate,g_vars.downstreamBitrate);

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetCommonLinkProperties: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return(ca_event->ErrCode);
}

/* get specified statistic from /proc/net/dev */
int GetTotal(struct Upnp_Action_Request *ca_event, stats_t stat)
{
    char dev[IFNAMSIZ], resultStr[RESULT_LEN];
    const char *methods[STATS_LIMIT] =
        { "BytesSent", "BytesReceived", "PacketsSent", "PacketsReceived" };
    unsigned long stats[STATS_LIMIT];
    FILE *proc;
    IXML_Document *result;
    int read;

    proc = fopen("/proc/net/dev", "r");
    if (!proc)
    {
        fprintf(stderr, "failed to open\n");
        return 0;
    }

    /* skip first two lines */
    fscanf(proc, "%*[^\n]\n%*[^\n]\n");

    /* parse stats */
    do
        read = fscanf(proc, "%[^:]:%lu %lu %*u %*u %*u %*u %*u %*u %lu %lu %*u %*u %*u %*u %*u %*u\n", dev, &stats[STATS_RX_BYTES], &stats[STATS_RX_PACKETS], &stats[STATS_TX_BYTES], &stats[STATS_TX_PACKETS]);
    while (read != EOF && (read == 5 && strncmp(dev, g_vars.extInterfaceName, IFNAMSIZ) != 0));

    fclose(proc);

    snprintf(resultStr, RESULT_LEN,
             "<u:GetTotal%sResponse xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">\n"
             "<NewTotal%s>%lu</NewTotal%s>\n"
             "</u:GetTotal%sResponse>",
             methods[stat], methods[stat], stats[stat], methods[stat], methods[stat]);

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing response to GetTotal: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return (ca_event->ErrCode);
}

// Returns connection status related information to the control points
int GetStatusInfo(struct Upnp_Action_Request *ca_event)
{
    long int uptime;
    char resultStr[RESULT_LEN];
    IXML_Document *result = NULL;

    uptime = (time(NULL) - startup_time);

    snprintf(resultStr, RESULT_LEN,
             "<u:GetStatusInfoResponse xmlns:u=\"urn:schemas-upnp-org:service:GetStatusInfo:1\">\n"
             "<NewConnectionStatus>Connected</NewConnectionStatus>\n"
             "<NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\n"
             "<NewUptime>%li</NewUptime>\n"
             "</u:GetStatusInfoResponse>",
             uptime);

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetStatusInfo: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return(ca_event->ErrCode);
}

// Add New Port Map to the IGD
int AddPortMapping(struct Upnp_Action_Request *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    char *int_port=NULL;
    char *int_ip=NULL;
    char *int_duration=NULL;
    char *bool_enabled=NULL;
    char *desc=NULL;
    struct portMap *ret;
    int result = 0;
    char resultStr[RESULT_LEN];

    if ( (remote_host = GetFirstDocumentItem(ca_event->ActionRequest, "NewRemoteHost") )
            && (ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort") )
            && (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol") )
            && (int_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalPort") )
            && (int_ip = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalClient") )
            && (int_duration = GetFirstDocumentItem(ca_event->ActionRequest, "NewLeaseDuration") )
            && (bool_enabled = GetFirstDocumentItem(ca_event->ActionRequest, "NewEnabled") )
            && (desc = GetFirstDocumentItem(ca_event->ActionRequest, "NewPortMappingDescription") ))
    {
        // If ext_port is <1024 control point needs to be authorized
        if (atoi(ext_port) < 1024 && AuthorizeControlPoint(ca_event) != CONTROL_POINT_AUTHORIZED)
        {
            return ca_event->ErrCode;
        }

        // Check RemoteHost and ExternalPort parameters
        if (checkForWildCard(remote_host)) {
            trace(1, "Wild cards not permitted in remote_host:%s", remote_host);
            addErrorData(ca_event, 715, "WildCardNotPermittedInSrcIp");
            result = 715;
        } else
        if (checkForWildCard(ext_port)) {
            trace(1, "Wild cards not permitted in external_port:%s", ext_port);
            addErrorData(ca_event, 716, "WildCardNotPermittedInExtPort");
            result = 716;
        } else
        // check that internal port == external port
        if (atoi(ext_port) != atoi(int_port))
        {
            trace(1, "Internal and External port values must be the same. external_port:%s, internal_port:%s",
                  ext_port, int_port);
            addErrorData(ca_event, 724, "SamePortValueRequired");
            result = 724;
        }

        if (result == 0)
        {
            // If port map with the same External Port, Protocol, and Internal Client exists
            // then, as per spec, we overwrite it (for simplicity, we delete and re-add at end of list)
            // Note: This may cause problems with GetGernericPortMappingEntry if a CP expects the overwritten
            // to be in the same place.
            if ((ret = pmlist_Find(remote_host, ext_port, proto, int_ip)) != NULL)
            {
                trace(3, "Found port map to already exist.  Replacing");
                pmlist_Delete(ret);
            }

            result = AddNewPortMapping(ca_event,bool_enabled,atoi(int_duration),remote_host,ext_port,int_port,proto,int_ip,desc);

            if (result == 1)
            {
                ca_event->ErrCode = UPNP_E_SUCCESS;
                snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
                         ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "", ca_event->ActionName);
                ca_event->ActionResult = ixmlParseBuffer(resultStr);
            }
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceAddPortMapping: Invalid Arguments!");
        trace(1, "  ExtPort: %s RemHost: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
              ext_port, remote_host, proto, int_port, int_ip, int_duration, bool_enabled, desc);
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if (ext_port) free(ext_port);
    if (int_port) free(int_port);
    if (proto) free(proto);
    if (int_ip) free(int_ip);
    if (bool_enabled) free(bool_enabled);
    if (desc) free(desc);
    if (remote_host) free(remote_host);

    return(ca_event->ErrCode);
}

int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event)
{
    char *mapindex = NULL;
    struct portMap *temp;
    char result_param[RESULT_LEN];
    char resultStr[RESULT_LEN];
    int action_succeeded = 0;

    if ((mapindex = GetFirstDocumentItem(ca_event->ActionRequest, "NewPortMappingIndex")))
    {
        temp = pmlist_FindByIndex(atoi(mapindex));
        if (temp)
        {
            snprintf(result_param, RESULT_LEN, "<NewRemoteHost>%s</NewRemoteHost><NewExternalPort>%s</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%s</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%d</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%li</NewLeaseDuration>",
                     temp->m_RemoteHost,
                     temp->m_ExternalPort,
                     temp->m_PortMappingProtocol,
                     temp->m_InternalPort,
                     temp->m_InternalClient,
                     temp->m_PortMappingEnabled,
                     temp->m_PortMappingDescription,
                     (temp->expirationTime-time(NULL)));
            action_succeeded = 1;
        }
        if (action_succeeded)
        {
            ca_event->ErrCode = UPNP_E_SUCCESS;
            snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
                     "urn:schemas-upnp-org:service:WANIPConnection:1",result_param, ca_event->ActionName);
            ca_event->ActionResult = ixmlParseBuffer(resultStr);
        }
        else
        {
            ca_event->ErrCode = 713;
            strcpy(ca_event->ErrStr, "SpecifiedArrayIndexInvalid");
            ca_event->ActionResult = NULL;
        }

    }
    else
    {
        trace(1, "Failure in GateDeviceGetGenericPortMappingEntry: Invalid Args");
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }
    if (mapindex) free (mapindex);
    return (ca_event->ErrCode);

}
int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    char result_param[RESULT_LEN];
    char resultStr[RESULT_LEN];
    int action_succeeded = 0;
    struct portMap *temp;

    if ((remote_host = GetFirstDocumentItem(ca_event->ActionRequest, "NewRemoteHost")) &&
            (ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort")) &&
            (proto = GetFirstDocumentItem(ca_event->ActionRequest,"NewProtocol")))
    {
        if ((strcmp(proto, "TCP") == 0) || (strcmp(proto, "UDP") == 0))
        {
            // Check if remote host is empty string or valid IP address
            if ((strcmp(remote_host, "") == 0) || (inet_addr(remote_host) != -1))
            {
                temp = pmlist_FindSpecific (remote_host, ext_port, proto);
                if (temp)
                {
                    snprintf(result_param, RESULT_LEN, "<NewInternalPort>%s</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%d</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%li</NewLeaseDuration>",
                             temp->m_InternalPort,
                             temp->m_InternalClient,
                             temp->m_PortMappingEnabled,
                             temp->m_PortMappingDescription,
                             (temp->expirationTime-time(NULL)));
                    action_succeeded = 1;
                }
                if (action_succeeded)
                {
                    ca_event->ErrCode = UPNP_E_SUCCESS;
                    snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
                             "urn:schemas-upnp-org:service:WANIPConnection:1",result_param, ca_event->ActionName);
                    ca_event->ActionResult = ixmlParseBuffer(resultStr);
                }
                else
                {
                    trace(2, "GateDeviceGetSpecificPortMappingEntry: PortMapping Doesn't Exist...");
                    ca_event->ErrCode = 714;
                    strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
                    ca_event->ActionResult = NULL;
                }
            }
            else
            {
                trace(1, "Failure in GateDeviceDeletePortMapping: Invalid NewRemoteHost=%s\n",remote_host);
                ca_event->ErrCode = 402;
                strcpy(ca_event->ErrStr, "Invalid Args");
                ca_event->ActionResult = NULL;
            }
        }
        else
        {
            trace(1, "Failure in GateDeviceGetSpecificPortMappingEntry: Invalid NewProtocol=%s\n",proto);
            ca_event->ErrCode = 402;
            strcpy(ca_event->ErrStr, "Invalid Args");
            ca_event->ActionResult = NULL;
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceGetSpecificPortMappingEntry: Invalid Args %s", remote_host);
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    return (ca_event->ErrCode);


}
int GetExternalIPAddress(struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    IXML_Document *result = NULL;

    ca_event->ErrCode = UPNP_E_SUCCESS;
    GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
    snprintf(resultStr, RESULT_LEN, "<u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
             "<NewExternalIPAddress>%s</NewExternalIPAddress>\n"
             "</u:GetExternalIPAddressResponse>", ExternalIPAddress);

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to ExternalIPAddress: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }

    return(ca_event->ErrCode);
}

int DeletePortMapping(struct Upnp_Action_Request *ca_event)
{
    char *remote_host=NULL;
    char *ext_port=NULL;
    char *proto=NULL;
    int result=0;
    char num[5];
    char resultStr[RESULT_LEN];
    IXML_Document *propSet= NULL;
    int action_succeeded = 0;
    struct portMap *temp;
    char tmp[11];

    if ((remote_host = GetFirstDocumentItem(ca_event->ActionRequest, "NewRemoteHost")) &&
            (ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort")) &&
            (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol")))
    {

        if ((strcmp(proto, "TCP") == 0) || (strcmp(proto, "UDP") == 0))
        {
            // Check if remote host is empty string or valid IP address
            if ((strcmp(remote_host, "") == 0) || (inet_addr(remote_host) != -1))
            {
                temp = pmlist_FindSpecific(remote_host, ext_port, proto);
                if (temp)
                    result = pmlist_Delete(temp);

                if (result==1)
                {
                    trace(2, "DeletePortMap: Remote Host: %s Proto:%s Port:%s\n", remote_host, proto, ext_port);
                    sprintf(num,"%d",pmlist_Size());
                    UpnpAddToPropertySet(&propSet,"PortMappingNumberOfEntries", num);
                    snprintf(tmp,11,"%ld",++SystemUpdateID);
                    UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
                    snprintf(ChangedPortMapping,100,"%s,%s,%s,%s,%s",ext_port,ext_port,proto,temp->m_InternalClient,remote_host);
                    UpnpAddToPropertySet(&propSet,"ChangedPortMapping", ChangedPortMapping);
                    UpnpNotifyExt(deviceHandle, ca_event->DevUDN,ca_event->ServiceID,propSet);
                    ixmlDocument_free(propSet);
                    action_succeeded = 1;
                }
                else
                {
                    trace(1, "Failure in GateDeviceDeletePortMapping: DeletePortMap: Remote Host:%s Proto:%s Port:%s\n",remote_host, proto, ext_port);
                    ca_event->ErrCode = 714;
                    strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
                    ca_event->ActionResult = NULL;
                }
            }
            else
            {
                trace(1, "Failure in GateDeviceDeletePortMapping: Invalid NewRemoteHost=%s\n",remote_host);
                ca_event->ErrCode = 402;
                strcpy(ca_event->ErrStr, "Invalid Args");
                ca_event->ActionResult = NULL;
            }
        }
        else
        {
            trace(1, "Failure in GateDeviceDeletePortMapping: Invalid NewProtocol=%s\n",proto);
            ca_event->ErrCode = 402;
            strcpy(ca_event->ErrStr, "Invalid Args");
            ca_event->ActionResult = NULL;
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceDeletePortMapping: Invalid Arguments!");
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if (action_succeeded)
    {
        ca_event->ErrCode = UPNP_E_SUCCESS;
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
                 ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "", ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
    }

    if (remote_host) free(remote_host);
    if (ext_port) free(ext_port);
    if (proto) free(proto);

    return(ca_event->ErrCode);
}

int DeletePortMappingRange(struct Upnp_Action_Request *ca_event)
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
    char resultStr[RESULT_LEN];
    IXML_Document *propSet= NULL;
    int action_succeeded = 0;
    struct portMap *temp;
    int authorized = 0;
    int managed = 0;
    int index = 0;
    int foundPortmapCount = 0;

    //chec if authorized
    if (AuthorizeControlPoint(ca_event) == CONTROL_POINT_AUTHORIZED)
        authorized = 1;

    if ((start_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewStartPort")) &&
            (end_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewEndPort")) &&
            (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol")) &&
            (bool_manage = GetFirstDocumentItem(ca_event->ActionRequest, "Manage")))
    {
        if ((strcmp(proto, "TCP") == 0) || (strcmp(proto, "UDP") == 0))
        {
            managed = resolveBoolean(bool_manage);
            start = atoi(start_port);
            end = atoi(end_port);

            //loop ports from start to end
            for (ext_port = start; ext_port <= end; ext_port++)
            {
                snprintf(del_port,str_len,"%d",ext_port);
                index = 0;
                // remove all instances with externalPort
                do
                {
                    temp = pmlist_FindSpecificAfterIndex("", del_port, proto, index);
                    if (temp)
                    {
                        foundPortmapCount++;
                        if ((authorized && managed) || ControlPointIP_equals_InternalClientIP(temp->m_InternalClient, &ca_event->CtrlPtIPAddr))
                        {
                            result = pmlist_DeleteIndex(temp, index);
                            SystemUpdateID++;
                            snprintf(ChangedPortMapping,100,"%s,%s,%s,%s,%s",start_port,end_port,proto,temp->m_InternalClient,temp->m_RemoteHost);
                        }
                        else
                            index++;
                    }
                }
                while (temp != NULL);
            }

            // maximum 5 events per second (from specification), that is why we send only one event after deleting all
            if (result==1)
            {
                trace(2, "DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s\n", start_port, end_port, proto, bool_manage);

                snprintf(tmp,11,"%d",pmlist_Size());
                UpnpAddToPropertySet(&propSet,"PortMappingNumberOfEntries", tmp);
                snprintf(tmp,11,"%ld",SystemUpdateID);
                UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);

                UpnpAddToPropertySet(&propSet,"ChangedPortMapping", ChangedPortMapping);

                UpnpNotifyExt(deviceHandle, ca_event->DevUDN,ca_event->ServiceID,propSet);
                action_succeeded = 1;
            }

            // portmappings which are in area of deletion exists, but none has been deleted -> Action is not permitted
            if (foundPortmapCount > 0 && !action_succeeded)
            {
                trace(1, "Failure in GateDeviceDeletePortMappingRange: DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s ActionNotPermitted!\n", start_port,end_port,proto,bool_manage);
                ca_event->ErrCode = 730;
                strcpy(ca_event->ErrStr, "ActionNotPermitted");
                ca_event->ActionResult = NULL;
            }
            else if (!action_succeeded)
            {
                trace(1, "Failure in GateDeviceDeletePortMappingRange: DeletePortMappingRange: StartPort:%s EndPort:%s Proto:%s Manage:%s NoSuchEntryInArray!\n", start_port,end_port,proto,bool_manage);
                ca_event->ErrCode = 714;
                strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
                ca_event->ActionResult = NULL;
            }
        }
        else
        {
            trace(1, "Failure in GateDeviceDeletePortMappingRange: Invalid NewProtocol=%s\n",proto);
            ca_event->ErrCode = 402;
            strcpy(ca_event->ErrStr, "Invalid Args");
            ca_event->ActionResult = NULL;
        }
    }
    else
    {
        trace(1, "Failure in GateDeviceDeletePortMappingRange: Invalid Arguments!");
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if (action_succeeded)
    {
        ca_event->ErrCode = UPNP_E_SUCCESS;
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
                 ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "", ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
    }

    if (propSet) ixmlDocument_free(propSet);
    if (start_port) free(start_port);
    if (end_port) free(end_port);
    if (proto) free(proto);
    if (bool_manage) free(bool_manage);

    return(ca_event->ErrCode);
}


int ExpirationTimerThreadInit(void)
{
    int retVal;
    ThreadPoolAttr attr;
    TPAttrInit( &attr );
    TPAttrSetMaxThreads( &attr, MAX_THREADS );
    TPAttrSetMinThreads( &attr, MIN_THREADS );
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

int ExpirationTimerThreadShutdown(void)
{
    return TimerThreadShutdown(&gExpirationTimerThread);
}

void free_expiration_event(expiration_event *event)
{
    if (event->mapping!=NULL)
        event->mapping->expirationEventId = -1;
    free(event);
}

/**
 * This timer is used to check periodically if values of some state variables have changed.
 * If some has chandeg then event is sent to control points which has subscribed those events.
 */
int createEventUpdateTimer(void)
{
    expiration_event *event;
    event = ( expiration_event * ) malloc( sizeof( expiration_event ) );
    if ( event == NULL )
    {
        return 0;
    }

    // Add event update job
    TPJobInit( &gEventUpdateJob, ( start_routine ) UpdateEvents, event );
    TimerThreadSchedule( &gExpirationTimerThread,
                         g_vars.eventUpdateInterval,
                         REL_SEC, &gEventUpdateJob, SHORT_TERM,
                         &( event->eventId ) );
    return  event->eventId;
}

/**
 * Send event for control point that state variable has changed
 */
void UpdateEvents(void *input)
{
    IXML_Document *propSet = NULL;

    trace(3, "Update Events");

    ithread_mutex_lock(&DevMutex);

    EthernetLinkStatusEventing(propSet);
    ExternalIPAddressEventing(propSet);
    ConnectionStatusEventing(propSet);

    ithread_mutex_unlock(&DevMutex);

    if (propSet) ixmlDocument_free(propSet);

    // create update event again
    createEventUpdateTimer();
}

// return 0 if no change
int EthernetLinkStatusEventing(IXML_Document *propSet)
{
    char prevStatus[12];

    strcpy(prevStatus,EthernetLinkStatus);
    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);

    // has status changed?
    if (strcmp(prevStatus,EthernetLinkStatus) != 0)
    {
        UpnpAddToPropertySet(&propSet, "EthernetLinkStatus", EthernetLinkStatus);
        UpnpNotifyExt(deviceHandle, wanConnectionUDN, "urn:upnp-org:serviceId:WANEthLinkC1", propSet);
        trace(2, "EthernetLinkStatus changed: From %s to %s",prevStatus,EthernetLinkStatus);
        propSet = NULL;
        return 1;
    }
    return 0;
}

// return 0 if no change
int ExternalIPAddressEventing(IXML_Document *propSet)
{
    char prevStatus[INET6_ADDRSTRLEN];

    strcpy(prevStatus,ExternalIPAddress);
    GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);

    // has status changed?
    if (strcmp(prevStatus,ExternalIPAddress) != 0)
    {
        UpnpAddToPropertySet(&propSet, "ExternalIPAddress", ExternalIPAddress);
        UpnpNotifyExt(deviceHandle, wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
        trace(2, "ExternalIPAddress changed: From %s to %s",prevStatus,ExternalIPAddress);
        propSet = NULL;
        return 1;
    }
    return 0;
}

int ConnectionStatusEventing(IXML_Document *propSet)
{
    char prevStatus[20];

    strcpy(prevStatus,ConnectionStatus);
    GetConnectionStatus(ConnectionStatus, g_vars.extInterfaceName);

    // has status changed?
    if (strcmp(prevStatus,ConnectionStatus) != 0)
    {
        UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
        UpnpNotifyExt(deviceHandle, wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
        trace(2, "ConnectionStatus changed: From %s to %s",prevStatus,ConnectionStatus);
        propSet = NULL;
        return 1;
    }
    return 0;
}

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
    event->mapping->expirationEventId = -1;
    pmlist_Delete(event->mapping);

    sprintf(num, "%d", pmlist_Size());
    UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);
    snprintf(tmp,11,"%ld",++SystemUpdateID);
    UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
    snprintf(ChangedPortMapping,100,"%s,%s,%s,%s,%s",event->mapping->m_ExternalPort,
             event->mapping->m_ExternalPort,event->mapping->m_PortMappingProtocol,
             event->mapping->m_InternalClient,event->mapping->m_RemoteHost);
    UpnpAddToPropertySet(&propSet,"ChangedPortMapping", ChangedPortMapping);
    UpnpNotifyExt(deviceHandle, event->DevUDN, event->ServiceID, propSet);
    ixmlDocument_free(propSet);
    trace(3, "ExpireMapping: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
          event->DevUDN, event->ServiceID, num);

    free_expiration_event(event);

    ithread_mutex_unlock(&DevMutex);
}

int ScheduleMappingExpiration(struct portMap *mapping, char *DevUDN, char *ServiceID)
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

void DeleteAllPortMappings(void)
{
    IXML_Document *propSet = NULL;
    char tmp[11];

    ithread_mutex_lock(&DevMutex);

    pmlist_FreeList();

    UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", "0");
    snprintf(tmp,11,"%ld",++SystemUpdateID);
    UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
    UpnpNotifyExt(deviceHandle, wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
    ixmlDocument_free(propSet);
    trace(2, "DeleteAllPortMappings: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
          wanConnectionUDN, "urn:upnp-org:serviceId:WANIPConn1", "0");

    ithread_mutex_unlock(&DevMutex);
}


/*
  AddAnyPortMapping
  IGDv2 addition
  TODO: Refactor common code with AddPortMapping...
*/
int AddAnyPortMapping
(struct Upnp_Action_Request *ca_event)
{

    char *new_remote_host=NULL;
    char *new_external_port=NULL;
    char *new_protocol=NULL;
    char *new_internal_port = NULL;
    char *new_internal_client=NULL;
    char *new_enabled=NULL;
    char *new_port_mapping_description=NULL;
    char *new_lease_duration=NULL;

    long leaseDuration = 0;
    int next_free_port = 0;

    struct portMap *ret;

    int result = 0;
    char resultStr[RESULT_LEN];
    char freePort[5];


    if ( (new_remote_host = GetFirstDocumentItem(ca_event->ActionRequest, "NewRemoteHost") )
            && (new_external_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort") )
            && (new_protocol = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol") )
            && (new_internal_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalPort") )
            && (new_internal_client = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalClient") )
            && (new_enabled = GetFirstDocumentItem(ca_event->ActionRequest, "NewEnabled") )
            && (new_port_mapping_description = GetFirstDocumentItem(ca_event->ActionRequest, "NewPortMappingDescription") )
            && (new_lease_duration = GetFirstDocumentItem(ca_event->ActionRequest, "NewLeaseDuration") ) )
    {
    // Check RemoteHost and ExternalPort parameters
    if (checkForWildCard(new_remote_host)) {
        trace(1, "Wild cards not permitted in remote_host:%s", new_remote_host);
        addErrorData(ca_event, 715, "WildCardNotPermittedInSrcIp");
                result = 715;
    } else
    if (checkForWildCard(new_external_port)) {
        trace(1, "Wild cards not permitted in external_port:%s", new_external_port);
        addErrorData(ca_event, 716, "WildCardNotPermittedInExtPort");
                result = 716;
    } else
    // check that internal port == external port
    if (atoi(new_external_port) != atoi(new_internal_port))
    {
        trace(1, "Internal and External port values must be the same. external_port:%s, internal_port:%s",
              new_external_port, new_internal_port);
        addErrorData(ca_event, 724, "SamePortValueRequired");
        result = 724;
    }
    leaseDuration = atol(new_lease_duration);

    // TODO: SecurityChecks here...

    // Parameters OK... proceed with adding port map
    if (result == 0)
        {
            // If port map with the same External Port, Protocol, and Internal Client exists
            // then get next free port map
            if ((ret = pmlist_Find(new_remote_host, new_external_port, new_protocol, new_internal_client)) != NULL)
            {
            // Find searches free external port...
            // TODO: free port mapping search
                    trace(3, "Found port map to already exist.  Finding next free");
                    next_free_port = pmlist_FindNextFreePort(new_protocol);
            if (next_free_port > 0)
                {
                trace(3, "Found free port:%d", next_free_port);
                sprintf(freePort, "%d", next_free_port);
                        result = AddNewPortMapping(ca_event, new_enabled, leaseDuration, new_remote_host,
                                  freePort, new_internal_port, new_protocol,
                                                  new_internal_client, new_port_mapping_description);
                    }
                    else {
                result = 718; /* no free port found... use ConflictInMappingEntry error code */
                    }
            }
            else {
            // Otherwise just add the port map
                result = AddNewPortMapping(ca_event, new_enabled, leaseDuration, new_remote_host,
                              new_external_port, new_internal_port, new_protocol,
                                              new_internal_client, new_port_mapping_description);
            }
    }
    if (result==718)
        {
            trace(1,"Failure in GateDeviceAddAnyPortMapping: RemoteHost: %s Protocol:%s ExternalPort: %s InternalClient: %s.%s\n",
                  new_remote_host, new_protocol, new_external_port, new_internal_client, new_internal_port);

        addErrorData(ca_event, 718, "ConflictInMappingEntry");
        }

    }
    else
    {
        trace(1, "Failure in GateDeviceAddAnyPortMapping: Invalid Arguments!");
        trace(1, "  RemoteHost: %s ExternalPort: %s Protocol: %s InternalClient: %s Enabled: %s PortMappingDesc: %s LeaseDuration: %s",
              new_remote_host, new_external_port, new_protocol, new_internal_client, new_enabled,
          new_port_mapping_description, new_lease_duration);
    addErrorData(ca_event, 402, "Invalid Args");
    }

    if (result == 1)
    {
        ca_event->ErrCode = UPNP_E_SUCCESS;
        if (next_free_port == 0) next_free_port = atoi(new_external_port);

    snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s%d%s\n</u:%sResponse>",
                 ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "<ReservedPort>",
         next_free_port, "</ReservedPort>", ca_event->ActionName);
    ca_event->ActionResult = ixmlParseBuffer(resultStr);
    }

    if (new_remote_host) free(new_remote_host);
    if (new_external_port) free(new_external_port);
    if (new_protocol) free(new_protocol);
    if (new_internal_client) free(new_internal_client);
    if (new_enabled) free(new_enabled);
    if (new_port_mapping_description) free(new_port_mapping_description);
    if (new_lease_duration) free(new_lease_duration);

    return(ca_event->ErrCode);
}

int AddNewPortMapping(struct Upnp_Action_Request *ca_event, char* new_enabled, int leaseDuration,
                      char* new_remote_host, char* new_external_port, char* new_internal_port,
                      char* new_protocol, char* new_internal_client, char* new_port_mapping_description)
{
    int result;
    char num[5]; // Maximum number of port mapping entries 9999
    IXML_Document *propSet = NULL;
    struct portMap *new;
    char tmp[11];

    new = pmlist_NewNode(atoi(new_enabled), leaseDuration, new_remote_host,
                  new_external_port, new_internal_port, new_protocol,
                          new_internal_client, new_port_mapping_description);

    result = pmlist_PushBack(new);

    if (result==1)
    {
        ScheduleMappingExpiration(new,ca_event->DevUDN,ca_event->ServiceID);
        sprintf(num, "%d", pmlist_Size());
        trace(3, "PortMappingNumberOfEntries: %d", pmlist_Size());
        UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);
        snprintf(tmp,11,"%ld",++SystemUpdateID);
        snprintf(ChangedPortMapping,100,"%s,%s,%s,%s,%s",new_external_port,new_external_port,new_protocol,new_internal_client,new_remote_host);
        UpnpAddToPropertySet(&propSet,"ChangedPortMapping", ChangedPortMapping);
        UpnpAddToPropertySet(&propSet,"SystemUpdateID", tmp);
        UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);

        ixmlDocument_free(propSet);
        trace(2, "%s: DevUDN: %s ServiceID: %s RemoteHost: %s Protocol: %s ExternalPort: %s InternalClient: %s.%s",
                    ca_event->ActionName,ca_event->DevUDN,ca_event->ServiceID,new_remote_host, new_protocol, new_external_port,
                    new_internal_client, new_internal_port);
    }

    return result;
}

/**
 * Action: Retrieves a list of all port mappings.
 */
int RetrieveListOfPortmappings(struct Upnp_Action_Request *ca_event)
{
    char *start_port = NULL;
    char *end_port = NULL;
    char *manage = NULL;
    char *proto = NULL;
    char *number_of_ports = NULL;
    char cp_ip[INET_ADDRSTRLEN] = "";
    char result_str[RESULT_LEN];

    int start, end;
    int max_entries;
    int action_succeeded = 0;
    int result_place = 0;
    struct portMap *pm = NULL;

    if ( (start_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewStartPort") )
            && (end_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewEndPort") )
            && (manage = GetFirstDocumentItem(ca_event->ActionRequest, "Manage") )
            && (number_of_ports = GetFirstDocumentItem(ca_event->ActionRequest, "NewNumberOfPorts") )
            && (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol") ))
    {
        start = atoi(start_port);
        end = atoi(end_port);
        max_entries = atoi(number_of_ports);
        if (max_entries == 0)
            max_entries = INT_MAX;

        // If manage is not true or CP is not authorized, list only CP's port mappings
        if ( !resolveBoolean(manage) || !AuthorizeControlPoint(ca_event) == CONTROL_POINT_AUTHORIZED )
            inet_ntop(AF_INET, &ca_event->CtrlPtIPAddr, cp_ip, INET_ADDRSTRLEN);

        // Write XML header
        result_place += snprintf(result_str, RESULT_LEN, xml_portmapListingHeader, ca_event->ActionName);

        // Loop through port mappings until we run out or max_entries reaches 0
        while ( (pm = pmlist_FindRangeAfter(start, end, proto, cp_ip, pm)) != NULL && max_entries--)
        {
            result_place += sprintf(&result_str[result_place], xml_portmapEntry,
                                   pm->m_RemoteHost, pm->m_ExternalPort, pm->m_PortMappingProtocol,
                                   pm->m_InternalPort, pm->m_InternalClient, pm->m_PortMappingEnabled,
                                   pm->m_PortMappingDescription, pm->m_PortMappingLeaseDuration);
            action_succeeded = 1;
        }

        if (action_succeeded)
        {
            ca_event->ErrCode = UPNP_E_SUCCESS;
            result_place += sprintf(&result_str[result_place], xml_portmapListingFooter, ca_event->ActionName);
            ca_event->ActionResult = ixmlParseBuffer(result_str);
        }
        else
        {
            trace(2, "RetrieveListOfPortmappings: Portmapping does not exist");
            ca_event->ErrCode = 714;
            strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
            ca_event->ActionResult = NULL;
        }
    }
    else
    {
        trace(1, "RetrieveListOfPortmappings: Invalid Arguments\n\tStartPort: %s EndPort: %s Proto: %s NumberOfPorts: %s Manage: %s",
              start_port, end_port, proto, number_of_ports, manage);
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if (start_port) free(start_port);
    if (end_port) free(end_port);
    if (proto) free(proto);
    if (manage) free(manage);
    if (number_of_ports) free(number_of_ports);

    return ca_event->ErrCode;
}

/**
 * WANEthernetLinkConfig Service
 *  GetEthernetLinkStatus Action
 */
int GetEthernetLinkStatus (struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    IXML_Document *result;


    setEthernetLinkStatus(EthernetLinkStatus, g_vars.extInterfaceName);

    snprintf(resultStr, RESULT_LEN,
             "<u:GetEthernetLinkStatusResponse xmlns:u=\"urn:schemas-upnp-org:service:WANEthernetLinkConfig:1\">\n"
             "<NewEthernetLinkStatus>%s</NewEthernetLinkStatus>\n"
             "</u:GetEthernetLinkStatusResponse>",EthernetLinkStatus);

    // Create a IXML_Document from resultStr and return with ca_event
    if ((result = ixmlParseBuffer(resultStr)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetEthernetLinkStatus: %s", resultStr);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 501;
    }

    return(ca_event->ErrCode);
}

// Checks if control point is authorized
// NOT YET IMPLEMENTED
int AuthorizeControlPoint(struct Upnp_Action_Request *ca_event)
{
    return CONTROL_POINT_AUTHORIZED;
}

