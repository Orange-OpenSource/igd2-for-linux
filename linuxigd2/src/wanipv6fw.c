/** 
 * This file is part of igd2-for-linux project
 * Copyright © 2011-2016 France Telecom / Orange.
 * Contact: fabrice.fontaine@orange.com
 * Developer(s): fabrice.fontaine@orange.com, rmenard.ext@orange-ftgroup.com
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <upnp/upnp.h>


#include "gatedevice.h"
#include "util.h"
#include "globals.h"
#include "wanipv6fw.h"
#include "pinholev6.h"


/**
 * -----------------------------------------------------------------------------
 * PRIVATE FONCTIONS ---
 * -----------------------------------------------------------------------------
 */

/**
 * check if the IPv6 address given in string is usable
 *
 * @param ipv6address the ipv6 address to check in presentation mode (string)
 * @return 1 if the adress is usable, 0 otherwise
 */
int checkIPv6addressUsable (char* ipv6address) {

    struct in6_addr addr;

    //todo : check if this is a DNS

    if(inet_pton(AF_INET6, ipv6address, &addr)==1)
    {
        return 1;
    }

    trace(1, "checkIPv6addressUsable : %s is NOT usable\n", ipv6address);
    return 0;
}

/**
 * check if the Ipv6 address given in parameter is used by the gateway
 *
 * @param ipv6address the ipv6 address to check in presentation mode (string)
 * @return 1 if true, 0 otherwise
 */
int checkGatewayIPv6Addresses(char* ipv6address)
{
    char addr6[8][5];
    FILE* inet6_procfd;
    struct in6_addr v6_addr, ICv6addr;
    char addrStr[INET6_ADDRSTRLEN];



    if( inet_pton(AF_INET6, ipv6address, &ICv6addr) != 1 ) {
        trace(1, "checkGatewayIPv6Addresses : cant evaluate ipv6 addresse %s\n",
                ipv6address);
        return 0;
    }

    inet6_procfd = fopen( "/proc/net/if_inet6", "r" );
    if( inet6_procfd != NULL ) {
        while( fscanf(inet6_procfd,
                "%4s%4s%4s%4s%4s%4s%4s%4s %*02x %*02x %*02x %*02x %*20s\n",
                addr6[0],addr6[1],addr6[2],addr6[3],
                addr6[4],addr6[5],addr6[6],addr6[7]) != EOF) {

            snprintf(addrStr, sizeof(addrStr), "%s:%s:%s:%s:%s:%s:%s:%s",
                    addr6[0],addr6[1],addr6[2],addr6[3],
                    addr6[4],addr6[5],addr6[6],addr6[7]);

            if( inet_pton(AF_INET6, addrStr, &v6_addr) > 0 ) {

                if(memcmp(&ICv6addr, &v6_addr, 16) == 0) {
                    trace(1, "ckeckGatewayIPv6addresses : %s found!!!\n",
                            ipv6address);
                    return 1;
                }
            }
        }
    }
    fclose( inet6_procfd );
    return 0;
}

/*
 * compare two IPv6 addresses (string and binary)
 *
 * @param ipv6address the ipv6 address to check in presentation mode (string)
 * @param ss the other ipv6 address in binary mode
 * @return 1 if both address are the same
 */
int ipv6StrAddrCmp(char * ipv6address, struct sockaddr_storage * ss)
{
    struct in6_addr str;
    struct in6_addr *sock=&(((struct sockaddr_in6 *)ss)->sin6_addr);

    if(ss->ss_family != AF_INET6) return 0;
    if(inet_pton(AF_INET6, ipv6address, &str)==1)
    {
        return IN6_ARE_ADDR_EQUAL(&str,sock);
    }
    return 0;
}

/*
 * compare two IPv6 addresses (binary and binary)
 *
 * @param ipv6address the ipv6 address to check in presentation mode (string)
 * @param ss the other ipv6 address in binary mode
 * @return 1 if both address are the same
 */
int ipv6BinAddrCmp(struct in6_addr * ipv6address, struct sockaddr_storage * ss)
{
    struct in6_addr *sock=&(((struct sockaddr_in6 *)ss)->sin6_addr);
    if(ss->ss_family != AF_INET6) return 0;
    return IN6_ARE_ADDR_EQUAL(ipv6address,sock);
}

/**
 * error management
 *
 * @param error an integer according to upnp specification
 * @param ca_event the action request which is used to answer to the control point
 */
void errorManagement(int error, struct Upnp_Action_Request *ca_event)
{

    ca_event->ActionResult = NULL;
    ca_event->ErrCode = error;

    switch(error)
    {
    case ERR_ACTION_NOT_AUTHORIZED :
        trace(1, "WANIPv6FW Error : Action not authorized");
        strcpy(ca_event->ErrStr, "Action not authorized");
        break;
    case ERR_PINHOLE_SPACE_EXHAUSTED :
        trace(1, "WANIPv6FW Error : Pinhole space exhausted");
        strcpy(ca_event->ErrStr, "PinholeSpaceExhausted");
        break;
    case ERR_FIREWALL_DISABLED :
        trace(1, "WANIPv6FW Error : Firewall disabled");
        strcpy(ca_event->ErrStr, "FirewallDisabled");
        break;
    case ERR_INBOUND_PINHOLE_NOT_ALLOWED :
        trace(1, "WANIPv6FW Error : Inbound pinhole not allowed");
        strcpy(ca_event->ErrStr, "InboundPinholeNotAllowed");
        break;
    case ERR_NO_SUCH_ENTRY :
        trace(1, "WANIPv6FW Error : No such entry");
        strcpy(ca_event->ErrStr, "NoSuchEntry");
        break;
    case ERR_PROTOCOL_NOT_SUPPORTED :
        trace(1, "WANIPv6FW Error : Protocol not supported");
        strcpy(ca_event->ErrStr, "ProtocolNotSupported");
        break;
    case ERR_INTERNAL_PORT_WILDCARD :
        trace(1, "WANIPv6FW Error : Internal port wildcarding not allowed");
        strcpy(ca_event->ErrStr, "InternalPortWildcardingNotAllowed");
        break;
    case ERR_PROTOCOL_WILDCARD :
        trace(1, "WANIPv6FW Error : Protocol wildcarding not allowed");
        strcpy(ca_event->ErrStr, "ProtocolWildcardingNotAllowed");
        break;
    case ERR_SRC_ADD_WILDCARD :
        trace(1, "WANIPv6FW Error : Src IP wildcarding not allowed");
        strcpy(ca_event->ErrStr, "WildCardNotPermittedInSrcIP");
        break;
    case ERR_NO_TRAFFIC :
        trace(1, "WANIPv6FW Error : No traffic to check pinhole");
        strcpy(ca_event->ErrStr, "NoTrafficReceived");
        break;
    case UPNP_SOAP_E_INVALID_ARGS :
    default :
        trace(1, "WANIPv6FW Error : Parsing problem");
        addErrorData(ca_event, UPNP_SOAP_E_INVALID_ARGS, "Invalid Args"); 
        break;
    }


}

/**
 * -----------------------------------------------------------------------------
 * PUBLIC FONCTIONS
 * -----------------------------------------------------------------------------
 */


/**
 * InitFirewallv6
 *
 * @return 1 if ok.
 */
int InitFirewallv6(void)
{
    if(g_vars.ipv6firewallEnabled)
    return phv6_init();
    return 1;

}
/**
 * CloseFirewallv6
 *
 * @return 1 if ok
 */
int CloseFirewallv6(void)
{
    return phv6_close();
}

/**
 * this function implements the WANIPv6FirewallControl:getFirewallStatus action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_getFirewallStatus(struct Upnp_Action_Request *ca_event)
{
    if(GetNbSoapParameters(ca_event->ActionRequest) == 0) {

        ParseResult( ca_event, "<FirewallEnabled>%i</FirewallEnabled>\n"
                "<InboundPinholeAllowed>%i</InboundPinholeAllowed>\n", 
                g_vars.ipv6firewallEnabled,
                g_vars.ipv6inboundPinholeAllowed );
    }

    else {
        trace(1, "GetFirewallStatus invalid number of parameters");
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
    }

    return(ca_event->ErrCode);

}

/**
 * this function implements the WANIPv6FirewallControl:getOutboundPinholeTimeOut action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_getOutboundPinholeTimeOut(struct Upnp_Action_Request *ca_event)
{
    char *remote_host=NULL;
    char *remote_port=NULL;
    char *internal_client=NULL;
    char *internal_port=NULL;
    char *protocol=NULL;
    int error = 0;

    if ( (remote_host = GetFirstDocumentItem(
            ca_event->ActionRequest, "RemoteHost") )
            && (remote_port = GetFirstDocumentItem(
                    ca_event->ActionRequest, "RemotePort") )
            && (internal_client = GetFirstDocumentItem(
                    ca_event->ActionRequest, "InternalClient") )
            && (internal_port = GetFirstDocumentItem(
                    ca_event->ActionRequest, "InternalPort") )
            && (protocol = GetFirstDocumentItem(
                    ca_event->ActionRequest, "Protocol") )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 5 ) )
    {

        if(!(checkForWildCard(internal_client))
                && (checkIPv6addressUsable(internal_client)==0))
        {
            //invalid args, not IPv6 adresses
            trace(1, "Failure in GetOutboundPinholeTimeout:Invalid Arguments!");
            trace(1, " Internal Client: %s \n",internal_client);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(!checkForWildCard(remote_host)
                && (checkIPv6addressUsable(remote_host)==0))
        {
            //invalid args, not IPv6 adresses
            trace(1, "Failure in GetOutboundPinholeTimeout:Invalid Arguments!");
            trace(1, " RemoteHost: %s \n",remote_host);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(!checkForWildCard(remote_port)
                && (!isStringInteger(remote_port)))
        {
            //invalid args, not a port number
            trace(1, "Failure in GetOutboundPinholeTimeout:Invalid Arguments!");
            trace(1, " RemotePort: %s \n",remote_port);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(!checkForWildCard(internal_port)
                && (!isStringInteger(internal_port)))
        {
            //invalid args, not a port number
            trace(1, "Failure in GetOutboundPinholeTimeout:Invalid Arguments!");
            trace(1, " InternalPort: %s \n",internal_port);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if ( atoi(protocol) != 65535
                &&(atoi(protocol) != IPPROTO_UDPLITE)
                && (atoi(protocol) != IPPROTO_UDP)
                && (atoi(protocol) != IPPROTO_TCP))
        {
            //error 705 protocol not supported
            errorManagement(ERR_PROTOCOL_NOT_SUPPORTED, ca_event);
            error = ERR_PROTOCOL_NOT_SUPPORTED;
        }

        if(error == 0)
        {
            int timeout = 0;
            FILE* timeout_file = NULL;

            if(atoi(protocol) == IPPROTO_UDPLITE) {
                timeout_file = fopen(
                        "/proc/sys/net/netfilter/nf_conntrack_udplite_timeout",
                        "r" );
            }
            else if(atoi(protocol) == IPPROTO_UDP) {
                timeout_file = fopen(
                        "/proc/sys/net/netfilter/nf_conntrack_udp_timeout",
                        "r" );
            }
            else if(atoi(protocol) == IPPROTO_TCP) {
                timeout_file = fopen(
                        "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
                        "r" );
            }

            if(timeout_file != NULL)
            {
                if(fscanf(timeout_file, "%i",&timeout) != EOF);
                fclose(timeout_file);
            }
            else
            {
                timeout_file = fopen(
                        "/proc/sys/net/netfilter/nf_conntrack_generic_timeout",
                        "r" );
                if( timeout_file != NULL ) {
                    if(fscanf(timeout_file, "%i",&timeout) != EOF);
                    fclose(timeout_file);
                }
                else
                {
                    //TODO no nf_conntrack module loaded
                }
            }

            ParseResult( ca_event,
                "<OutboundPinholeTimeout>%i</OutboundPinholeTimeout>\n", 
                timeout );
        }

    }
    else
    {
        trace(1, "Failure in GetOutboundPinholeTimeout:"
                "Invalid Arguments!");
        trace(1, "  RemoteHost: %s RemotePort: %s InternalClient: "
                "%s InternalPort: %s Protocol: ",
                remote_host, remote_port, internal_client,
                internal_port, protocol);
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
        return UPNP_SOAP_E_INVALID_ARGS;
    }

    free(remote_host);
    free(remote_port);
    free(internal_client);
    free(internal_port);
    free(protocol);

    return(ca_event->ErrCode);
}

/**
 * this function implements the WANIPv6FirewallControl:addPinhole action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_addPinhole(struct Upnp_Action_Request *ca_event)
{

    char *remote_host=NULL;
    char *remote_port=NULL;
    char *internal_client=NULL;
    char *internal_port=NULL;
    char *protocol=NULL;
    char *lease_time=NULL;
    uint32_t UniqueId;
    int error = 0;

    if ( (remote_host = GetFirstDocumentItem(
            ca_event->ActionRequest, "RemoteHost") )
            && (remote_port = GetFirstDocumentItem(
                    ca_event->ActionRequest, "RemotePort") )
            && (internal_client = GetFirstDocumentItem(
                    ca_event->ActionRequest, "InternalClient") )
            && (internal_port = GetFirstDocumentItem(
                    ca_event->ActionRequest, "InternalPort") )
            && (protocol = GetFirstDocumentItem(
                    ca_event->ActionRequest, "Protocol") )
            && (lease_time = GetFirstDocumentItem(
                    ca_event->ActionRequest, "LeaseTime") )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 6 ) )
    {
        if(!g_vars.ipv6firewallEnabled)
        {
            //error 702 firewall disabled
            errorManagement(ERR_FIREWALL_DISABLED, ca_event);
            return(ERR_FIREWALL_DISABLED);
        }

        if(!g_vars.ipv6inboundPinholeAllowed)
        {
            //error 703 not authorized
            errorManagement(ERR_INBOUND_PINHOLE_NOT_ALLOWED, ca_event);
            return(ERR_INBOUND_PINHOLE_NOT_ALLOWED);
        }

        if( (!checkForWildCard(remote_host)
                && checkIPv6addressUsable(remote_host)==0) )
        {
            //invalid args, not IPv6 adresses
            trace(1, " RemoteHost: %s \n",remote_host);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(!checkForWildCard(remote_port)
                && (!isStringInteger(remote_port)))
        {
            //invalid args, not a port number
            trace(1, "Failure in AddPinhole:Invalid Arguments!");
            trace(1, " RemotePort: %s \n",remote_port);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(checkForWildCard(internal_client))
        {
            trace(1, " Internal client is wildcarded");
            errorManagement(ERR_SRC_ADD_WILDCARD, ca_event);
            error = ERR_SRC_ADD_WILDCARD;
        }

        else if(checkIPv6addressUsable(internal_client)==0) {
            trace(1, " Internal client : %s",internal_client);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if(checkGatewayIPv6Addresses(internal_client))
        {
            trace(1, "Can not use the gateway's IP address");
            errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
            error = ERR_ACTION_NOT_AUTHORIZED;
        }

        else if (!isStringInteger(protocol))
        {
            trace(1, "Invalid protocol:%s", protocol);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        else if (atoi(protocol) == 65535)
        {
            trace(1, "Wild cards not permitted in protocol:%s", protocol);
            errorManagement(ERR_PROTOCOL_WILDCARD, ca_event);
            error = ERR_PROTOCOL_WILDCARD;
        }

        else if ( (atoi(protocol) != IPPROTO_UDPLITE)
                && (atoi(protocol) != IPPROTO_UDP)
                && (atoi(protocol) != IPPROTO_TCP) )
        {
            //error 705 protocol not supported
            errorManagement(ERR_PROTOCOL_NOT_SUPPORTED, ca_event);
            error = ERR_PROTOCOL_NOT_SUPPORTED;
        }

        // if Internal port is <1024 and InternalClient is different from control point
        // control point needs to be authorized
        else if ( ( (atoi(internal_port) < 1024 && atoi(internal_port) > 0)
                || !ipv6StrAddrCmp(internal_client, &ca_event->CtrlPtIPAddr))
                && ( AuthorizeControlPoint(ca_event, 0, 1) != CONTROL_POINT_NOT_AUTHORIZED ))
        {
            trace(1, "Internal port number must be greater than 1023 "
                    "and InternalClient must be same as IP of Control point "
                    "unless control point is authorized. "
                    "internal_port:%s internal_client:%s",
                    internal_port, internal_client);
            errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
            error = ERR_ACTION_NOT_AUTHORIZED;
        }

        // Check InternalPort parameter
        else if (checkForWildCard(internal_port))
        {
            trace(1, "Wild cards not permitted in internal port:%s",
                    internal_port);
            errorManagement(ERR_INTERNAL_PORT_WILDCARD, ca_event);
            error = ERR_INTERNAL_PORT_WILDCARD;
        }

        else if(!isStringInteger(internal_port))
        {
            trace(1, "InternalPort is not a port number:%s",
                    internal_port);
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }

        // check that leaseduration is between 1 and 86400
        else if ((atoi(lease_time) < 1) || (atoi(lease_time) > 86400)
                || !isStringInteger(lease_time))
        {
            trace(1, "lease time must be between 1 and 86400");
            errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
            error = UPNP_SOAP_E_INVALID_ARGS;
        }


        else if(phv6_existingPinhole(internal_client,
                remote_host,
                internal_port,
                remote_port,
                protocol,
                &UniqueId))
        {
            phv6_updatePinhole(UniqueId,(uint32_t)atoi(lease_time));
        }
        //else add the pinhole int the list
        else if(phv6_addPinhole(internal_client,
                remote_host,
                internal_port,
                remote_port,
                protocol,
                (uint32_t)atoi(lease_time),
                &UniqueId) < 0)
        {
            trace(1, "AddPinhole out of memory");
            errorManagement(ERR_PINHOLE_SPACE_EXHAUSTED, ca_event);
            error = ERR_PINHOLE_SPACE_EXHAUSTED;
        }


        if(error == 0)
        {
            ParseResult( ca_event, "<UniqueID>%i</UniqueID>\n", UniqueId );
        }

    }

    else
    {
        trace(1, "Failure in AddPinhole: Invalid Arguments!");
        trace(1, "  RemotePort: %s RemoteHost: %s Protocol: %s "
                "InternalPort: %s InternalClient: %s leaseTime: %s",
                remote_port, remote_host, protocol,
                internal_port, internal_client, lease_time);
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
    }


    free(remote_host);
    free(remote_port);
    free(internal_client);
    free(internal_port);
    free(protocol);
    free(lease_time);


    return(ca_event->ErrCode);

}

/**
 * this function implements the WANIPv6FirewallControl:updatePinhole action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_updatePinhole(struct Upnp_Action_Request *ca_event)
{
    char internal_client[INET6_ADDRSTRLEN];
    char *lease_time=NULL;
    char *unique_id=NULL;
    int error = 0;
    struct pinholev6 * pinhole;

    if ( (unique_id = GetFirstDocumentItem(
            ca_event->ActionRequest, "UniqueID") )
            && (isStringInteger(unique_id) )
            && (lease_time = GetFirstDocumentItem(
                    ca_event->ActionRequest, "NewLeaseTime") )
            && (isStringInteger(lease_time) )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 2 ) )
    {
        if(!g_vars.ipv6firewallEnabled)
        {
            //error 702 firewall disabled
            errorManagement(ERR_FIREWALL_DISABLED, ca_event);
            return(ERR_FIREWALL_DISABLED);
        }

        if(!g_vars.ipv6inboundPinholeAllowed)
        {
            errorManagement(ERR_INBOUND_PINHOLE_NOT_ALLOWED, ca_event);
            return(ERR_INBOUND_PINHOLE_NOT_ALLOWED);
        }

        if(phv6_findPinhole((uint32_t)atoi(unique_id), &pinhole)) {
            //pinhole found

            // if Internal port is <1024 and InternalClient is different from control point
            // control point needs to be authorized
            if ((( pinhole->internal_port < 1024
                    && pinhole->internal_port > 0)
                    || !ipv6BinAddrCmp(pinhole->internal_client,
                            &ca_event->CtrlPtIPAddr) )
                    && ( AuthorizeControlPoint(ca_event, 0, 1) != CONTROL_POINT_NOT_AUTHORIZED ))
            {
                trace(1, "Internal port number must be greater than 1023 "
                        "and InternalClient must be same as IP of Control point \
                        unless control point is authorized. "
                        "internal_port:%i internal_client:%s",
                        pinhole->internal_port, internal_client);
                errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
                error = ERR_ACTION_NOT_AUTHORIZED;
            }

            // check that leaseduration is between 1 and 86400
            else if ((atoi(lease_time) < 1) || (atoi(lease_time) > 86400))
            {
                trace(1, "lease time must be between 1 and 86400");
                errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
                error = UPNP_SOAP_E_INVALID_ARGS;
            }


            if(error == 0)
            {
                phv6_updatePinhole((uint32_t)atoi(unique_id),
                        (uint32_t)atoi(lease_time));

                ParseResult( ca_event, "" );
            }
        }
        else
        {
            //pinhole not found
            errorManagement(ERR_NO_SUCH_ENTRY, ca_event);
            error = ERR_NO_SUCH_ENTRY;
        }
    }
    else
    {
        trace(1, "Failure in UpdatePinhole: Invalid Arguments!");
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);
    }

    free(lease_time);
    free(unique_id);

    return(ca_event->ErrCode);
}

/**
 * this function implements the WANIPv6FirewallControl:deletePinhole action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_deletePinhole(struct Upnp_Action_Request *ca_event)
{
    char internal_client[INET6_ADDRSTRLEN];
    char *unique_id = NULL;
    struct pinholev6 * pinhole;
    int error = 0;

    if ( (unique_id = GetFirstDocumentItem(
            ca_event->ActionRequest, "UniqueID"))
            && (isStringInteger(unique_id) )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 1 ) )
    {
        if(!g_vars.ipv6firewallEnabled)
        {
            errorManagement(ERR_FIREWALL_DISABLED, ca_event);
            return(ERR_FIREWALL_DISABLED);
        }

        if(!g_vars.ipv6inboundPinholeAllowed)
        {
            errorManagement(ERR_INBOUND_PINHOLE_NOT_ALLOWED, ca_event);
            return(ERR_INBOUND_PINHOLE_NOT_ALLOWED);
        }

        if(phv6_findPinhole((uint32_t)atoi(unique_id), &pinhole)) {
            //pinhole found
            // if Internal port is <1024 and InternalClient is different from control point
            // control point needs to be authorized
            if (((pinhole->internal_port < 1024 && pinhole->internal_port > 0)
                    || !ipv6BinAddrCmp(pinhole->internal_client,
                            &ca_event->CtrlPtIPAddr) )
                    && ( AuthorizeControlPoint(ca_event, 0, 1) != CONTROL_POINT_NOT_AUTHORIZED ))
            {
                trace(1, "Internal port number must be greater than 1023"
                        " and InternalClient must be same as IP of Control point \
                        unless control point is authorized. "
                        "internal_port:%i internal_client:%s",
                        pinhole->internal_port, internal_client);
                errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
                error = ERR_ACTION_NOT_AUTHORIZED;
            }

            if(error == 0) {

                phv6_deletePinhole((uint32_t)atoi(unique_id));

                ParseResult( ca_event, "" );
            }

        }
        else
        {
            //pinhole not found
            errorManagement(ERR_NO_SUCH_ENTRY, ca_event);
            error = ERR_NO_SUCH_ENTRY;
        }
    }
    else
    {
        trace(1, "Failure in DeletePinhole: Invalid Arguments!");
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);

    }

    free(unique_id);

    return(ca_event->ErrCode);

}

/**
 * this function implements the WANIPv6FirewallControl:getPinholePackets action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_getPinholePackets(struct Upnp_Action_Request *ca_event)
{
    char internal_client[INET6_ADDRSTRLEN];
    char *unique_id = NULL;
    struct pinholev6 * pinhole;
    int error = 0;
    int packets = 0;

    if ( (unique_id = GetFirstDocumentItem(
            ca_event->ActionRequest, "UniqueID"))
            && (isStringInteger(unique_id) )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 1 ) )
    {
        if(!g_vars.ipv6firewallEnabled)
        {
            errorManagement(ERR_FIREWALL_DISABLED, ca_event);
            return(ERR_FIREWALL_DISABLED);
        }

        if(!g_vars.ipv6inboundPinholeAllowed)
        {
            errorManagement(ERR_INBOUND_PINHOLE_NOT_ALLOWED, ca_event);
            return(ERR_INBOUND_PINHOLE_NOT_ALLOWED);
        }

        if(phv6_findPinhole((uint32_t)atoi(unique_id), &pinhole)) {
            //pinhole found
            // if Internal port is <1024 and InternalClient is different from control point
            // control point needs to be authorized
            if (((pinhole->internal_port < 1024 && pinhole->internal_port > 0)
                    || !ipv6BinAddrCmp(pinhole->internal_client,
                            &ca_event->CtrlPtIPAddr) )
                    && ( AuthorizeControlPoint(ca_event, 0, 1) != CONTROL_POINT_NOT_AUTHORIZED ))
            {
                trace(1, "Internal port number must be greater than 1023 "
                        "and InternalClient must be same as IP of Control point \
                        unless control point is authorized. "
                        "internal_port:%i internal_client:%s",
                        pinhole->internal_port, internal_client);
                errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
                error = ERR_ACTION_NOT_AUTHORIZED;
            }

            if(error == 0) {

                phv6_getPinholePackets((uint32_t)atoi(unique_id), &packets);

                ParseResult( ca_event, "<PinholePackets>%i</PinholePackets>\n",
                        packets );
            }

        }
        else
        {
            //pinhole not found
            errorManagement(ERR_NO_SUCH_ENTRY, ca_event);
            error = ERR_NO_SUCH_ENTRY;
        }
    }
    else
    {
        trace(1, "Failure in DeletePinhole: Invalid Arguments!");
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);

    }

    free(unique_id);

    return(ca_event->ErrCode);
}

/**
 * this function implements the WANIPv6FirewallControl:checkPinholeWorking action
 *
 * @param ca_event The UPnP action request from the control point
 * @return UPnP error code
 */
int upnp_wanipv6_checkPinholeWorking(struct Upnp_Action_Request *ca_event)
{
    char internal_client[INET6_ADDRSTRLEN];
    char *unique_id = NULL;
    struct pinholev6 * pinhole;
    int error = 0;

    if ( (unique_id = GetFirstDocumentItem(
            ca_event->ActionRequest, "UniqueID") )
            && (isStringInteger(unique_id) )
            && (GetNbSoapParameters(ca_event->ActionRequest) == 1 ) )
    {
        if(!g_vars.ipv6firewallEnabled)
        {
            errorManagement(ERR_FIREWALL_DISABLED, ca_event);
            return(ERR_FIREWALL_DISABLED);
        }

        if(!g_vars.ipv6inboundPinholeAllowed)
        {
            errorManagement(ERR_INBOUND_PINHOLE_NOT_ALLOWED, ca_event);
            return(ERR_INBOUND_PINHOLE_NOT_ALLOWED);
        }

        if(phv6_findPinhole((uint32_t)atoi(unique_id), &pinhole)) {
            //pinhole found


            // if Internal port is <1024 or InternalClient is different from control point
            // control point needs to be authorized
            if (((pinhole->internal_port < 1024 && pinhole->internal_port > 0)
                    || !ipv6BinAddrCmp(pinhole->internal_client,
                            &ca_event->CtrlPtIPAddr) )
                    && ( AuthorizeControlPoint(ca_event, 0, 1) != CONTROL_POINT_NOT_AUTHORIZED ))
            {
                trace(1, "Internal port number must be greater than 1023"
                        " and InternalClient must be same as IP of Control point \
                        unless control point is authorized. "
                        "internal_port:%i internal_client:%s",
                        pinhole->internal_port, internal_client);
                errorManagement(ERR_ACTION_NOT_AUTHORIZED, ca_event);
                error = ERR_ACTION_NOT_AUTHORIZED;
            }



            if(error == 0)
            {
                int isWorking = phv6_checkPinholeWorking((uint32_t)atoi(unique_id));

                if(isWorking == -1)
                {
                    //no traffic detected
                    errorManagement(ERR_NO_TRAFFIC, ca_event);
                    error = ERR_NO_TRAFFIC;
                }

                else {
                    ParseResult( ca_event, "<IsWorking>%i</IsWorking>\n",
                        isWorking );
                }
            }

        }
        else
        {
            //pinhole not found
            errorManagement(ERR_NO_SUCH_ENTRY, ca_event);
            error = ERR_NO_SUCH_ENTRY;
        }
    }
    else
    {
        trace(1, "Failure in CheckPinholeWorking: Invalid Arguments!");
        errorManagement(UPNP_SOAP_E_INVALID_ARGS, ca_event);

    }

    free(unique_id);

    return(ca_event->ErrCode);

}

#ifdef __cplusplus
}
#endif
