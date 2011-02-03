/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 *  
 * This file is part of igd2-for-linux project
 * Copyright © 2011 France Telecom.
 * Contact: fabrice.fontaine@orange-ftgroup.com
 * Developer(s): fabrice.fontaine@orange-ftgroup.com, rmenard.ext@orange-ftgroup.com
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
 
#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include <net/if.h>
#include <arpa/inet.h>
#include <upnp/ixml.h>

#define PIN_SIZE 32
#define CHAIN_NAME_LEN 32
#define BITRATE_LEN 32
#define OPTION_LEN 64
#define RESULT_LEN 4096
#define RESULT_LEN_LONG 65536
#define NUM_LEN 32

#define SUB_MATCH 2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

struct GLOBALS
{
    char pinCode[PIN_SIZE];  // Device Protection PIN code of device
    char adminPassword[OPTION_LEN];  // Device Protection Admin password
    char extInterfaceName[IFNAMSIZ]; // The name of the external interface, picked up from the
    // command line
    char intInterfaceName[IFNAMSIZ]; // The name of the internal interface, picked from command line

    // All vars below are read from /etc/upnpd.conf in main.c
    int debug;  // 1 - print debug messages to syslog
    // 0 - no debug messages
    char iptables[OPTION_LEN];  // The full name and path of the iptables executable, used in pmlist.c
    char upstreamBitrate[OPTION_LEN];  // The upstream bitrate reported by the daemon
    char downstreamBitrate[OPTION_LEN]; // The downstream bitrate reported by the daemon
    char forwardChainName[OPTION_LEN];  // The name of the iptables chain to put FORWARD rules in
    char preroutingChainName[OPTION_LEN]; // The name of the chain to put PREROUTING rules in
    int createForwardRules;     // 1 - create rules in forward chain
    // 0 - do not create rules in forward chain
    int forwardRulesAppend; // 1 - add rules to end of forward chain
    // 0 - add rules to start of forward chain
    long int duration;    // 0 - no duration
    // >0 - duration in seconds
    // <0 - expiration time
    char descDocName[OPTION_LEN];
    char xmlPath[OPTION_LEN];
    int listenport;	//The port to listen on

    // dnsmasq start / stop script
    char dnsmasqCmd[OPTION_LEN];
    // dhcrelay command
    char dhcrelayCmd[OPTION_LEN];
    // dhcrelay server
    char dhcrelayServer[OPTION_LEN];
    // dhcrelay server
    char networkCmd[OPTION_LEN];
    // uci command
    char uciCmd[OPTION_LEN];
    // resolv.conf location
    char resolvConf[OPTION_LEN];

    // Event update thread checking interval
    int eventUpdateInterval;

    // dhcp-client command
    char dhcpc[OPTION_LEN];

    // How often alive notifications are send
    int advertisementInterval;
    char certPath[OPTION_LEN];

    // name of access level xml file
    char accessLevelXml[OPTION_LEN];

    /**
     * WANIPv6 Firewall control
     */
    //enables ipv6 firewall
    int ipv6firewallEnabled;

    //enables the creation of inbound pinhole
    int ipv6inboundPinholeAllowed;

    //authorized the control point
    //TODO: must be replaced by DeviceProtection
    int controlPointAuthorized;

    //define the ipv6 forward chain
    char ipv6forwardChain[OPTION_LEN];

    //enables IPv4
    //TODO: should be removed, only for testing purpose
    int ipv4Enabled;

    //enables IPv6
    //TODO: should be removed, only for testing purpose
    int ipv6UlaGuaEnabled;

    //enables IPv6 Link Local
    //TODO: should be removed, only for testing purpose
    int ipv6LinkLocalEnabled;
};

typedef struct GLOBALS* globals_p;
typedef struct GLOBALS globals;
extern globals g_vars;


#define CONF_FILE "/etc/upnpd.conf"
#define MAX_CONFIG_LINE 256
#define IPTABLES_DEFAULT_FORWARD_CHAIN "FORWARD"
#define IPTABLES_DEFAULT_PREROUTING_CHAIN "PREROUTING"
#define DEFAULT_DURATION 3600
#define MINIMUM_DURATION 1
#define MAXIMUM_DURATION 604800
#define DEFAULT_UPSTREAM_BITRATE "0"
#define DEFAULT_DOWNSTREAM_BITRATE "0"
#define DESC_DOC_DEFAULT "gatedesc.xml"
#define XML_PATH_DEFAULT "/etc/linuxigd"
#define LISTENPORT_DEFAULT 0
#define DNSMASQ_CMD_DEFAULT "/etc/init.d/dnsmasq"
#define DHCRELAY_CMD_DEFAULT "dhcrelay"
#define UCI_CMD_DEFAULT "/sbin/uci"
#define RESOLV_CONF_DEFAULT "/etc/resolv.conf"
#define RESOLV_CONF_TMP "/tmp/resolv.conf.IGDv2"
// How often check if update events should be sent
#define DEFAULT_EVENT_UPDATE_INTERVAL 60
#define DHCPC_DEFAULT "udhcpc"
#define NETWORK_CMD_DEFAULT "/etc/init.d/network"

#define ROUTE_COMMAND "route"
#define ADVERTISEMENT_INTERVAL 1800

// location of ACL (access control list) xml file. This is totally internal file, and is not listed in config file. 
#define ACL_XML "/etc/upnpd_ACL.xml"

#define IP6TABLES_DEFAULT_FORWARD_CHAIN "FORWARD_upnp"

#endif // _GLOBALS_H_
