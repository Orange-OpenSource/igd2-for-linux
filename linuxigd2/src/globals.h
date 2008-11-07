#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include <net/if.h>
#include <arpa/inet.h>

#define CHAIN_NAME_LEN 32
#define BITRATE_LEN 32
#define OPTION_LEN 64
#define RESULT_LEN 4096
#define NUM_LEN 32

#define SUB_MATCH 2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

struct GLOBALS
{
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
    // uci command
    char uciCmd[OPTION_LEN];
    // resolv.conf location
    char resolvConf[OPTION_LEN];

    // Event update thread checking interval
    int eventUpdateInterval;
    
    // dhcp-client command
    char dhcpc[OPTION_LEN];
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

#endif // _GLOBALS_H_
