#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "lanhostconfig.h"
#include "globals.h"
#include "util.h"

#define SERVICE_START "start"
#define SERVICE_STOP "stop"

#define COMMAND_LEN 64
#define LINE_LEN 256
#define DEFAULT_GATEWAY_IP "0.0.0.0"

struct LanHostConfig
{
    int DHCPServerConfigurable;
    int dhcrelay;
} lanHostConfig;

/**
 * Runs given command with given parameters.
 * Forks the process and returns status returned by other process.
 */
int RunCommand(char *cmd, char **parm)
{
    pid_t pid;
    int status;

    if ((pid = fork()) == -1)
        return 1;
    else if (pid == 0)
        execvp(cmd, parm);
    else
        wait(&status);

    return status;
}

/**
 * Runs "uci commit".
 * Commits all changes made by uci commands.
 */
void UciCommit()
{
    // TODO: uci commit
    char *args[] = { g_vars.uciCmd, "commit", NULL };
    RunCommand(g_vars.uciCmd, args);
}

/**
 * Runs dnsmasq start/stop script based on parameters.
 */
void DnsmasqCommand(char *cmd)
{
    // TODO: restart dnsmasq server
    char *args[] = { g_vars.dnsmasqCmd, cmd, NULL };
    RunCommand(g_vars.dnsmasqCmd, args);
}

/**
 * Restarts dnsmasq service.
 */
void DnsmasqRestart()
{
    DnsmasqCommand(SERVICE_STOP);
    DnsmasqCommand(SERVICE_START);
}

/**
 * Starts dhcrelay daemon. Server parameter is taken from conf-file.
 */
void DhcrelayStart()
{
    if (g_vars.dhcrelayServer == NULL)
        // can't start dhcrelay without server
        return;

    char *args[] = { g_vars.dhcrelayCmd, g_vars.dhcrelayServer, NULL };
    RunCommand(g_vars.dhcrelayCmd, args);
}

/**
 * Stops dhcrelay daemon.
 */
void DhcrelayStop()
{
    char *args[] = { "killall", g_vars.dhcrelayCmd, NULL };
    RunCommand("killall", args);
}

/**
 * Checks if dhcp server is set to configurable.
 * Returns 0 if it is, upnp error code otherwise.
 */
int CheckDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    if (lanHostConfig.DHCPServerConfigurable == FALSE)
    {
        trace(1, "%s: DHCPServerConfigurable is false.", ca_event->ActionName);
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    return 0;
}

/**
 * Set Upnp error 402: Invalid Arguments as return value
 */
void InvalidArgs(struct Upnp_Action_Request *ca_event)
{
    trace(2, "%s: Invalid Args", ca_event->ActionName);
    ca_event->ErrCode = 402;
    strcpy(ca_event->ErrStr, "Invalid Args");
    ca_event->ActionResult = NULL;
}

/**
 * Form and parse upnp action result xml.
 */
void ParseResult(struct Upnp_Action_Request *ca_event, const char *str, ...)
{
    char result[RESULT_LEN];
    char parameters[RESULT_LEN];
    va_list arg;

    // write all parameters into one string
    va_start(arg, str);
    vsnprintf(parameters, RESULT_LEN, str, arg);
    va_end(arg);

    // and form final xml
    snprintf(result, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
             ca_event->ActionName,
             "urn:schemas-upnp-org:service:LANHostConfigManagement:1",
             parameters,
             ca_event->ActionName);

    ParseXMLResponse(ca_event, result);
}

/**
 * GetDefaultGateway returns default gateway address.
 *
 * First parameter must be large enough to hold IPv4 address
 * Returns TRUE on success.
 */
int GetDefaultGateway(char *gateway)
{
    FILE *cmd;
    char line[LINE_LEN];
    char *addr;

    // try to run route command
    cmd = popen("route -n", "r");
    if (cmd == NULL)
        return FALSE;

    // get result
    while (fgets(line, LINE_LEN, cmd) != NULL)
    {
        // get first column in line
        addr = strtok(line, " ");
        // is default gw in this line?
        if (strcmp(addr, DEFAULT_GATEWAY_IP) == 0)
        {
            // default gw is in next column
            addr = strtok(NULL, " ");
            strcpy(gateway, addr);
            pclose(cmd);
            return TRUE;
        }
    }

    pclose(cmd);
    return FALSE;
}

int SetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    char *configurable;
    int config;

    if ( (configurable = GetFirstDocumentItem(ca_event->ActionRequest, "NewDHCPServerConfigurable") ) )
    {
        config = resolveBoolean(configurable);

        // if user is setting configurable to true, check that init can be run successfully
        if (config && InitLanHostConfig())
        {
            // init failed, send action failed response
            ca_event->ErrCode = 501;
            strcpy(ca_event->ErrStr, "Action Failed");
            ca_event->ActionResult = NULL;
        }
        else
        {
            lanHostConfig.DHCPServerConfigurable = config;
            ParseResult(ca_event, "");
        }
    }
    else
        InvalidArgs(ca_event);

    if (configurable) free(configurable);

    return ca_event->ErrCode;
}

int GetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    ParseResult(ca_event, "<NewDHCPServerConfigurable>%d</NewDHCPServerConfigurable>\n", (lanHostConfig.DHCPServerConfigurable ? 1 : 0));

    return ca_event->ErrCode;
}

int SetDHCPRelay(struct Upnp_Action_Request *ca_event)
{
    char *dhcrelay;
    int b_dhcrelay;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ((dhcrelay = GetFirstDocumentItem(ca_event->ActionRequest, "NewDHCPRelay")))
    {
        b_dhcrelay = resolveBoolean(dhcrelay);

        if (b_dhcrelay != lanHostConfig.dhcrelay)
        {
            // TODO: check return value if these functions
            if (b_dhcrelay)
            {
                DnsmasqCommand(SERVICE_STOP);
                DhcrelayStart();
            }
            else
            {
                DhcrelayStop();
                DnsmasqCommand(SERVICE_START);
            }

            lanHostConfig.dhcrelay = b_dhcrelay;
        }
    }
    else
        InvalidArgs(ca_event);

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    if (dhcrelay) free(dhcrelay);

    return ca_event->ErrCode;
}

int GetDHCPRelay(struct Upnp_Action_Request *ca_event)
{
    ParseResult(ca_event, "<NewDHCPRelay>%d</NewDHCPRelay>\n", (lanHostConfig.dhcrelay ? 1 : 0));

    return ca_event->ErrCode;
}

int SetSubnetMask(struct Upnp_Action_Request *ca_event)
{
    char *subnet_mask;
    char command[40];
    char *args[] = { g_vars.uciCmd, "get", NULL, NULL };

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ((subnet_mask = GetFirstDocumentItem(ca_event->ActionRequest, "NewSubnetMask")))
    {
        // TODO: check that new netmask is valid
        snprintf(command, 40, "network.lan.netmask=%s", subnet_mask);
        RunCommand(g_vars.uciCmd, args);
        UciCommit();
    }
    else
        InvalidArgs(ca_event);

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    return ca_event->ErrCode;
}

int GetSubnetMask(struct Upnp_Action_Request *ca_event)
{
    FILE *cmd;
    char subnet_mask[48];

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    // try to run uci command
    cmd = popen("uci get network.lan.netmask", "r");
    if (cmd == NULL)
    {
        trace(1, "GetSubnetMask: getting subnet mask failed.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // get result
    if (fgets(subnet_mask, 48, cmd) != NULL)
        ParseResult(ca_event, "<NewSubnetMask>%s</NewSubnetMask>\n", subnet_mask);
    else
    {
        trace(1, "GetSubnetMask: uci command returned null.");
        addErrorData(ca_event, 501, "Action Failed");
    }

    pclose(cmd);

    return ca_event->ErrCode;
}

int SetIPRouter(struct Upnp_Action_Request *ca_event)
{
    char *parmList[] = { ROUTE_COMMAND, NULL, "default", "gw", NULL, NULL };
    char addr[LINE_LEN];
    char *new_router;
    int  status;

    if ((new_router = GetFirstDocumentItem(ca_event->ActionRequest, "NewIPRouters")))
    {
        // if default gateway already exists, delete it
        if (GetDefaultGateway(addr))
        {
            // check that new gateway is different than current
            if(strcmp(new_router, addr) == 0)
            {
                addErrorData(ca_event, 701, "ValueAlreadySpecified");
                trace(2, "SetIPRouter: new default gw '%s' is the same as current one '%s'", new_router, addr);
                free(new_router);
                return ca_event->ErrCode;
            }

            parmList[1] = "del";
            parmList[4] = addr;

            // TODO: check return value
            RunCommand(ROUTE_COMMAND, parmList);
        }

        // add new default gw
        parmList[1] = "add";
        parmList[4] = new_router;

        status = RunCommand(ROUTE_COMMAND, parmList);

        if (!status)
            ParseResult(ca_event, "");
        else
        {
            trace(2, "SetIPRouter: Route command returned error: %d", status);
            addErrorData(ca_event, 501, "Action Failed");
        }

    }

    if (new_router) free(new_router);

    return ca_event->ErrCode;
}

int DeleteIPRouter(struct Upnp_Action_Request *ca_event)
{
    char *parmList[] = { ROUTE_COMMAND, "del", "default", "gw", NULL, NULL };
    int status;

    if ((parmList[4] = GetFirstDocumentItem(ca_event->ActionRequest, "NewIPRouters")))
    {
        // run route del command
        status = RunCommand(ROUTE_COMMAND, parmList);
        if (!status)
            ParseResult(ca_event, "");
        else
        {
            trace(2, "DeleteIPRouter: Route command returned error: %d", status);
            addErrorData(ca_event, 702, "ValueSpecifiedIsInvalid");
        }
    }
    else
        InvalidArgs(ca_event);

    if (parmList[4]) free(parmList[4]);

    return ca_event->ErrCode;
}

int GetIPRoutersList(struct Upnp_Action_Request *ca_event)
{
    char addr[LINE_LEN];
    int gw_found = FALSE;

    gw_found = GetDefaultGateway(addr);

    if (gw_found)
        ParseResult(ca_event, "<NewIPRouters>%s</NewIPRouters>\n", addr);
    else
        addErrorData(ca_event, 501, "Invalid Args");

    return ca_event->ErrCode;
}

int SetDomainName(struct Upnp_Action_Request *ca_event)
{
    FILE *cmd = NULL;
    char *domainName;
    char setDname[60];

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ( (domainName = GetFirstDocumentItem(ca_event->ActionRequest, "NewDomainName") ) )
    {
        // try to run uci command
        snprintf(setDname,60,"uci set dhcp.@dnsmasq[0].domain=%s",domainName );
        cmd = popen(setDname, "r");
        if (cmd == NULL)
        {
            trace(1, "SetDomainName: setting Domain Name failed.");
            addErrorData(ca_event, 501, "Action Failed");
            return ca_event->ErrCode;
        }

        UciCommit();

        ParseResult(ca_event, "");
    }
    else
        InvalidArgs(ca_event);

    if (cmd)pclose(cmd);
    if (domainName) free(domainName);

    return ca_event->ErrCode;
}

int GetDomainName(struct Upnp_Action_Request *ca_event)
{
    FILE *cmd;
    char domain_name[40];

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    // try to run uci command
    cmd = popen("uci get -q dhcp.@dnsmasq[0].domain", "r");
    if (cmd == NULL)
    {
        trace(1, "GetDomainName: getting Domain Name failed.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // get result
    if (fgets(domain_name, 40, cmd) != NULL)
        ParseResult(ca_event, "<NewDomainName>%s</NewDomainName>\n", domain_name);
    else
    {
        trace(1, "GetDomainName: uci command returned null.");
        addErrorData(ca_event, 501, "Action Failed");
    }

    pclose(cmd);

    return ca_event->ErrCode;
}

int SetAddressRange(struct Upnp_Action_Request *ca_event)
{
    char *parmList[] = { g_vars.uciCmd, "set", "dhcp.lan.start", NULL, NULL };
    char *start, *limit;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ( (start = GetFirstDocumentItem(ca_event->ActionRequest, "NewMinAddress")) &&
            (limit = GetFirstDocumentItem(ca_event->ActionRequest, "NewMaxAddress")))
    {
        // TODO: check that values are sane
        parmList[2] = start;
        RunCommand(g_vars.uciCmd, parmList);
        parmList[1] = "dhcp.lan.limit";
        parmList[2] = limit;
        RunCommand(g_vars.uciCmd, parmList);
        parmList[1] = "commit";
        parmList[2] = NULL;
        RunCommand(g_vars.uciCmd, parmList);
    }
    else
        InvalidArgs(ca_event);

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    return ca_event->ErrCode;
}

int GetAddressRange(struct Upnp_Action_Request *ca_event)
{
    FILE *cmd = NULL, *cmd_2 = NULL;
    char start[12] = {0}, limit[12] = {0};

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    // try to run uci commands
    cmd = popen("uci get dhcp.lan.start", "r");
    cmd_2 = popen("uci get dhcp.lan.limit", "r");
    if (cmd == NULL || cmd_2 == NULL)
    {
        trace(1, "GetAddressRange: uci command failed.");
        addErrorData(ca_event, 501, "Action Failed");
    }
    else
    {
        // get result
        // TODO: add error checking, if uci returns something invalid
        if (fgets(start, 12, cmd) == NULL ||
                fgets(limit, 12, cmd_2) == NULL)
        {
            trace(1, "GetAddressRange: error reading values.");
            addErrorData(ca_event, 501, "Action Failed");
        }
    }

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "<NewMinAddress>%s</NewMinAddress>\n<NewMaxAddress>%s</NewMaxAddress>\n", start, limit);

    if (cmd) pclose(cmd);
    if (cmd_2) pclose(cmd_2);

    return ca_event->ErrCode;
}

int SetReservedAddress(struct Upnp_Action_Request *ca_event)
{
    char command[COMMAND_LEN];
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    char *all_addr, *addr;
    char *add_args[] = { g_vars.uciCmd, "-q", "add", "dhcp", "host", NULL };
    char *set_args[] = { g_vars.uciCmd, "-q", "set", NULL, NULL };
    int i=0;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ( (all_addr = GetFirstDocumentItem(ca_event->ActionRequest, "NewReservedAddresses")) == NULL)
    {
        InvalidArgs(ca_event);
        return ca_event->ErrCode;
    }

    // delete all hosts
    while (i < 256)
    {
        sprintf(command, "uci -q get dhcp.@host[0]");
        cmd = popen(command, "r");
        if (cmd == NULL)
        {
            trace(1, "SetReservedAddress: Error running command: '%s'", command);
            addErrorData(ca_event, 501, "Action Failed");
            break;
        }
        // if nothing is returned, we have removed all hosts
        if (fgets(line, MAX_CONFIG_LINE, cmd) == NULL)
            break;

        fclose(cmd);
        sprintf(command, "uci -q delete dhcp.@host[0]");
        cmd = popen(command, "r");
        if (cmd == NULL)
        {
            trace(1, "SetReservedAddress: Error running command: '%s'", command);
            addErrorData(ca_event, 501, "Action Failed");
            break;
        }
        fclose(cmd);

        i++;
    }

    // if deleting was successful then add new hosts
    if (ca_event->ErrCode == 0)
    {
        addr = strtok(all_addr, ",");
        while (addr != NULL)
        {
            // add new host
            RunCommand(g_vars.uciCmd, add_args);

            // set host values
            set_args[3] = "dhcp.@host[-1].name=IGDv2";
            RunCommand(g_vars.uciCmd, set_args);
            set_args[3] = "dhcp.@host[-1].mac=00:00:00:00:00:00";
            RunCommand(g_vars.uciCmd, set_args);
            sprintf(command, "dhcp.@host[-1].ip=%s", addr);
            set_args[3] = command;
            RunCommand(g_vars.uciCmd, set_args);

            addr = strtok(NULL, ",");
        }
    }

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    if (all_addr) free(all_addr);

    return ca_event->ErrCode;
}

int DeleteReservedAddress(struct Upnp_Action_Request *ca_event)
{
    char command[COMMAND_LEN];
    char *del_addr;
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    int i = 0;
    int deleted = FALSE;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    if ( (del_addr = GetFirstDocumentItem(ca_event->ActionRequest, "NewReservedAddresses")) == NULL)
    {
        InvalidArgs(ca_event);
        return ca_event->ErrCode;
    }

    // added 256 as precaution, if under some conditions uci returns always something
    // if that is reached, give internal error
    while (i < 256)
    {
        sprintf(command, "uci -q get dhcp.@host[%d].ip", i);
        cmd = popen(command, "r");
        if (cmd == NULL)
        {
            trace(1, "DeleteReservedAddress: Error running command: '%s'", command);
            addErrorData(ca_event, 501, "Action Failed");
            break;
        }
        if (fgets(line, MAX_CONFIG_LINE, cmd) == NULL)
        {
            // returned nothing, no more hosts defined
            break;
        }

        if (strncmp(line, del_addr, MAX_CONFIG_LINE) == 0)
        {
            sprintf(command, "uci -q delete dhcp.@host[%d]", i);
            cmd = popen(command, "r");
            if (cmd == NULL)
            {
                trace(1, "DeleteReservedAddress: Error running command: '%s'", command);
                addErrorData(ca_event, 501, "Action Failed");
            }
            else
            {
                // entry successfully deleted
                deleted = TRUE;
                UciCommit();
                DnsmasqRestart();
            }

            break;
        }

        fclose(cmd);
        i++;
    }
    if (i == 256)
    {
        trace(1, "DeleteReservedAddress: Internal error in function.");
        addErrorData(ca_event, 501, "Action Failed");
    }

    if (deleted == FALSE)
    {
        trace(2, "DeleteReservedAddress: Can't find address to delete: '%s'.", del_addr);
        addErrorData(ca_event, 702, "ValueSpecifiedIsInvalid");
    }

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    if (cmd) fclose(cmd);
    if (del_addr) free(del_addr);

    return ca_event->ErrCode;
}

int GetReservedAddresses(struct Upnp_Action_Request *ca_event)
{
    char command[COMMAND_LEN];
    char addresses[RESULT_LEN];
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    int i = 0;
    int addr_place = 0;

    addresses[0] = 0;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    // added 2048 as precaution, if under some conditions uci returns always something
    // if that is reached, give internal error
    while (i < 2048)
    {
        sprintf(command, "uci -q get dhcp.@host[%d].ip", i);
        cmd = popen(command, "r");
        if (cmd == NULL)
        {
            trace(1, "GetReservedAddresses: Error running command: '%s'", command);
            addErrorData(ca_event, 501, "Action Failed");
            break;
        }
        if (fgets(line, MAX_CONFIG_LINE, cmd) == NULL)
        {
            // returned nothing, no more hosts defined
            break;
        }

        // add comma separator before all except first address
        if (addr_place > 0)
            addr_place += snprintf(&addresses[addr_place], RESULT_LEN - addr_place, ",");

        addr_place += snprintf(&addresses[addr_place], RESULT_LEN - addr_place, "%s", line);

        fclose(cmd);
        i++;
    }
    if (i == 2048)
    {
        trace(1, "GetReservedAddresses: Internal error in function.");
        addErrorData(ca_event, 501, "Action Failed");
    }

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "<NewReservedAddresses>%s</NewReservedAddresses>\n", addresses);

    if (cmd) fclose(cmd);

    return ca_event->ErrCode;
}

int SetDNSServer(struct Upnp_Action_Request *ca_event)
{
    FILE *file = NULL, *new_file = NULL;
    char line[MAX_CONFIG_LINE];
    char *dns = NULL;
    char *dns_list = NULL;
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    // TODO: seems to accept for example 192.168.0.0.0 ?
    regcomp(&nameserver, "nameserver[[:blank:]]*([[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3})", REG_EXTENDED);
    ca_event->ErrCode = 0;

    if ((dns_list = GetFirstDocumentItem(ca_event->ActionRequest, "NewDNSServers")))
    {
        // open resolv.conf for reading
        file = fopen(g_vars.resolvConf, "r");
        // and temporary file for writing
        new_file = fopen(RESOLV_CONF_TMP, "w");
        if (file == NULL || new_file == NULL)
        {
            if (file == NULL)
                trace(1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf);
            if (new_file == NULL)
                trace(1, "Failed to open temp resolv.conf: %s.", RESOLV_CONF_TMP);

            addErrorData(ca_event, 501, "Action Failed");
        }
        else
        {
            while (fgets(line, MAX_CONFIG_LINE, file) != NULL)
            {
                if (regexec(&nameserver, line, SUB_MATCH, submatch, 0) == 0)
                    continue;

                // line isn't a nameserver, adding it to the temp file
                fputs(line, new_file);
            }

            // add all new nameservers
            dns = strtok(dns_list, ",");
            while (dns != NULL)
            {
                sprintf(line, "nameserver %s\n", dns);
                // check that resulted line syntax is correct
                if (regexec(&nameserver, line, SUB_MATCH, submatch, 0) == 0)
                {
                    fputs(line, new_file);
                }
                else
                {
                    InvalidArgs(ca_event);
                    break;
                }
                dns = strtok(NULL, ",");
            }

            if (ca_event->ErrCode == 0)
            {
                // operation was successful
                // replace the real file with our temp file
                if (remove(g_vars.resolvConf))
                {
                    trace(1, "SetDNSServer: removing resolv.conf failed: '%s'.", g_vars.resolvConf);
                    addErrorData(ca_event, 501, "Action Failed");
                }
                if (rename(RESOLV_CONF_TMP, g_vars.resolvConf))
                {
                    trace(1, "SetDNSServer: renaming resolv.conf failed, old: '%s' new '%s'.", RESOLV_CONF_TMP, g_vars.resolvConf);
                    addErrorData(ca_event, 501, "Action Failed");
                }
            }
        }
    }
    else
        InvalidArgs(ca_event);

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    regfree(&nameserver);
    if (file) fclose(file);
    if (new_file) fclose(new_file);
    if (dns_list) free(dns_list);

    return ca_event->ErrCode;
}

int DeleteDNSServer(struct Upnp_Action_Request *ca_event)
{
    FILE *file = NULL, *new_file = NULL;
    char line[MAX_CONFIG_LINE];
    char dns[INET6_ADDRSTRLEN];
    char *dns_to_delete = NULL;
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];
    int dns_found = 0;

    if (CheckDHCPServerConfigurable(ca_event))
        return ca_event->ErrCode;

    regcomp(&nameserver, "nameserver[[:blank:]]*([[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3})", REG_EXTENDED);
    ca_event->ErrCode = 0;

    if ((dns_to_delete = GetFirstDocumentItem(ca_event->ActionRequest, "NewDNSServers")))
    {
        file = fopen(g_vars.resolvConf, "r");
        new_file = fopen(RESOLV_CONF_TMP, "w");
        if (file == NULL || new_file == NULL)
        {
            if (file == NULL)
                trace(1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf);
            if (new_file == NULL)
                trace(1, "Failed to open temp resolv.conf: %s.", RESOLV_CONF_TMP);

            addErrorData(ca_event, 501, "Action Failed");
        }
        else
        {
            while (fgets(line, MAX_CONFIG_LINE, file) != NULL)
            {
                if (regexec(&nameserver, line, SUB_MATCH, submatch, 0) == 0)
                {
                    // nameserver found, get it
                    strncpy(dns, &line[submatch[1].rm_so], min(submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN));
                    dns[min(submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN-1)] = 0;

                    // if this one needs to be deleted, then continue while loop
                    if (strncmp(dns, dns_to_delete, INET6_ADDRSTRLEN) == 0)
                    {
                        dns_found = 1;
                        continue;
                    }
                }
                // line isn't a nameserver or not the nameserver we want to delete, adding it to the temp file
                fputs(line, new_file);
            }

            if (dns_found)
            {
                // operation was successful
                // replace the real file with our temp file
                if (remove(g_vars.resolvConf))
                {
                    trace(1, "DeleteDNSServer: removing resolv.conf failed: '%s'.", g_vars.resolvConf);
                    addErrorData(ca_event, 501, "Action Failed");
                }
                if (rename(RESOLV_CONF_TMP, g_vars.resolvConf))
                {
                    trace(1, "DeleteDNSServer: renaming resolv.conf failed, old: '%s' new '%s'.", RESOLV_CONF_TMP, g_vars.resolvConf);
                    addErrorData(ca_event, 501, "Action Failed");
                }
            }
            else
            {
                trace(2, "DeleteDNSServer: dns server not found: '%s'.", dns_to_delete);
                addErrorData(ca_event, 702, "ValueSpecifiedIsInvalid");
            }
        }
    }
    else
        InvalidArgs(ca_event);

    if (ca_event->ErrCode == 0)
        ParseResult(ca_event, "");

    regfree(&nameserver);
    if (file) fclose(file);
    if (new_file) fclose(new_file);
    if (dns_to_delete) free(dns_to_delete);

    return ca_event->ErrCode;
}

int GetDNSServers(struct Upnp_Action_Request *ca_event)
{
    FILE *file;
    char dns_servers[RESULT_LEN];
    char line[MAX_CONFIG_LINE];
    char dns[INET6_ADDRSTRLEN];
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];
    int dns_place = 0;

    dns_servers[0] = 0;

    regcomp(&nameserver, "nameserver[[:blank:]]*([[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3}[.][[:digit:]]{1,3})", REG_EXTENDED);

    file = fopen(g_vars.resolvConf, "r");
    if (file == NULL)
    {
        trace(1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf);
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    while (fgets(line, MAX_CONFIG_LINE, file) != NULL)
    {
        if (regexec(&nameserver, line, SUB_MATCH, submatch, 0) == 0)
        {
            // nameserver found, get it and add to list
            if (dns_place > 0)
                dns_place += snprintf(&dns_servers[dns_place], RESULT_LEN - dns_place, ",");

            strncpy(dns, &line[submatch[1].rm_so], min(submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN));
            dns[min(submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN-1)] = 0;
            dns_place += snprintf(&dns_servers[dns_place], RESULT_LEN - dns_place, "%s", dns);
        }
    }

    ParseResult(ca_event, "<NewDNSServers>%s</NewDNSServers>\n", dns_servers);

    regfree(&nameserver);
    fclose(file);

    return ca_event->ErrCode;
}

/**
 * Checks that all required programs are present.
 */
int InitLanHostConfig()
{
    struct stat buf;

    lanHostConfig.DHCPServerConfigurable = TRUE;
    lanHostConfig.dhcrelay = FALSE;

    // check that dnsmasq exists
    if (stat(g_vars.dnsmasqCmd, &buf))
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace(1, "DHCPServerConfigurable set to false, dnsmasq not found at: %s.", g_vars.dnsmasqCmd);
        return 1;
    }
    // check that uci exists
    if (stat(g_vars.uciCmd, &buf))
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace(1, "DHCPServerConfigurable set to false, uci not found at: %s.", g_vars.uciCmd);
        return 1;
    }

    return 0;
}

/**
 * Free reserved memory.
 */
void FreeLanHostConfig()
{

}
