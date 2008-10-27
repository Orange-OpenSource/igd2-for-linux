#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include "lanhostconfig.h"
#include "globals.h"
#include "util.h"

#define SUB_MATCH 2

struct LanHostConfig
{
    gboolean DHCPServerConfigurable;
} lanHostConfig;

int SetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;
    char *configurable;
    int config;

    result_str = g_string_new("");

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
            ca_event->ErrCode = UPNP_E_SUCCESS;
            g_string_printf(result_str, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
                            ca_event->ActionName, "urn:schemas-upnp-org:service:LANHostConfigManagement:1", "", ca_event->ActionName);
            ca_event->ActionResult = ixmlParseBuffer(result_str->str);
        }
    }
    else
    {
        trace(1, "Failure in SetDHCPServerConfigurable: Invalid Args");
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if (configurable) free(configurable);
    g_string_free(result_str, TRUE);

    return ca_event->ErrCode;
}

int GetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;

    ca_event->ErrCode = UPNP_E_SUCCESS;

    result_str = g_string_new("");
    g_string_printf(result_str, "<u:GetDHCPServerConfigurableResponse xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
                    "<NewDHCPServerConfigurable>%d</NewDHCPServerConfigurable>\n"
                    "</u:GetDHCPServerConfigurableResponse>", (lanHostConfig.DHCPServerConfigurable ? 1 : 0));

    ParseResponse(ca_event, result_str);

    g_string_free(result_str, TRUE);

    return ca_event->ErrCode;
}

int SetDHCPRelay(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int GetDHCPRelay(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int SetSubnetMask(struct Upnp_Action_Request *ca_event)
{

    return 0;
}

int GetSubnetMask(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;
    FILE *cmd;
    char subnet_mask[48];

    result_str = g_string_new("");

    if (lanHostConfig.DHCPServerConfigurable == FALSE)
    {
        trace(1, "GetSubnetMask: DHCPServerConfigurable is false.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // try to run uci command
    cmd = popen("uci get network.lan.netmask", "r");
    if (cmd == NULL)
    {
        trace(1, "GetSubnetMask: getting subnet mask failed.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // get result
    fgets(subnet_mask, 48, cmd);

    g_string_printf(result_str, "<u:%sResponse xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
                    "<NewSubnetMask>%s</NewSubnetMask>\n"
                    "</u:%sResponse>", ca_event->ActionName, subnet_mask, ca_event->ActionName);
    ParseResponse(ca_event, result_str);

    pclose(cmd);

    g_string_free(result_str, TRUE);

    return 0;
}

int SetIPRouter(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int DeleteIPRouter(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int GetIPRoutersList(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int SetDomainName(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;
    FILE *cmd = NULL;
    char *domainName;
    char setDname[60];

    if (lanHostConfig.DHCPServerConfigurable == FALSE)
    {
        trace(1, "SetDomainName: DHCPServerConfigurable is false.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    result_str = g_string_new("");

    if ( (domainName = GetFirstDocumentItem(ca_event->ActionRequest, "NewDomainName") ) )
    {
        // try to run uci command
        snprintf(setDname,60,"uci set dchp.@dnsmasq[0].domain=%s",domainName );
        cmd = popen(setDname, "r");
        if (cmd == NULL)
        {
            trace(1, "SetDomainName: setting Domain Name failed.");
            addErrorData(ca_event, 501, "Action Failed");
            return ca_event->ErrCode;
        }

        // TODO: to call uci commit function

        ca_event->ErrCode = UPNP_E_SUCCESS;
        g_string_printf(result_str, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
                        ca_event->ActionName, "urn:schemas-upnp-org:service:LANHostConfigManagement:1", "", ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(result_str->str);

    }
    else
    {
        trace(1, "Failure in SetDomainName: Invalid Args");
        ca_event->ErrCode = 402;
        strcpy(ca_event->ErrStr, "Invalid Args");
        ca_event->ActionResult = NULL;
    }

    if(cmd)pclose(cmd);
    if (domainName) free(domainName);
    g_string_free(result_str, TRUE);

    return ca_event->ErrCode;
}

int GetDomainName(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;
    FILE *cmd;
    char domain_name[40];

    result_str = g_string_new("");

    if (lanHostConfig.DHCPServerConfigurable == FALSE)
    {
        trace(1, "GetDomainName: DHCPServerConfigurable is false.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // try to run uci command
    cmd = popen("uci get dchp.@dnsmasq[0].domain", "r");
    if (cmd == NULL)
    {
        trace(1, "GetDomainName: getting Domain Name failed.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // get result
    fgets(domain_name, 40, cmd);

    g_string_printf(result_str, "<u:%sResponse xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
                    "<NewDomainName>%s</NewDomainName>\n"
                    "</u:%sResponse>", ca_event->ActionName, domain_name, ca_event->ActionName);
    ParseResponse(ca_event, result_str);

    pclose(cmd);
    g_string_free(result_str, TRUE);

    return ca_event->ErrCode;
}

int SetAddressRange(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int GetAddressRange(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int SetReservedAddress(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int DeleteReservedAddress(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int GetReservedAddresses(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int SetDNSServer(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int DeleteDNSServer(struct Upnp_Action_Request *ca_event)
{
    return 0;
}

int GetDNSServers(struct Upnp_Action_Request *ca_event)
{
    FILE *file;
    GString *result_str;
    GString *dns_servers;
    char line[MAX_CONFIG_LINE];
    char dns[16];
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];

    result_str = g_string_new("");
    dns_servers = g_string_new("");
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
            if (strlen(dns_servers->str) > 0)
                g_string_append(dns_servers, ",");
            strncpy(dns, &line[submatch[1].rm_so], min(submatch[1].rm_eo-submatch[1].rm_so, 16));
            dns[min(submatch[1].rm_eo-submatch[1].rm_so, 16)] = 0;
            g_string_append_printf(dns_servers, "%s", dns);
        }
    }

    g_string_printf(result_str, "<u:%sResponse xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
                    "<NewDNSServers>%s</NewDNSServers>\n"
                    "</u:%sResponse>", ca_event->ActionName, dns_servers->str, ca_event->ActionName);
    ParseResponse(ca_event, result_str);

    g_string_free(result_str, TRUE);
    g_string_free(dns_servers, TRUE);
    regfree(&nameserver);
    fclose(file);

    return 0;
}

int InitLanHostConfig()
{
    lanHostConfig.DHCPServerConfigurable = TRUE;
    // check that dnsmasq exists
    if (!g_file_test(g_vars.dnsmasqCmd, G_FILE_TEST_EXISTS))
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace(1, "DHCPServerConfigurable set to false, dnsmasq not found at: %s.", g_vars.dnsmasqCmd);
        return 1;
    }
    // check that uci exists
    if (!g_file_test(g_vars.uciCmd, G_FILE_TEST_EXISTS))
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace(1, "DHCPServerConfigurable set to false, uci not found at: %s.", g_vars.uciCmd);
        return 1;
    }

    return 0;
}

void FreeLanHostConfig()
{

}

