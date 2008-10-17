#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include "lanhostconfig.h"
#include "globals.h"
#include "util.h"

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

    if( (configurable = GetFirstDocumentItem(ca_event->ActionRequest, "NewDHCPServerConfigurable") ) )
    {
        config = resolveBoolean(configurable);

        // if user is setting configurable to true, check that init can be run successfully
        if(config && InitLanHostConfig())
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

    if(configurable) free(configurable);
    g_string_free(result_str, TRUE);

    return ca_event->ErrCode;
}

int GetDHCPServerConfigurable(struct Upnp_Action_Request *ca_event)
{
    GString *result_str;

    ca_event->ErrCode = UPNP_E_SUCCESS;

    result_str = g_string_new("");
    g_string_printf(result_str, "<u:GetDHCPServerConfigurable xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
             "<NewDHCPServerConfigurable>%d</NewDHCPServerConfigurable>\n"
             "</u:GetDHCPServerConfigurable>", (lanHostConfig.DHCPServerConfigurable ? 1 : 0));

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

    if(lanHostConfig.DHCPServerConfigurable == FALSE)
    {
        trace(1, "GetSubnetMask: DHCPServerConfigurable is false.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // try to run uci command
    cmd = popen("uci get network.lan.netmask", "r");
    if(cmd == NULL)
    {
        trace(1, "GetSubnetMask: getting subnet mask failed.");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    // get result
    fgets(subnet_mask, 48, cmd);

    g_string_printf(result_str, "<u:%s xmlns:u=\"urn:schemas-upnp-org:service:LANHostConfigManagement:1\">\n"
             "<NewSubnetMask>%s</NewSubnetMask>\n"
             "</u:%s>", ca_event->ActionName, subnet_mask, ca_event->ActionName);
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
    return 0;
}

int GetDomainName(struct Upnp_Action_Request *ca_event)
{
    return 0;
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
    return 0;
}

int InitLanHostConfig()
{
    lanHostConfig.DHCPServerConfigurable = TRUE;
    // check that dnsmasq exists
    if(!g_file_test(g_vars.dnsmasqCmd, G_FILE_TEST_EXISTS))
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace(1, "DHCPServerConfigurable set to false, dnsmasq not found at: %s.", g_vars.dnsmasqCmd);
        return 1;
    }
    // check that uci exists
    if(!g_file_test(g_vars.uciCmd, G_FILE_TEST_EXISTS))
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

