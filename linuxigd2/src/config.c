#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include <glib.h>
#include "globals.h"
#include "util.h"

#define NMATCH 3

int getConfigOptionArgument(char var[],int varlen, char line[], regmatch_t *submatch)
{
    /* limit buffer operations to varlen - 1 */
    int match_length = min(submatch[1].rm_eo-submatch[1].rm_so, varlen - 1);

    strncpy(var,&line[submatch[1].rm_so],match_length);
    // Make sure var[] is null terminated
    var[match_length] = '\0';
    return 0;
}

int getConfigOptionDuration(long int *duration,char line[], regmatch_t *submatch)
{
    long int dur;
    int absolute_time = submatch[1].rm_eo-submatch[1].rm_so; // >0 if @ was present
    char num[NUM_LEN];
    char *p;

    /* limit buffer operations to NUM_LEN - 1 */
    unsigned int len = min(submatch[2].rm_eo-submatch[2].rm_so, NUM_LEN - 1);

    strncpy(num, &line[submatch[2].rm_so], len);
    num[len] = '\0';
    if ((p=index(num,':'))==NULL)
    {
        dur = atol(num);
    }
    else
    {
        *p++ = '\0';
        dur = atol(num)*3600 + atol(p)*60;
    }

    if (dur > MAXIMUM_DURATION)
        dur = MAXIMUM_DURATION;

    if (absolute_time)
        dur *= -1;
    *duration = dur;
    return 0;
}

int parseConfigFile(globals_p vars)
{
    GKeyFile *file;
    GError *error = NULL;

    file = g_key_file_new();
    if (!g_key_file_load_from_file(file, CONF_FILE, 0, &error))
    {
        fprintf(stderr, "Can't open config file \"%s\": %s", CONF_FILE, error->message);
        return -1;
    }

    if (g_key_file_has_key(file, "upnpd", "iptables_location", &error))
        vars->iptables = g_key_file_get_string(file, "upnpd", "iptables_location", &error);
    else
    {
        fprintf(stderr, "No config file value for iptables location.");
        return -1;
    }

    if (g_key_file_has_key(file, "upnpd", "debug_mode", &error))
        vars->debug = g_key_file_get_integer(file, "upnpd", "debug_mode", &error);
    else
        vars->debug = 0;

    if (g_key_file_has_key(file, "upnpd", "forward_chain_name", &error))
        vars->forwardChainName = g_key_file_get_string(file, "upnpd", "forward_chain_name", &error);
    else
        snprintf(vars->forwardChainName, CHAIN_NAME_LEN, IPTABLES_DEFAULT_FORWARD_CHAIN);

    if (g_key_file_has_key(file, "upnpd", "prerouting_chain_name", &error))
        vars->preroutingChainName = g_key_file_get_string(file, "upnpd", "prerouting_chain_name", &error);
    else
        snprintf(vars->preroutingChainName, CHAIN_NAME_LEN, IPTABLES_DEFAULT_PREROUTING_CHAIN);

    if (g_key_file_has_key(file, "upnpd", "create_forward_rules", &error))
        vars->createForwardRules = resolveBoolean(g_key_file_get_string(file, "upnpd", "create_forward_rules", &error));
    else
        vars->createForwardRules = 0;

    if (g_key_file_has_key(file, "upnpd", "forward_rules_append", &error))
        vars->forwardRulesAppend = resolveBoolean(g_key_file_get_string(file, "upnpd", "forward_rules_append", &error));
    else
        vars->forwardRulesAppend = 0;

    if (g_key_file_has_key(file, "upnpd", "upstream_bitrate", &error))
        vars->upstreamBitrate = g_key_file_get_string(file, "upnpd", "upstream_bitrate", &error);
    else
        snprintf(vars->upstreamBitrate, BITRATE_LEN, DEFAULT_UPSTREAM_BITRATE);

    if (g_key_file_has_key(file, "upnpd", "downstream_bitrate", &error))
        vars->downstreamBitrate = g_key_file_get_string(file, "upnpd", "downstream_bitrate", &error);
    else
        snprintf(vars->downstreamBitrate, BITRATE_LEN, DEFAULT_DOWNSTREAM_BITRATE);

    if (g_key_file_has_key(file, "upnpd", "duration", &error))
        vars->duration = g_key_file_get_integer(file, "upnpd", "duration", &error);
    else
        vars->duration = DEFAULT_DURATION;

    if (g_key_file_has_key(file, "upnpd", "description_document_name", &error))
        vars->descDocName = g_key_file_get_string(file, "upnpd", "description_document_name", &error);
    else
        snprintf(vars->downstreamBitrate, BITRATE_LEN, DESC_DOC_DEFAULT);

    if (g_key_file_has_key(file, "upnpd", "xml_document_path", &error))
        vars->xmlPath = g_key_file_get_string(file, "upnpd", "xml_document_path", &error);
    else
        snprintf(vars->downstreamBitrate, BITRATE_LEN, XML_PATH_DEFAULT);

    if (g_key_file_has_key(file, "upnpd", "listenport", &error))
        vars->listenport = g_key_file_get_integer(file, "upnpd", "listenport", &error);
    else
        vars->listenport = LISTENPORT_DEFAULT;

    if (g_key_file_has_key(file, "upnpd", "dnsmasq_script", &error))
        vars->dnsmasqCmd = g_key_file_get_string(file, "upnpd", "dnsmasq_script", &error);
    else
        snprintf(vars->dnsmasqCmd, BITRATE_LEN, DNSMASQ_CMD_DEFAULT);

    if (g_key_file_has_key(file, "upnpd", "uci_command", &error))
        vars->uciCmd = g_key_file_get_string(file, "upnpd", "uci_command", &error);
    else
        snprintf(vars->uciCmd, BITRATE_LEN, UCI_CMD_DEFAULT);

    return 0;
}
