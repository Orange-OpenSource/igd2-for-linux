/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
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
 * along with this program. If not, see http://www.gnu.org/licenses/. 
 * 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include "globals.h"

#define NMATCH 3

/**
 * Get value for argument found in config file.
 *  
 * @param var Target string for argument value.
 * @param varlen Max length of argument value.
 * @param line Line as string from config file where config option locates.
 * @param submatch Regexp location of found value.
 * @return 0
 */
int getConfigOptionArgument(char var[],int varlen, char line[], regmatch_t *submatch)
{
    /* limit buffer operations to varlen - 1 */
    int match_length = min(submatch[1].rm_eo-submatch[1].rm_so, varlen - 1);

    strncpy(var,&line[submatch[1].rm_so],match_length);
    // Make sure var[] is null terminated
    var[match_length] = '\0';
    return 0;
}

/**
 * Get value for default duration of portmapping found in config file.
 *  
 * @param duration Target long int for argument value.
 * @param line Line as string from config file where config option locates.
 * @param submatch Regexp location of found value.
 * @return 0
 */
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

/**
 * Parse config file (upnpd.conf) and set default values for global values.
 *  
 * @param vars Struct of global default values.
 * @return -1 if error, else 0.
 */
int parseConfigFile(globals_p vars)
{
    FILE *conf_file;
    regmatch_t submatch[NMATCH]; // Stores the regex submatch start and end index

    regex_t re_comment;
    regex_t re_empty_row;
    regex_t re_pin_code;
    regex_t re_admin_passwd;
    regex_t re_iptables_location;
    regex_t re_debug_mode;
    regex_t re_create_forward_rules;
    regex_t re_forward_rules_append;
    regex_t re_forward_chain_name;
    regex_t re_prerouting_chain_name;
    regex_t re_upstream_bitrate;
    regex_t re_downstream_bitrate;
    regex_t re_duration;
    regex_t re_desc_doc;
    regex_t re_xml_path;
    regex_t re_listenport;
    regex_t re_https_listenport;
    regex_t re_dnsmasq;
    regex_t re_uci;
    regex_t re_resolv;
    regex_t re_dhcrelay;
    regex_t re_dhcrelay_server;
    regex_t re_dhcpc;
    regex_t re_network;
    regex_t re_advertisement_interval;
    regex_t re_cert_path;
    regex_t re_acc_lvl_xml;

    // Make sure all vars are 0 or \0 terminated
    vars->debug = 0;
    vars->createForwardRules = 0;
    vars->forwardRulesAppend = 0;
    strcpy(vars->pinCode,"");
    strcpy(vars->adminPassword,"");
    strcpy(vars->iptables,"");
    strcpy(vars->forwardChainName,"");
    strcpy(vars->preroutingChainName,"");
    strcpy(vars->upstreamBitrate,"");
    strcpy(vars->downstreamBitrate,"");
    vars->duration = DEFAULT_DURATION;
    strcpy(vars->descDocName,"");
    strcpy(vars->xmlPath,"");
    vars->listenport = 0;
    vars->httpsListenport = 0;
    strcpy(vars->dnsmasqCmd, "");
    strcpy(vars->uciCmd, "");
    strcpy(vars->resolvConf, "");
    strcpy(vars->dhcrelayCmd, "");
    strcpy(vars->dhcrelayServer, "");
    strcpy(vars->dhcpc, "");
    strcpy(vars->networkCmd, "");
    vars->advertisementInterval = ADVERTISEMENT_INTERVAL;
    strcpy(vars->certPath,"");
    strcpy(vars->accessLevelXml,"");

    // Regexp to match a comment line
    regcomp(&re_comment,"^[[:blank:]]*#",0);
    regcomp(&re_empty_row,"^[[:blank:]]*\r?\n$",REG_EXTENDED);

    // Regexps to match configuration file settings
    regcomp(&re_pin_code,"pin_code[[:blank:]]*=[[:blank:]]*([[:alnum:][:punct:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_admin_passwd,"admin_password[[:blank:]]*=[[:blank:]]*\"([[:alpha:][:blank:]_/.]{1,50})\"",REG_EXTENDED);
    regcomp(&re_iptables_location,"iptables_location[[:blank:]]*=[[:blank:]]*\"([^\"]+)\"",REG_EXTENDED);
    regcomp(&re_debug_mode,"debug_mode[[:blank:]]*=[[:blank:]]*([[:digit:]])",REG_EXTENDED);
    regcomp(&re_forward_chain_name,"forward_chain_name[[:blank:]]*=[[:blank:]]*([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_prerouting_chain_name,"prerouting_chain_name[[:blank:]]*=[[:blank:]]([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_create_forward_rules,"create_forward_rules[[:blank:]]*=[[:blank:]]*(yes|no)",REG_EXTENDED);
    regcomp(&re_forward_rules_append,"forward_rules_append[[:blank:]]*=[[:blank:]]*(yes|no)",REG_EXTENDED);
    regcomp(&re_upstream_bitrate,"upstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_downstream_bitrate,"downstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_duration,"duration[[:blank:]]*=[[:blank:]]*(@?)([[:digit:]]+|[[:digit:]]{2,}:[[:digit:]]{2})",REG_EXTENDED);
    regcomp(&re_desc_doc,"description_document_name[[:blank:]]*=[[:blank:]]*([[:alpha:].]{1,20})",REG_EXTENDED);
    regcomp(&re_xml_path,"xml_document_path[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_listenport,"listenport[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_https_listenport,"https_listenport[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_dnsmasq,"dnsmasq_script[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_uci,"uci_command[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_dhcrelay,"dhcrelay_script[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_resolv,"resolf_conf[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_dhcrelay_server,"dhcrelay_server[[:blank:]]*=[[:blank:]]*([[:digit:].:]+)",REG_EXTENDED);
    regcomp(&re_dhcpc,"dhcpc_cmd[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_network,"network_script[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_advertisement_interval,"advertisement_interval[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_cert_path,"certificate_path[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);
    regcomp(&re_acc_lvl_xml,"access_level_xml[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);

    if ((conf_file=fopen(CONF_FILE,"r")) != NULL)
    {
        char line[MAX_CONFIG_LINE];
        // Walk through the config file line by line
        while (fgets(line,MAX_CONFIG_LINE,conf_file) != NULL)
        {
            // Check if a comment line or an empty one
            if ( (0 != regexec(&re_comment,line,0,NULL,0)  )  &&
                    (0 != regexec(&re_empty_row,line,0,NULL,0))  )
            {
                // Check if pin_code
                if (regexec(&re_pin_code,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->pinCode, PIN_SIZE, line, submatch);
                }
                else if (regexec(&re_admin_passwd,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->adminPassword, OPTION_LEN, line, submatch);
                }
                // Check if iptables_location
                else if (regexec(&re_iptables_location,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->iptables, OPTION_LEN, line, submatch);
                }
                // Check if create_forward_rules
                else if (regexec(&re_create_forward_rules,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[4];
                    getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
                    vars->createForwardRules = strcmp(tmp,"yes")==0 ? 1 : 0;
                }
                // Check if forward_rules_append
                else if (regexec(&re_forward_rules_append,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[4];
                    getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
                    vars->forwardRulesAppend = strcmp(tmp,"yes")==0 ? 1 : 0;
                }
                // Check forward_chain_name
                else if (regexec(&re_forward_chain_name,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->forwardChainName, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_debug_mode,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[2];
                    getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
                    vars->debug = atoi(tmp);
                }
                else if (regexec(&re_prerouting_chain_name,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->preroutingChainName, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_upstream_bitrate,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->upstreamBitrate, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_downstream_bitrate,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->downstreamBitrate, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_duration,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionDuration(&vars->duration,line,submatch);
                }
                else if (regexec(&re_desc_doc,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->descDocName, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_xml_path,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->xmlPath, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_listenport,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[6];
                    getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
                    vars->listenport = atoi(tmp);
                }
                else if (regexec(&re_https_listenport,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[6];
                    getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
                    vars->httpsListenport = atoi(tmp);
                }
                else if (regexec(&re_dnsmasq,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->dnsmasqCmd, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_uci,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->uciCmd, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_dhcrelay,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->dhcrelayCmd, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_resolv,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->resolvConf, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_dhcrelay_server,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->dhcrelayServer, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_dhcpc,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->dhcpc, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_network,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->networkCmd, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_advertisement_interval,line,NMATCH,submatch,0) == 0)
                {
                    char tmp[6];
                    getConfigOptionArgument(tmp, OPTION_LEN, line, submatch);
                    vars->advertisementInterval = atoi(tmp);
                }
                else if (regexec(&re_cert_path,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->certPath, OPTION_LEN, line, submatch);
                }
                else if (regexec(&re_acc_lvl_xml,line,NMATCH,submatch,0) == 0)
                {
                    getConfigOptionArgument(vars->accessLevelXml, OPTION_LEN, line, submatch);
                }
                else
                {
                    // We end up here if ther is an unknown config directive
                    printf("Unknown config line: %s",line);
                }
            }
        }
        fclose(conf_file);
    }
    regfree(&re_comment);
    regfree(&re_empty_row);
    regfree(&re_pin_code);
    regfree(&re_admin_passwd);
    regfree(&re_iptables_location);
    regfree(&re_debug_mode);
    regfree(&re_create_forward_rules);
    regfree(&re_forward_rules_append);
    regfree(&re_forward_chain_name);
    regfree(&re_prerouting_chain_name);
    regfree(&re_upstream_bitrate);
    regfree(&re_downstream_bitrate);
    regfree(&re_duration);
    regfree(&re_desc_doc);
    regfree(&re_xml_path);
    regfree(&re_listenport);
    regfree(&re_https_listenport);
    regfree(&re_dnsmasq);
    regfree(&re_uci);
    regfree(&re_dhcrelay);
    regfree(&re_dhcrelay_server);
    regfree(&re_resolv);
    regfree(&re_dhcpc);
    regfree(&re_network);
    regfree(&re_advertisement_interval);
    regfree(&re_cert_path);
    regfree(&re_acc_lvl_xml);

    // Set default values for options not found in config file
    if (strnlen(vars->forwardChainName, OPTION_LEN) == 0)
    {
        // No forward chain name was set in conf file, set it to default
        snprintf(vars->forwardChainName, OPTION_LEN, IPTABLES_DEFAULT_FORWARD_CHAIN);
    }
    if (strnlen(vars->preroutingChainName, OPTION_LEN) == 0)
    {
        // No prerouting chain name was set in conf file, set it to default
        snprintf(vars->preroutingChainName, OPTION_LEN, IPTABLES_DEFAULT_PREROUTING_CHAIN);
    }
    if (strnlen(vars->upstreamBitrate, OPTION_LEN) == 0)
    {
        // No upstream_bitrate was found in the conf file, set it to default
        snprintf(vars->upstreamBitrate, OPTION_LEN, DEFAULT_UPSTREAM_BITRATE);
    }
    if (strnlen(vars->downstreamBitrate, OPTION_LEN) == 0)
    {
        // No downstream bitrate was found in the conf file, set it to default
        snprintf(vars->downstreamBitrate, OPTION_LEN, DEFAULT_DOWNSTREAM_BITRATE);
    }
    if (strnlen(vars->descDocName, OPTION_LEN) == 0)
    {
        snprintf(vars->descDocName, OPTION_LEN, DESC_DOC_DEFAULT);
    }
    if (strnlen(vars->xmlPath, OPTION_LEN) == 0)
    {
        snprintf(vars->xmlPath, OPTION_LEN, XML_PATH_DEFAULT);
    }
    if (vars->httpsListenport == 0)
    {
        vars->httpsListenport = HTTPS_LISTENPORT_DEFAULT;
    }
    if (strnlen(vars->dnsmasqCmd, OPTION_LEN) == 0)
    {
        snprintf(vars->dnsmasqCmd, OPTION_LEN, DNSMASQ_CMD_DEFAULT);
    }
    if (strnlen(vars->dhcrelayCmd, OPTION_LEN) == 0)
    {
        snprintf(vars->dhcrelayCmd, OPTION_LEN, DHCRELAY_CMD_DEFAULT);
    }
    if (strnlen(vars->uciCmd, OPTION_LEN) == 0)
    {
        snprintf(vars->uciCmd, OPTION_LEN, UCI_CMD_DEFAULT);
    }
    if (strnlen(vars->resolvConf, OPTION_LEN) == 0)
    {
        snprintf(vars->resolvConf, OPTION_LEN, RESOLV_CONF_DEFAULT);
    }
    if (strnlen(vars->dhcpc, OPTION_LEN) == 0)
    {
        snprintf(vars->dhcpc, OPTION_LEN, DHCPC_DEFAULT);
    }
    if (strnlen(vars->networkCmd, OPTION_LEN) == 0)
    {
        snprintf(vars->networkCmd, OPTION_LEN, NETWORK_CMD_DEFAULT);
    }
    if (vars->advertisementInterval < 300) // smaller would mess everything
    {
        vars->advertisementInterval = 300;
    }
    if (strnlen(vars->certPath, OPTION_LEN) == 0)
    {
        snprintf(vars->certPath, OPTION_LEN, CERT_PATH_DEFAULT);
    }
    if (strnlen(vars->accessLevelXml, OPTION_LEN) == 0)
    {
        snprintf(vars->accessLevelXml, OPTION_LEN, ACCESS_LEVEL_XML_DEFAULT);
    }
    if (strnlen(vars->iptables, OPTION_LEN) == 0)
    {
        // Can't find the iptables executable, return -1 to
        // indicate en error
        return -1;
    }
    if (strnlen(vars->adminPassword, OPTION_LEN) == 0)
    {
        // Can't find the admin password code, return -1 to
        // indicate en error
        return -1;
    }
    else
    {
        return 0;
    }
}
