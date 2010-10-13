/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 * 
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU (Lesser) General Public License as 
 * published by the Free Software Foundation, version 2 of the License. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU (Lesser) General Public License for more details. 
 * 
 * You should have received a copy of the GNU (Lesser) General Public 
 * License along with this program. If not, see http://www.gnu.org/licenses/. 
 * 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "lanhostconfig.h"
#include "globals.h"
#include "util.h"

/**
 * Settings for lanhostconfig-module.
 */
struct LanHostConfig
{
    int DHCPServerConfigurable;
    int dhcrelay;
} lanHostConfig;

/**
 * Runs given command with given parameters.
 * Forks the process and returns status returned by child process.
 *
 * @param cmd Command to run.
 * @param parm Parameters for the command.
 * @return Status returned by the child process.
 */
int RunCommand( char *cmd, char **parm )
{
    pid_t pid;
    int status;

    if ( ( pid = fork() ) == -1 )
        return 1;
    else if ( pid == 0 )
        execvp( cmd, parm );
    else
        waitpid( pid, &status, 0 );

    return status;
}

/**
 * Runs "uci commit".
 * Commits all changes made by uci commands.
 */
void UciCommit()
{
    char *args[] = { g_vars.uciCmd, "commit", NULL };
    RunCommand( g_vars.uciCmd, args );
}

/**
 * Runs dnsmasq start/stop script based on parameters.
 *
 * @param param Parameter for dnsmasq script.
 */
int DnsmasqCommand( char *param )
{
    char *args[] = { g_vars.dnsmasqCmd, param, NULL };
    return RunCommand( g_vars.dnsmasqCmd, args );
}

/**
 * Restarts dnsmasq service, if dhcrelay server is not used.
 */
void DnsmasqRestart()
{
    if(lanHostConfig.dhcrelay)
        return;

    DnsmasqCommand( SERVICE_STOP );
    DnsmasqCommand( SERVICE_START );
}

/**
 * Sends commands to network init script.
 *
 * @param param Command to give for the init script.
 * @return Value returned by the script.
 */
int NetworkCommand( char *param )
{
    char *args[] = { g_vars.networkCmd, param, NULL };
    return RunCommand( g_vars.networkCmd, args );
}

/**
 * Starts dhcrelay daemon. Server parameter is taken from conf-file.
 */
void DhcrelayStart()
{
    if ( g_vars.dhcrelayServer == NULL )
    {
        // can't start dhcrelay without server
        trace( 1, "DhcrelayStart: Can't start dhcrelay without server" );
        return;
    }

    char *args[] = { g_vars.dhcrelayCmd, g_vars.dhcrelayServer, NULL };
    RunCommand( g_vars.dhcrelayCmd, args );
}

/**
 * Stops dhcrelay daemon.
 */
void DhcrelayStop()
{
    char *args[] = { "killall", g_vars.dhcrelayCmd, NULL };
    RunCommand( "killall", args );
}

/**
 * Checks if dhcp server is set to configurable.
 * Returns 0 if it is, upnp error code otherwise.
 *
 * @param ca_event Upnp action.
 * @return Upnp error code if LanHostConfig is not configurable. 0 on success.
 */
int CheckDHCPServerConfigurable( struct Upnp_Action_Request *ca_event )
{
    if ( lanHostConfig.DHCPServerConfigurable == FALSE )
    {
        trace( 1, "%s: DHCPServerConfigurable is false.", ca_event->ActionName );
        addErrorData( ca_event, 501, "Action Failed" );
        return ca_event->ErrCode;
    }

    return 0;
}

/**
 * Set Upnp error 402: Invalid Arguments as return value and
 * print a log message.
 *
 * @param ca_event Upnp action struct.
 */
void InvalidArgs( struct Upnp_Action_Request *ca_event )
{
    trace( 2, "%s: Invalid Args", ca_event->ActionName );
    ca_event->ErrCode = 402;
    strcpy( ca_event->ErrStr, "Invalid Args" );
    ca_event->ActionResult = NULL;
}

/**
 * Form and parse upnp action result xml.
 *
 * @param ca_event Upnp action struct.
 * @param str Format string for extra parameters.
 * @param ... Extra parameters
 */
void ParseResult( struct Upnp_Action_Request *ca_event, const char *str, ... )
{
    char result[RESULT_LEN];
    char parameters[RESULT_LEN];
    va_list arg;

    // write all parameters into one string
    va_start( arg, str );
    vsnprintf( parameters, RESULT_LEN, str, arg );
    va_end( arg );

    // and form final xml
    snprintf( result, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
              ca_event->ActionName,
              "urn:schemas-upnp-org:service:LANHostConfigManagement:1",
              parameters,
              ca_event->ActionName );

    ParseXMLResponse( ca_event, result );
}

/**
 * Parses default gateway address from 'route -n' command and writes it to gateway parameter.
 *
 * @param gateway Function will write default gateway address to this parameter. Must be large enough to hold IPv4 ip address.
 * @return TRUE on success.
 */
int GetDefaultGateway( char *gateway )
{
    FILE *cmd;
    char line[LINE_LEN];
    char *addr;

    // try to run route command
    cmd = popen( "route -n", "r" );
    if ( cmd == NULL )
        return FALSE;

    // get result
    while ( fgets( line, LINE_LEN, cmd ) != NULL )
    {
        // get first column in line
        addr = strtok( line, " " );
        // is default gw in this line?
        if ( strcmp( addr, DEFAULT_GATEWAY_IP ) == 0 )
        {
            // default gw is in next column
            addr = strtok( NULL, " " );
            strcpy( gateway, addr );
            pclose( cmd );
            return TRUE;
        }
    }

    pclose( cmd );
    return FALSE;
}


//-----------------------------------------------------------------------------
//
//                      LANHostConfigManagement:1 Service Actions
//
//-----------------------------------------------------------------------------

/**
 * LANHostConfigManagement:1 Action: SetDHCPServerConfigurable.
 *
 * Set dhcp server configuration flag.
 * It fails if CheckLanHostConfigFiles fails.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetDHCPServerConfigurable( struct Upnp_Action_Request *ca_event )
{
    char *configurable;
    int config;

    if ( ( configurable = GetFirstDocumentItem( ca_event->ActionRequest, "NewDHCPServerConfigurable" ) ) )
    {
        config = resolveBoolean( configurable );

        // if user is setting configurable to true, check that all necessary files are installed
        if ( config && CheckLanHostConfigFiles() )
        {
            // init failed, send action failed response
            ca_event->ErrCode = 501;
            strcpy( ca_event->ErrStr, "Action Failed" );
            ca_event->ActionResult = NULL;
        }
        else
        {
            lanHostConfig.DHCPServerConfigurable = config;
            ParseResult( ca_event, "" );
        }
    }
    else
        InvalidArgs( ca_event );

    free( configurable );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetDHCPServerConfigurable.
 *
 * Returns the dhcp configuration flag.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetDHCPServerConfigurable( struct Upnp_Action_Request *ca_event )
{
    ParseResult( ca_event, "<NewDHCPServerConfigurable>%d</NewDHCPServerConfigurable>\n", ( lanHostConfig.DHCPServerConfigurable ? 1 : 0 ) );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetDHCPRelay.
 *
 * Change dhcp mode between relay server and normal dhcp server.
 * Start / Stop dhcrelay and dnsmasq accordingly.
 *
 * @todo check that dhcrelay is installed in the system
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetDHCPRelay( struct Upnp_Action_Request *ca_event )
{
    char *dhcrelay;
    int b_dhcrelay;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( dhcrelay = GetFirstDocumentItem( ca_event->ActionRequest, "NewDHCPRelay" ) ) )
    {
        b_dhcrelay = resolveBoolean( dhcrelay );

        if ( b_dhcrelay != lanHostConfig.dhcrelay )
        {
            if ( b_dhcrelay )
            {
                DnsmasqCommand( SERVICE_STOP );
                DhcrelayStart();
            }
            else
            {
                DhcrelayStop();
                DnsmasqCommand( SERVICE_START );
            }

            lanHostConfig.dhcrelay = b_dhcrelay;
        }
    }
    else
        InvalidArgs( ca_event );

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    free( dhcrelay );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetDHCPRelay.
 *
 * Returns the state of dhcrelay server.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetDHCPRelay( struct Upnp_Action_Request *ca_event )
{
    ParseResult( ca_event, "<NewDHCPRelay>%d</NewDHCPRelay>\n", ( lanHostConfig.dhcrelay ? 1 : 0 ) );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetSubnetMask.
 *
 * Set the subnet mask of the LAN.
 * Uses uci option network.lan.netmask.
 * After setting the parameter network is restarted.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetSubnetMask( struct Upnp_Action_Request *ca_event )
{
    char *subnet_mask;
    char command[INET6_ADDRSTRLEN];
    char *args[] = { g_vars.uciCmd, "set", NULL, NULL };
    regex_t reg_ip;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( subnet_mask = GetFirstDocumentItem( ca_event->ActionRequest, "NewSubnetMask" ) ) )
    {
        // sanitize input
        regcomp(&reg_ip, REGEX_IP_LASTBYTE, REG_EXTENDED);
        if( regexec( &reg_ip, subnet_mask, 0, 0, 0 ) != 0 )
        {
            trace( 1, "SetDomainName: subnet mask contains invalid characters: '%s'.", subnet_mask );
            InvalidArgs( ca_event );
            regfree( &reg_ip );
            return ca_event->ErrCode;
        }
        regfree( &reg_ip );

        snprintf( command, INET6_ADDRSTRLEN, "network.lan.netmask=%s", subnet_mask );
        args[2] = command;
        RunCommand( g_vars.uciCmd, args );
        UciCommit();
        NetworkCommand( SERVICE_RESTART );
    }
    else
        InvalidArgs( ca_event );

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetSubnetMask.
 *
 * Returns subnet mask using uci option
 * network.lan.netmask.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetSubnetMask( struct Upnp_Action_Request *ca_event )
{
    FILE *cmd;
    char subnet_mask[INET6_ADDRSTRLEN];

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    // try to run uci command
    cmd = popen( "uci get network.lan.netmask", "r" );
    if ( cmd == NULL )
    {
        trace( 1, "GetSubnetMask: getting subnet mask failed." );
        addErrorData( ca_event, 501, "Action Failed" );
        return ca_event->ErrCode;
    }

    // get result
    if ( fgets( subnet_mask, INET6_ADDRSTRLEN, cmd ) != NULL )
        ParseResult( ca_event, "<NewSubnetMask>%s</NewSubnetMask>\n", subnet_mask );
    else
    {
        trace( 1, "GetSubnetMask: uci command returned null." );
        addErrorData( ca_event, 501, "Action Failed" );
    }

    pclose( cmd );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetIPRouter.
 *
 * Sets the default router.
 * This action only affects the default router, not all routers like defined in the spec.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetIPRouter( struct Upnp_Action_Request *ca_event )
{
    char *parmList[] = { ROUTE_COMMAND, NULL, "default", "gw", NULL, NULL };
    char addr[LINE_LEN];
    char *new_router;
    int  status;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( new_router = GetFirstDocumentItem( ca_event->ActionRequest, "NewIPRouters" ) ) )
    {
        // if default gateway already exists, delete it
        if ( GetDefaultGateway( addr ) )
        {
            // check that new gateway is different than current
            if ( strcmp( new_router, addr ) == 0 )
            {
                addErrorData( ca_event, 701, "ValueAlreadySpecified" );
                trace( 2, "SetIPRouter: new default gw '%s' is the same as current one '%s'", new_router, addr );
                free( new_router );
                return ca_event->ErrCode;
            }

            parmList[1] = "del";
            parmList[4] = addr;

            RunCommand( ROUTE_COMMAND, parmList );
        }

        // add new default gw
        parmList[1] = "add";
        parmList[4] = new_router;

        status = RunCommand( ROUTE_COMMAND, parmList );

        if ( !status )
            ParseResult( ca_event, "" );
        else
        {
            trace( 2, "SetIPRouter: Route command returned error: %d", status );
            addErrorData( ca_event, 501, "Action Failed" );
        }

    }

    free( new_router );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: DeleteIPRouter.
 *
 * Deletes the default router.
 * This action only affects the default router, not all routers like defined in the spec.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int DeleteIPRouter( struct Upnp_Action_Request *ca_event )
{
    char *parmList[] = { ROUTE_COMMAND, "del", "default", "gw", NULL, NULL };
    int status;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( parmList[4] = GetFirstDocumentItem( ca_event->ActionRequest, "NewIPRouters" ) ) )
    {
        // run route del command
        status = RunCommand( ROUTE_COMMAND, parmList );
        if ( !status )
            ParseResult( ca_event, "" );
        else
        {
            trace( 2, "DeleteIPRouter: Route command returned error: %d", status );
            addErrorData( ca_event, 702, "ValueSpecifiedIsInvalid" );
        }
    }
    else
        InvalidArgs( ca_event );

    free( parmList[4] );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetIPRoutersList.
 *
 * Returns the default router.
 * This action returns only the default router, not all routers like defined in the spec.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetIPRoutersList( struct Upnp_Action_Request *ca_event )
{
    char addr[LINE_LEN];
    int gw_found = FALSE;

    gw_found = GetDefaultGateway( addr );

    if ( gw_found )
        ParseResult( ca_event, "<NewIPRouters>%s</NewIPRouters>\n", addr );
    else
        addErrorData( ca_event, 501, "Invalid Args" );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetDomainName.
 *
 * Uses uci option dhcp.@dnsmasq[0].domain
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetDomainName( struct Upnp_Action_Request *ca_event )
{
    FILE *cmd = NULL;
    char *domainName;
    char setdomain_cmd[LINE_LEN];
    regex_t reg_domain;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( domainName = GetFirstDocumentItem( ca_event->ActionRequest, "NewDomainName" ) ) )
    {
        // sanitize input
        regcomp(&reg_domain, REGEX_DOMAIN_NAME, REG_EXTENDED);
        if( regexec( &reg_domain, domainName, 0, 0, 0 ) != 0 )
        {
            trace( 1, "SetDomainName: Domain Name contains invalid characters: '%s'.", domainName );
            InvalidArgs( ca_event );
            regfree(&reg_domain);
            return ca_event->ErrCode;
        }
        regfree(&reg_domain);

        snprintf( setdomain_cmd, LINE_LEN, "uci set dhcp.@dnsmasq[0].domain=%s", domainName );
        cmd = popen( setdomain_cmd, "r" );
        if ( cmd == NULL )
        {
            trace( 1, "SetDomainName: setting Domain Name failed." );
            addErrorData( ca_event, 501, "Action Failed" );
            return ca_event->ErrCode;
        }

        UciCommit();
        NetworkCommand( SERVICE_RESTART );

        ParseResult( ca_event, "" );
    }
    else
        InvalidArgs( ca_event );

    if ( cmd ) pclose( cmd );
    free( domainName );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetDomainName.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetDomainName( struct Upnp_Action_Request *ca_event )
{
    FILE *cmd;
    char domain_name[LINE_LEN];

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    // try to run uci command
    cmd = popen( "uci get -q dhcp.@dnsmasq[0].domain", "r" );
    if ( cmd == NULL )
    {
        trace( 1, "GetDomainName: getting Domain Name failed." );
        addErrorData( ca_event, 501, "Action Failed" );
        return ca_event->ErrCode;
    }

    // get result
    if ( fgets( domain_name, LINE_LEN, cmd ) != NULL )
        ParseResult( ca_event, "<NewDomainName>%s</NewDomainName>\n", domain_name );
    else
    {
        trace( 1, "GetDomainName: uci command returned null." );
        addErrorData( ca_event, 501, "Action Failed" );
    }

    pclose( cmd );

    return ca_event->ErrCode;
}

/**
 * Parses and returns last part from given ip address
 *
 * @param ip_addr Ip address as char array
 * @param regmatch_t Regular expression submatch array
 * @return -1 on failure
 */
int ParseIPLastPart( const char *ip_addr, regmatch_t *submatch )
{
    regex_t ip;
    char ip_last[MAX_IP_LAST_PART];

    regcomp( &ip, REGEX_IP_LASTBYTE, REG_EXTENDED );

    // check that address is an IP address
    if ( regexec( &ip, ip_addr, SUB_MATCH, submatch, 0 ) == 0 )
    {
        // parse last part of the ip address
        strncpy( ip_last, &ip_addr[submatch[1].rm_so], min( submatch[1].rm_eo-submatch[1].rm_so, MAX_IP_LAST_PART ) );
        ip_last[min( submatch[1].rm_eo-submatch[1].rm_so, MAX_IP_LAST_PART-1 )] = 0;
        return atoi( ip_last );
    }
    // start address not valid
    return -1;
}

/**
 * Parses start and limit variables used by Uci-command from given ip addresses.
 *
 * @param ca_event Upnp event struct.
 * @param start Start parameter for Uci, parsed by this function
 * @param limit Limit parameter for Uci, parsed by this function
 * @param start_addr Start ip address
 * @param last_addr Last ip address
 * @return Upnp error code, 0 on success.
 */
int ParseAddressRange( struct Upnp_Action_Request *ca_event,
                       char *start,
                       char *limit,
                       const char *start_addr,
                       const char *last_addr )
{
    int start_nro, last_nro;
    regmatch_t submatch[SUB_MATCH];

    start_nro = ParseIPLastPart( start_addr, submatch );
    last_nro = ParseIPLastPart( last_addr, submatch );

    if ( start_nro == -1 || last_nro == -1 )
    {
        InvalidArgs( ca_event );
        trace( 2, "SetAddressRange: Address not valid, start '%s' limit '%s'", start_addr, last_addr );
        return ca_event->ErrCode;
    }

    // check that start address isn't 254 or over it
    if ( start_nro >= 254 )
    {
        trace( 2, "%s: Start address last part is over 253, %s.", ca_event->ActionName, start_addr );
        InvalidArgs(ca_event);
        return ca_event->ErrCode;
    }

    // check that limit address isn't 255 or over it
    if ( last_nro >= 255 )
    {
        trace( 2, "%s: Last address last part is over 254, %s.", ca_event->ActionName, start_addr );
        InvalidArgs(ca_event);
        return ca_event->ErrCode;
    }

    // write start address
    snprintf( start, MAX_IP_LAST_PART, "%d", start_nro );

    // are 3 parts of the ip address same
    if ( strncmp( start_addr, last_addr, submatch[1].rm_so ) == 0 )
    {
        // limit is last - start
        if ( last_nro - start_nro > 0 )
            snprintf( limit, MAX_IP_LAST_PART, "%d", ( last_nro-start_nro ) );
        else
        {
            trace( 2, "%s: Last address higher than start address, start '%s' limit '%s'",
                   ca_event->ActionName, start_addr, last_addr );
            InvalidArgs( ca_event );
            return ca_event->ErrCode;
        }
    }
    else
    {
        trace( 2, "%s: First 3 parts of the ip addresses don't match, setting last to 254.", ca_event->ActionName );
        snprintf( limit, MAX_IP_LAST_PART, "%d", ( 254-start_nro ) );
    }

    return 0;
}

/**
 * LANHostConfigManagement:1 Action: SetAddressRange.
 *
 * Sets the address range dhcp server will give out.
 *
 * @todo Maybe we should use the 3 first parts of the ip address to set the ip address of this router?
 * Now they are just ignored.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetAddressRange( struct Upnp_Action_Request *ca_event )
{
    char *parmList[] = { g_vars.uciCmd, "set", NULL, NULL };
    char *start_addr, *limit_addr;
    char command[MAX_IP_LAST_PART+15];
    char start[MAX_IP_LAST_PART], limit[MAX_IP_LAST_PART];

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    start_addr = GetFirstDocumentItem( ca_event->ActionRequest, "NewMinAddress" );
    limit_addr = GetFirstDocumentItem( ca_event->ActionRequest, "NewMaxAddress" );

    if ( start_addr && limit_addr )
    {
        // parse last part of both ip addresses
        if ( ParseAddressRange( ca_event, start, limit, start_addr, limit_addr ) )
            return ca_event->ErrCode;

        snprintf( command, MAX_IP_LAST_PART+15, "dhcp.lan.start=%s", start );
        parmList[2] = command;
        RunCommand( g_vars.uciCmd, parmList );

        snprintf( command, MAX_IP_LAST_PART+15, "dhcp.lan.limit=%s", limit );
        parmList[2] = command;
        RunCommand( g_vars.uciCmd, parmList );

        UciCommit();
        DnsmasqRestart();
    }
    else
        InvalidArgs( ca_event );

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    free( start_addr );
    free( limit_addr );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetAddressRange.
 *
 * Gets the address range dhcp server will give out.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetAddressRange( struct Upnp_Action_Request *ca_event )
{
    FILE *cmd = NULL, *cmd_2 = NULL;
    char start[INET6_ADDRSTRLEN] = {0}, limit[INET6_ADDRSTRLEN] = {0};

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    // try to run uci commands
    cmd = popen( "uci get dhcp.lan.start", "r" );
    cmd_2 = popen( "uci get dhcp.lan.limit", "r" );
    if ( cmd == NULL || cmd_2 == NULL )
    {
        trace( 1, "GetAddressRange: uci command failed." );
        addErrorData( ca_event, 501, "Action Failed" );
    }
    else
    {
        // get result
        /** @todo add error checking, if uci returns something invalid */
        if ( fgets( start, INET6_ADDRSTRLEN, cmd ) == NULL ||
                fgets( limit, INET6_ADDRSTRLEN, cmd_2 ) == NULL )
        {
            trace( 1, "GetAddressRange: error reading values." );
            addErrorData( ca_event, 501, "Action Failed" );
        }
    }

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "<NewMinAddress>%s</NewMinAddress>\n<NewMaxAddress>%s</NewMaxAddress>\n", start, limit );

    if ( cmd ) pclose( cmd );
    if ( cmd_2 ) pclose( cmd_2 );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetReservedAddress.
 *
 * Sets the reserved addesses, that dhcp server won't give to clients.
 * Old values will be deleted before the new list is applied.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetReservedAddress( struct Upnp_Action_Request *ca_event )
{
    char command[COMMAND_LEN];
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    char *all_addr, *addr;
    char *add_args[] = { g_vars.uciCmd, "-q", "add", "dhcp", "host", NULL };
    char *set_args[] = { g_vars.uciCmd, "-q", "set", NULL, NULL };
    char *del_args[] = { g_vars.uciCmd, "-q", "delete", "dhcp.@host[0]", NULL };
    int i=0;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( all_addr = GetFirstDocumentItem( ca_event->ActionRequest, "NewReservedAddresses" ) ) == NULL )
    {
        InvalidArgs( ca_event );
        return ca_event->ErrCode;
    }

    // delete all hosts
    while ( i < MAX_RESERVED_ADDRESS )
    {
        sprintf( command, "uci -q get dhcp.@host[0]" );
        cmd = popen( command, "r" );
        if ( cmd == NULL )
        {
            trace( 1, "SetReservedAddress: Error running command: '%s'", command );
            addErrorData( ca_event, 501, "Action Failed" );
            break;
        }
        // if nothing is returned, we have removed all hosts
        if ( fgets( line, MAX_CONFIG_LINE, cmd ) == NULL )
        {
            pclose( cmd );
            break;
        }

        pclose( cmd );

        RunCommand( g_vars.uciCmd, del_args );

        i++;
    }

    // if deleting was successful then add new hosts
    if ( ca_event->ErrCode == 0 )
    {
        addr = strtok( all_addr, "," );
        while ( addr != NULL )
        {
            // add new host
            RunCommand( g_vars.uciCmd, add_args );

            // set host values
            set_args[3] = "dhcp.@host[-1].name=IGDv2";
            RunCommand( g_vars.uciCmd, set_args );
            set_args[3] = "dhcp.@host[-1].mac=00:00:00:00:00:00";
            RunCommand( g_vars.uciCmd, set_args );
            sprintf( command, "dhcp.@host[-1].ip=%s", addr );
            set_args[3] = command;
            RunCommand( g_vars.uciCmd, set_args );

            addr = strtok( NULL, "," );
        }
    }

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    free( all_addr );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: DeleteReservedAddress.
 *
 * Deletes specified ip-address from reserved addresses if it can be found.
 * This action only takes one ip-address at a time, not a comma separated list.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int DeleteReservedAddress( struct Upnp_Action_Request *ca_event )
{
    char command[COMMAND_LEN];
    char *del_addr;
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    int i = 0;
    int deleted = FALSE;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    if ( ( del_addr = GetFirstDocumentItem( ca_event->ActionRequest, "NewReservedAddresses" ) ) == NULL )
    {
        InvalidArgs( ca_event );
        return ca_event->ErrCode;
    }

    // added MAX_RESERVED_ADDRESS as precaution, if under some conditions uci returns always something
    // if that is reached, give internal error
    while ( i < MAX_RESERVED_ADDRESS )
    {
        sprintf( command, "uci -q get dhcp.@host[%d].ip", i );
        cmd = popen( command, "r" );
        if ( cmd == NULL )
        {
            trace( 1, "DeleteReservedAddress: Error running command: '%s'", command );
            addErrorData( ca_event, 501, "Action Failed" );
            break;
        }
        if ( fgets( line, MAX_CONFIG_LINE, cmd ) == NULL )
        {
            // returned nothing, no more hosts defined
            pclose( cmd );
            break;
        }

        pclose( cmd );

        if ( strncmp( line, del_addr, strlen( del_addr ) ) == 0 )
        {
            sprintf( command, "uci -q delete dhcp.@host[%d]", i );
            cmd = popen( command, "r" );
            if ( cmd == NULL )
            {
                trace( 1, "DeleteReservedAddress: Error running command: '%s'", command );
                addErrorData( ca_event, 501, "Action Failed" );
            }
            else
            {
                // entry successfully deleted
                deleted = TRUE;
                UciCommit();
                DnsmasqRestart();
                pclose( cmd );
            }

            break;
        }

        i++;
    }
    if ( i == MAX_RESERVED_ADDRESS )
    {
        trace( 1, "DeleteReservedAddress: Internal error in function." );
        addErrorData( ca_event, 501, "Action Failed" );
    }

    if ( deleted == FALSE )
    {
        trace( 2, "DeleteReservedAddress: Can't find address to delete: '%s'.", del_addr );
        addErrorData( ca_event, 702, "ValueSpecifiedIsInvalid" );
    }

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    if ( cmd ) pclose( cmd );
    free( del_addr );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetReservedAddresses.
 *
 * Returns all reserved addresses in a comma separated list.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetReservedAddresses( struct Upnp_Action_Request *ca_event )
{
    char command[COMMAND_LEN];
    char addresses[RESULT_LEN];
    FILE *cmd;
    char line[MAX_CONFIG_LINE];
    int i = 0;
    int addr_place = 0;

    addresses[0] = 0;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    // added MAX_RESERVED_ADDRESS as precaution, if under some conditions uci returns always something
    // if that is reached, give internal error
    while ( i < MAX_RESERVED_ADDRESS )
    {
        sprintf( command, "uci -q get dhcp.@host[%d].ip", i );
        cmd = popen( command, "r" );
        if ( cmd == NULL )
        {
            trace( 1, "GetReservedAddresses: Error running command: '%s'", command );
            addErrorData( ca_event, 501, "Action Failed" );
            break;
        }
        if ( fgets( line, MAX_CONFIG_LINE, cmd ) == NULL )
        {
            // returned nothing, no more hosts defined
            pclose( cmd );
            break;
        }

        // add comma separator before all except first address
        if ( addr_place > 0 )
            addr_place += snprintf( &addresses[addr_place], RESULT_LEN - addr_place, "," );
        // remove extra linechange
        line[strlen( line )-1] = 0;
        addr_place += snprintf( &addresses[addr_place], RESULT_LEN - addr_place, "%s", line );

        pclose( cmd );
        i++;
    }
    if ( i == MAX_RESERVED_ADDRESS )
    {
        trace( 1, "GetReservedAddresses: Internal error in function." );
        addErrorData( ca_event, 501, "Action Failed" );
    }

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "<NewReservedAddresses>%s</NewReservedAddresses>\n", addresses );

    if ( cmd ) pclose( cmd );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: SetDNSServer.
 *
 * Sets dns servers.
 * Opens resolv.conf file and a temp file. Copies all but nameservers from original
 * file to the temp file. Adds new nameservers to the temp file. Copies the temp file
 * over the original file.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetDNSServer( struct Upnp_Action_Request *ca_event )
{
    FILE *file = NULL, *new_file = NULL;
    char line[MAX_CONFIG_LINE];
    char *dns = NULL;
    char *dns_list = NULL;
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    regcomp( &nameserver, REGEX_NAMESERVER, REG_EXTENDED );
    ca_event->ErrCode = 0;

    if ( ( dns_list = GetFirstDocumentItem( ca_event->ActionRequest, "NewDNSServers" ) ) )
    {
        // open resolv.conf for reading
        file = fopen( g_vars.resolvConf, "r" );
        // and temporary file for writing
        new_file = fopen( RESOLV_CONF_TMP, "w" );
        if ( file == NULL || new_file == NULL )
        {
            if ( file == NULL )
                trace( 1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf );
            if ( new_file == NULL )
                trace( 1, "Failed to open temp resolv.conf: %s.", RESOLV_CONF_TMP );

            addErrorData( ca_event, 501, "Action Failed" );
        }
        else
        {
            while ( fgets( line, MAX_CONFIG_LINE, file ) != NULL )
            {
                if ( regexec( &nameserver, line, SUB_MATCH, submatch, 0 ) == 0 )
                    continue;

                // line isn't a nameserver, adding it to the temp file
                fputs( line, new_file );
            }

            // add all new nameservers
            dns = strtok( dns_list, "," );
            while ( dns != NULL )
            {
                sprintf( line, "nameserver %s\n", dns );
                // check that resulted line syntax is correct
                if ( regexec( &nameserver, line, SUB_MATCH, submatch, 0 ) == 0 )
                {
                    fputs( line, new_file );
                }
                else
                {
                    InvalidArgs( ca_event );
                    break;
                }
                dns = strtok( NULL, "," );
            }

            if ( ca_event->ErrCode == 0 )
            {
                // operation was successful
                // replace the real file with our temp file
                if ( remove( g_vars.resolvConf ) )
                {
                    trace( 1, "SetDNSServer: removing resolv.conf failed: '%s'.", g_vars.resolvConf );
                    addErrorData( ca_event, 501, "Action Failed" );
                }
                if ( rename( RESOLV_CONF_TMP, g_vars.resolvConf ) )
                {
                    trace( 1, "SetDNSServer: renaming resolv.conf failed, old: '%s' new '%s'.", RESOLV_CONF_TMP, g_vars.resolvConf );
                    addErrorData( ca_event, 501, "Action Failed" );
                }
            }
        }
    }
    else
        InvalidArgs( ca_event );

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    regfree( &nameserver );
    if ( file ) fclose( file );
    if ( new_file ) fclose( new_file );
    free( dns_list );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: DeleteDNSServer.
 *
 * Deletes one dns server.
 * Opens resolv.conf file and a temp file. Copies everything except the deleted nameserver from original
 * file to the temp file. The temp file is copied over the original file.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int DeleteDNSServer( struct Upnp_Action_Request *ca_event )
{
    FILE *file = NULL, *new_file = NULL;
    char line[MAX_CONFIG_LINE];
    char dns[INET6_ADDRSTRLEN];
    char *dns_to_delete = NULL;
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];
    int dns_found = 0;

    if ( CheckDHCPServerConfigurable( ca_event ) )
        return ca_event->ErrCode;

    regcomp( &nameserver, REGEX_NAMESERVER, REG_EXTENDED );
    ca_event->ErrCode = 0;

    if ( ( dns_to_delete = GetFirstDocumentItem( ca_event->ActionRequest, "NewDNSServers" ) ) )
    {
        file = fopen( g_vars.resolvConf, "r" );
        new_file = fopen( RESOLV_CONF_TMP, "w" );
        if ( file == NULL || new_file == NULL )
        {
            if ( file == NULL )
                trace( 1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf );
            if ( new_file == NULL )
                trace( 1, "Failed to open temp resolv.conf: %s.", RESOLV_CONF_TMP );

            addErrorData( ca_event, 501, "Action Failed" );
        }
        else
        {
            while ( fgets( line, MAX_CONFIG_LINE, file ) != NULL )
            {
                if ( regexec( &nameserver, line, SUB_MATCH, submatch, 0 ) == 0 )
                {
                    // nameserver found, get it
                    strncpy( dns, &line[submatch[1].rm_so], min( submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN ) );
                    dns[min( submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN-1 )] = 0;

                    // if this one needs to be deleted, then continue while loop
                    if ( strncmp( dns, dns_to_delete, INET6_ADDRSTRLEN ) == 0 )
                    {
                        dns_found = 1;
                        continue;
                    }
                }
                // line isn't a nameserver or not the nameserver we want to delete, adding it to the temp file
                fputs( line, new_file );
            }

            if ( dns_found )
            {
                // operation was successful
                // replace the real file with our temp file
                if ( remove( g_vars.resolvConf ) )
                {
                    trace( 1, "DeleteDNSServer: removing resolv.conf failed: '%s'.", g_vars.resolvConf );
                    addErrorData( ca_event, 501, "Action Failed" );
                }
                if ( rename( RESOLV_CONF_TMP, g_vars.resolvConf ) )
                {
                    trace( 1, "DeleteDNSServer: renaming resolv.conf failed, old: '%s' new '%s'.", RESOLV_CONF_TMP, g_vars.resolvConf );
                    addErrorData( ca_event, 501, "Action Failed" );
                }
            }
            else
            {
                trace( 2, "DeleteDNSServer: dns server not found: '%s'.", dns_to_delete );
                addErrorData( ca_event, 702, "ValueSpecifiedIsInvalid" );
            }
        }
    }
    else
        InvalidArgs( ca_event );

    if ( ca_event->ErrCode == 0 )
        ParseResult( ca_event, "" );

    regfree( &nameserver );
    if ( file ) fclose( file );
    if ( new_file ) fclose( new_file );
    free( dns_to_delete );

    return ca_event->ErrCode;
}

/**
 * LANHostConfigManagement:1 Action: GetDNSServers.
 *
 * Returns all dns servers as a comma separated list.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetDNSServers( struct Upnp_Action_Request *ca_event )
{
    FILE *file;
    char dns_servers[RESULT_LEN];
    char line[MAX_CONFIG_LINE];
    char dns[INET6_ADDRSTRLEN];
    regex_t nameserver;
    regmatch_t submatch[SUB_MATCH];
    int dns_place = 0;

    dns_servers[0] = 0;

    regcomp( &nameserver, REGEX_NAMESERVER, REG_EXTENDED );

    file = fopen( g_vars.resolvConf, "r" );
    if ( file == NULL )
    {
        trace( 1, "Failed to open resolv.conf at: %s.", g_vars.resolvConf );
        addErrorData( ca_event, 501, "Action Failed" );
        return ca_event->ErrCode;
    }

    while ( fgets( line, MAX_CONFIG_LINE, file ) != NULL )
    {
        if ( regexec( &nameserver, line, SUB_MATCH, submatch, 0 ) == 0 )
        {
            // nameserver found, get it and add to list
            // if this is not the first dns server, add comma
            if ( dns_place > 0 )
                dns_place += snprintf( &dns_servers[dns_place], RESULT_LEN - dns_place, "," );

            strncpy( dns, &line[submatch[1].rm_so], min( submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN ) );
            dns[min( submatch[1].rm_eo-submatch[1].rm_so, INET6_ADDRSTRLEN-1 )] = 0;
            dns_place += snprintf( &dns_servers[dns_place], RESULT_LEN - dns_place, "%s", dns );
        }
    }

    ParseResult( ca_event, "<NewDNSServers>%s</NewDNSServers>\n", dns_servers );

    regfree( &nameserver );
    fclose( file );

    return ca_event->ErrCode;
}

/**
 * Checks that all necessary programs for lanhostconfig are installed.
 * 
 * @return 1 on failure, 0 on success.
 */
int CheckLanHostConfigFiles()
{
    struct stat buf;

    // check that dnsmasq exists
    if ( stat( g_vars.dnsmasqCmd, &buf ) )
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace( 1, "DHCPServerConfigurable set to false, dnsmasq not found at: %s.", g_vars.dnsmasqCmd );
        return 1;
    }
    // check that uci exists
    if ( stat( g_vars.uciCmd, &buf ) )
    {
        lanHostConfig.DHCPServerConfigurable = FALSE;
        trace( 1, "DHCPServerConfigurable set to false, uci not found at: %s.", g_vars.uciCmd );
        return 1;
    }

    return 0;
}

/**
 * Checks that all required programs are present.
 *
 * @return 0 on success. 1 when LanHostConfig can't be used.
 */
int InitLanHostConfig()
{
    lanHostConfig.DHCPServerConfigurable = TRUE;
    lanHostConfig.dhcrelay = FALSE;

    // check that all necessary programs to run lanhostconfig are installed
    if(CheckLanHostConfigFiles())
        return 1;

    /** @todo We should save the state of dhcrelay and dnsmasq and start/stop them based on that. */

    DhcrelayStop();
    DnsmasqCommand( SERVICE_STOP );

    DnsmasqCommand( SERVICE_START );

    return 0;
}

/**
 * Free reserved memory.
 */
void FreeLanHostConfig()
{

}
