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
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <upnp/upnp.h>
#include "globals.h"
#include "config.h"
#include "pmlist.h"
#include "gatedevice.h"
#include "util.h"

#if HAVE_LIBIPTC
#include "iptc.h"
#endif

/**
 * Create new portMap struct of rule to add iptables. 
 * portMap-struct is internal presentation of iptables rule in IGD. 
 *
 * @param enabled Is rule enabled.
 * @param duration How long portmapping should exist.
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param internalPort The local TCP or UDP port number of the client.
 * @param protocol Portmapping protocol, either TCP or UDP.
 * @param internalClient The local IP address of the client.
 * @param desc Textual description of portmapping.
 * @return Pointer to newly created portMap-struct.
 */
struct portMap* pmlist_NewNode(int enabled, long int duration, char *remoteHost,
                                           char *externalPort, char *internalPort,
                                           char *protocol, char *internalClient, char *desc)
{
    struct portMap* temp = (struct portMap*) malloc(sizeof(struct portMap));

    temp->m_PortMappingEnabled = enabled;

    if (remoteHost && strlen(remoteHost) < sizeof(temp->m_RemoteHost)) strcpy(temp->m_RemoteHost, remoteHost);
    else strcpy(temp->m_RemoteHost, "");
    if (strlen(externalPort) < sizeof(temp->m_ExternalPort)) strcpy(temp->m_ExternalPort, externalPort);
    else strcpy(temp->m_ExternalPort, "");
    if (strlen(internalPort) < sizeof(temp->m_InternalPort)) strcpy(temp->m_InternalPort, internalPort);
    else strcpy(temp->m_InternalPort, "");
    if (strlen(protocol) < sizeof(temp->m_PortMappingProtocol)) strcpy(temp->m_PortMappingProtocol, protocol);
    else strcpy(temp->m_PortMappingProtocol, "");
    if (strlen(internalClient) < sizeof(temp->m_InternalClient)) strcpy(temp->m_InternalClient, internalClient);
    else strcpy(temp->m_InternalClient, "");
    if (strlen(desc) < sizeof(temp->m_PortMappingDescription)) strcpy(temp->m_PortMappingDescription, desc);
    else strcpy(temp->m_PortMappingDescription, "");
    temp->m_PortMappingLeaseDuration = duration;

    temp->next = NULL;
    temp->prev = NULL;

    return temp;
}

/**
 * Search if portmapping with given parameters exist in IGD's portmapping list. 
 * Starts searching from the beginning of list. 
 *
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network. If empty string, then it is assumed as wildcarded address and matches all addresses.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param proto Portmapping protocol, either TCP or UDP.
 * @param internalClient The local IP address of the client.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_Find(char * remoteHost, char *externalPort, char *proto, char *internalClient)
{
    struct portMap* temp;

    temp = pmlist_Head;
    if (temp == NULL)
        return NULL;
    do
    {
        if ( (strcmp(temp->m_RemoteHost, remoteHost) == 0) &&
                (strcmp(temp->m_ExternalPort, externalPort) == 0) &&
                (strcmp(temp->m_PortMappingProtocol, proto) == 0) &&
                (strcmp(temp->m_InternalClient, internalClient) == 0) )
            return temp; // We found a match, return pointer to it
        else
            temp = temp->next;
    }
    while (temp != NULL);

    // If we made it here, we didn't find it, so return NULL
    return NULL;
}

/**
 * Search if portmapping with given parameters exist in IGD's portmapping list. 
 * Starts searching from the beginning of list. 
 *
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param proto Portmapping protocol, either TCP or UDP.
 * @param internalClient The local IP address of the client.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_FindBy_extPort_proto_intClient(char *externalPort, char *proto, char *internalClient)
{
    struct portMap* temp;

    temp = pmlist_Head;
    if (temp == NULL)
        return NULL;
    do
    {
        if  (  (strcmp(temp->m_ExternalPort, externalPort) == 0) &&
               (strcmp(temp->m_PortMappingProtocol, proto) == 0) &&
               (strcmp(temp->m_InternalClient, internalClient) == 0) )
            return temp; // We found a match, return pointer to it
        else
            temp = temp->next;
    }
    while (temp != NULL);

    // If we made it here, we didn't find it, so return NULL
    return NULL;
}

/**
 * Search if portmapping with given parameters exist in IGD's portmapping list. 
 * Starts searching from the beginning of list. 
 *
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param proto Portmapping protocol, either TCP or UDP.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_FindBy_extPort_proto(char *externalPort, char *proto)
{
    struct portMap* temp;

    temp = pmlist_Head;
    if (temp == NULL)
        return NULL;
    do
    {
        if  (  (strcmp(temp->m_ExternalPort, externalPort) == 0) &&
               (strcmp(temp->m_PortMappingProtocol, proto) == 0) )
            return temp; // We found a match, return pointer to it
        else
            temp = temp->next;
    }
    while (temp != NULL);

    // If we made it here, we didn't find it, so return NULL
    return NULL;
}

/**
 * Fetch portmapping from given index in portmapping list. 
 *
 * @param index Index of searched portmapping. 0 is first.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_FindByIndex(int index)
{
    int i=0;
    struct portMap* temp;

    temp = pmlist_Head;
    if (temp == NULL)
        return NULL;
    do
    {
        if (i == index)
            return temp;
        else
        {
            temp = temp->next;
            i++;
        }
    }
    while (temp != NULL);

    return NULL;
}

/**
 * Search if portmapping matching given parameters exist in IGD's portmapping list. 
 * Starts searching from the beginning of list. 
 *
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network. If empty string, then it is assumed as wildcarded address and matches all addresses.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param protocol Portmapping protocol, either TCP or UDP.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_FindSpecific(char * remoteHost, char *externalPort, char *protocol)
{
    struct portMap* temp;

    temp = pmlist_Head;
    if (temp == NULL)
        return NULL;

    do
    {
        if ( (strcmp(temp->m_RemoteHost, remoteHost) == 0) &&
                (strcmp(temp->m_ExternalPort, externalPort) == 0) &&
                (strcmp(temp->m_PortMappingProtocol, protocol) == 0))
            return temp;
        else
            temp = temp->next;
    }
    while (temp != NULL);

    return NULL;
}

/**
 * Search if portmapping matching given parameters exist in IGD's portmapping list. 
 * Starts searching from the given index of list. 
 *
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network. If empty string, then it is assumed as wildcarded address and matches all addresses.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param protocol Portmapping protocol, either TCP or UDP.
 * @param index Index of portmapping list where searching is started from.
 * @return Pointer to found portmapping. If portmapping is not found, return NULL.
 */
struct portMap* pmlist_FindSpecificAfterIndex(char * remoteHost, char *externalPort, char *protocol, int index)
{
    struct portMap* temp;

    if ((index >= pmlist_Size()) || (index < 0))
        return NULL;

    temp = pmlist_FindByIndex(index);
    if (temp == NULL)
        return NULL;

    do
    {
        if ( (strcmp(temp->m_RemoteHost, remoteHost) == 0) &&
                (strcmp(temp->m_ExternalPort, externalPort) == 0) &&
                (strcmp(temp->m_PortMappingProtocol, protocol) == 0))
            return temp;
        else
            temp = temp->next;
    }
    while (temp != NULL);

    return NULL;
}

/**
 * Search for next free external_port between ports 1024 and 9999.
 * 
 * @param protocol Next free portnumber of which protocol is searched.
 * @return Next free portnumber of given protocol or -1 if no ports are free.
 */
int pmlist_FindNextFreePort(char *protocol)
{
    // Iteratively search for free port...
    // lousy implementation....
    int i;
    int freePort = -1;
    char portBuf[5];

    struct portMap* temp;

    for (i = 1024; i < 9999; i++) 
    {   
	sprintf(portBuf, "%d", i);
	temp = pmlist_FindBy_extPort_proto(portBuf, protocol);
        if (temp == NULL) {
	   freePort = i;
	   break;
	}
    }
   
    return freePort;	
}

/**
 *  Find next port mapping in port range. If internal_client value is empty string, then it is treated as wildcard
 *  and all internal client values matches.
 * 
 * @param start_port Lower limit for port value in portmappings included in search.
 * @param end_port Upper limit for port value in portmappings included in search.
 * @param protocol Protocol of portmapping searched.
 * @param internal_client Internal client IP value.
 * @param pm Portmapping from where searching is started in list.
 * @return Portmapping matching parameters or NULL if none found.
 */
struct portMap* pmlist_FindRangeAfter(int start_port, int end_port, char *protocol, char *internal_client, struct portMap *pm)
{
    if (pmlist_Head == NULL)
        return NULL;

    // start from head if pm is null, otherwise start from next
    if (pm == NULL)
        pm = pmlist_Head;
    else
        pm = pm->next;

    while( pm != NULL )
    {
        if ( ((strcmp(pm->m_InternalClient, internal_client) == 0) || (strcmp(internal_client, "") == 0)) &&
             (strcmp(pm->m_PortMappingProtocol, protocol) == 0) &&
               atoi(pm->m_ExternalPort) >= start_port &&
               atoi(pm->m_ExternalPort) <= end_port)
            return pm;

        pm = pm->next;
    }

    return NULL;
}

/**
 * Check if portmapping list is empty.
 * 
 * @return 0 if not empty, 1 if is empty.
 */
int pmlist_IsEmtpy(void)
{
    if (pmlist_Head)
        return 0;
    else
        return 1;
}

/**
 * Count how many portmappings there is in IGD's portmapping list.
 * 
 * @return Size of portmapping list.
 */
int pmlist_Size(void)
{
    struct portMap* temp;
    int size = 0;

    temp = pmlist_Head;
    if (temp == NULL)
        return 0;

    while (temp->next)
    {
        size++;
        temp = temp->next;
    }
    size++;
    return size;
}

/**
 * Delete all pormappings from portmapping list and from iptables.
 * 
 * @return 1 allways.
 */
int pmlist_FreeList(void)
{
    struct portMap *temp, *next;

    temp = pmlist_Head;
    while (temp)
    {
        CancelMappingExpiration(temp->expirationEventId);
        pmlist_DeletePortMapping(temp->m_PortMappingEnabled, temp->m_RemoteHost, temp->m_PortMappingProtocol,
                                 temp->m_ExternalPort, temp->m_InternalClient, temp->m_InternalPort);
        next = temp->next;
        free(temp);
        temp = next;
    }
    pmlist_Head = pmlist_Tail = NULL;
    return 1;
}

/**
 * Append new portmapping node at the end of portmapping list and
 * add portmaping into iptables with pmlist_AddPortMapping.
 * 
 * @param item Portmapping struct which is added into list.
 * @return 1 if addition succeeded, 0 if failed.
 */
int pmlist_PushBack(struct portMap* item)
{
    int action_succeeded = 0;

    if (pmlist_Tail) // We have a list, place on the end
    {
        pmlist_Tail->next = item;
        item->prev = pmlist_Tail;
        item->next = NULL;
        pmlist_Tail = item;
        action_succeeded = 1;
    }
    else // We obviously have no list, because we have no tail :D
    {
        pmlist_Head = pmlist_Tail = pmlist_Current = item;
        item->prev = NULL;
        item->next = NULL;
        action_succeeded = 1;
        trace(3, "appended %d %s %s %s %s %s %ld", item->m_PortMappingEnabled,
              item->m_PortMappingProtocol, item->m_RemoteHost, item->m_ExternalPort, item->m_InternalClient,
              item->m_InternalPort, item->m_PortMappingLeaseDuration);
    }
    if (action_succeeded == 1)
    {
        pmlist_AddPortMapping(item->m_PortMappingEnabled, item->m_PortMappingProtocol, item->m_RemoteHost,
                              item->m_ExternalPort, item->m_InternalClient, item->m_InternalPort);
        return 1;
    }
    else
        return 0;
}

/**
 * Delete portmapping node from portmapping list.
 * 
 * @param item Portmapping struct which is deleted from list.
 * @return 1 if deleting succeeded, 0 if failed.
 */
int pmlist_Delete(struct portMap* item)
{
    struct portMap *temp;
    int action_succeeded = 0;

    temp = pmlist_Find(item->m_RemoteHost, item->m_ExternalPort, item->m_PortMappingProtocol, item->m_InternalClient);
    if (temp) // We found the item to delete
    {
        CancelMappingExpiration(temp->expirationEventId);
        pmlist_DeletePortMapping(item->m_PortMappingEnabled, item->m_RemoteHost, item->m_PortMappingProtocol,
                                 item->m_ExternalPort, item->m_InternalClient, item->m_InternalPort);
        if (temp == pmlist_Head) // We are the head of the list
        {
            if (temp->next == NULL) // We're the only node in the list
            {
                pmlist_Head = pmlist_Tail = pmlist_Current = NULL;
                free (temp);
                action_succeeded = 1;
            }
            else // we have a next, so change head to point to it
            {
                pmlist_Head = temp->next;
                pmlist_Head->prev = NULL;
                free (temp);
                action_succeeded = 1;
            }
        }
        else if (temp == pmlist_Tail) // We are the Tail, but not the Head so we have prev
        {
            pmlist_Tail = pmlist_Tail->prev;
            free (pmlist_Tail->next);
            pmlist_Tail->next = NULL;
            action_succeeded = 1;
        }
        else // We exist and we are between two nodes
        {
            temp->prev->next = temp->next;
            temp->next->prev = temp->prev;
            pmlist_Current = temp->next; // We put current to the right after a extraction
            free (temp);
            action_succeeded = 1;
        }
    }
    else  // We're deleting something that's not there, so return 0
        action_succeeded = 0;

    return action_succeeded;
}

/**
 * Delete portmapping node in given index from portmapping list.
 * 
 * @param index Index of portmapping which is deleted from list.
 * @return 1 if deleting succeeded, 0 if failed.
 */
int pmlist_DeleteIndex(int index)
{
    struct portMap *temp;
    int action_succeeded = 0;

    temp = pmlist_FindByIndex(index);
    if (temp) // We found the item to delete
    {
        CancelMappingExpiration(temp->expirationEventId);
        pmlist_DeletePortMapping(temp->m_PortMappingEnabled, temp->m_RemoteHost, temp->m_PortMappingProtocol,
                                 temp->m_ExternalPort, temp->m_InternalClient, temp->m_InternalPort);
        if (temp == pmlist_Head) // We are the head of the list
        {
            if (temp->next == NULL) // We're the only node in the list
            {
                pmlist_Head = pmlist_Tail = pmlist_Current = NULL;
                free (temp);
                action_succeeded = 1;
            }
            else // we have a next, so change head to point to it
            {
                pmlist_Head = temp->next;
                pmlist_Head->prev = NULL;
                free (temp);
                action_succeeded = 1;
            }
        }
        else if (temp == pmlist_Tail) // We are the Tail, but not the Head so we have prev
        {
            pmlist_Tail = pmlist_Tail->prev;
            free (pmlist_Tail->next);
            pmlist_Tail->next = NULL;
            action_succeeded = 1;
        }
        else // We exist and we are between two nodes
        {
            temp->prev->next = temp->next;
            temp->next->prev = temp->prev;
            pmlist_Current = temp->next; // We put current to the right after a extraction
            free (temp);
            action_succeeded = 1;
        }
    }
    else  // We're deleting something that's not there, so return 0
        action_succeeded = 0;

    return action_succeeded;
}

/**
 * Add new portmapping rule in iptables.
 * Use either libiptc or iptables commandline command for adding.
 * 
 * @param enabled Is rule enabled. Rule is added only if it is enabled (1).
 * @param protocol Portmapping protocol, either TCP or UDP.
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param internalClient The local IP address of the client.
 * @param internalPort The local TCP or UDP port number of the client.
 * @return 1 if addition succeeded, 0 if failed.
 */
int pmlist_AddPortMapping (int enabled, char *protocol, char *remoteHost, char *externalPort, char *internalClient, char *internalPort)
{
    if (enabled)
    {
        //check if remoteHost is empty string then remoteHost = NULL
        if (strcmp(remoteHost, "") == 0) remoteHost = NULL;

        char dest[DEST_LEN];
        snprintf(dest, DEST_LEN, "%s:%s", internalClient, internalPort);

#if HAVE_LIBIPTC
        char *buffer = malloc(strlen(internalClient) + strlen(internalPort) + 2);
        if (buffer == NULL)
        {
            fprintf(stderr, "failed to malloc memory\n");
            return 0;
        }

        if (g_vars.createForwardRules)
        {
            trace(3, "iptc_add_rule %s %s %s %s %s %s %s %s",
                  "filter", g_vars.forwardChainName, protocol, remoteHost, internalClient, internalPort, "ACCEPT",
                  g_vars.forwardRulesAppend ? "APPEND" : "INSERT");
            iptc_add_rule("filter", g_vars.forwardChainName, protocol, NULL, NULL, remoteHost, internalClient, NULL, internalPort, "ACCEPT", NULL, g_vars.forwardRulesAppend ? TRUE : FALSE);
        }
        trace(3, "iptc_add_rule %s %s %s %s %s %s %s %s %s",
              "nat", g_vars.preroutingChainName, protocol, g_vars.extInterfaceName, remoteHost, externalPort, "DNAT", dest, "APPEND");
        iptc_add_rule("nat", g_vars.preroutingChainName, protocol, g_vars.extInterfaceName, NULL, remoteHost, NULL, NULL, externalPort, "DNAT", dest, TRUE);
#else
        int status;
        char *args[18];

        if (g_vars.createForwardRules)
        {
            if (remoteHost) {
                args[0] = g_vars.iptables;
                args[1] = g_vars.forwardRulesAppend ? "-A" : "-I";
                args[2] = g_vars.forwardChainName;
                args[3] = "-s";
                args[4] = remoteHost;
                args[5] = "-p";
                args[6] = protocol;
                args[7] = "-d";
                args[8] = internalClient;
                args[9] = "--dport";
                args[10] = internalPort;
                args[11] = "-j";
                args[12] = "ACCEPT";
                args[13] =  NULL;

                trace(3, "%s %s %s -s %s -p %s -d %s --dport %s -j ACCEPT",
                      g_vars.iptables,g_vars.forwardRulesAppend ? "-A" : "-I",g_vars.forwardChainName, remoteHost, protocol, internalClient, internalPort);

            }
            else {
                args[0] = g_vars.iptables;
                args[1] = g_vars.forwardRulesAppend ? "-A" : "-I";
                args[2] = g_vars.forwardChainName;
                args[3] = "-p";
                args[4] = protocol;
                args[5] = "-d";
                args[6] = internalClient;
                args[7] = "--dport";
                args[8] = internalPort;
                args[9] = "-j";
                args[10] = "ACCEPT";
                args[11] =  NULL;

                trace(3, "%s %s %s -p %s -d %s --dport %s -j ACCEPT",
                      g_vars.iptables,g_vars.forwardRulesAppend ? "-A" : "-I",g_vars.forwardChainName, protocol, internalClient, internalPort);
            }

            if (!fork())
            {
                int rc = execv(g_vars.iptables, args);
                exit(rc);
            }
            else
            {
                wait(&status);
            }
        }

        // Pre routing
        if (remoteHost) {
            args[0] = g_vars.iptables;
            args[1] = "-t";
            args[2] = "nat";
            args[3] = "-A";
            args[4] = g_vars.preroutingChainName;
            args[5] = "-i";
            args[6] = g_vars.extInterfaceName;
            args[7] = "-s";
            args[8] = remoteHost;
            args[9] = "-p";
            args[10] = protocol;
            args[11] = "--dport";
            args[12] = externalPort;
            args[13] = "-j";
            args[14] = "DNAT";
            args[15] = "--to";
            args[16] = dest;
            args[17] = NULL;

            trace(3, "%s -t nat -A %s -i %s -s %s -p %s --dport %s -j DNAT --to %s",
                  g_vars.iptables, g_vars.preroutingChainName, g_vars.extInterfaceName, remoteHost, protocol, externalPort, dest);
        }
        else {
            args[0] = g_vars.iptables;
            args[1] = "-t";
            args[2] = "nat";
            args[3] = "-A";
            args[4] = g_vars.preroutingChainName;
            args[5] = "-i";
            args[6] = g_vars.extInterfaceName;
            args[7] = "-p";
            args[8] = protocol;
            args[9] = "--dport";
            args[10] = externalPort;
            args[11] = "-j";
            args[12] = "DNAT";
            args[13] = "--to";
            args[14] = dest;
            args[15] = NULL;

            trace(3, "%s -t nat -A %s -i %s -p %s --dport %s -j DNAT --to %s",
                  g_vars.iptables, g_vars.preroutingChainName, g_vars.extInterfaceName, protocol, externalPort, dest);
        }

        if (!fork())
        {
            int rc = execv(g_vars.iptables, args);
            exit(rc);
        }
        else
        {
            wait(&status);
        }

#endif
    }
    return 1;
}

/**
 * Add new portmapping rule in iptables.
 * Use either libiptc or iptables commandline command for adding.
 * 
 * @param enabled Is rule enabled. Rule is deleted only if it is enabled (1).
 * @param remoteHost WAN IP address (destination) of connections initiated by a client in the local network.
 * @param protocol Portmapping protocol, either TCP or UDP.
 * @param externalPort TCP or UDP port number of the Client as seen by the remote host.
 * @param internalClient The local IP address of the client.
 * @param internalPort The local TCP or UDP port number of the client.
 * @return 1 allways.
 */
int pmlist_DeletePortMapping(int enabled, char *remoteHost, char *protocol, char *externalPort, char *internalClient, char *internalPort)
{
    if (enabled)
    {
        //check if remoteHost is empty string then remoteHost = NULL
        if (strcmp(remoteHost, "") == 0) remoteHost = NULL;

        char dest[DEST_LEN];
        snprintf(dest, DEST_LEN, "%s:%s", internalClient, internalPort);

#if HAVE_LIBIPTC
        trace(3, "iptc_delete_rule %s %s %s %s %s %s %s %s",
              "nat", g_vars.preroutingChainName, protocol, g_vars.extInterfaceName, remoteHost, externalPort, "DNAT", dest);
        iptc_delete_rule("nat", g_vars.preroutingChainName, protocol, g_vars.extInterfaceName, NULL, remoteHost, NULL, NULL, externalPort, "DNAT", dest);
        if (g_vars.createForwardRules)
        {
            trace(3, "iptc_delete_rule %s %s %s %s %s %s %s",
                  "filter", g_vars.forwardChainName, protocol, remoteHost, internalClient, internalPort, "ACCEPT");
            iptc_delete_rule("filter", g_vars.forwardChainName, protocol, NULL, NULL, remoteHost, internalClient, NULL, internalPort, "ACCEPT", NULL);
        }
#else
        int status;
        char *args[18];

        if (remoteHost) {
            args[0] = g_vars.iptables;
            args[1] = "-t";
            args[2] = "nat";
            args[3] = "-D";
            args[4] = g_vars.preroutingChainName;
            args[5] = "-i";
            args[6] = g_vars.extInterfaceName;
            args[7] = "-s";
            args[8] = remoteHost;
            args[9] = "-p";
            args[10] = protocol;
            args[11] = "--dport";
            args[12] = externalPort;
            args[13] = "-j";
            args[14] = "DNAT";
            args[15] = "--to";
            args[16] = dest;
            args[17] = NULL;

            trace(3, "%s -t nat -D %s -i %s -s %s -p %s --dport %s -j DNAT --to %s",
                  g_vars.iptables, g_vars.preroutingChainName, g_vars.extInterfaceName, remoteHost, protocol, externalPort, dest);
        }
        else {
            args[0] = g_vars.iptables;
            args[1] = "-t";
            args[2] = "nat";
            args[3] = "-D";
            args[4] = g_vars.preroutingChainName;
            args[5] = "-i";
            args[6] = g_vars.extInterfaceName;
            args[7] = "-p";
            args[8] = protocol;
            args[9] = "--dport";
            args[10] = externalPort;
            args[11] = "-j";
            args[12] = "DNAT";
            args[13] = "--to";
            args[14] = dest;
            args[15] = NULL;

            trace(3, "%s -t nat -D %s -i %s -p %s --dport %s -j DNAT --to %s",
                  g_vars.iptables, g_vars.preroutingChainName, g_vars.extInterfaceName, protocol, externalPort, dest);
        }

        if (!fork())
        {
            int rc = execv(g_vars.iptables, args);
            exit(rc);
        }
        else
        {
            wait(&status);
        }

        if (g_vars.createForwardRules)
        {
            if (remoteHost) {
                args[0] = g_vars.iptables;
                args[1] = "-D";
                args[2] = g_vars.forwardChainName;
                args[3] = "-s";
                args[4] = remoteHost;
                args[5] = "-p";
                args[6] = protocol;
                args[7] = "-d";
                args[8] = internalClient;
                args[9] = "--dport";
                args[10] = internalPort;
                args[11] = "-j";
                args[12] = "ACCEPT";
                args[13] =  NULL;

                //char *args[] = {g_vars.iptables, "-D", g_vars.forwardChainName, "-p", protocol, "-d", internalClient, "--dport", internalPort, "-j", "ACCEPT", NULL};

                trace(3, "%s -D %s -s %s -p %s -d %s --dport %s -j ACCEPT",
                          g_vars.iptables, g_vars.forwardChainName, remoteHost, protocol, internalClient, internalPort);
             }
             else {
                args[0] = g_vars.iptables;
                args[1] = "-D";
                args[2] = g_vars.forwardChainName;
                args[3] = "-p";
                args[4] = protocol;
                args[5] = "-d";
                args[6] = internalClient;
                args[7] = "--dport";
                args[8] = internalPort;
                args[9] = "-j";
                args[10] = "ACCEPT";
                args[11] =  NULL;

                trace(3, "%s -D %s -p %s -d %s --dport %s -j ACCEPT",
                          g_vars.iptables, g_vars.forwardChainName, protocol, internalClient, internalPort);
             }

            if (!fork())
            {
                int rc = execv(g_vars.iptables, args);
                exit(rc);
            }
            else
            {
                wait(&status);
            }
        }
#endif
    }
    return 1;
}
