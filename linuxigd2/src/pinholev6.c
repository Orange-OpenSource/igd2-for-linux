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

#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <upnp/TimerThread.h>
#include <upnp/upnpconfig.h>
#include <regex.h>
#include <sys/types.h>
#include <time.h>

#include "util.h"
#include "globals.h"
#include "gatedevice.h"
#include "pinholev6.h"

struct pinholev6 *ph_first;

static const char * add_rule_str = "ip6tables -I %s " //upnp forward chain
        "-i %s "        //input interface
        "-o %s "        //output interface
        "-s %s "        //source address
        "-d %s "        //destionation address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j ACCEPT";

static const char * add_rule_raw_str = "ip6tables -t raw -I PREROUTING "
        "-i %s "        //input interface
        "-s %s "        //source address
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j TRACE";

//no remote -> no source address in the rule
static const char * add_rule_no_remote_str = "ip6tables "
        "-I %s "        //upnp forward chain
        "-i %s "        //input interface
        "-o %s "        //output interface
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j ACCEPT";

static const char * add_rule_raw_no_remote_str = "ip6tables -t raw "
        "-I PREROUTING "
        "-i %s "        //input interface
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j TRACE";


static const char * del_rule_str = "ip6tables -D %s " //upnp forward chain
        "-i %s "        //input interface
        "-o %s "        //output interface
        "-s %s "        //source address
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j ACCEPT";

static const char * del_rule_raw_str = "ip6tables -t raw -D PREROUTING "
        "-i %s "        //input interface
        "-s %s "        //source address
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j TRACE";

static const char * del_rule_no_remote_str = "ip6tables "
        "-D %s "        //upnp forward chain
        "-i %s "        //input interface
        "-o %s "        //output interface
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j ACCEPT";

static const char * del_rule_raw_no_remote_str = "ip6tables -t raw "
        "-D PREROUTING "
        "-i %s "        //input interface
        "-d %s "        //destination address
        "-p %i "        //protocol
        "--sport %i "   //source port
        "--dport %i "   //destination port
        "-j TRACE";

/**
 * PRIVATE FUNCTIONS
 */

extern ithread_mutex_t DevMutex;

int phv6_scheduleExpiration(struct pinholev6 *pinhole);

int phv6_cancelExpiration(struct pinholev6 *pinhole);


/**
 * this functions seeks an available id in the pinhole list
 *
 * @param pointer to the newly found unique id.
 * @return 1 if ok, 0 otherwise
 */
int findUniqueID(uint32_t * uniqueId)
{
    struct pinholev6 *pinhole;
    uint32_t candidate_id;

    pinhole = ph_first;
    candidate_id = 0;


    while(pinhole != NULL)
    {
        if(pinhole->unique_id == candidate_id) {
            candidate_id++;
            if (candidate_id == 0) {
                //integer overflow, no Unique ID available
                return 0;
            }
            pinhole = ph_first;
        }
        else pinhole = pinhole->next;
    }

    *uniqueId = candidate_id;

    return 1;

}

/**
 * -----------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 * -----------------------------------------------------------------------------
 */

/**
 * This functions initializes ip6tables and the pinhole list
 *
 * @return 1 if ok
 */
int phv6_init(void)
{
    //pinhole list initialization
    ph_first = NULL;
#ifdef UPNP_ENABLE_IPV6
    int rc;
    //string used for system commands
    char command[250];

    //the nf_conntrack module gives the outbound pinhole timeout information
    trace(3, "loading nf_conntrack module");
    rc = system("/sbin/modprobe nf_conntrack");

    //the ip6t_LOG module enables the "raw" table for ip6tables
    //this is useful for the checkpinholeworking action
    trace(3, "loading ip6t_LOG module");
    rc = system("/sbin/modprobe ip6t_LOG");

    trace(3, "ip6tables initialization");

    snprintf(command, 250, "ip6tables -I INPUT -p tcp --dport %i -j ACCEPT", UpnpGetServerPort6());
    rc = system(command);
    snprintf(command, 250, "ip6tables -I INPUT -p udp --dport %i -j ACCEPT", UpnpGetServerPort6());
    rc = system(command);
#endif

    return 1;
}



/**
 * This function closes ip6tables and free the pinhole list
 *
 * @return 1 if ok
 */
int phv6_close(void)
{
    //pinhole list deletion
    struct pinholev6 * pinhole;
    struct pinholev6 * p_delete = ph_first;
    //int rc;

    while(p_delete!=NULL)
    {
        pinhole = p_delete->next;
        phv6_cancelExpiration(p_delete);
        phv6_ip6table_deleteRule(p_delete->internal_client,
                p_delete->remote_host,
                p_delete->internal_port,
                p_delete->remote_port,
                p_delete->protocol);
        free(p_delete->internal_client);
        if(p_delete->remote_host != NULL) free(p_delete->remote_host);
        free(p_delete);
        p_delete = pinhole;
    }

    trace(3, "ip6tables reset");

    return 1;
}

/**
 * This function gives the rule number associated with the
 * given pinhole id in the ip6tables policies
 *
 * @param id the pinhole's unique id
 * @param lineNumber a pointer to an int that stores the line number
 * @return 1 if the pinhole is found, 0 otherwise
 */
int phv6_findLineNumber(uint32_t id, int * lineNumber)
{
    struct pinholev6 *p;
    //the rule number begins at 1
    int index = 1;

    p = ph_first;

    //as the newest pinhole are inserted at the beginning of queue
    //the index is the depth of the pinhole in the queue
    while( p != NULL )
    {
        if( p->unique_id == id )
        {
            *lineNumber = index;
            return 1;
        }
        else
        {
            p = p->next;
        }
        index++;
    }

    return 0;
}

/**
 * This function gives the number of packets that went through
 * the given pinhole
 *
 * @param id the pinhole's unique id
 * @param packets a pointer to an int that stores the result
 * @return 1 if the pinhole has been found, 0 otherwise
 */
int phv6_getPinholePackets(uint32_t id, int * packets)
{
    int lineNumber;
    FILE * pipe;
    char command[100];
    char garbage[100];
    int rc;

    if(phv6_findLineNumber(id, &lineNumber))
    {
        trace(1, "line number : %i", lineNumber);
        snprintf(command, 100, "ip6tables -L %s %i -v -n -x",
                g_vars.ipv6forwardChain,
                lineNumber);
        pipe = popen(command, "r");
        rc = fscanf(pipe, "%i %s", packets, garbage);
        pclose(pipe);

        return 1;
    }

    return 0;
}

/**
 * This funtion seeks the pinhole according to the id given in parameter
 * if the pinhole is found, the pointer given in paramter is updated with the
 * pinhole
 *
 * @param the searched id
 * @param a pointer to the searched pinhole
 * @return 1 if found, 0 otherwise
 */
int phv6_findPinhole(uint32_t id, struct pinholev6 ** pinhole)
{
    struct pinholev6 *p;

    p = ph_first;

    while( p != NULL )
    {
        if( p->unique_id == id )
        {
            *pinhole = p;
            return 1;
        }
        else
        {
            p = p->next;
        }
    }

    return 0;

}

/**
 * This function verifies if the given pinhole already exists in the list
 *
 * @param internal_client A string representing the client address
 * @param remote_host A string representing the remote host
 * @param internal_port A string representing the internal port
 * @param remote_port A string representing the remote port
 * @param protocol A string representing the protocol
 * @param uniqueID An int pointer giving the uniqueid of the existing pinhole
 * @return 1 if true with the uniqueID value, 0 otherwise
 */
int phv6_existingPinhole(char *_internal_client,
        char *_remote_host,
        char *_internal_port,
        char *_remote_port,
        char *_protocol,
        uint32_t *uniqueID)
{
    struct pinholev6 *p = ph_first;
    struct in6_addr internal_client;
    struct in6_addr remote_host;
    uint16_t internal_port;
    uint16_t remote_port;
    uint16_t protocol;

    inet_pton(AF_INET6, _internal_client, &internal_client);
    inet_pton(AF_INET6, _remote_host, &remote_host);
    internal_port = atoi(_internal_port);
    remote_port = atoi(_remote_port);
    protocol = atoi(_protocol);

    while(p != NULL)
    {
        if((memcmp(p->internal_client, &internal_client, 16) == 0)
                && (p->internal_port == internal_port)
                && (p->remote_port == remote_port)
                && (p->protocol == protocol))
        {
            if(p->remote_host != NULL) {
                if(memcmp(p->remote_host, &remote_host, 16) == 0) {
                    *uniqueID = p->unique_id;
                    return 1;
                }
            }
            //wildcard case
            else if(strcmp(_remote_host, "") == 0) {
                *uniqueID = p->unique_id;
                return 1;
            }


        }
        p = p->next;
    }
    return 0;
}

/**
 * This functions adds a pinhole in the pinhole list
 *
 * @param internal_client A string representing the client address
 * @param remote_host A string representing the remote host
 * @param internal_port A string representing the internal port
 * @param remote_port A string representing the remote port
 * @param protocol A string representing the protocol
 * @param lease_time A unsigned integer giving the desired lease_time
 * @param uniqueId An int pointer giving the uniqueid of the existing pinhole
 * @return 1 if Ok, 0 otherwise. The new unique_id is given in the pointer
 */
int phv6_addPinhole(char *internal_client,
        char *remote_host,
        char *internal_port,
        char *remote_port,
        char *protocol,
        uint32_t lease_time,
        uint32_t *uniqueId)
{
    struct pinholev6 *p_new;

    //allocate the pinhole memory
    p_new = (struct pinholev6 *)malloc(sizeof(struct pinholev6));
    if(p_new == NULL) return -1;

    //copy the internal client address
    p_new->internal_client = (struct in6_addr *)malloc(sizeof(struct in6_addr));
    if(p_new->internal_client == NULL) {
        free(p_new);
        return -1;
    }
    inet_pton(AF_INET6, internal_client, p_new->internal_client);

    //copy the remote host address (if not wildcarded)
    if(strcmp(remote_host, "") != 0) {
        p_new->remote_host = (struct in6_addr *)malloc(sizeof(struct in6_addr));
        if(p_new->remote_host == NULL) {
            free(p_new->internal_client);
            free(p_new);
            return -1;
        }

        inet_pton(AF_INET6, remote_host, p_new->remote_host);
    }
    else p_new->remote_host = NULL;

    p_new->internal_port = atoi(internal_port);
    p_new->remote_port = atoi(remote_port);
    p_new->protocol = atoi(protocol);
    p_new->lease_time = lease_time;
    p_new->next = NULL;

    findUniqueID(&p_new->unique_id);
    *uniqueId = p_new->unique_id;

    if(ph_first == NULL)
    {
        ph_first = p_new;
    }
    else
    {
        //adding the new pinhole at the top of the queue
        p_new->next = ph_first;
        ph_first = p_new;
    }

    phv6_scheduleExpiration(p_new);
    phv6_ip6table_addRule(p_new->internal_client,
            p_new->remote_host,
            p_new->internal_port,
            p_new->remote_port,
            p_new->protocol);


    return 1;
}

/**
 * Deletes the pinhole which unique_id is given in parameter.
 *
 * @param id The unique id of the pinhole to delete
 * @return 1 if ok, 0 otherwise
 */
int phv6_deletePinhole(uint32_t id)
{
    struct pinholev6 *p;
    struct pinholev6 *p_delete;

    if(ph_first == NULL) return 0;

    //this case is when the first pinhole of the list is the targeted one
    if(ph_first->unique_id == id)
    {
        if(ph_first->event_id >= 0)
            phv6_cancelExpiration(ph_first);

        if(ph_first->next!= NULL)
        {
            p = ph_first->next;
            phv6_ip6table_deleteRule(ph_first->internal_client,
                    ph_first->remote_host,
                    ph_first->internal_port,
                    ph_first->remote_port,
                    ph_first->protocol);
            free(ph_first->internal_client);
            if(ph_first->remote_host != NULL) free(ph_first->remote_host);
            free(ph_first);
            ph_first = p;
        }
        else
        {
            phv6_ip6table_deleteRule(ph_first->internal_client,
                    ph_first->remote_host,
                    ph_first->internal_port,
                    ph_first->remote_port,
                    ph_first->protocol);

            free(ph_first->internal_client);
            if(ph_first->remote_host != NULL) free(ph_first->remote_host);
            free(ph_first);
            ph_first = NULL;
        }

        return 1;
    }

    p = ph_first;

    while(p->next != NULL)
    {
        if(p->next->unique_id == id)
        {
            //the pinhole has been found
            p_delete = p->next;
            p->next = p_delete->next;

            if(p_delete->event_id >= 0)
                phv6_cancelExpiration(p_delete);

            phv6_ip6table_deleteRule(p_delete->internal_client,
                    p_delete->remote_host,
                    p_delete->internal_port,
                    p_delete->remote_port,
                    p_delete->protocol);
            free(p_delete->internal_client);
            if(p_delete->remote_host != NULL) free(p_delete->remote_host);
            free(p_delete);
            return 1;
        }
        p = p->next;
    }

    return 0;
}

/**
 * Updates the pinhole given in parameter with the new lease time
 *
 * @param id The unique id of the pinhole to update
 * @param lease_time The new lease time
 * @return 1 if ok 0 otherwise.
 */
int phv6_updatePinhole(uint32_t id, uint32_t lease_time)
{
    struct pinholev6 * pinhole;

    if(phv6_findPinhole(id, &pinhole))
    {
        pinhole->lease_time = lease_time;
        phv6_cancelExpiration(pinhole);
        phv6_scheduleExpiration(pinhole);
        return 1;
    }

    return 0;
}

/**
 * adds a new rule in the IP6table configuration
 *
 * @param internal_client A string representing the client address
 * @param remote_host A string representing the remote host
 * @param internal_port A string representing the internal port
 * @param remote_port A string representing the remote port
 * @param protocol A string representing the protocol
 * @return 1 if Ok
 */
int phv6_ip6table_addRule(struct in6_addr *internal_client,
        struct in6_addr *remote_host,
        uint16_t internal_port,
        uint16_t remote_port,
        uint16_t protocol)
{

    //string used to pass ip6tables commands
    char command[250];
    int rc;

    //pinhole parameters. The remote host is tested
    //to see if it is wildcarded
    char internal_client_str[INET6_ADDRSTRLEN];
    char remote_host_str[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, internal_client,
            internal_client_str, INET6_ADDRSTRLEN);

    //not wildcard
    if (remote_host)
    {
        //add the firewall rule
        inet_ntop(AF_INET6, remote_host,
                remote_host_str, INET6_ADDRSTRLEN);

        snprintf(command, 250, add_rule_str,
                g_vars.ipv6forwardChain,
                g_vars.extInterfaceName,
                g_vars.intInterfaceName,
                remote_host_str,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);

        trace(3, command);

        //add the trace rule
        snprintf(command, 250, add_rule_raw_str,
                g_vars.extInterfaceName,
                remote_host_str,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);

        trace(3, command);

    }
    //remote host wildcarded
    else
    {
        snprintf(command, 250, add_rule_no_remote_str,
                g_vars.ipv6forwardChain,
                g_vars.extInterfaceName,
                g_vars.intInterfaceName,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

        snprintf(command, 250, add_rule_raw_no_remote_str,
                g_vars.extInterfaceName,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

    }

    return 1;
}

/**
 * Deletes a rule in ip6tables
 *
 * @param internal_client A string representing the client address
 * @param remote_host A string representing the remote host
 * @param internal_port A string representing the internal port
 * @param remote_port A string representing the remote port
 * @param protocol A string representing the protocol
 * @return 1 if Ok
 */
int phv6_ip6table_deleteRule(struct in6_addr *internal_client,
        struct in6_addr *remote_host,
        uint16_t internal_port,
        uint16_t remote_port,
        uint16_t protocol)
{


    char command[250];
    char internal_client_str[INET6_ADDRSTRLEN];
    char remote_host_str[INET6_ADDRSTRLEN];
    int rc;

    inet_ntop(AF_INET6, internal_client,
            internal_client_str, INET6_ADDRSTRLEN);

    if (remote_host)
    {
        inet_ntop(AF_INET6, remote_host,
                remote_host_str, INET6_ADDRSTRLEN);

        snprintf(command, 250, del_rule_str,
                g_vars.ipv6forwardChain,
                g_vars.extInterfaceName,
                g_vars.intInterfaceName,
                remote_host_str,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

        snprintf(command, 250, del_rule_raw_str,
                g_vars.extInterfaceName,
                remote_host_str,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

    }
    else
    {
        snprintf(command, 250, del_rule_no_remote_str,
                g_vars.ipv6forwardChain,
                g_vars.extInterfaceName,
                g_vars.intInterfaceName,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

        snprintf(command, 250, del_rule_raw_no_remote_str,
                g_vars.extInterfaceName,
                internal_client_str,
                protocol,
                remote_port,
                internal_port);

        rc = system(command);
        trace(3, command);

    }

    return 1;
}

/**
 * Set expiration event free.
 *
 * @param event Expiration event.
 */
void phv6_freeEvent(struct phv6_expirationEvent *event)
{
    if (event != NULL && event->pinhole !=NULL)
        event->pinhole->event_id = -1;
    free(event);
}

/**
 * This function makes a pinhole expires as its lease time is reached
 *
 * @param data Expiration event.
 */
void phv6_expiration(void *data)
{
    struct phv6_expirationEvent *event = ( struct phv6_expirationEvent * ) data;

    ithread_mutex_lock(&DevMutex);

    event->pinhole->event_id = -1;
    phv6_deletePinhole(event->pinhole->unique_id);
    phv6_freeEvent(event);

    ithread_mutex_unlock(&DevMutex);
}

/**
 * This function schedules the expiration when this pinhole is created or updated
 *
 * @param pinhole The pinhole to expire
 * @return the event_id created
 */
int phv6_scheduleExpiration(struct pinholev6 *pinhole)
{
    ThreadPoolJob job;
    struct phv6_expirationEvent *event;

    event = (struct phv6_expirationEvent *)malloc(
            sizeof(struct phv6_expirationEvent));
    if(event == NULL)
    {
        return 0;
    }

    event->pinhole = pinhole;

    TPJobInit( &job, ( start_routine ) phv6_expiration, event );
    TPJobSetFreeFunction( &job, ( free_routine ) phv6_freeEvent );

    if( TimerThreadSchedule(&gExpirationTimerThread,
            pinhole->lease_time,
            REL_SEC,
            &job,
            SHORT_TERM,
            &(event->event_id))
            != UPNP_E_SUCCESS )
    {
        free( event );
        return 0;
    }

    pinhole->event_id = event->event_id;

    return event->event_id;
}

/**
 * This function cancels the expiration when the pinhole is updated or deleted
 *
 * @param pinhole The pinhole to expire
 * @return 1 if Ok
 */
int phv6_cancelExpiration(struct pinholev6 * pinhole)
{
    ThreadPoolJob job;

    trace(1,"Canceling expiration for pinhole : %i",pinhole->unique_id);

    if( TimerThreadRemove(&gExpirationTimerThread,pinhole->event_id, &job)==0 )
    {
        phv6_freeEvent((struct phv6_expirationEvent *)job.arg);
    }
    else
    {
        trace(1,"  TimerThreadRemove failed!");
        return 0;
    }
    return 1;
}

/**
 * This function checks if a pinhole really manages the packets that have to be
 * treated by the pinhole given in parameter
 *
 * NB : this function does not literraly checks if the pinhole is working. This
 * function verifies if some traffic matching the pinhole parameters is
 * received by checking the data stored in /var/log/kern.log. Those data are generated
 * by the ip6t_LOG module. If some traffic is received, it checks that the last packet
 * matching the pinhole parameters passed through this pinhole. It the packets did so,
 * the function returns 1. If the packet passed through another rule, it will return 0.
 * If no traffic is detected, it returns -1.
 *
 * @param pinhole The pinhole to inspect
 * @return -1 No traffic detected
 * @return 0 Packet treated by another rule
 * @return 1 The Pinhole manages the packets
 */
int phv6_checkPinholeWorking(int pinhole_id)
{
    regex_t re_packet;
    regex_t re_rule;

    char regex_packet[512];
    char regex_rule[256];

    regmatch_t pmatch[4];
    time_t current_time = time(NULL);
    time_t old_time = current_time - 60;
    //60 sec before the action is called, traffic is detected
    //within 1 minute


    struct tm * cur_time_tm = malloc(sizeof(struct tm));
    struct tm * old_time_tm = malloc(sizeof(struct tm));

    char cur_time_str[100];
    char old_time_str[100];

    //this string is used to store the last occurence
    //of a matching packet
    char packet_line[1024];

    //the pinhole to check
    struct pinholev6 * pinhole = NULL;

    int rule = 0;

    char * protocol = "";

    char internal_client_str[INET6_ADDRSTRLEN];
    char remote_host_str[INET6_ADDRSTRLEN];

    struct in6_addr internal_client;
    struct in6_addr remote_host;

    FILE * log_file;

    phv6_findPinhole(pinhole_id, &pinhole);
    phv6_findLineNumber(pinhole_id, &rule);

    //processing the current time, and the curren_time - 60 sec
    localtime_r(&current_time,cur_time_tm);
    localtime_r(&old_time,old_time_tm);

    //building the regex for those times.
    strftime(cur_time_str, 100, "%b[[:blank:]]+%d[[:blank:]]+%H:%M", cur_time_tm);
    strftime(old_time_str, 100, "%b[[:blank:]]+%d[[:blank:]]+%H:%M", old_time_tm);

    if(pinhole->protocol == 6 ) protocol = "TCP";
    else if(pinhole->protocol == 17) protocol = "UDP";
    else if(pinhole->protocol == 136) protocol = "UDP_LITE";


    // The trace is as following :
    //Jul  2 16:31:38 r-lnx-bang000 kernel: [27793.027210]
    //TRACE: filter:FORWARD_upnp:rule:4 IN=eth0 OUT=eth1
    //SRC=3ffe:0000:0000:0000:0000:0000:0000:0004
    //DST=2032:0000:0000:0000:0000:0000:0000:0002
    //LEN=72 TC=0 HOPLIMIT=63 FLOWLBL=0 PROTO=TCP SPT=1234 DPT=5678
    //SEQ=3186301092 ACK=1756907998 WINDOW=90 RES=0x00 ACK FIN URGP=0 OPT (0101080A001FA3A4006866CD)

    //Building the regex matching the above trace
    snprintf(regex_packet, 512,
            "(%s|%s):[[:print:]]+filter:%s:[[:print:]]+"
            "SRC=([[:graph:]]+)[[:blank:]]DST=([[:graph:]]+)[[:blank:]]"
            "[[:print:]]+"
            "PROTO=%s[[:blank:]]"
            "SPT=%i[[:blank:]]"
            "DPT=%i[[:blank:]][[:print:]]+",
            cur_time_str,
            old_time_str,
            g_vars.ipv6forwardChain,
            protocol,
            pinhole->remote_port,
            pinhole->internal_port);

    //Building the regex to find the rule number in ip6tables
    snprintf(regex_rule, 256, "filter:%s:rule:([[:digit:]]+)",g_vars.ipv6forwardChain);

    regcomp(&re_packet,regex_packet, REG_EXTENDED);
    regcomp(&re_rule, regex_rule, REG_EXTENDED);

    //all the acket traces are store in kern.log (kernel module)
    if ((log_file=fopen("/var/log/kern.log","r")) == NULL) return -1;
    else {
        char line[1024];
        int found = 0;
        // Walk through the file line by line
        while (fgets(line,1024,log_file) != NULL)
        {
            // Search the last line where the packet is traced
            if ( regexec(&re_packet,line,4,pmatch,0) == 0 )
            {

                //find the remote_host
                strncpy (remote_host_str,
                        &line[pmatch[2].rm_so],
                        pmatch[2].rm_eo-pmatch[2].rm_so);
                remote_host_str[pmatch[2].rm_eo-pmatch[2].rm_so] = '\0';

                //find the internal_client
                strncpy (internal_client_str,
                        &line[pmatch[3].rm_so],
                        pmatch[3].rm_eo-pmatch[3].rm_so);
                internal_client_str[pmatch[3].rm_eo-pmatch[3].rm_so] = '\0';

                inet_pton(AF_INET6, internal_client_str, &internal_client);
                inet_pton(AF_INET6, remote_host_str, &remote_host);

                //testing the addresses
                if(IN6_ARE_ADDR_EQUAL(&internal_client,
                        pinhole->internal_client) )

                {
                    //if remote_host is wildcarded
                    if (pinhole->remote_host != NULL) {
                        if (IN6_ARE_ADDR_EQUAL(&remote_host,
                                pinhole->remote_host))
                        {
                            found = 1;
                            strncpy(packet_line,line, 1024);
                        }
                    }
                    else {
                        //traffic found
                        found = 1;
                        strncpy(packet_line,line, 1024);
                    }

                }
            }
        }

        fclose(log_file);
        regfree(&re_packet);
        free(cur_time_tm);
        free(old_time_tm);

        if(found == 0)
        {
            //no match found for this pinhole, no traffic error
            regfree(&re_rule);
            return -1;

        } else {

            //traffic has been found, check if this is the good pinhole
            if(regexec(&re_rule,packet_line,2,pmatch,0) == 0 )
            {
                char * rule_str;
                int start = pmatch[1].rm_so;
                int end = pmatch[1].rm_eo;
                size_t size = end - start;

                rule_str = malloc (sizeof (char) * (size + 1));
                if (rule_str)
                {
                    strncpy (rule_str, &packet_line[start], size);
                    rule_str[size] = '\0';
                    trace(1,"check ip6tables rule : %i", rule);
                    if(rule == atoi(rule_str))
                    {
                        //the pinhole manages the packets
                        regfree(&re_rule);
                        free (rule_str);
                        return 1;
                    }
                    else {
                        //this is not managed by the good rule
                        regfree(&re_rule);
                        free (rule_str);
                        return 0;
                    }
                }
            }
        }
    }

    return -1;
}


#ifdef __cplusplus
}
#endif

