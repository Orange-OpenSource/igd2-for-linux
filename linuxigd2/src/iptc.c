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

#if HAVE_LIBIPTC
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include "globals.h"
#include "util.h"
#include "iptc.h"

static u_int16_t ipt_parse_port(const char *port);
static void parse_ports(const char *portstring, u_int16_t *ports);
static int ipt_service_to_port(const char *name);

static void parse_range(const char *input, struct nf_nat_range *range);
static struct ipt_natinfo *append_range(struct ipt_natinfo *info, const struct nf_nat_range *range);

static int matchcmp(const struct ipt_entry_match *match, const char *srcports, const char *destports);

/**
 * Add new rule into iptables with libiptc.
 *
 * @param table Name of table where rule is added.
 * @param chain Name of chain where rule is added.
 * @param protocol Network protocol of packet (tcp or udp).
 * @param iniface Name of an interface via which a packet was received.
 * @param outiface  Name of an interface via which a packet is going to be sent.
 * @param src Source address of packet.
 * @param dest Destination address of packet.
 * @param srcports Source port of packet.
 * @param destports Destination port of packet. 
 * @param target What rule should do if packet match. (ACCEPT or DNAT)
 * @param dnat_to In case of DNAT this is same as src:srcports
 * @param append If true, rule is appended as last chain, else rule is inserted as first in chain.
 */
void iptc_add_rule(const char *table,
                   const char *chain,
                   const char *protocol,
                   const char *iniface,
                   const char *outiface,
                   const char *src,
                   const char *dest,
                   const char *srcports,
                   const char *destports,
                   const char *target,
                   const char *dnat_to,
                   const int append)
{
    iptc_handle_t handle;
    struct ipt_entry *chain_entry;
    struct ipt_entry_match *entry_match = NULL;
    struct ipt_entry_target *entry_target = NULL;
    ipt_chainlabel labelit;
    long match_size;
    int result = 0;

    chain_entry = calloc(1, sizeof(*chain_entry));

    if (src)
    {
        chain_entry->ip.src.s_addr = inet_addr(src);
        chain_entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }
    if (dest)
    {
        chain_entry->ip.dst.s_addr = inet_addr(dest);
        chain_entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    if (iniface) strncpy(chain_entry->ip.iniface, iniface, IFNAMSIZ);
    if (outiface) strncpy(chain_entry->ip.outiface, outiface, IFNAMSIZ);

    if (strcmp(protocol, "TCP") == 0)
    {
        chain_entry->ip.proto = IPPROTO_TCP;
        entry_match = get_tcp_match(srcports, destports, &chain_entry->nfcache);
    }
    else if (strcmp(protocol, "UDP") == 0)
    {
        chain_entry->ip.proto = IPPROTO_UDP;
        entry_match = get_udp_match(srcports, destports, &chain_entry->nfcache);
    }
    else
    {
        trace(1, "Unsupported protocol: %s", protocol);
        return;
    }

    if (strcmp(target, "") == 0
            || strcmp(target, IPTC_LABEL_ACCEPT) == 0
            || strcmp(target, IPTC_LABEL_DROP) == 0
            || strcmp(target, IPTC_LABEL_QUEUE) == 0
            || strcmp(target, IPTC_LABEL_RETURN) == 0)
    {
        size_t size;

        size = IPT_ALIGN(sizeof(struct ipt_entry_target)) + IPT_ALIGN(sizeof(int));
        entry_target = calloc(1, size);
        entry_target->u.user.target_size = size;
        strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);
    }
    else if (strcmp(target, "DNAT") == 0)
    {
        entry_target = get_dnat_target(dnat_to, &chain_entry->nfcache);
    }

    if (entry_match)
        match_size = entry_match->u.match_size;
    else
        match_size = 0;

    chain_entry = realloc(chain_entry, sizeof(*chain_entry) + match_size + entry_target->u.target_size);
    memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
    chain_entry->target_offset = sizeof(*chain_entry) + match_size;
    chain_entry->next_offset = sizeof(*chain_entry) + match_size + entry_target->u.target_size;

    if (entry_match)
        memcpy(chain_entry->elems, entry_match, match_size);

    handle = iptc_init(table);
    if (!handle)
    {
        trace(1, "libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
        return;
    }

    strncpy(labelit, chain, sizeof(ipt_chainlabel));
    result = iptc_is_chain(chain, handle);
    if (!result)
    {
        trace(1, "libiptc error: Chain %s does not exist!", chain);
        return;
    }
    if (append)
        result = iptc_append_entry(labelit, chain_entry, &handle);
    else
        result = iptc_insert_entry(labelit, chain_entry, 0, &handle);

    if (!result)
    {
        trace(1, "libiptc error: Can't add, %s", iptc_strerror(errno));
        return;
    }
    result = iptc_commit(&handle);
    if (!result)
    {
        trace(1, "libiptc error: Commit error, %s", iptc_strerror(errno));
        return;
    }
    else
        trace(3, "added new rule to block successfully");

    if (entry_match) free(entry_match);
    free(entry_target);
    free(chain_entry);
}

/**
 * Delete rule from iptables with libiptc.
 *
 * @param table Name of table.
 * @param chain Name of chain.
 * @param protocol Network protocol of packet (tcp or udp).
 * @param iniface Name of an interface via which a packet was received.
 * @param outiface  Name of an interface via which a packet is going to be sent.
 * @param src Source address of packet.
 * @param dest Destination address of packet.
 * @param srcports Source port of packet.
 * @param destports Destination port of packet. 
 * @param target What rule should do if packet match. (ACCEPT or DNAT)
 * @param dnat_to In case of DNAT this is same as src:srcports
 */
void iptc_delete_rule(const char *table,
                      const char *chain,
                      const char *protocol,
                      const char *iniface,
                      const char *outiface,
                      const char *src,
                      const char *dest,
                      const char *srcports,
                      const char *destports,
                      const char *target,
                      const char *dnat_to)
{
    iptc_handle_t handle;
    const struct ipt_entry *e;
    ipt_chainlabel labelit;
    int i, result;
    unsigned long int s_src = INADDR_NONE, s_dest = INADDR_NONE;

    if (src) s_src = inet_addr(src);
    if (dest) s_dest = inet_addr(dest);

    handle = iptc_init(table);
    if (!handle)
    {
        trace(1, "libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
        return;
    }

    strncpy(labelit, chain, sizeof(ipt_chainlabel));
    result = iptc_is_chain(chain, handle);
    if (!result)
    {
        trace(1, "libiptc error: Chain %s does not exist!", chain);
        return;
    }

    /* check through rules to find match */
    for (e = iptc_first_rule(chain, &handle), i=0; e; e = iptc_next_rule(e, &handle), i++)
    {
        if (s_src != INADDR_NONE && e->ip.src.s_addr != s_src) continue;
        if (s_dest != INADDR_NONE && e->ip.dst.s_addr != s_dest) continue;
        if (iniface && strcmp(e->ip.iniface, iniface) != 0) continue;
        if (outiface && strcmp(e->ip.outiface, outiface) != 0) continue;
        if (protocol && strcmp(protocol, "TCP") == 0 && e->ip.proto != IPPROTO_TCP) continue;
        if (protocol && strcmp(protocol, "UDP") == 0 && e->ip.proto != IPPROTO_UDP) continue;
        if ((srcports || destports) && IPT_MATCH_ITERATE(e, matchcmp, srcports, destports) == 0) continue;
        if (target && strcmp(target, iptc_get_target(e, &handle)) != 0) continue;
        if (dnat_to && strcmp(target, "DNAT") == 0)
        {
            struct ipt_entry_target *t;
            struct nf_nat_multi_range_compat *mr;
            struct nf_nat_range *r, range;

            t = (void *) e+e->target_offset;
            mr = (void *) &t->data;

            if (mr->rangesize != 1) continue; /* we have only single dnat_to target now */
            r = mr->range;
            parse_range(dnat_to, &range);
            if (r->flags == range.flags
                    && r->min_ip == range.min_ip
                    && r->max_ip == range.max_ip
                    && r->min.all == range.min.all
                    && r->max.all == range.max.all)
            {
                break;
            }
        }

        break;
    }
    if (!e) return;
    result = iptc_delete_num_entry(chain, i, &handle);
    if (!result)
    {
        trace(1, "libiptc error: Delete error, %s", iptc_strerror(errno));
        return;
    }
    result = iptc_commit(&handle);
    if (!result)
    {
        trace(1, "libiptc error: Commit error, %s", iptc_strerror(errno));
        return;
    }
    else
        trace(3, "deleted rule from block successfully");
}

static int matchcmp(const struct ipt_entry_match *match, const char *srcports, const char *destports)
{
    u_int16_t temp[2];

    if (strcmp(match->u.user.name, "tcp") == 0)
    {
        struct ipt_tcp *tcpinfo = (struct ipt_tcp *)match->data;

        if (srcports)
        {
            parse_ports(srcports, temp);
            if (temp[0] != tcpinfo->spts[0] || temp[1] != tcpinfo->spts[1]) return 0;
        }
        if (destports)
        {
            parse_ports(destports, temp);
            if (temp[0] != tcpinfo->dpts[0] || temp[1] != tcpinfo->dpts[1]) return 0;
        }
        return 1;
    }
    else if (strcmp(match->u.user.name, "udp") == 0)
    {
        struct ipt_udp *udpinfo = (struct ipt_udp *)match->data;

        if (srcports)
        {
            parse_ports(srcports, temp);
            if (temp[0] != udpinfo->spts[0] || temp[1] != udpinfo->spts[1]) return 0;
        }
        if (destports)
        {
            parse_ports(destports, temp);
            if (temp[0] != udpinfo->dpts[0] || temp[1] != udpinfo->dpts[1]) return 0;
        }
        return 1;
    }
    else return 0;
}

/* These functions are used to create structs */

struct ipt_entry_match *
            get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_tcp *tcpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof(*match)) + IPT_ALIGN(sizeof(*tcpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);

    tcpinfo = (struct ipt_tcp *)match->data;
    tcpinfo->spts[1] = tcpinfo->dpts[1] = 0xFFFF;

    if (sports)
    {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, tcpinfo->spts);
    }
    if (dports)
    {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, tcpinfo->dpts);
    }

    return match;
}

struct ipt_entry_match *
            get_udp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_udp *udpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof(*match)) + IPT_ALIGN(sizeof(*udpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);

    udpinfo = (struct ipt_udp *)match->data;
    udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;

    if (sports)
    {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, udpinfo->spts);
    }
    if (dports)
    {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, udpinfo->dpts);
    }

    return match;
}

struct ipt_entry_target *
            get_dnat_target(const char *input, unsigned int *nfcache)
{
    struct ipt_entry_target *target;
    struct ipt_natinfo *info;
    struct nf_nat_range range;

    char *buffer;
    size_t size;

    /* Can't cache this */
    *nfcache |= NFC_UNKNOWN;

    buffer = strdup(input);
    size = IPT_ALIGN(sizeof(*target)) + IPT_ALIGN(sizeof(struct nf_nat_multi_range_compat));
    target = calloc(1, size);
    target->u.target_size = size;
    strncpy(target->u.user.name, "DNAT", IPT_FUNCTION_MAXNAMELEN);

    info = (void *)target;
    parse_range(buffer, &range);
    target = &(append_range(info, &range)->t);
    free(buffer);

    return target;
}

/* Copied and modified from libipt_tcp.c and libipt_udp.c */

static u_int16_t ipt_parse_port(const char *port)
{
    unsigned int portnum;

    if ((portnum = ipt_service_to_port(port)) != -1)
    {
        return (u_int16_t)portnum;
    }
    else
    {
        return atoi(port);
    }
}

static void
parse_ports(const char *portstring, u_int16_t *ports)
{
    char *buffer;
    char *cp;

    buffer = strdup(portstring);
    if ((cp = strchr(buffer, ':')) == NULL)
        ports[0] = ports[1] = ipt_parse_port(buffer);
    else
    {
        *cp = '\0';
        cp++;

        ports[0] = buffer[0] ? ipt_parse_port(buffer) : 0;
        ports[1] = cp[0] ? ipt_parse_port(cp) : 0xFFFF;
    }
    free(buffer);
}

static int ipt_service_to_port(const char *name)
{
    struct servent *service;

    if ((service = getservbyname(name, "tcp")) != NULL)
        return ntohs((unsigned short) service->s_port);

    return -1;
}




/* Copied and modified from libipt_DNAT.c */

static void
parse_range(const char *input, struct nf_nat_range *range)
{
    char *colon, *dash, *buffer;
    in_addr_t ip;

    buffer = strdup(input);
    memset(range, 0, sizeof(*range));
    colon = strchr(buffer, ':');

    if (colon)
    {
        int port;

        range->flags |= IP_NAT_RANGE_PROTO_SPECIFIED;

        port = atoi(colon+1);
        dash = strchr(colon, '-');
        if (!dash)
        {
            range->min.all
            = range->max.all
              = htons(port);
        }
        else
        {
            int maxport;

            maxport = atoi(dash + 1);
            range->min.all = htons(port);
            range->max.all = htons(maxport);
        }
        /* Starts with a colon? No IP info...*/
        if (colon == buffer)
        {
            free(buffer);
            return;
        }
        *colon = '\0';
    }

    range->flags |= IP_NAT_RANGE_MAP_IPS;
    dash = strchr(buffer, '-');
    if (colon && dash && dash > colon)
        dash = NULL;

    if (dash)
        *dash = '\0';

    ip = inet_addr(buffer);
    range->min_ip = ip;
    if (dash)
    {
        ip = inet_addr(dash+1);
        range->max_ip = ip;
    }
    else
        range->max_ip = range->min_ip;

    free(buffer);
    return;
}


static struct ipt_natinfo *
            append_range(struct ipt_natinfo *info, const struct nf_nat_range *range)
{
    unsigned int size;

    /* One nf_nat_range already included in nf_nat_multi_range_compat */
    size = IPT_ALIGN(sizeof(*info) + info->mr.rangesize * sizeof(*range));

    info = realloc(info, size);

    info->t.u.target_size = size;
    info->mr.range[info->mr.rangesize] = *range;
    info->mr.rangesize++;

    return info;
}
#endif
