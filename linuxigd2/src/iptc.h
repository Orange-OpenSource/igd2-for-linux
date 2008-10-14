#ifndef _IPTC_H_
#define _IPTC_H_

#include <iptables.h>
#include <libiptc/libiptc.h>
#include <net/netfilter/nf_nat.h>

struct ipt_natinfo
{
    struct ipt_entry_target t;
    struct nf_nat_multi_range_compat mr;
};

struct ipt_entry_match *get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache);
struct ipt_entry_match *get_udp_match(const char *sports, const char *dports, unsigned int *nfcache);
struct ipt_entry_target *get_dnat_target(const char *input, unsigned int *nfcache);

void iptc_add_rule(const char *table,
                   const char *chain,
                   const char *protocol,
                   const char *iiface,
                   const char *oiface,
                   const char *src,
                   const char *dest,
                   const char *srcports,
                   const char *destports,
                   const char *target,
                   const char *dnat_to,
                   const int append);

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
                      const char *dnat_to);

#endif // _IPTC_H_
