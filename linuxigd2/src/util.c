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

#include <regex.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <wchar.h>
#include <wctype.h>
#include <ctype.h>
#include <upnp/upnp.h>
#include <upnp/ixml.h>
#include "globals.h"
#include "util.h"


/**
 * Open new socket.
 *
 * @return created socket if success, -1 if failure.
 */
static int get_sockfd(void)
{
    static int sockfd = -1;

    if (sockfd == -1)
    {
        if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        {
            perror("user: socket creating failed");
            return (-1);
        }
    }
    return sockfd;
}

/**
 * Create union from items separated with space in strings given.
 * Use free() for created string.
 *
 * @param str1 First string to unionize
 * @param str2 Second string to unionize
 * @return New allocated union string or NULL if fails.
 */
char* createUnion(const char *str1, const char *str2)
{
    if (!str1 || !str2)
        return NULL;

    char *unionStr = NULL;
    size_t size = strlen(str1) + strlen(str2) + 2;
    unionStr = (char *)malloc(size);
    if (!unionStr)
        return NULL;

    // base for the union is created by copying whole str1 to it
    strcpy(unionStr,str1);

    // make copy of str2 so we can tokenize it
    char copystr[strlen(str1)];
    // go through all roles in list
    strcpy(copystr,str2);
    char *item = strtok(copystr, " ");
    if (item)
    {
        do
        {
            // do "raw" check that this item isn't already in current items
            if ( strstr(unionStr,item) == NULL )
            {
                // add new item at the end of rolelist
                if (strlen(unionStr) > 0)
                {
                    strcat(unionStr, " ");
                }
                strcat(unionStr, item);
            }
        } while ((item = strtok(NULL, " ")));

    }

    return unionStr;
}

/**
 * Get values for send bytes and packets and received bytes and packets for 
 * external interface from /proc/net/dev
 *
 * @param stats Unsigned long array with size of STATS_LIMIT
 * @return 0 if fails to open file, 1 if succeed to get values.
 */
int readStats(unsigned long stats[STATS_LIMIT])
{
    char dev[IFNAMSIZ];
    FILE *proc;
    int read;

    proc = fopen("/proc/net/dev", "r");
    if (!proc)
    {
        fprintf(stderr, "failed to open\n");
        return 0;
    }

    /* skip first two lines */
    read = fscanf(proc, "%*[^\n]\n%*[^\n]\n");

    /* parse stats */
    do
        read = fscanf(proc, "%[^:]:%lu %lu %*u %*u %*u %*u %*u %*u %lu %lu %*u %*u %*u %*u %*u %*u\n", dev, &stats[STATS_RX_BYTES], &stats[STATS_RX_PACKETS], &stats[STATS_TX_BYTES], &stats[STATS_TX_PACKETS]);
    while (read != EOF && (read == 5 && strncmp(dev, g_vars.extInterfaceName, IFNAMSIZ) != 0));

    fclose(proc);

    return 1;
}

/**
 * Trims leading and trailing white spaces from a string.
 *
 * @param str String to trim.
 * @return Trimmed string or NULL
 */
char *trimString(char *str)
{
    char *ptr;
    if (!str)
        return NULL;
    if (!*str)
        return str;

    // trim leading white spaces
    while(isspace(*str)) str++;

    // trim trailing white spaces
    ptr = str + strlen(str);
    while (isspace(*--ptr))
        *ptr = '\0';

    return str;
}

/**
 * THIS FUNCTION IS NOT ACTUALLY NEEDED, if you use UpnpMakeActionResponse and such
 * functions for creating responses. libupnp then takes care of escaping xmls. 
 * Unescaping on the other hand must be done by ourself here. 
 * 
 * Change given XML string in escaped form. 
 * Following characters are converted:
 *  '<'  -->  "&lt;"
 *  '>'  -->  "&gt;"
 *  '"'  -->  "&quot;"
 *  '''  -->  "&apos;"
 *  '&'  -->  "&amp;"
 * 
 * User should free returned pointer.
 *
 * @param xml String to turn escaped xml.
 * @return Escaped xml string or NULL if failure.
 */
char* escapeXMLString(char *xml)
{
    xml = trimString(xml);
    if (xml == NULL)
        return NULL;

    char *escXML = NULL;
    size_t size = strlen(xml);
    size_t alloc = size +1;

    escXML = realloc(NULL, alloc);
    if (!escXML)
        return NULL;

    int i,j; // i goes through original xml and j through escaped escXML
    for (i=0,j=0; i < size; i++)
    {
        switch (xml[i])
        {
            case '<' :
            {
                char *new_buf;
                alloc += strlen("&lt;");
                new_buf = realloc (escXML, alloc);
                if (!new_buf) {
                    return NULL;
                }
                escXML = new_buf;

                strcpy(escXML+j, "&lt;");
                j += strlen("&lt;");
                break;
            }
            case '>' :
            {
                char *new_buf;
                alloc += strlen("&gt;");
                new_buf = realloc (escXML, alloc);
                if (!new_buf) {
                    return NULL;
                }
                escXML = new_buf;

                strcpy(escXML+j, "&gt;");
                j += strlen("&gt;");
                break;
            }
            case '"' :
            {
                char *new_buf;
                alloc += strlen("&quot;");
                new_buf = realloc (escXML, alloc);
                if (!new_buf) {
                    return NULL;
                }
                escXML = new_buf;

                strcpy(escXML+j, "&quot;");
                j += strlen("&quot;");
                break;
            }
            case '\'' :
            {
                char *new_buf;
                alloc += strlen("&apos;");
                new_buf = realloc (escXML, alloc);
                if (!new_buf) {
                    return NULL;
                }
                escXML = new_buf;

                strcpy(escXML+j, "&apos;");
                j += strlen("&apos;");
                break;
            }
            case '&' :
            {
                char *new_buf;
                alloc += strlen("&amp;");
                new_buf = realloc (escXML, alloc);
                if (!new_buf) {
                    return NULL;
                }
                escXML = new_buf;

                strcpy(escXML+j, "&amp;");
                j += strlen("&amp;");
                break;
            }
            default :
            {
                escXML[j++] = xml[i];
                break;
            }
        }
    }

    if (j > 0)
        escXML[j] = '\0';

    return escXML;
}

/**
 * Change given XML string in unescaped form. 
 * Following characters are converted:
 *  "&lt;"    -->  '<'
 *  "&gt;"    -->  '>'
 *  "&quot;"  -->  '"'
 *  "&apos;"  -->  '''
 *  "&amp;"   -->  '&'
 * 
 * User should free returned pointer.
 *
 * @param escXML String to turn unescaped xml.
 * @return Unescaped xml string or NULL if failure.
 */
char* unescapeXMLString(char *escXML)
{
    escXML = trimString(escXML);
    if (escXML == NULL)
        return NULL;

    char *xml = NULL;
    size_t size = strlen(escXML);

    xml = (char *)malloc(size);
    if (!xml)
        return NULL;

    memset(xml, '\0', size);

    int i,j; // i goes through unescaped xml and j through escaped escXML
    for (i=0,j=0; i < size && j < size; i++)
    {
        if (strncmp(escXML+j, "&lt;", strlen("&lt;")) == 0)
        {
            xml[i] = '<';
            j += strlen("&lt;");
        }
        else if (strncmp(escXML+j, "&gt;", strlen("&gt;")) == 0)
        {
            xml[i] = '>';
            j += strlen("&gt;");
        }
        else if (strncmp(escXML+j, "&quot;", strlen("&quot;")) == 0)
        {
            xml[i] = '"';
            j += strlen("&quot;");
        }
        else if (strncmp(escXML+j, "&apos;", strlen("&apos;")) == 0)
        {
            xml[i] = '\'';
            j += strlen("&apos;");
        }
        else if (strncmp(escXML+j, "&amp;", strlen("&amp;")) == 0)
        {
            xml[i] = '&';
            j += strlen("&amp;");
        }
        else
        {
            xml[i] = escXML[j];
            j++;
        }
    }

    xml[i] = '\0';

    return xml;
}


/**
 * Change given string in uppercase. Converts given string first as wide-character string
 * and then transliterate that to upper case. Finally convert upper case wide-character string
 * back to character string and return it. Such a complex procedure guarantees that umlaut chars
 * are uppercased correctly, not sure if even all utf-8 chars.
 * 
 * User should free returned pointer.
 *
 * @param str String to turn uppercase.
 * @return Upper cased string or NULL if failure.
 */
char *toUpperCase(const char * str)
{
    if (str == NULL)
        return NULL;

    int slen = strlen(str);
    int wcslen;
    wchar_t wc[2*slen];  // doubling original string length should guarantee that there is enough space for wchar_t
    char *UPPER = (char *)malloc(slen+1);

    wcslen = mbsrtowcs(wc, &str, slen, NULL); // to wide-character string

    int i;
    for (i=0; i<wcslen; i++)
    {
        wc[i] = towupper(wc[i]);   // to upper-case
    }

    const wchar_t *ptr = wc;
    wcslen = wcsrtombs(UPPER, &ptr, slen, NULL);  // to character string, requires that wide-char string is constant

    if (wcslen != slen)
        return NULL;

    UPPER[slen] = '\0';
    return UPPER;
}

/**
 * Do case insensitive string comparison for strings. 
 * Works like normal strcmp(), but turns both string to uppercase before comparing
 *
 * @param str1 First string to compare.
 * @param str2 Second string to compare.
 * @return An integer greater than, equal to or less than 0, if the string pointed to by s1 is greater than, equal to or less than the string pointed to by s2 respectively.
 *         ~0 if fails to turn strings to uppercase
 */
int caseInsesitive_strcmp(const char *str1, const char *str2)
{
    int ret = ~0;
    char *STR1 = toUpperCase(str1);
    char *STR2 = toUpperCase(str2);

    if (STR1 && STR2)
    {
        ret = strcmp(STR1, STR2);
    }
    free(STR1);
    free(STR2);

    return ret;
}

/**
 * Get MAC address of given network interface.
 *
 * @param address MAC address is wrote into this.
 * @param ifname Interface name.
 * @return 1 if success, 0 if failure. MAC address is returned in address parameter.
 */
int GetMACAddressStr(unsigned char *address, int addressSize, char *ifname)
{
    struct ifreq ifr;
    int fd;
    int succeeded = 0;

    fd = get_sockfd();
    if (fd >= 0 )
    {
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        {
            memcpy(address, ifr.ifr_hwaddr.sa_data, addressSize);
            succeeded = 1;
        }
        else
        {
            syslog(LOG_ERR, "Failure obtaining MAC address of interface %s", ifname);
            succeeded = 0;
        }
    }
    return succeeded;
}

/**
 * Get IP address assigned for given network interface.
 * If fails to get IP, sets value of address to empty string.
 *
 * @param address IP address is wrote into this.
 * @param ifname Interface name.
 * @return 1 if success, 0 if failure. IP address is returned in address parameter.
 */
int GetIpAddressStr(char *address, char *ifname)
{
    struct ifreq ifr;
    struct sockaddr_in *saddr;
    int fd;
    int succeeded = 0;

    fd = get_sockfd();
    if (fd >= 0 )
    {
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        ifr.ifr_addr.sa_family = AF_INET;
        if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
        {
            saddr = (struct sockaddr_in *)&ifr.ifr_addr;
            strcpy(address,inet_ntoa(saddr->sin_addr));
            succeeded = 1;
        }
        else
        {
            syslog(LOG_ERR, "Failure obtaining ip address of interface %s", ifname);
            strcpy(address,"");
            succeeded = 0;
        }
    }
    return succeeded;
}

/**
 * Get connection status string used as ConnectionStatus state variable.
 * If interface has IP, status id connected. Else disconnected
 * There are also manually adjusted states Unconfigured, Connecting and Disconnecting!
 *
 * @param conStatus Connection status string is written in this.
 * @param ifname Interface name.
 * @return 1 if success, 0 if failure. Connection status is returned in conStatus parameter.
 */
int GetConnectionStatus(char *conStatus, char *ifname)
{
    char tmp[INET_ADDRSTRLEN];
    int status = GetIpAddressStr(tmp, ifname);

    if (status == 1)
        strcpy(conStatus,"Connected");
    else
        strcpy(conStatus,"Disconnected");

    return status;
}

/**
 * Check if address is either valid IP address or network host address.
 * 
 * @param address String to check
 * @return 1 if it is IP or host address, 0 else.
 */
int IsIpOrDomain(char *address)
{
    int result;

    // is it IP
    regex_t re_IP;
    regcomp(&re_IP, REGEX_IP_LASTBYTE, REG_EXTENDED|REG_NOSUB);
    result = regexec(&re_IP, address, (size_t) 0, NULL, 0);
    regfree(&re_IP);
    if (result == 0) {
        return 1;
    }

    // is it domain name
    regex_t re_host;
    regcomp(&re_host, REGEX_DOMAIN_NAME, REG_EXTENDED|REG_NOSUB|REG_ICASE);
    result = regexec(&re_host, address, (size_t) 0, NULL, 0);
    regfree(&re_host);
    if (result == 0) {
        return 1;
    }

    return 0;
}

/**
 * Check if IP of control point is same as internal client address in portmapping.
 * 
 * @param ICAddresscon IP of Internalclient in portmapping.
 * @param in_ad IP of control point.
 * @return 1 if match, 0 else.
 */
int ControlPointIP_equals_InternalClientIP(char *ICAddress, struct in_addr *in_ad)
{
    char cpAddress[INET_ADDRSTRLEN];
    int result;
    int succeeded = 0;

    inet_ntop(AF_INET, in_ad, cpAddress, INET_ADDRSTRLEN);

    result = strcmp(ICAddress, cpAddress);

    // Check the compare result InternalClient IP address is same than Control Point
    if (result == 0)
    {
        succeeded = 1;
    }
    else
    {
        syslog(LOG_ERR, "CP and InternalClient IP addresees won't match:  %s %s", ICAddress, cpAddress);
        succeeded = 0;
    }

    return succeeded;
}

void trace(int debuglevel, const char *format, ...)
{
    va_list ap;
    va_start(ap,format);
    if (g_vars.debug>=debuglevel)
    {
        vsyslog(LOG_DEBUG,format,ap);
    }
    va_end(ap);
}

/**
 * Check if parameter string has a wildcard character '*', or if string is '0' which might be used as wildcard
 * for port number, or if string is empty string which wildcard form of ip addresses.
 * 
 * @param str String to check.
 * @return 1 if found, 0 else.
 */
int checkForWildCard(const char *str)
{
    int retVal = 0;

    if ((strchr(str, '*') != NULL) || (strcmp(str,"0") == 0) || (strcmp(str,"") == 0))
        retVal = 1;

    return retVal;
}

/**
 * Add error data to event structure used by libupnp for creating response for action request message.
 * 
 * @param ca_event Response structure used for response.
 * @param errorCode Error code number.
 * @param message Error message string.
 */
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message)
{
    ca_event->ErrCode = errorCode;
    strcpy(ca_event->ErrStr, message);
    ca_event->ActionResult = NULL;
}

/**
 * Resolve if given string is acceptable as boolean value used in upnp action request messages.
 * 'yes', 'true' and '1' currently acceptable values.
 * 
 * @param value String to check.
 * @return 1 if true, 0 else.
 */
int resolveBoolean(char *value)
{
    if ( strcasecmp(value, "yes") == 0 ||
         strcasecmp(value, "true") == 0 ||
         strcasecmp(value, "1") == 0 )
    {
        return 1;
    }

    return 0;
}

void ParseXMLResponse(struct Upnp_Action_Request *ca_event, const char *result_str)
{
    IXML_Document *result = NULL;

    if ((result = ixmlParseBuffer(result_str)) != NULL)
    {
        ca_event->ActionResult = result;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing response to %s: %s", ca_event->ActionName, result_str);
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 402;
    }
}


/**
 * Resolve up/down status of given network interface and insert it into given string.
 * Status is up if interface is listed in /proc/net/dev_mcast -file, else down.
 * 
 * @param ethLinkStatus Pointer to string where status is wrote.
 * @param iface Network interface name.
 * @return 0 if status is up, 1 if down or failed to open dev_mcast file.
 */
int setEthernetLinkStatus(char *ethLinkStatus, char *iface)
{
    FILE *fp;
    char str[60];

    // check from dev_mcast if interface is up (up if listed in file)
    // This could be done "finer" with reading registers from socket. Check from ifconfig.c or mii-tool.c. Do if nothing better to do.
    if((fp = fopen("/proc/net/dev_mcast", "r"))==NULL) {
        syslog(LOG_ERR, "Cannot open /proc/net/dev_mcast");
        return 1;
    }

    while(!feof(fp)) {
        if(fgets(str,60,fp) && strstr(str,iface))
        {
            strcpy(ethLinkStatus,"Up");
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    strcpy(ethLinkStatus,"Down");
    return 1;
}

/**
 * Read integer value from given file. File should only contain this one numerical value.
 * 
 * @param file Name of file to read.
 * @param iface Network interface name.
 * @return Value read from file. -1 if fails to open file, -2 if no value found from file.
 */ 
int readIntFromFile(char *file)
{
    FILE *fp;
    int read;
    int value = -1;

    trace(3,"Read integer value from %s", file);

    if((fp = fopen(file, "r"))==NULL) {
        return -1;
    }

    while(!feof(fp)) {
        read = fscanf(fp,"%d", &value);
        if (value > -1)
        {
            fclose(fp);
            return value;
        }
    }
    fclose(fp);
    return -2;
}

/**
 * Kill DHCP client. After killing check that IP of iface has been released.
 * 
 * @param iface Network interface name.
 * @return 1 if DHCP client is killed and IP released, 0 else.
 */
int killDHCPClient(char *iface)
{
    char tmp[30];
    int pid, ret;

    trace(2,"Killing DHCP client...");
    snprintf(tmp, 30, "/var/run/%s.pid", iface);
    pid = readIntFromFile(tmp);
    if (pid > -1)
    {
        snprintf(tmp, 30, "kill %d", pid);
        trace(3,"system(%s)",tmp);
        ret = system(tmp);
    }
    else
    {
        // brute force
        trace(3,"No PID file available for %s of %s",g_vars.dhcpc,iface);
        snprintf(tmp, 30, "killall -9 %s", g_vars.dhcpc);
        trace(3,"system(%s)",tmp);
        ret = system(tmp);
    }

    sleep(2); // wait that IP is released

    if (!GetIpAddressStr(tmp, iface))
    {
        trace(3,"Success IP of %s is released",iface);
        return 1;
    }
    else
    {
        trace(3,"Failure IP of %s: %s",iface,tmp);
        return 0;
    }
}

/**
 * Start DHCP client. After starting check that iface has IP.
 * 
 * @param iface Network interface name.
 * @return 1 if DHCP client is started and iface has IP, 0 else.
 */
int startDHCPClient(char *iface)
{
    char tmp[100];
    int ret;

    trace(2,"Starting DHCP client...");
    if (strcmp(g_vars.dhcpc,"dhclient") == 0)
    {
        snprintf(tmp, 100, "%s -pf /var/run/%s.pid %s", g_vars.dhcpc, iface, iface);
    }
    else
    {
        snprintf(tmp, 100, "%s -i %s -R -p /var/run/%s.pid", g_vars.dhcpc, iface, iface);
    }
    trace(3,"system(%s)",tmp);
    ret = system(tmp);

    sleep(2); // wait that IP is acquired

    if (GetIpAddressStr(tmp, iface))
    {
        trace(3,"Success IP of %s: %s",iface,tmp);
        return 1;
    }
    else
    {
        trace(3,"Failure %s doens't have IP",iface);
        return 0;
    }
}

/**
 * Release IP address of given interface.
 *
 * @param iface Network interface name.
 * @return 1 if iface doesn't have IP, 0 else.
 */
int releaseIP(char *iface)
{
    char tmp[INET6_ADDRSTRLEN];
    int ret, success = 0;

    // check does IP exist
    if (!GetIpAddressStr(tmp, iface))
        return 1;

    // if used dhcp client is dhclient, use -r parameter to release IP
    if (strcmp(g_vars.dhcpc,"dhclient") == 0)
    {
        char tmp[50];

        trace(2,"Releasing IP...");
        snprintf(tmp, 50, "%s -r %s", g_vars.dhcpc, iface);
        trace(3,"system(%s)",tmp);
        ret = system(tmp);

        sleep(2); // wait that IP is released

        if (!GetIpAddressStr(tmp, iface))
        {
            trace(3,"Success IP of %s is released",iface);
            return 1;
        }
        else
        {
            trace(3,"Failure IP of %s: %s",iface,tmp);
            return 0;
        }
    }
    // if used dhcp client is udhcpc, IP is released when udhcpc is killed if udhcpc was started with -R parameter
    else
    {
        // kill already running udhcpc-client for given iface and check if IP was released
        if (killDHCPClient(iface))
            success = 1; //OK
        else
        {
            // start udhcpc-clientdaemon with parameter -R which will release IP after quiting daemon
            startDHCPClient(iface);

            // then kill udhcpc-client running. Now there shouldn't be IP anymore.
            if(killDHCPClient(iface))
                success = 1;
        }
    }
    return success;
}



//-----------------------------------------------------------------------------
//
//                      Common extensions for ixml
//
//-----------------------------------------------------------------------------
/**
 * Get document item which is at position index in nodelist (all nodes with same name item).
 * Index 0 means first, 1 second, etc.
 * 
 * @param doc XML document where item is fetched.
 * @param item Name of xml-node to fetch.
 * @param index Which one of nodes with same name is selected.
 * @return Value of desired node.
 */
char* GetDocumentItem(IXML_Document * doc, const char *item, int index)
{
    IXML_NodeList *nodeList = NULL;
    IXML_Node *textNode = NULL;
    IXML_Node *tmpNode = NULL;

    char *ret = NULL;

    nodeList = ixmlDocument_getElementsByTagName( doc, ( char * )item );

    if ( nodeList )
    {
        if ( ( tmpNode = ixmlNodeList_item( nodeList, index ) ) )
        {
            textNode = ixmlNode_getFirstChild( tmpNode );
            if (textNode != NULL)
            {
                ret = strdup( ixmlNode_getNodeValue( textNode ) );
            }
            // if desired node exist, but textNode is NULL, then value of node propably is ""
            else
                ret = strdup("");
        }
    }

    ixmlNodeList_free( nodeList );
    return ret;
}

/**
 * Get first document item in nodelist with name given in item parameter.
 * 
 * @param doc XML document where item is fetched.
 * @param item Name of xml-node to fetch.
 * @return Value of desired node.
 */
char* GetFirstDocumentItem( IN IXML_Document * doc,
                            IN const char *item )
{
    return GetDocumentItem(doc,item,0);
}

