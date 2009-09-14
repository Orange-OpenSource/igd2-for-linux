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
#include <upnp/upnp.h>
#include <upnp/ixml.h>
#include "globals.h"
#include "util.h"

// Document containing action access levels.
static IXML_Document *accessLevelDoc = NULL;


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
char* escapeXMLString(const char *xml)
{
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
 * @param xml String to turn unescaped xml.
 * @return Unescaped xml string or NULL if failure.
 */
char* unescapeXMLString(const char *escXML)
{
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
    if (STR1) free(STR1);
    if (STR2) free(STR2);
    
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
    int value = -1;

    trace(3,"Read integer value from %s", file);

    if((fp = fopen(file, "r"))==NULL) {
        return -1;
    }

    while(!feof(fp)) {
        fscanf(fp,"%d", &value);
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
    int pid;

    trace(2,"Killing DHCP client...");
    snprintf(tmp, 30, "/var/run/%s.pid", iface);
    pid = readIntFromFile(tmp);
    if (pid > -1)
    {
        snprintf(tmp, 30, "kill %d", pid);
        trace(3,"system(%s)",tmp);
        system(tmp);
    }
    else
    {
        // brute force
        trace(3,"No PID file available for %s of %s",g_vars.dhcpc,iface);
        snprintf(tmp, 30, "killall %s", g_vars.dhcpc);
        trace(3,"system(%s)",tmp);
        system(tmp);
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
    char tmp[50];

    trace(2,"Starting DHCP client...");
    snprintf(tmp, 50, "%s -t 0 -i %s -R", g_vars.dhcpc, iface);
    trace(3,"system(%s)",tmp);
    system(tmp);

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
    int success = 0;

    // check does IP exist
    if (!GetIpAddressStr(tmp, iface))
        return 1;

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
    return success;
}




/**
 * Check if list containing items separated with separator contains item searchItem.
 * 
 * List could be for example: "Admin Basic Public", separator " " and searchItem "Basic".
 * These values would return 1
 *
 * @param list String containing values separated with separator
 * @param separator Separator used in list
 * @param searchItem Token value which is searched from list
 * @param caseInsesitive Is searching case-sensitive or not. 0 means that comparison is case-sensitive.
 * @return 1 if item is found, 0 if not found or any of the parameters is NULL
 */
int tokenizeAndSearch(const char *constList, const char *separator, const char *searchItem, int caseInsensitive)
{
    if (!constList || !separator || !searchItem)
        return 0;
    
    char list[strlen(constList)];
    strcpy(list,constList);
    
    char *token = strtok(list, separator);
    if (token)
    {
        do 
        {
            if (!caseInsensitive && strcmp(searchItem,token) == 0)
            {
                return 1;
            }
            else if (caseInsensitive && caseInsesitive_strcmp(searchItem,token) == 0)
            {
                return 1;
            }            
                
        } while ((token = strtok(NULL, separator)));

    }
    
    return 0;
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

    //fprintf(stderr,"%s\n",ixmlPrintDocument(doc)); //DEBUG

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

    if ( nodeList )
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

/**
 * Write given IXML_Document into file
 *
 * @param doc IXML_Document to write to file
 * @param file Name of file where document is written. Include full path if different than execution folder is targeted.
 * @return 0 on success, -1 if fails to open file, -2 if fails to read IXML_Document
 */
int writeDocumentToFile(IXML_Document *doc, const char *file)
{
    int ret = 0;
    FILE *stream = fopen(file, "w");
    if (!stream) return -1;
    
    char *contents = ixmlPrintDocument(doc);
    if (!contents)
        ret =-2;
    else
        fprintf(stream, "%s\n", contents);
    
    fclose(stream);
    
    ixmlFreeDOMString(contents);
    return ret;         
}

/**
 * Get text value of given IXML_Node. Node containing '<accessLevel>Admin</accessLevel>'
 * would return 'Admin'
 *
 * @param tmpNode Node which value is returned
 * @return Value of node or NULL
 */
char* GetTextValueOfNode(IXML_Node *tmpNode)
{
    IXML_Node *textNode = NULL;
    char *value = NULL;
    const char *tmp =NULL;
        
    if ( tmpNode )
    {
        textNode = ixmlNode_getFirstChild( tmpNode );
        if ( textNode )
        {
            tmp = ixmlNode_getNodeValue(textNode);
            if ( tmp == NULL)
                value = strdup(""); // in this case node has childnodes
            else    
                value = strdup(tmp);
        }
        else
            value = strdup("");
    } 
    
    return value;        
}


/**
 * Get first occurence of node with name nodeName and
 * value nodeValue
 *
 * @param doc IXML_Document where node is searched
 * @param nodeName Name of searched element
 * @param nodeValue Value of searched element
 * @param caseInsensitive Is value comparing case insensitive: 0 = no, else yes
 * @return Node or NULL
 */
static IXML_Node *GetNodeWithValue(IXML_Document *doc, const char *nodeName, const char *nodeValue, int caseInsensitive)
{
    int listLen, i;
    IXML_NodeList *nodeList = NULL;
    IXML_Node *tmpNode = NULL;
    char *tmp = NULL;
    char *valueUP = NULL;
    
    if (caseInsensitive)
    {
        valueUP = toUpperCase(nodeValue);
        if (!valueUP)
            return NULL;
    }
    
    nodeList = ixmlDocument_getElementsByTagName( doc, nodeName );

    if (nodeList)
    {
        listLen = ixmlNodeList_length(nodeList);
        
        for (i = 0; i < listLen; i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                tmp = GetTextValueOfNode(tmpNode);
                
                // if case insensitive, convert tmp to uppercase and compare to uppercased nodevalue
                if (caseInsensitive)
                {
                    tmp = toUpperCase(tmp);
                    if ( tmp && (strcmp( tmp,  valueUP) == 0))
                    {
                        if (valueUP) free(valueUP);
                        ixmlNodeList_free( nodeList );
                        free(tmp);
                        return tmpNode;
                    }
                    if (tmp) free(tmp);                     
                }
                // case sensitive
                else
                {
                    if ( tmp && (strcmp( tmp,  nodeValue) == 0))
                    {
                        if (valueUP) free(valueUP);
                        ixmlNodeList_free( nodeList );
                        return tmpNode;
                    } 
                }               
            }            
        }
    }
    if (valueUP) free(valueUP);
    if ( nodeList ) ixmlNodeList_free( nodeList );
    
    return NULL;
}


/**
 * Get first occurence of node with name nodeName
 *
 * @param doc IXML_Document where node is searched
 * @param nodeName Name of searched element
 * @return Node or NULL
 */
IXML_Node *GetNode(IXML_Document *doc, const char *nodeName)
{
    int listLen, i;
    IXML_NodeList *nodeList = NULL;
    IXML_Node *tmpNode = NULL;

    
    nodeList = ixmlDocument_getElementsByTagName( doc, nodeName );

    if (nodeList)
    {
        listLen = ixmlNodeList_length(nodeList);
        
        for (i = 0; i < listLen; i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                if ( nodeList ) ixmlNodeList_free( nodeList );
                return tmpNode;
            }            
        }
    }
    if ( nodeList ) ixmlNodeList_free( nodeList );
    
    return NULL;
}

/**
 * Get first occurence of node with name nodeName
 * and return that node as char array.
 *
 * @param doc IXML_Document from where node is searched
 * @param nodeName Name of searched element
 * @return Node as string or NULL
 */
char *NodeWithNameToString(IXML_Document *doc, char *nodeName)
{
    IXML_Node *tmpNode = GetNode(doc, nodeName);
    
    if (tmpNode == NULL)
    {
        return NULL;
    }
    
    return ixmlNodetoString(tmpNode);
}


/**
 * Get first occurence of sibling node with name nodeName
 *
 * @param node IXML_Node which sibling is searched
 * @param nodeName Name of searched element
 * @return Sibling node or NULL
 */
static IXML_Node *GetSiblingWithTagName(IXML_Node *node, const char *nodeName)
{
    // get first sibling. No need to get and check previous siblings then.
    IXML_Node *tmpNode = ixmlNode_getFirstChild( ixmlNode_getParentNode(node) );
         
    while (tmpNode != NULL)
    {
        // is name of element nodename?
        if (strcmp(ixmlNode_getNodeName(tmpNode), nodeName) == 0)
        {
            return tmpNode;
        }
        tmpNode = ixmlNode_getNextSibling(tmpNode);
    }

    return NULL;
}


/**
 * Get value of attribute with given name from node.
 *
 * @param tmpNode IXML_Node which attribute value is fetched 
 * @param attrName Name of searched attribute
 * @return String value of attribute or NULL
 */
static char* GetAttributeValueOfNode(IXML_Node *tmpNode, const char *attrName)
{
    if (tmpNode == NULL) return NULL;
    
    IXML_NamedNodeMap *attrs = ixmlNode_getAttributes(tmpNode);
    
    if (attrs == NULL) return NULL;
    
    tmpNode = ixmlNamedNodeMap_getNamedItem(attrs, attrName);
    
    if (tmpNode == NULL) return NULL;
    
    if ( attrs ) ixmlNamedNodeMap_free( attrs );
    
    return tmpNode->nodeValue;    
}


/**
 * Get node with name nodeName and attribute with name attrName and value attrValue.
 *
 * @param doc IXML_Document where node is searched 
 * @param nodeName Name of searched node
 * @param attrName Name of attribute which searched node must have
 * @param attrValue Value of attribute which searched node must have
 * @return IXML_Node or NULL
 */
static IXML_Node *GetNodeWithNameAndAttribute(IXML_Document *doc, const char *nodeName, const char *attrName, const char *attrValue)
{
    IXML_Node *tmpNode = NULL;
    IXML_NodeList *nodeList = NULL;
    
    int i;
    char *tmp;
    nodeList = ixmlDocument_getElementsByTagName( doc, nodeName );

    if ( nodeList )
    {
        for (i = 0; i < ixmlNodeList_length(nodeList); i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                tmp = GetAttributeValueOfNode(tmpNode, attrName);
                if ( tmp && (strcmp(attrValue, tmp) == 0) )
                {
                    ixmlNodeList_free( nodeList );  
                    return tmpNode;
                }
            }
        }
    }

    if ( nodeList )
        ixmlNodeList_free( nodeList );  
        
    return NULL;
}


/**
 * Create new child node for parent node.
 *
 * @param doc Owner IXML_Document of created node
 * @param parent Pointer to parent node of new node
 * @param childNodeName Tagname of new node
 * @param childNodeValue Value of new node
 * @return Pointer to new node or NULL
 */
IXML_Node *AddChildNode(IXML_Document *doc, IXML_Node *parent, const char *childNodeName, const char *childNodeValue)
{
    IXML_Element *tmpElement = NULL;
    IXML_Node *textNode = NULL;
    
    if (!childNodeName || !childNodeValue)
        return NULL;
        
    tmpElement = ixmlDocument_createElement(doc, childNodeName);
    textNode = ixmlDocument_createTextNode(doc,childNodeValue);
    
    ixmlNode_appendChild(&tmpElement->n,textNode);
    ixmlNode_appendChild(parent,&tmpElement->n);
    
    return &tmpElement->n;
}


/**
 * Create new child node for parent node. Child node must also have one attribute
 *
 * @param doc Owner IXML_Document of created node
 * @param parent Pointer to parent node of new node
 * @param childNodeName Tagname of new node
 * @param childNodeValue Value of new node
 * @param attrName Name of attribute
 * @param attrValue Value of attribute
 * @return Pointer to new node or NULL
 */
static IXML_Node *AddChildNodeWithAttribute(IXML_Document *doc, IXML_Node *parent, const char *childNodeName, const char *childNodeValue, const char *attrName, const char *attrValue)
{
    IXML_Element *tmpElement = NULL;
    IXML_Node *textNode = NULL;
    
    if (!childNodeName || !childNodeValue || !attrName || !attrValue)
        return NULL;
        
    tmpElement = ixmlDocument_createElement(doc, childNodeName);
    textNode = ixmlDocument_createTextNode(doc, childNodeValue);
    
    ixmlElement_setAttribute(tmpElement, attrName, attrValue);
    
    ixmlNode_appendChild(&tmpElement->n,textNode);
    ixmlNode_appendChild(parent,&tmpElement->n);
    
    return &tmpElement->n;
}


/**
 * Remove node from document
 *
 * @param doc Owner IXML_Document of node
 * @param node Pointer to node remove
 * @return 0 on success, -2 node or its parent is not found, -1 else
 */
int RemoveNode(IXML_Node *node)
{
    if (node == NULL)
        return 0;
        
    int ret = ixmlNode_removeChild(node->parentNode, node, NULL);
    
    if (ret == IXML_SUCCESS)
        ret = 0;
    else if (ret == IXML_INVALID_PARAMETER)
        ret = -2;
    else 
        ret = -1; 
        
    return ret;
}


/**
 * Find first childnode of parent with nodename. 
 *
 * @param parent Pointer to parent node
 * @param childNodeName Name of searched childnode
 * @return Pointer to node found or NULL if not found
 */
static IXML_Node *GetChildNodeWithName(IXML_Node *parent, const char *childNodeName)
{
    int i;
    IXML_Node *tmpNode = NULL;
    IXML_NodeList *nodeList = ixmlNode_getChildNodes( parent );
    char *tmp = NULL;
    
    // name of node must be known
    if (!childNodeName)
        return NULL;
    
    if ( nodeList )
    {
        for (i = 0; i < ixmlNodeList_length(nodeList); i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                if ((tmp = (char *)ixmlNode_getNodeName(tmpNode)) != NULL && (strcmp(tmp, childNodeName) == 0))
                {
                    // nodename matches, quit and return
                    if ( nodeList ) ixmlNodeList_free( nodeList );
                    return tmpNode;
                }
            }
        }
    }

    if ( nodeList ) ixmlNodeList_free( nodeList );
    return NULL;
}


/**
 * Find childnode of parent with nodename and -value, attributename and -value.
 * Parent node, name of child node, name of child node's attribute and value of attribute must
 * be given. Value of child node may be NULL.
 *
 * @param parent Pointer to parent node
 * @param childNodeName Name of searched child node
 * @param childNodeValue Value of searched child node. If NULL this is ignored
 * @param attrName Name of attribute that child node must have
 * @param attrValue Value of attribute that child node must have
 * @return Pointer to node found or NULL if not found
 */
static IXML_Node *GetChildNodeWithAttribute(IXML_Node *parent, const char *childNodeName, const char *childNodeValue, const char *attrName, const char *attrValue)
{
    int i;
    IXML_Node *tmpNode = NULL;
    IXML_NodeList *nodeList = ixmlNode_getChildNodes( parent );
    char *tmp = NULL;
    
    // name of node, name of attribute and value of attribute must be known
    if (!childNodeName || !attrName || !attrValue)
        return NULL;
    
    if ( nodeList )
    {
        for (i = 0; i < ixmlNodeList_length(nodeList); i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                // if nodename doesn't match, continue to next child
                if ((tmp = (char *)ixmlNode_getNodeName(tmpNode)) == NULL || (strcmp(tmp, childNodeName) != 0))
                    continue;
                
                // if childnode is given and nodevalue doesn't match, continue to next child
                if (childNodeValue)
                {
                    if ((tmp = GetTextValueOfNode(tmpNode)) || (strcmp(tmp, childNodeValue) != 0))
                        continue;
                }
                
                // check that attribute with right name and value exist 
                if ((tmp = GetAttributeValueOfNode(tmpNode, attrName)) && (strcmp(tmp, attrValue) == 0))
                {
                    // we have perfect match
                    if ( nodeList ) ixmlNodeList_free( nodeList ); 
                    return tmpNode;
                }
            }
        }
    }

    if ( nodeList ) ixmlNodeList_free( nodeList );
    return NULL;
}

//-----------------------------------------------------------------------------
//
//                      AccessLevel xml handling
//
//-----------------------------------------------------------------------------


/**
 * Read action access level settings file and create IXML_Document from it.
 *
 * @param pathToFile Full path of access level xml
 * @return 0 if success, -1 else.
 */
int initActionAccessLevels(const char *pathToFile)
{
    accessLevelDoc = ixmlLoadDocument(pathToFile);
    if (accessLevelDoc == NULL)
    {
        return -1;
    }
    
    return 0;
}

/**
 * Get accesslevel value from accesslevel xml for given action.
 * initActionAccessLevels must have been called before this.
 *
 * @param serviceId ServiceId of service which child action actionName is
 * @param actionName Name of action
 * @param manage Is value of accessLevelManage (1) or accessLevel (0) returned.
 * @return Access level string or NULL
 */
char* getAccessLevel(const char *serviceId, const char *actionName, int manage)
{
    char *accesslevel = NULL;
    char *tmp = NULL;
    IXML_Node *tmpNode = NULL, *actionNode = NULL;

    // get node with given serviceId
    tmpNode = GetNodeWithValue(accessLevelDoc, "serviceId", serviceId, 0);
    if (tmpNode == NULL) return NULL;
    // get sibling actionList
    tmpNode = GetSiblingWithTagName(tmpNode, "actionList");

    // get first action from actionList
    actionNode = ixmlNode_getFirstChild(tmpNode);
    
    while (actionNode != NULL)
    {
        // get value of child name
        tmpNode = GetChildNodeWithName(actionNode, "name");
        tmp = GetTextValueOfNode(tmpNode);
        if (!tmpNode || !tmp)
            continue;
            
        if (strcmp(tmp, actionName) == 0)
        {   
            // right name node is found, get desired accesslevel-node
            if (manage)
            {
                tmpNode = GetSiblingWithTagName(tmpNode, "accessLevelManage");
            }
            else
            {    
                tmpNode = GetSiblingWithTagName(tmpNode, "accessLevel");
            }
            
            if (tmpNode == NULL) return NULL;
            accesslevel = GetTextValueOfNode(tmpNode);
            
            free(tmp);    
            return accesslevel;
        }
        
        free(tmp);
        actionNode = ixmlNode_getNextSibling(actionNode);   
    }
  
    return NULL;
}


/**
 * Release accesslevel document.
 *
 * @return void
 */
void deinitActionAccessLevels()
{
    ixmlDocument_free(accessLevelDoc);
}


//-----------------------------------------------------------------------------
//
//                      ACL xml handling
//
//-----------------------------------------------------------------------------
/* Example of ACL
<ACL>
<Identities>
<User>
   <Name>Admin</Name>
   <RoleList>Admin</RoleList>
</User>
<User>
   <Name>Mika</Name>
   <RoleList>Basic</RoleList>
</User>
<CP introduced="1">
   <Name>ACME Widget Model XYZ</Name>
   <Alias>Mark’s Game Console</Alias>
   <ID>TM0NZomIzI2OTsmIzM0NTueYgi93Q==</ID>
   <RoleList>Admin Basic</RoleList>
</CP>
<CP>
   <Name>Some CP</Name>
   <ID>feeNZomIfI2erfrmIzefTufew==</ID>
   <RoleList>Public</RoleList>
</CP>
</Identities>
<Roles>
<Role><Name>Admin</Name></Role>
<Role><Name>Basic</Name></Role>
<Role><Name>Public</Name></Role>
</Roles>
</ACL>
 */ 

/**
 * Validate that all rolenames in space-separated form found from parameter roles,
 * are valid rolenames and defined in ACL.xml 
 * 
 * @param doc IXML_Document ACL document
 * @param roles Roles to validate
 * @return ACL_SUCCESS on succes, ACL_ROLE_ERROR if any of roles in invalid
 */
static int ACL_validateRoleNames(IXML_Document *doc, const char *roles)
{
    int i, OK;
    IXML_NodeList *nodeList = NULL;
    IXML_Node *tmpNode = NULL;
    char *tmp = NULL; 
    
    nodeList = ixmlDocument_getElementsByTagName( doc, "Role" );

    if (nodeList)
    {
        char rolelist[strlen(roles)];    
        // go through all roles in roles parameter
        strcpy(rolelist,roles);   
        char *role = strtok(rolelist, " ");
        if (role)
        {
            do 
            {
                OK = 0;
                for (i = 0; i < ixmlNodeList_length(nodeList); i++)
                {
                    if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
                    {
                        // here we make assumption that format of Role definition is following:
                        // <Role><Name>Admin</Name></Role>
                        // Role has only one child named Name
                        tmp = GetTextValueOfNode(tmpNode->firstChild);
                        if ( tmp && (strcmp( tmp,  role) == 0))
                        {
                            OK = 1;
                            break;
                        }            
                    } 
                }
                if (!OK)
                {
                    ixmlNodeList_free( nodeList );
                    return ACL_ROLE_ERROR;
                }                
                    
            } while ((role = strtok(NULL, " ")));
        } 
    }
    
    if ( nodeList ) ixmlNodeList_free( nodeList );    
    
    return  ACL_SUCCESS; 
}

/**
 * Add roles for user/CP. 
 * 
 * @param doc IXML_Document ACL document
 * @param roleListNode IXML_Node "RoleList" for which new roles are added
 * @param roles New roles
 * @return 0 on succes negative value if failure
 */
static int ACL_addRolesToRoleList(IXML_Document *doc, IXML_Node *roleListNode, const char *roles)
{
    IXML_Node *textNode = NULL;
    
    // check validity of rolenames
    if (ACL_validateRoleNames(doc, roles) != ACL_SUCCESS) return ACL_ROLE_ERROR;
       
    // get current value of "RoleList"
    char *currentRoles = GetTextValueOfNode(roleListNode);
    if (currentRoles == NULL) return ACL_COMMON_ERROR;
   
    char newRoleList[strlen(roles) + strlen(currentRoles)+1];
    strcpy(newRoleList, currentRoles);
    
    char rolelist[strlen(roles)];    
    // go through all roles in list
    strcpy(rolelist,roles);   
    char *role = strtok(rolelist, " ");
    if (role)
    {
        do 
        {
            // do "raw" check that this role isn't already in current roles
            if ( strstr(newRoleList,role) == NULL )
            {
                // add new role at the end of rolelist
                if (strlen(newRoleList) > 0)
                    strcat(newRoleList, " ");
                strcat(newRoleList, role);
            }
                
        } while ((role = strtok(NULL, " ")));

    }
  
    // set text value of "RoleList" as new rolelist
    textNode = ixmlNode_getFirstChild(roleListNode);
    if (textNode == NULL)
    {
        textNode = ixmlDocument_createTextNode(doc, newRoleList);
        return ixmlNode_appendChild(roleListNode,textNode);
    }
    
    return ixmlNode_setNodeValue(textNode, newRoleList);    
}


/**
 * Remove roles from user/CP. 
 * 
 * @param doc IXML_Document ACL document
 * @param roleListNode IXML_Node "RoleList" from where roles are removed
 * @param roles Roles to remove (Admin Basic)
 * @return 0 on succes negative value if failure
 */
static int ACL_removeRolesFromRoleList(IXML_Document *doc, IXML_Node *roleListNode, const char *roles)
{
    IXML_Node *textNode = NULL;
    
    // check validity of rolenames
    if (ACL_validateRoleNames(doc, roles) != ACL_SUCCESS) return ACL_ROLE_ERROR;
 
    // get current value of "RoleList"
    char *currentRoles = GetTextValueOfNode(roleListNode);
    if (currentRoles == NULL) return ACL_COMMON_ERROR;
    
    char newRoleList[strlen(currentRoles)];
    strcpy(newRoleList,"");
    
    char rolelist[strlen(roles)];    
    // go through all roles in current roles
    strcpy(rolelist,currentRoles);   
    char *role = strtok(rolelist, " ");
    if (role)
    {
        do 
        {        
            // do "raw" check that this current role isn't in roles which are to remove
            if ( strstr(roles,role) == NULL )
            {
                // add new role at the end of rolelist
                strcat(newRoleList, role);
                strcat(newRoleList, " ");
            }
                
        } while ((role = strtok(NULL, " ")));
    }
    
    // remove last useless space from end of new rolelist
    if (strlen(newRoleList) > 0)
        newRoleList[strlen(newRoleList) - 1] = '\0';

    // DP spec says that if RoleList goes empty, then device must add "Public" role 
    if (strlen(newRoleList) <= 0)
        strcpy(newRoleList, "Public");

    // set text value of "RoleList" as new rolelist
    textNode = ixmlNode_getFirstChild(roleListNode);
    if (textNode == NULL)
    {
        textNode = ixmlDocument_createTextNode(doc, newRoleList);
        return ixmlNode_appendChild(roleListNode,textNode);
    }
    
    return ixmlNode_setNodeValue(textNode, newRoleList);    
}

/**
 * Get RoleList of given username in ACL.
 *
 * @param doc ACL IXML_Document
 * @param username Username whose roles are returned
 * @return Value of RoleList or NULL
 */
char *ACL_getRolesOfUser(IXML_Document *doc, const char *username)
{
    // get element with name "Name" and value username
    IXML_Node *tmpNode = GetNodeWithValue(doc, "Name", username, 1);
    if (tmpNode == NULL) return NULL;    
    
    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    
    if (tmpNode == NULL) return NULL;   
    
    return GetTextValueOfNode(tmpNode);
}

/**
 * Get RoleList of control point with "ID" id
 *
 * @param doc ACL IXML_Document
 * @param id Value of ID element
 * @return Value of RoleList or NULL.
 */
char *ACL_getRolesOfCP(IXML_Document *doc, const char *id)
{
    // get element with name "ID" and value id
    IXML_Node *tmpNode = GetNodeWithValue(doc, "ID", id, 1);
    if (tmpNode == NULL) return NULL;    

    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    
    if (tmpNode == NULL) return NULL;   
    
    return GetTextValueOfNode(tmpNode);
}

/**
 * Get Name, Alias and RoleList of control point with "ID" id
 *
 * @param doc ACL IXML_Document
 * @param id Value of ID element
 * @param name Value of Name element. Use free() for this.
 * @param alias Value of Alias element. Use free() for this.
 * @param rolelist Value of RoleList element. Use free() for this.
 * @return -1 if no CP with ID id is found, 0 else.
 */
int ACL_getCP(IXML_Document *doc, const char *id, char **name, char **alias, char **rolelist)
{
    // get element with name "ID" and value id
    IXML_Node *tmpNode = GetNodeWithValue(doc, "ID", id, 1);
    if (tmpNode == NULL) return -1;    

    if (name)
    {
        tmpNode = GetSiblingWithTagName(tmpNode, "Name");
        *name = GetTextValueOfNode(tmpNode);
    }
    if (alias)
    {
        tmpNode = GetSiblingWithTagName(tmpNode, "Alias");
        *alias = GetTextValueOfNode(tmpNode);
    }
    if (rolelist)
    {
        tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
        *rolelist = GetTextValueOfNode(tmpNode);
    }
    
    return 0;
}

/**
 * Add new Control point into ACL xml.
 *
 * <CP introduced="1">
 *    <Name>ACME Widget Model XYZ</Name>
 *    <Alias>Mark’s Game Console</Alias>
 *    <ID>3543d8e6-3b8b-4000-80cb-212886b5b044</ID>
 *    <RoleList>Admin Basic</RoleList>
 * </CP>
 * 
 * @param doc ACL IXML_Document
 * @param name Value of Name element
 * @param alias Value of Alias element. May be NULL
 * @param id Value of ID element
 * @param roles Value of RoleList element
 * @param introduced Does "CP" has attribute introduced with value 1 (0 means no, 1 yes)
 * @return ACL_SUCCESS on success, ACL_USER_ERROR if same id already exist in ACL, ACL_COMMON_ERROR else
 */
int ACL_addCP(IXML_Document *doc, const char *name, const char *alias, const char *id, const char *roles, int introduced)
{
    // Check that ID doesn't already exist
    if ( GetNodeWithValue(doc, "ID", id, 1) != NULL )
    {
        return ACL_USER_ERROR;
    } 
    
    int ret = ACL_SUCCESS;
    
    // create new element called "CP"
    IXML_Element *CP = ixmlDocument_createElement(doc, "CP");

    if (introduced)
        ixmlElement_setAttribute(CP, "introduced", "1");
        
    AddChildNode(doc, &CP->n, "Name", name);
    if (alias)
        AddChildNode(doc, &CP->n, "Alias", alias);
    AddChildNode(doc, &CP->n, "ID", id);
    AddChildNode(doc, &CP->n, "RoleList", roles);
    
    IXML_Node *tmpNode = NULL;
    IXML_NodeList *nodeList = NULL;
    nodeList = ixmlDocument_getElementsByTagName( doc, "Identities" );

    if ( nodeList )
    {
        if ( ( tmpNode = ixmlNodeList_item( nodeList, 0 ) ) )    
            ixmlNode_appendChild(tmpNode,&CP->n);
        else
            ret = ACL_COMMON_ERROR;
    }
    
    //fprintf(stderr,"\n\n\n%s\n",ixmlPrintDocument(doc));
    if ( nodeList ) ixmlNodeList_free( nodeList ); 
    return ret;
}

/**
 * Add or update Alias value of CP.
 * 
 * <CP introduced="1">
 *    <Name>ACME Widget Model XYZ</Name>
 *    <Alias>Mark’s Game Console</Alias>
 *    <ID>TM0NZomIzI2OTsmIzM0NTueYgi93Q==</ID>
 *    <RoleList>Admin Basic</RoleList>
 * </CP>
 * 
 * @param doc ACL IXML_Document
 * @param id Value of ID element which sibling Alias is modified or added
 * @param alias Value of Alias element 
 * @param forceChange Is existing Alias value changed, 1 is yes, 0 is no
 * @return ACL_SUCCESS on success, ACL_COMMON_ERROR if fails to add or update alias
 */
int ACL_updateCPAlias(IXML_Document *doc, const char *id, const char *alias, int forceChange)
{
    IXML_Node *tmpNode = GetNodeWithValue(doc, "ID", id, 1);
    IXML_Node *aliasNode = NULL;
    
    // Check that ID does exist
    if ( tmpNode == NULL )
    {
        return ACL_USER_ERROR;
    }
    
    aliasNode = GetSiblingWithTagName(tmpNode, "Alias");
    
    // if changing Alias value is forced, first thing to do is to remove aliasNode (even if it doesn't exist)
    if (forceChange)
    {
        RemoveNode(aliasNode);
    }
    // if change is not forced and alias already exists, return SUCCESS
    else if (!forceChange && aliasNode != NULL)
    {
        return ACL_SUCCESS;
    }

    // then add new child. If fails to add new node, and aliasNode is removed, or didn't even exist, return ACL_COMMON_ERROR
    if ( AddChildNode(doc, tmpNode->parentNode, "Alias", alias) == NULL )
    {
        return ACL_COMMON_ERROR;
    }
    
    return ACL_SUCCESS;
}

/**
 * Add new User into ACL xml.
 * 
 * <User>
 *  <Name>Admin</Name>
 *  <RoleList>Admin</RoleList>
 * </User>
 * 
 * @param doc ACL IXML_Document
 * @param name Username which is added to ACL
 * @param roles Value of RoleList element 
 * @return ACL_SUCCESS on success, ACL_USER_ERROR if same username already exist in ACL, ACL_COMMON_ERROR else
 */
int ACL_addUser(IXML_Document *doc, const char *name, const char *roles)
{
    // Check that user doesn't already exist
    if ( GetNodeWithValue(doc, "Name", name, 1) != NULL )
    {
        return ACL_USER_ERROR;
    } 
    
    int ret = ACL_SUCCESS;
    
    // create new element called "User"
    IXML_Element *user = ixmlDocument_createElement(doc, "User");

    AddChildNode(doc, &user->n, "Name", name);
    AddChildNode(doc, &user->n, "RoleList", roles);
    
    IXML_Node *tmpNode = NULL;
    IXML_NodeList *nodeList = NULL;
    nodeList = ixmlDocument_getElementsByTagName( doc, "Identities" );

    if ( nodeList )
    {
        if ( ( tmpNode = ixmlNodeList_item( nodeList, 0 ) ) )    
            ixmlNode_appendChild(tmpNode,&user->n);
        else
            ret = ACL_COMMON_ERROR;
    }
    
    //fprintf(stderr,"\n\n\n%s\n",ixmlPrintDocument(doc));
    if ( nodeList ) ixmlNodeList_free( nodeList ); 
    return ret;
}


/**
 * Remove User from ACL xml.
 *
 * 
 * @param doc ACL IXML_Document
 * @param name Username which is removed from ACL
 * @return ACL_SUCCESS on success, -1 else. ACL_USER_ERROR if Name is not found
 */
int ACL_removeUser(IXML_Document *doc, const char *name)
{
    IXML_Node *userNode = NULL;  
    
    userNode = GetNodeWithValue(doc, "Name", name, 1);
    if (!userNode) return ACL_USER_ERROR;
    
    return RemoveNode(userNode->parentNode);
}


/**
 * Remove control point from ACL xml.
 *
 * 
 * @param doc ACL IXML_Document
 * @param id ID of control point which is removed from ACL
 * @return 0 on success, -1 else. ACL_USER_ERROR if ID is not found
 */
int ACL_removeCP(IXML_Document *doc, const char *id)
{
    IXML_Node *idNode = NULL;
    
    idNode = GetNodeWithValue(doc, "ID", id, 1);
    if (!idNode) return ACL_USER_ERROR;
    
    // remove <CP> node
    return RemoveNode(idNode->parentNode);
}


/**
 * Add roles for given identity in ACL xml.
 * Identity might be
 * <CP><ID>9a43d8e6-3b8b-449d-812e-a13986b2b090</ID></CP>
 * or
 * <User><Name>Mika</Name></User>
 * 
 * 
 * @param ACLdoc ACL IXML_Document
 * @param identityDoc IXML_Document containing identity for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return 0 on succes,
 *         ACL_USER_ERROR if identity is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_addRolesForIdentity(IXML_Document *ACLdoc, IXML_Document *identityDoc, const char *roles)
{
    int result = -1;
    char *id = NULL;

    id = GetFirstDocumentItem(identityDoc, "ID");
    if ( id == NULL )
    {
        id = GetFirstDocumentItem(identityDoc, "Name");
        if ( id == NULL )
        {
            // identityDoc is invalid
            return ACL_COMMON_ERROR;
        }
        else
        {
            result = ACL_addRolesForUser(ACLdoc, id, roles);
        }               
    }
    else
    {
        result = ACL_addRolesForCP(ACLdoc, id, roles);
    }
    
    return result;
}


/**
 * Add roles for User in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param name Username for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return 0 on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_addRolesForUser(IXML_Document *doc, const char *name, const char *roles)
{
    IXML_Node *tmpNode = GetNodeWithValue(doc, "Name", name, 1);

    // Check that name does exist
    // remember to check that parent of "Name" is "User" 
    if ( tmpNode == NULL || (strcmp(tmpNode->parentNode->nodeName, "User") != 0))
    {
        return ACL_USER_ERROR;
    } 
    
    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    if (tmpNode == NULL) 
    {
        // if Rolelist element is not found at all, just add it for User-element
        AddChildNode(doc, tmpNode->parentNode, "RoleList", roles);
        return ACL_SUCCESS;
    }    
    
    return ACL_addRolesToRoleList(doc, tmpNode, roles);
}


/**
 * Add roles for Control point in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param id ID of control for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return ACL_SUCCESS on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_addRolesForCP(IXML_Document *doc, const char *id, const char *roles)
{
    IXML_Node *tmpNode = GetNodeWithValue(doc, "ID", id, 1);
    
    // Check that CP with ID does exist
    // remember to check that parent of "ID" is "CP" 
    if ( tmpNode == NULL || (strcmp(tmpNode->parentNode->nodeName, "CP") != 0))
    {
        return ACL_USER_ERROR;
    } 
    
    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    if (tmpNode == NULL) 
    {
        // if Rolelist element is not found at all, just add it for User-element
        AddChildNode(doc, tmpNode->parentNode, "RoleList", roles);
        return ACL_SUCCESS;
    }    
    
    return ACL_addRolesToRoleList(doc, tmpNode, roles);
}


/**
 * Remove roles from given identity in ACL xml.
 * Identity might be
 * <CP><ID>9a43d8e6-3b8b-449d-812e-a13986b2b090</ID></CP>
 * or
 * <User><Name>Mika</Name></User>
 * 
 * 
 * @param ACLdoc ACL IXML_Document
 * @param identityDoc IXML_Document containing identity for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return 0 on succes,
 *         ACL_USER_ERROR if identity is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_removeRolesFromIdentity(IXML_Document *ACLdoc, IXML_Document *identityDoc, const char *roles)
{
    int result = -1;
    char *id = NULL;

    id = GetFirstDocumentItem(identityDoc, "ID");
    if ( id == NULL )
    {
        id = GetFirstDocumentItem(identityDoc, "Name");
        if ( id == NULL )
        {
            // identityDoc is invalid
            return ACL_COMMON_ERROR;
        }
        else
        {
            result = ACL_removeRolesFromUser(ACLdoc, id, roles);
        }               
    }
    else
    {
        result = ACL_removeRolesFromCP(ACLdoc, id, roles);
    }
    
    return result;
}


/**
 * Remove roles from User in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param name Username from which roles are removed
 * @param roles Space-separated string of rolenames which are removed from user (Admin Basic)
 * @return 0 on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_removeRolesFromUser(IXML_Document *doc, const char *name, const char *roles)
{
    IXML_Node *tmpNode = GetNodeWithValue(doc, "Name", name, 1);
    
    // Check that name does exist
    if ( tmpNode == NULL || (strcmp(tmpNode->parentNode->nodeName, "User") != 0))
    {
        return ACL_USER_ERROR;
    } 
    
    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    if (tmpNode == NULL) 
    {
        // if Rolelist element is not found at all, just add it for User-element
        AddChildNode(doc, tmpNode->parentNode, "RoleList", roles);
        return ACL_SUCCESS;
    }    
    
    return ACL_removeRolesFromRoleList(doc, tmpNode, roles);
}


/**
 * Remove roles from Control point in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param id ID of control from which roles are removed
 * @param roles Space-separated string of rolenames which are removed from user (Admin Basic)
 * @return ACL_SUCCESS on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_removeRolesFromCP(IXML_Document *doc, const char *id, const char *roles)
{
    IXML_Node *tmpNode = GetNodeWithValue(doc, "ID", id, 1);
    
    // Check that CP with id does exist
    if ( tmpNode == NULL || (strcmp(tmpNode->parentNode->nodeName, "CP") != 0))
    {
        return ACL_USER_ERROR;
    } 
    
    tmpNode = GetSiblingWithTagName(tmpNode, "RoleList");
    if (tmpNode == NULL) 
    {
        // if Rolelist element is not found at all, just add it for User-element
        AddChildNode(doc, tmpNode->parentNode, "RoleList", roles);
        return ACL_SUCCESS;
    }    
    
    return ACL_removeRolesFromRoleList(doc, tmpNode, roles);
}


/**
 * This doesn't actually do much validating anymore. It adds all CP's and User's it found
 * from identitiesDoc to ACL. If admin is true, then also Alias and RoleList values are tried to 
 * read from identitiesDoc. Else NULL and 'Public' values are used.
 * 
 * This function is used by AddIdentityList() action.
 * 
 * <Identities>
 * <CP>
 *    <Name>Vendor X Device</Name>
 *    <Alias>Joe’s phone</Alias>
 *    <ID>e593d8e6-6b8b-49d9-845a-21828db570e9</ID>
 * </CP>
 * <CP>…</CP>
 * <User>
 *    <Name>Mika</Name>
 * </User>
 * </Identities>
 * 
 * 
 * @param doc ACL IXML_Document
 * @param identitiesDoc IXML_Document which contains new CP-elements to add to ACL
 * @param admin Is identitiesDoc handled with admin rights
 * @return upnp error codes:
 *         0 on succes,
 *         600 if identitiesDoc contains invalid values
 *         501 if processing error occurs
 */
int ACL_validateListAndUpdateACL(IXML_Document *ACLdoc, IXML_Document *identitiesDoc, int admin)
{
    int result;
    IXML_Node *tmpNode = NULL;
    char *name = NULL;
    char *id = NULL;
    char *alias = NULL;
    char *rolelist =NULL;

    // let's start adding new CP's to ACL
    // get first ID from new list 
    while ( (tmpNode = GetNode(identitiesDoc, "ID")) != NULL )
    {
        id = GetTextValueOfNode(tmpNode);
        name = GetTextValueOfNode( GetSiblingWithTagName(tmpNode, "Name") );
        
        if (name == NULL)
        {
            trace(2,"(ACL) Name must be given for CP. Skip.");
            RemoveNode(tmpNode);
            continue;
            //return 600;
        }
        
        // if admin, try to get Alias and RoleList values
        if (admin)
        {
            alias = GetTextValueOfNode( GetSiblingWithTagName(tmpNode, "Alias") );
            rolelist = GetTextValueOfNode( GetSiblingWithTagName(tmpNode, "RoleList") );          
            if (rolelist == NULL || strlen(rolelist) < 1)
                rolelist = "Public";
        }
        else
        {
            alias = NULL;
            rolelist = "Public";
        }
            
        // just try to add new
        result = ACL_addCP(ACLdoc, name, alias, id, rolelist, 0);

        // if same CP already exists, it is OK for us. All we care if something else has gone wrong      
        if (result != ACL_USER_ERROR && result != ACL_SUCCESS)
        {
            trace(2,"(ACL) Failed to add new CP. Name: '%s', ID: '%s'",name,id);
            return 501;
        }
        
        // remove node from identitiesDoc, so we can proceed to next one (if there is one)
        RemoveNode(tmpNode);
    }

    // let's start adding new usernames to ACL
    // get first User from new list 
    while ( (tmpNode = GetNode(identitiesDoc, "User")) != NULL )
    {
        name = GetTextValueOfNode( GetChildNodeWithName(tmpNode, "Name") );
        
        if (name == NULL)
        {
            trace(2,"(ACL) Name must be given for User. Skip.");
            RemoveNode(tmpNode);
            continue;
            //return 600;
        }
        // if admin, try to get RoleList value
        if (admin)
        {
            rolelist = GetTextValueOfNode( GetChildNodeWithName(tmpNode, "RoleList") );           
            if (rolelist == NULL || strlen(rolelist) < 1)
                rolelist = "Public";
        }
        else
        {
            rolelist = "Public";
        }            
        // just try to add new
        result = ACL_addUser(ACLdoc, name, rolelist);

        // if same User already exists, it is OK for us. All we care if something else has gone wrong      
        if (result != ACL_USER_ERROR && result != ACL_SUCCESS)
        {
            trace(2,"(ACL) Failed to add new User. Name: '%s'",name);
            return 501;
        }
        
        // remove node from identitiesDoc, so we can proceed to next one (if there is one)
        RemoveNode(tmpNode);
    }
        
    return 0;  
}


/**
 * Validates given ixml document (identityDoc) which contains CP/User to remove from ACL.
 * 
 * This function is used by RemoveIdentity() action.
 * 
 * @param doc ACL IXML_Document
 * @param identitiesDoc IXML_Document which contains CP-elements to remove from ACL
 * @return upnp error codes:
 *         0 on success,
 *         600 if identitiesDoc contains invalid values
 *         501 if processing error occurs
 */
int ACL_validateAndRemoveIdentity(IXML_Document *ACLdoc, IXML_Document *identityDoc)
{
    int result;
    char *id = NULL;

    // first try to get CP ID
    id = GetFirstDocumentItem(identityDoc, "ID");
    if (id == NULL)
    {
        id = GetFirstDocumentItem(identityDoc, "Name");
        if (id == NULL)
        {
            trace(2,"(ACL) Failed to find any ID or Name from given parameter");
            return 600;
        }
        else if (strcmp(toUpperCase(id), "ADMIN") == 0) // username must not be Admin
        {
            trace(2,"(ACL) Trying to remove Admin, that's not allowed");
            return 600;            
        }
        else
        {
            // remove User form ACL
            result = ACL_removeUser(ACLdoc, id);
            if (result == ACL_USER_ERROR)
            {
                trace(2,"(ACL) No User with Name '%s' is found from ACL",id);
                return 600;
            }
            else if (result != ACL_SUCCESS)
            {
                trace(2,"(ACL) Failed to remove User with Name '%s' from ACL",id);
                return 501;
            }
        }               
    }    
    else
    {
        // remove CP form ACL
        result = ACL_removeCP(ACLdoc, id);
        if (result == ACL_USER_ERROR)
        {
            trace(2,"(ACL) No CP with ID '%s' is found from ACL",id);
            return 600;
        }
        else if (result != ACL_SUCCESS)
        {
            trace(2,"(ACL) Failed to remove CP with ID '%s' from ACL",id);
            return 501;
        }
    }
    
    return 0;
}


/**
 * Validates given ixml document (identityDoc) which contains CP's new alias.
 * 
 * This function is used by SetCPIdentityAlias() action.
 * 
 * @param doc ACL IXML_Document
 * @param identitiesDoc IXML_Document which contains CP-elements alias value
 * @return upnp error codes:
 *         0 on succes,
 *         600 if identitiesDoc contains invalid values
 *         501 if processing error occurs
 */
int ACL_validateAndUpdateCPAlias(IXML_Document *ACLdoc, IXML_Document *identityDoc)
{
    int result;
    char *id = NULL;
    char *alias = NULL;

    // following assumes that identityDoc contains only one pair of ID and Alias elements
    
    id = GetFirstDocumentItem(identityDoc, "ID");
    if (id == NULL)
    {
        trace(2,"(ACL) Failed to find any ID from given parameter");
        return 600;                
    } 

    alias = GetFirstDocumentItem(identityDoc, "Alias");
    if (alias == NULL)
    {
        trace(2,"(ACL) Failed to get value of Alias");
        return 600;                
    } 
    
    // update alias
    result = ACL_updateCPAlias(ACLdoc, id, alias, 1);
    if (result == ACL_USER_ERROR)
    {
        trace(2,"(ACL) No CP with ID '%s' is found from ACL",id);
        return 600;
    }
    else if (result != ACL_SUCCESS)
    {
        trace(2,"(ACL) Failed to update Alias value '%s' to ACL (id: '%s')",alias,id);
        return 501;
    }
    
    return 0;
}


//-----------------------------------------------------------------------------
//
//                      SIR xml handling (Session-User Relationship)
//
//-----------------------------------------------------------------------------
/**
 * Create empty SIR document containing only begin and end elments os SIR
 *
 * @return SIR IXML_Document
 */
IXML_Document *SIR_init()
{
    return ixmlParseBuffer("<SIR></SIR>");
}


/**
 * Add new Session/Identity -pair into SIR. If session with same id already exist in SIR,
 * error is returned.
 * Identity is current username or id identifier created from client's certificate.
 * Rolelist contains union of roles asigned for CP in ACL and roles of username which CP may
 * have logged in. 
 * NOTE:rolelist also automatically adds "lower roles" to rolelist. For example if role parameter
 *      contains role "Admin" then also roles "Basic" and "Public" are added to rolelist. Value of 
 *      rolelist would in this case be rolelist>Public Basic Admin</rolelist>
 * 
 * Logindata contains information received/send in GetUserLoginChallenge. "name" is username/
 * role that CP wishes to login, "challenge" is value of challenge that device send for CP
 * as response for GetUserLoginChallenge.
 * 
 * Challenge is base64 encoded strings.
 *
 * <SIR>
 *  <session id="AHHuendfn372jsuGDS==" active="1">
 *      <identity>username</identity>
 *      <rolelist>Public</rolelist>
 *      <logindata>
 *          <name>Admin</name>
 *          <challenge>83h83288J7YGHGS778jsJJHGDn=</challenge>
 *      </logindata>
 *  </session>
 * </SIR>
 *
 * @param doc SIR IXML_Document
 * @param id Session identifier. uuid created form certificate. Value of id-attribute
 * @param active Is session active. Value of active-attribute
 * @param identity Value of identity element
 * @param role Value of rolelist element
 * @param attempts Value of "loginattempts" attribute
 * @param loginName Username or role that CP wishes to login. If this parameter is given, also loginChallenge must be given.
 * @param loginChallenge Login challenge which was send to CP as challenge for this login attempt. If this parameter is given, also loginName must be given.
 * @return 0 on success, -1 if same id is exist, something neagetive else.
 */
int SIR_addSession(IXML_Document *doc, const char *id, int active, const char *identity, const char *role, int *attempts, const char *loginName, const char *loginChallenge)
{
    IXML_Node *tmpNode = NULL;
    int ret = 0;
    
    // Check that same session id doesn't already exist
    tmpNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( tmpNode != NULL )
    {
        return -1;
    } 

    // create new element called "session"
    IXML_Element *sessionElement = ixmlDocument_createElement(doc, "session");
    // set id-attribute
    ixmlElement_setAttribute(sessionElement, "id", id);
    
    // set active-attribute
    if (active)
        ixmlElement_setAttribute(sessionElement, "active", "1");
    else
        ixmlElement_setAttribute(sessionElement, "active", "0");
    
    // add identity element
    if (identity)      
        AddChildNode(doc, &sessionElement->n, "identity", identity);

    // add role element
    if (role)      
        AddChildNode(doc, &sessionElement->n, "rolelist", role);
    
    // create logindata element
    if (loginName && loginChallenge)
    {
        // create new element called "logindata"
        IXML_Element *logindataElement = ixmlDocument_createElement(doc, "logindata");
        
        if (attempts == NULL)
            *attempts = 0;
        
        char tmp[2];
        snprintf(tmp, 2, "%d", *attempts);
        // add "loginattempts" attribute to logindata
        ixmlElement_setAttribute(logindataElement, "loginattempts", tmp);
        
        AddChildNode(doc, &logindataElement->n, "name", loginName);
        AddChildNode(doc, &logindataElement->n, "challenge", loginChallenge); 
        
        // add logindata as child of session
        ixmlNode_appendChild(&sessionElement->n, &logindataElement->n);
    }
    

    // add session to SIR
    IXML_NodeList *nodeList = NULL;
    nodeList = ixmlDocument_getElementsByTagName( doc, "SIR" );

    if ( nodeList )
    {
        if ( ( tmpNode = ixmlNodeList_item( nodeList, 0 ) ) )    
            ixmlNode_appendChild(tmpNode, &sessionElement->n);
        else
            ret = -2;
    }
    
    //fprintf(stderr,"\n\n\n%s\n",ixmlPrintDocument(doc));
    if ( nodeList ) ixmlNodeList_free( nodeList ); 
    return ret;
}


/**
 * Update values of Session with given identifier id to SIR.
 * Any of the values, except id, may be NULL. If value is NULL, existing old value is left 
 * untouched. 
 * Value of "rolelist" will be an union of old and new roles.
 *
 * <SIR>
 *  <session id="AHHuendfn372jsuGDS==" active="1">
 *      <identity>username</identity>
 *      <rolelist>Public Basic</rolelist>
 *      <logindata loginattempts="5">
 *          <name>Admin</name>
 *          <challenge>83h83288J7YGHGS778jsJJHGDn=</challenge>
 *      </logindata>
 *  </session>
 * </SIR>
 *
 * @param doc SIR IXML_Document
 * @param id Session id. Value of id-attribute
 * @param active Pointer to new value of "active"
 * @param identity New value of "identity"
 * @param roles New value added to "rolelist". "Value of rolelist" is union of old roles and new roles 
 * @param attempts Value of "loginattempts" attribute
 * @param loginName New value of "name"
 * @param loginChallenge New value of "challenge"
 * @return 0 on success, negative integer else
 */
int SIR_updateSession(IXML_Document *doc, const char *id, int *active, const char *identity, const char *roles, int *attempts, const char *loginName, const char *loginChallenge)
{
    IXML_Node *tmpNode = NULL;
    int ret = 0;
    char *oldIdentity = NULL;
    char *oldRole = NULL;
    int oldActive = 0;
    int oldAttempts = 0;
    char *oldLoginName = NULL;
    char *oldLoginChallenge = NULL;
    char *newRoleList = NULL;
    
    int newActive = 0;
    int newAttempts = 0;
    char *newIdentity = NULL;
    char *newRole = NULL;
    char *newLoginName = NULL;
    char *newLoginChallenge = NULL;    
    
    // Check if session id does exist
    tmpNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( tmpNode == NULL )
    {
        return -1;
    }
    
    // get old values
    oldIdentity = SIR_getIdentityOfSession(doc, id, &oldActive, &oldRole);
    ret = SIR_getLoginDataOfSession(doc, id, &oldAttempts, &oldLoginName, &oldLoginChallenge);
    
    if (active != NULL)
        newActive = *active;
    else 
        newActive = oldActive;
    
    if (identity != NULL)
        newIdentity = (char *)identity;
    else
        newIdentity = oldIdentity;

    if (roles != NULL)
    {   
        // create union of old and new roles    
        newRoleList = (char *)malloc(strlen(roles) + strlen(oldRole)+1);
        strcpy(newRoleList, oldRole);
        
        char rolelist[strlen(roles)];    
        // go through all roles in list
        strcpy(rolelist,roles);   
        char *role = strtok(rolelist, " ");
        if (role)
        {
            do 
            {
                // do "raw" check that this role isn't already in current roles
                if ( strstr(newRoleList,role) == NULL )
                {
                    // add new role at the end of rolelist
                    if (strlen(newRoleList) > 0)
                        strcat(newRoleList, " ");
                    strcat(newRoleList, role);
                }
                    
            } while ((role = strtok(NULL, " ")));
    
        }       
        newRole = newRoleList;     
    }
    else
        newRole = oldRole;

    if (attempts != NULL)
        newAttempts = *attempts;
    else 
        newAttempts = oldAttempts;
        
    if (loginName != NULL)
        newLoginName = (char *)loginName;
    else
        newLoginName = oldLoginName;        

    if (loginChallenge != NULL)
        newLoginChallenge = (char *)loginChallenge;
    else
        newLoginChallenge = oldLoginChallenge;    
    
    // first remove old session, then add new
    SIR_removeSession(doc, id);
    
    return SIR_addSession(doc, id , newActive, newIdentity, newRole, &newAttempts, newLoginName, newLoginChallenge);
}


/**
 * Remove Session with given id from SIR.
 *
 * @param doc SIR IXML_Document
 * @param id Session id. Value of id-attribute
 * @return 0 on success, -1 else
 */
int SIR_removeSession(IXML_Document *doc, const char *id)
{
    IXML_Node *tmpNode = NULL;
    
    // Check that same session id doesn't already exist
    tmpNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( tmpNode != NULL )
    {
        return RemoveNode(tmpNode); 
    }
    
    // there's no session with that id at all
    return 0; 
}


/**
 * Get identity correspondign given id where id means that cool uuid thingy
 *
 * <SIR>
 *  <session id="e7fd60a2-2053-447d-be2f-45f2d611cd1a" active="1">
 *      <identity>username</identity>
 *      <rolelist>Basic</rolelist>
 *  </session>
 * </SIR>
 *
 * @param doc SIR IXML_Document
 * @param id Session id. Value of id-attribute
 * @param active Pointer to integer where value of "active" attribute is inserted 0 or 1
 * @param role Pointer to string where value of "rolelist" is inserted
 * @return Identity or NULL
 */
char *SIR_getIdentityOfSession(IXML_Document *doc, const char *id, int *active, char **role)
{
    IXML_Node *sessionNode = NULL;
    IXML_Node *tmpNode = NULL;
    char *act = NULL;
    
    // initial presumption is that session is not active
    *active = 0;
    
    // Check that session id does exist
    sessionNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( sessionNode != NULL )
    {
        // set value of active. Is session still active, or has user logged out
        act = GetAttributeValueOfNode(sessionNode, "active");
        if ( strcmp(act, "1") == 0 )
            *active = 1;
        
        // get value of childnode "rolelist"
        tmpNode = GetChildNodeWithName(sessionNode, "rolelist");
        if ( tmpNode != NULL )
            *role = GetTextValueOfNode(tmpNode);
        else
            *role = NULL;    
        
        // get value of childnode "identity"
        tmpNode = GetChildNodeWithName(sessionNode, "identity");
        if ( tmpNode != NULL )
            return GetTextValueOfNode(tmpNode); 
    } 
    
    return NULL;
}


/**
 * Get login data from session with given identifier id.
 *
 * <SIR>
 *  <session id="AHHuendfn372jsuGDS==" active="1">
 *      <identity>username</identity>
 *      <logindata>
 *          <name>Admin</name>
 *          <challenge>83h83288J7YGHGS778jsJJHGDn=</challenge>
 *      </logindata>
 *  </session>
 * </SIR>
 *
 * @param doc SIR IXML_Document
 * @param id Session id. Value of id-attribute
 * @param loginattempts Pointer to integer where value of "loginattempts" attribute is inserted
 * @param loginName Pointer to string where value of "name" of logindata  is inserted
 * @param loginChallenge Pointer to string where value of "challenge" of logindata  is inserted
 * @return 0 on success, negative value else.
 */
int SIR_getLoginDataOfSession(IXML_Document *doc, const char *id, int *loginattempts, char **loginName, char **loginChallenge)
{
    IXML_Node *tmpNode = NULL;
    
    if (id == NULL)
        return -1;
    
    // Check that session id does exist
    tmpNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( tmpNode == NULL )
        return -1;
    
    // get logindata element
    tmpNode = GetChildNodeWithName(tmpNode, "logindata");
    if ( tmpNode == NULL )
        return -2;    

    char *tmp = GetAttributeValueOfNode(tmpNode, "loginattempts");
    if (tmp)
        *loginattempts = atoi(tmp);
    else
        *loginattempts = 0; 
    
    // get name element
    tmpNode = GetChildNodeWithName(tmpNode, "name");
    if ( tmpNode == NULL )
        return -3;    
    // get value of "name"
    *loginName = GetTextValueOfNode(tmpNode);
    
    // get challenge element
    tmpNode = GetSiblingWithTagName(tmpNode, "challenge");
    if ( tmpNode == NULL )
        return -4;    
    // get value of "name"
    *loginChallenge = GetTextValueOfNode(tmpNode);
    
    return 0;
}


/**
 * Remove logindata from session with given identifier id.
 *
 * @param doc SIR IXML_Document
 * @param id Session id. Value of id-attribute
 * @return 0 on success, negative value else.
 */
int SIR_removeLoginDataOfSession(IXML_Document *doc, const char *id)
{
    IXML_Node *tmpNode = NULL;
    
    // get session node
    tmpNode = GetNodeWithNameAndAttribute(doc, "session", "id", id);
    if ( tmpNode == NULL )
        return -1;
        
    // get logindata node of session
    tmpNode = GetChildNodeWithName(tmpNode, "logindata");
    if ( tmpNode == NULL )
        return 0;
    
    return RemoveNode(tmpNode);
}
