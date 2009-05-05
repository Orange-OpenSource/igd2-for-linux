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
    int slen = strlen(str);
    int wcslen;
    wchar_t wc[2*slen];  // doubling original string length should guarantee that there is enough space for wchar_t
    char *UPPER = (char *)malloc(slen);
    
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
    snprintf(tmp, 50, "/var/run/%s.pid", iface);
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
    return ret;         
}

/**
 * Get text value of given IXML_Node. Node containing 'accessLevel>Admin</accessLevel>'
 * would return 'Admin'
 *
 * @param tmpNode Node which value is returned
 * @return Value of node or NULL
 */
static char* GetTextValueOfNode(IXML_Node *tmpNode)
{
    IXML_Node *textNode = NULL;
    char *value = NULL;
    
    if ( tmpNode )
    {
        textNode = ixmlNode_getFirstChild( tmpNode );
        if ( textNode )
        {
            value = strdup(ixmlNode_getNodeValue(textNode));
        }
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
 * @return Node or NULL
 */
static IXML_Node *GetNodeWithValue(IXML_Document *doc, const char *nodeName, const char *nodeValue)
{
    int listLen, i;
    IXML_NodeList *nodeList = NULL;
    IXML_Node *tmpNode = NULL;
    char *tmp = NULL; 
    
    nodeList = ixmlDocument_getElementsByTagName( doc, nodeName );

    if (nodeList)
    {
        listLen = ixmlNodeList_length(nodeList);
        
        for (i = 0; i < listLen; i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                tmp = GetTextValueOfNode(tmpNode);
                if ( tmp && (strcmp( tmp,  nodeValue) == 0))
                {
                    ixmlNodeList_free( nodeList );
                    return tmpNode;
                }                
            }            
        }
    }
    if ( nodeList ) ixmlNodeList_free( nodeList );
    
    return NULL;
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
static IXML_Node *AddChildNode(IXML_Document *doc, IXML_Node *parent, const char *childNodeName, const char *childNodeValue)
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
static int RemoveNode(IXML_Node *node)
{
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
 * @param actionName Name of action
 * @param manage Is value of accessLevelManage (1) or accessLevel (0) returned.
 * @return Access level string or NULL
 */
char* getAccessLevel(const char *actionName, int manage)
{
    char *accesslevel = NULL;
    
    // lets assume that there is only one action with same name in document
    IXML_Node *tmpNode = GetNodeWithValue(accessLevelDoc, "name", actionName);
    
    if (tmpNode == NULL) return NULL;
    
    // get accessLevel
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
    
    return accesslevel;
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
   <Hash type=“DP:1”>TM0NZomIzI2OTsmIzM0NTueYgi93Q==</Hash>
   <RoleList>Admin Basic</RoleList>
</CP>
<CP>
   <Name>Some CP</Name>
   <Hash type=“DP:1”>feeNZomIfI2erfrmIzefTufew==</Hash>
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
 * Get rolenames that are defined for identity with "id" id .
 * Rolenames are returned as space separated: role1 role2
 * Returned value must be released with free()
 *
 * @param doc ACL IXML_Document
 * @param id id attribute of identity
 * @return Roles as space separated string, or empty string if no roles found, or NULL if error occurs.
 */
static char *ACL_getRolesOfID(IXML_Document *doc, const char *id)
{
    char *roleref = NULL;
    char *rolename = NULL;
    char *rolelist= (char *)malloc(100 * sizeof(char));
    strcpy(rolelist,"");  

    IXML_Node *tmpNode = NULL;
    IXML_Node *roleRefNode = NULL;
    
    // get identity/role pairs: Entry-element with attribute identity and value id
    tmpNode = GetNodeWithNameAndAttribute(doc, "Entry", "identity", id);
    if (tmpNode == NULL) return NULL;
    
    // get first RoleRef-node
    roleRefNode = ixmlNode_getFirstChild(tmpNode);
    
    do
    {
        // get value of attribute "role"
        roleref = GetAttributeValueOfNode(roleRefNode,"role");
        if (roleref == NULL) continue;
        
        // get element named "Role" with attribute "id" and value roleref
        tmpNode = GetNodeWithNameAndAttribute(doc, "Role", "id", roleref);
        if (tmpNode == NULL) continue;
        
        // get rolename
        rolename = GetTextValueOfNode(tmpNode);
        if (rolename == NULL) continue;
        
        strcat(rolelist,rolename);
        strcat(rolelist," ");
        
        // get next RoleRef element from Entry
    } while ((roleRefNode = ixmlNode_getNextSibling(roleRefNode)));
    
    //remove last extra comma
    if (strlen(rolelist) > 0)
        rolelist[strlen(rolelist)-1] = '\0';
        
    return rolelist;  
}


/**
 * Add roles for user/CP with given id. 
 * 
 * @param doc ACL IXML_Document
 * @param id id attribute of identity
 * @return Roles as space separated string, or empty string if no roles found, or NULL if error occurs.
 */
static int ACL_addRolesForId(IXML_Document *doc, const char *id, const char *roles)
{
    int ret = ACL_SUCCESS;
    char *role;
    char *roleid = NULL;
    char rolelist[strlen(roles)];
    IXML_Node *entryNode = NULL;
    IXML_Node *tmpNode = NULL;

    // needs to check first if there is Entry with same id!!!
    // if is, add new rolerefs there
    entryNode = GetNodeWithNameAndAttribute(doc, "Entry", "identity", id);
    
    if (entryNode == NULL)
    {
        // create new element called "Entry"
        IXML_Element *entry = ixmlDocument_createElement(doc, "Entry");
    
        // set attributes for "Entry"
        ixmlElement_setAttribute(entry, "identity", id);
        entryNode = &entry->n;
    }

    // go through all roles in list
    strcpy(rolelist,roles);   
    role = strtok(rolelist, " ");
    if (role)
    {
        do 
        {
            tmpNode = GetNodeWithValue(doc, "Role", role);
            if ( tmpNode == NULL )
            {
                return ACL_ROLE_ERROR;
            }        
            roleid = GetAttributeValueOfNode(tmpNode, "id");
            if (roleid == NULL)
            {
                return ACL_COMMON_ERROR;
            }
            
            // check if RoleRef with same role id already exist for this entry
            tmpNode = GetChildNodeWithAttribute(entryNode, "RoleRef", NULL, "role", roleid);
            if (tmpNode == NULL)
                // insert new Roleref
                tmpNode = AddChildNodeWithAttribute(doc, entryNode, "RoleRef", "", "role", roleid);
                
        } while ((role = strtok(NULL, " ")));

    }

    IXML_NodeList *nodeList = ixmlDocument_getElementsByTagName( doc, "Entries" );
    if ( nodeList )
    {
        if ( ( tmpNode = ixmlNodeList_item( nodeList, 0 ) ) ) // only one <Entries> allowed in document
            ixmlNode_appendChild(tmpNode, entryNode);
        else
            ret = ACL_COMMON_ERROR;
    }

 
    if ( nodeList ) ixmlNodeList_free( nodeList );
    return ret;
}


/**
 * Get rolenames that are defined for given username in ACL.
 * Rolenames are returned as comma separated: role1,role2
 * Returned value must be released with free()
 *
 * @param doc ACL IXML_Document
 * @param username Username whose roles are returned
 * @return Roles as comma separated string, or empty string if no roles found, or NULL if error occurs.
 */
char *ACL_getRolesOfUser(IXML_Document *doc, const char *username)
{
    // get element with name "User" and value username
    IXML_Node *tmpNode = GetNodeWithValue(doc, "User", username);
    if (tmpNode == NULL) return NULL;    
    
    // get value of attribute named "id"
    char *id = GetAttributeValueOfNode(tmpNode,"id");
    if (id == NULL) return NULL;    
    
    return ACL_getRolesOfID(doc, id);
}

/**
 * Get rolenames that are defined for control point with "Hash" hash.
 * Rolenames are returned as comma separated: role1,role2
 * Returned value must be released with free()
 *
 * @param doc ACL IXML_Document
 * @param hash Value of Hash element
 * @return Roles as comma separated string, or empty string if no roles found, or NULL if error occurs.
 */
char *ACL_getRolesOfCP(IXML_Document *doc, const char *hash)
{
    // get element with name "Hash" and value hash
    IXML_Node *tmpNode = GetNodeWithValue(doc, "Hash", hash);
    if (tmpNode == NULL) return NULL;    

    // get parent node of "Hash" which is "CP"
    tmpNode = ixmlNode_getParentNode(tmpNode);
    if (tmpNode == NULL) return NULL;

    // get value of attribute named "id"
    char *id = GetAttributeValueOfNode(tmpNode,"id");
    if (id == NULL) return NULL;    

    return ACL_getRolesOfID(doc, id);  
}

/**
 * Create XML representation of rolenames for use with GetCurrentRoles action
 * <Roles>
 * <Role>Admin</Role>
 * </Roles>
 * 
 * If csv_roles is empty string or NULL, returned XML is this:
 * <Roles>
 * <Role>Public</Role>
 * </Roles>
 * 
 * Returned string must be released with free()
 *
 * @param csv_roles Roles in space separated string
 * @return XML as string
 */
char *ACL_createRoleListXML(const char *csv_roles)
{
    if (csv_roles == NULL || strlen(csv_roles) == 0)
        return "<Roles><Role>Public</Role></Roles>";

    char *role;
    char *xml = (char *)malloc(400 * sizeof(char));
    
    char roles[strlen(csv_roles)];
    
    strcpy(xml,"<Roles>");
    strcpy(roles,csv_roles);
    
    role = strtok(roles, " ");
    
    if (role)
    {
        strcat(xml,"<Role>");
        strcat(xml,role);
        strcat(xml,"</Role>");
    }
    
    while ((role = strtok(NULL, " ")))
    {       
        strcat(xml,"<Role>");
        strcat(xml,role);
        strcat(xml,"</Role>");
    }
    
    strcat(xml,"</Roles>");    
    return xml;
}


/**
 * Add new Control point into ACL xml.
 *
 * <CP introduced="1">
 *    <Name>ACME Widget Model XYZ</Name>
 *    <Alias>Mark’s Game Console</Alias>
 *    <Hash type="DP:1">TM0NZomIzI2OTsmIzM0NTueYgi93Q==</Hash>
 *    <RoleList>Admin Basic</RoleList>
 * </CP>
 * 
 * @param doc ACL IXML_Document
 * @param name Value of Name element
 * @param alias Value of Alias element
 * @param hash Value of Hash element
 * @param type Value of type-attribute in hash-element 
 * @param roles Value of RoleList element
 * @param introduced Does "CP" has attribute introduced with value 1 (0 means no, 1 yes)
 * @return ACL_SUCCESS on success, ACL_USER_ERROR if same hash already exist in ACL, ACL_COMMON_ERROR else
 */
int ACL_addCP(IXML_Document *doc, const char *name, const char *alias, const char *hash, const char *type, const char *roles, int introduced)
{
    // Check that hash doesn't already exist
    if ( GetNodeWithValue(doc, "Hash", hash) != NULL )
    {
        return ACL_USER_ERROR;
    } 
    
    int ret = ACL_SUCCESS;
    
    // create new element called "CP"
    IXML_Element *CP = ixmlDocument_createElement(doc, "CP");

    if (introduced)
        ixmlElement_setAttribute(CP, "introduced", "1");
        
    AddChildNode(doc, &CP->n, "Name", name);
    AddChildNode(doc, &CP->n, "Alias", alias);
    AddChildNodeWithAttribute(doc, &CP->n, "Hash", hash, "type", type);
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
    if ( GetNodeWithValue(doc, "Name", name) != NULL )
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
 * @return ACL_SUCCESS on success, -1 else. 
 */
int ACL_removeUser(IXML_Document *doc, const char *name)
{
    IXML_Node *userNode = NULL;  
    
    userNode = GetNodeWithValue(doc, "Name", name);
    if (!userNode) return ACL_SUCCESS;
    
    return RemoveNode(userNode->parentNode);
}


/**
 * Remove control point from ACL xml.
 *
 * 
 * @param doc ACL IXML_Document
 * @param hash Hash of control point which is removed from ACL
 * @return 0 on success, -1 else
 */
int ACL_removeCP(IXML_Document *doc, const char *hash)
{
    IXML_Node *hashNode = NULL;
    
    hashNode = GetNodeWithValue(doc, "Hash", hash);
    if (!hashNode) return ACL_SUCCESS;
    
    // remove <CP> node
    return RemoveNode(hashNode->parentNode);
}


/**
 * Add roles for User in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param name Username for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return ACL_SUCCESS on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_addRolesForUser(IXML_Document *doc, const char *name, const char *roles)
{
    char *id = NULL;
    IXML_Node *tmpNode = GetNodeWithValue(doc, "User", name);
    
    // Check that user does exist
    if ( tmpNode == NULL )
    {
        return ACL_USER_ERROR;
    } 
    
    // get id of user. Do not use free for id because it is free'd from document itself
    id = GetAttributeValueOfNode(tmpNode, "id");
    if (id == NULL)
    {
        return ACL_COMMON_ERROR;
    }

    return ACL_addRolesForId(doc, id, roles);
}


/**
 * Add roles for Control point in ACL xml.
 * 
 * @param doc ACL IXML_Document
 * @param hash Hash of control for which roles are added
 * @param roles Space-separated string of rolenames which are added for user (Admin Basic)
 * @return ACL_SUCCESS on succes,
 *         ACL_USER_ERROR if username is not found, 
 *         ACL_ROLE_ERROR if rolelist has invalid role
 *         ACL_COMMON_ERROR else
 */
int ACL_addRolesForCP(IXML_Document *doc, const char *hash, const char *roles)
{
    char *id = NULL;
    IXML_Node *tmpNode = GetNodeWithValue(doc, "Hash", hash);
    
    // Check that CP with hash does exist
    if ( tmpNode == NULL )
    {
        return ACL_USER_ERROR;
    } 
    
    // get id of CP. Do not use free for id because it is free'd from document itself
    id = GetAttributeValueOfNode(tmpNode->parentNode, "id");
    if (id == NULL)
    {
        return ACL_COMMON_ERROR;
    }

    return ACL_addRolesForId(doc, id, roles);
}

