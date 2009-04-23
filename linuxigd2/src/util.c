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
    
    nodeList = ixmlDocument_getElementsByTagName( doc, nodeName );

    if (nodeList)
    {
        listLen = ixmlNodeList_length(nodeList);
        
        for (i = 0; i < listLen; i++)
        {
            if ( ( tmpNode = ixmlNodeList_item( nodeList, i ) ) )
            {
                if (strcmp( GetTextValueOfNode(tmpNode),  nodeValue) == 0)
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
