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
#include <upnp/upnp.h>
#include "globals.h"


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

// if interface has IP, status id connected. Else disconnected
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

// check if IP of control point is same as ICAddress
// return 0 if not, something else if match
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

// check if parameter has a wild card
int checkForWildCard(const char *str)
{
    int retVal = 0;

    if (strchr(str, '*') != NULL)
	retVal = 1;

    return retVal;
}

// add error data to event structure
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message)
{
    ca_event->ErrCode = errorCode;
    strcpy(ca_event->ErrStr, message);
    ca_event->ActionResult = NULL;
}

/*
 * Returns true if value is "yes", "true" or "1".
 * TODO: uppercase yes/true?
 */
int resolveBoolean(char *value)
{
    if ( strcmp(value, "yes") == 0 ||
         strcmp(value, "true") == 0 ||
         strcmp(value, "1") == 0 )
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

// get document item which is at position index in nodelist (all nodes with name item)
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

// From sampleutil.c included with libupnp
char* GetFirstDocumentItem( IN IXML_Document * doc,
                            IN const char *item )
{
    return GetDocumentItem(doc,item,0);
}

/**
 * Resolve up/down status of given network interface and insert it into given string.
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
