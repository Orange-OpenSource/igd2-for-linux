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

