/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
 *  
 * This file is part of igd2-for-linux project
 * Copyright © 2011 France Telecom.
 * Contact: fabrice.fontaine@orange-ftgroup.com
 * Developer(s): fabrice.fontaine@orange-ftgroup.com, rmenard.ext@orange-ftgroup.com
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <net/if.h>
#include <upnp/upnp.h>
#include <upnp/upnpconfig.h>
#include "globals.h"
#include "config.h"
#include "gatedevice.h"
#include "util.h"
#include "pmlist.h"
#include "lanhostconfig.h"
#include "wanipv6fw.h"
#include <locale.h>



// Global variables
globals g_vars;

int main (int argc, char** argv)
{
    // http://ipaddr:port/docName<null>
    char descDocUrl[7+INET_ADDRSTRLEN+1+5+1+sizeof(g_vars.descDocName)+1];

#ifdef UPNP_ENABLE_IPV6
    // http://[ipaddr6]:port/docName<null>
    char descDocUrlv6[7+INET6_ADDRSTRLEN+1+5+1+sizeof(g_vars.descDocName)+1];
    char descDocUrlUlaGua[7+INET6_ADDRSTRLEN+1+5+1+sizeof(g_vars.descDocName)+1];
#endif

    deviceHandle = 0;
    deviceHandleIPv6 = 0;
    deviceHandleIPv6UlaGua = 0;

    char intIpAddress[INET6_ADDRSTRLEN];     // Server internal ip address updated IPv6 address length 16 -> 46
    sigset_t sigsToCatch;
    int ret, signum, arg = 1, foreground = 0;

    if (!setlocale(LC_CTYPE, "")) {
      fprintf(stderr, "Can't set the specified locale! "
              "Check LANG, LC_CTYPE, LC_ALL.\n");
      return 1;
    }


    if (argc < 3 || argc > 4)
    {
        printf("Usage: upnpd [-f] <external ifname> <internal ifname>\n");
        printf("  -f\tdon't daemonize\n");
        printf("Example: upnpd ppp0 eth0\n");
        exit(0);
    }

    if(parseConfigFile(&g_vars))
    {
        perror("Error parsing config file");
        exit(0);
    }

    if(!g_vars.ipv4Enabled && !g_vars.ipv6UlaGuaEnabled && !g_vars.ipv6LinkLocalEnabled)
    {
        perror("Error IPv4 and IPv6 are disabled");
        exit(0);
    }

    // check for '-f' option
    if (strcmp(argv[arg], "-f") == 0)
    {
        foreground = 1;
        arg++;
    }

    // Save interface names for later use
    strncpy(g_vars.extInterfaceName, argv[arg++], IFNAMSIZ);
    strncpy(g_vars.intInterfaceName, argv[arg++], IFNAMSIZ);

    // Get the internal ip address to start the daemon on
    if (GetIpAddressStr(intIpAddress, g_vars.intInterfaceName) == 0)
    {
        // Check if IP has been set by avahi-autoipd which uses aliases :avahi or :3 (br-lan:3)
        char tempIface[IFNAMSIZ];
        strncpy(tempIface, g_vars.intInterfaceName, IFNAMSIZ);
        strncat(tempIface,":3",IFNAMSIZ);
        if (GetIpAddressStr(intIpAddress, tempIface) != 0)
        {
            strncpy(g_vars.intInterfaceName, tempIface, IFNAMSIZ);
            trace(2,"Using %s as internal interface configured by avahi-autoipd\n",g_vars.intInterfaceName);
        }
        else
        {
            strncpy(tempIface, g_vars.intInterfaceName, IFNAMSIZ);
            strncat(tempIface,":avahi",IFNAMSIZ);
            if (GetIpAddressStr(intIpAddress, tempIface) != 0)
            {
                strncpy(g_vars.intInterfaceName, tempIface, IFNAMSIZ);
                trace(2,"Using %s as internal interface configured by avahi-autoipd\n",g_vars.intInterfaceName);
            }
            else
            {
                fprintf(stderr, "Invalid internal interface name '%s'\n", g_vars.intInterfaceName);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (!foreground)
    {
        struct rlimit resourceLimit =
        {
            0, 0
        };
        pid_t pid, sid;
        unsigned int i;

        // Put igd in the background as a daemon process.
        pid = fork();
        if (pid < 0)
        {
            perror("Error forking a new process.");
            exit(EXIT_FAILURE);
        }
        if (pid > 0)
            exit(EXIT_SUCCESS);

        // become session leader
        if ((sid = setsid()) < 0)
        {
            perror("Error running setsid");
            exit(EXIT_FAILURE);
        }

        // close all file handles
        resourceLimit.rlim_max = 0;
        ret = getrlimit(RLIMIT_NOFILE, &resourceLimit);
        if (ret == -1) /* shouldn't happen */
        {
            perror("error in getrlimit()");
            exit(EXIT_FAILURE);
        }
        if (0 == resourceLimit.rlim_max)
        {
            fprintf(stderr, "Max number of open file descriptors is 0!!\n");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < resourceLimit.rlim_max; i++)
            close(i);

        // fork again so child can never acquire a controlling terminal
        pid = fork();
        if (pid < 0)
        {
            perror("Error forking a new process.");
            exit(EXIT_FAILURE);
        }
        if (pid > 0)
            exit(EXIT_SUCCESS);

        if ((chdir("/")) < 0)
        {
            perror("Error setting root directory");
            exit(EXIT_FAILURE);
        }
    }

    umask(0);

// End Daemon initialization

    openlog("upnpd", LOG_CONS | LOG_NDELAY | LOG_PID | (foreground ? LOG_PERROR : 0), LOG_LOCAL6);

    // Initialize UPnP SDK on the internal Interface
    trace(3, "Initializing UPnP SDK ... ");
#ifdef UPNP_ENABLE_IPV6
    if ( (ret = UpnpInit2(g_vars.intInterfaceName,g_vars.listenport) ) != UPNP_E_SUCCESS)
#else
    if ( (ret = UpnpInit(intIpAddress,g_vars.listenport) ) != UPNP_E_SUCCESS)
#endif
    {
        syslog (LOG_ERR, "Error Initializing UPnP SDK on IP %s port %d",intIpAddress,g_vars.listenport);
        syslog (LOG_ERR, "  UpnpInit returned %d", ret);
        UpnpFinish();
        exit(1);
    }
    trace(2, "UPnP SDK Successfully Initialized.");
    
    // Set the Device Web Server Base Directory
    trace(3, "Setting the Web Server Root Directory to %s",g_vars.xmlPath);
    if ( (ret = UpnpSetWebServerRootDir(g_vars.xmlPath)) != UPNP_E_SUCCESS )
    {
        syslog (LOG_ERR, "Error Setting Web Server Root Directory to: %s", g_vars.xmlPath);
        syslog (LOG_ERR, "  UpnpSetWebServerRootDir returned %d", ret);
        UpnpFinish();
        exit(1);
    }
    trace(2, "Succesfully set the Web Server Root Directory.");

    //initialize the timer thread for expiration of mappings
    if (ExpirationTimerThreadInit()!=0)
    {
        syslog(LOG_ERR,"ExpirationTimerInit failed");
        UpnpFinish();
        exit(1);
    }

    InitFirewallv6();

    /**
     * IPv4 register
     */
    if(g_vars.ipv4Enabled)
    {
        // Form the Description Doc URL to pass to RegisterRootDevice
        sprintf(descDocUrl, "http://%s:%d/%s", UpnpGetServerIpAddress(),
                UpnpGetServerPort(), g_vars.descDocName);

        // Register our IGD as a valid UPnP Root device for IPv4
        trace(3, "IPv4 Registering the root device with descDocUrl %s for byebye sending", descDocUrl);
        if ( (ret = UpnpRegisterRootDevice3(descDocUrl, EventHandler, &deviceHandle,
                &deviceHandle, AF_INET)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
    }

#ifdef UPNP_ENABLE_IPV6
    /**
     * IPv6 register
     */
    if(g_vars.ipv6UlaGuaEnabled)
    {
        //registering the ULA or GUA address
        if(strlen(UpnpGetServerUlaGuaIp6Address())>0)
        {
            sprintf(descDocUrlUlaGua, "http://[%s]:%d/%s", UpnpGetServerUlaGuaIp6Address(),
                    UpnpGetServerPort6(), g_vars.descDocName);
            trace(3, "IPv6 Registering the root device with descDocUrlUlaGua %s for byebye sending", descDocUrlUlaGua);
            if ( (ret = UpnpRegisterRootDevice3(descDocUrlUlaGua, EventHandler, &deviceHandleIPv6UlaGua,
                    &deviceHandleIPv6UlaGua, AF_INET6)) != UPNP_E_SUCCESS )
            {
                syslog(LOG_ERR, "IPv6 Error registering the root device with descDocUrl: %s", descDocUrlUlaGua);
                syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
                UpnpFinish();
                exit(1);
            }
        }
        else strcpy(descDocUrlUlaGua, "");
    }

    if(g_vars.ipv6LinkLocalEnabled)
    {
        //registering the link local address
        sprintf(descDocUrlv6, "http://[%s]:%d/%s", UpnpGetServerIp6Address(),
                UpnpGetServerPort6(), g_vars.descDocName);
        trace(3, "IPv6 Registering the root device with descDocUrl %s for byebye sending", descDocUrlv6);
        if ( (ret = UpnpRegisterRootDevice3(descDocUrlv6, EventHandler, &deviceHandleIPv6,
                &deviceHandleIPv6, AF_INET6)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "IPv6 Error registering the root device with descDocUrl: %s", descDocUrlv6);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
    }
#endif

    // This should be moved into libupnp if this is going to be part of UDA1.1?
    /*
     * From WANIPConnection spec:
     * UPnP IGD MUST broadcast an ssdp:byebye before sending the initial ssdp:alive onto 
     * the local network upon startup. Sending an ssdp:byebye as part of the normal start 
     * up process for a UPnP device ensures that UPnP control points with information about 
     * the previous device instance will safely discard state information about the previous 
     * device instance before communicating with the new device instance.
     * 
     * NOTE: LOCATION header field value might be false because portnumber might have changed since 
     * last shutdown. But LOCATION is not needed in byebye's... 
     */
    if(g_vars.ipv4Enabled)
    {
        trace(3, "Send initial sspd:byebye messages");
        UpnpUnRegisterRootDevice(deviceHandle); // this will send byebye's
    }

#ifdef UPNP_ENABLE_IPV6
    if(g_vars.ipv6UlaGuaEnabled)
    {
        if(strlen(descDocUrlUlaGua) > 0) {
            UpnpUnRegisterRootDevice(deviceHandleIPv6UlaGua);
            trace(3, "IPv6 sending byebye on ULA or GUA");
        }
    }

    if(g_vars.ipv6LinkLocalEnabled)
    {
        UpnpUnRegisterRootDevice(deviceHandleIPv6);
        trace(3, "IPv6 sending byebye on Link Local");
    }
#endif


    if(g_vars.ipv4Enabled)
    {
        // Register our IGD as a valid UPnP Root device
        trace(3, "IPv4 Registering the root device again with descDocUrl %s", descDocUrl);
        if ( (ret = UpnpRegisterRootDevice3(descDocUrl, EventHandler, &deviceHandle,
                &deviceHandle, AF_INET)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
    }

#ifdef UPNP_ENABLE_IPV6
    /**
     * Added for IPv6
     */
    if(g_vars.ipv6UlaGuaEnabled)
    {
        if(strlen(descDocUrlUlaGua) > 0)
        {
            trace(3, "IPv6 Registering the root device again with descDocUrlUlaGua %s", descDocUrlUlaGua);
            if ( (ret = UpnpRegisterRootDevice3(descDocUrlUlaGua, EventHandler, &deviceHandleIPv6UlaGua,
                    &deviceHandleIPv6UlaGua, AF_INET6)) != UPNP_E_SUCCESS )
            {
                syslog(LOG_ERR, "IPv6 Error registering the root device with descDocUrl: %s", descDocUrlUlaGua);
                syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
                UpnpFinish();
                exit(1);
            }
        }
    }

    if(g_vars.ipv6LinkLocalEnabled)
    {
        //registering link local address
        trace(3, "IPv6 Registering the root device again with descDocUrl %s", descDocUrlv6);
        if ( (ret = UpnpRegisterRootDevice3(descDocUrlv6, EventHandler, &deviceHandleIPv6,
                &deviceHandleIPv6, AF_INET6)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "IPv6 Error registering the root device with descDocUrl: %s", descDocUrlv6);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
    }
#endif
    //end of byebye

    trace(2, "IGD root device successfully registered.");

    // Initialize the state variable table.
    if(g_vars.ipv4Enabled)
        StateTableInit(descDocUrl);
#ifdef UPNP_ENABLE_IPV6
    else if(g_vars.ipv6LinkLocalEnabled)
        StateTableInit(descDocUrlv6);
    else
        StateTableInit(descDocUrlUlaGua);
#endif

    // Initialize lanhostconfig module
    InitLanHostConfig();

    if(g_vars.ipv4Enabled)
    {
        // Send out initial advertisements of our device's services (with timeouts of 30 minutes, default value,can be changed from config file)
        if ( (ret = UpnpSendAdvertisement(deviceHandle, g_vars.advertisementInterval) != UPNP_E_SUCCESS ))
        {
            syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
            UpnpFinish();
            exit(1);
        }
        trace(2, "IPv4 Advertisements Sent. Advertisement sending interval set to %d seconds.  Listening for requests ...",g_vars.advertisementInterval);
    }

#ifdef UPNP_ENABLE_IPV6
    if(g_vars.ipv6UlaGuaEnabled)
    {
        if(strlen(descDocUrlUlaGua) > 0 )
        {
            if ( (ret = UpnpSendAdvertisement(deviceHandleIPv6UlaGua, g_vars.advertisementInterval) != UPNP_E_SUCCESS ))
            {
                syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
                UpnpFinish();
                exit(1);
            }
            trace(2, "IPv6 Advertisements Sent for ULA or GUA. Advertisement sending interval set to %d seconds.  Listening for requests ...",g_vars.advertisementInterval);
        }
    }

    if(g_vars.ipv6LinkLocalEnabled)
    {
        if ( (ret = UpnpSendAdvertisement(deviceHandleIPv6, g_vars.advertisementInterval) != UPNP_E_SUCCESS ))
        {
            syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
            UpnpFinish();
            exit(1);
        }
        trace(2, "IPv6 Advertisements Sent on Link Local. Advertisement sending interval set to %d seconds.  Listening for requests ...",g_vars.advertisementInterval);
    }
#endif
    trace(2, "Advertisements Sent. Advertisement sending interval set to %d seconds.  Listening for requests ...",g_vars.advertisementInterval);

    // Loop until program exit signals received
    do
    {
        sigemptyset(&sigsToCatch);
        sigaddset(&sigsToCatch, SIGINT);
        sigaddset(&sigsToCatch, SIGTERM);
        sigaddset(&sigsToCatch, SIGUSR1);
        pthread_sigmask(SIG_SETMASK, &sigsToCatch, NULL);
        sigwait(&sigsToCatch, &signum);
        trace(3, "Caught signal %d...\n", signum);
        switch (signum)
        {
        case SIGUSR1:
            DeleteAllPortMappings();
            CloseFirewallv6();
            break;
        default:
            break;
        }
    }
    while (signum!=SIGTERM && signum!=SIGINT);

    if(g_vars.ipv4Enabled)
    {
        UpnpUnRegisterRootDevice(deviceHandle);
        trace(3, "IPv4 sending byebye");
    }

#ifdef UPNP_ENABLE_IPV6
    if(g_vars.ipv6UlaGuaEnabled)
    {
        if(strlen(descDocUrlUlaGua) > 0)
        {
            UpnpUnRegisterRootDevice(deviceHandleIPv6UlaGua);
            trace(3, "IPv6 sending byebye on ULA GUA");
        }
    }

    if(g_vars.ipv6LinkLocalEnabled)
    {
        UpnpUnRegisterRootDevice(deviceHandleIPv6);
        trace(3, "IPv6 sending byebye on Link Local");
    }
#endif

    trace(2, "Shutting down on signal %d...\n", signum);

    // Cleanup UPnP SDK and free memory
    DeleteAllPortMappings();
    ExpirationTimerThreadShutdown();
    CloseFirewallv6();

    // Cleanup lanhostconfig module
    FreeLanHostConfig();

    UpnpUnRegisterRootDevice(deviceHandle);
    UpnpFinish();

    // Cleanup UDNs as they were allocated through malloc
    free(gateUDN);
    free(wanUDN);
    free(wanConnectionUDN);

    // Exit normally
    return (0);
}
