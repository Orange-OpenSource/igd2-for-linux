/** 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
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
#include "globals.h"
#include "config.h"
#include "gatedevice.h"
#include "util.h"
#include "pmlist.h"
#include "lanhostconfig.h"
#include "deviceprotection.h"
#include "crypt.h"
#include <locale.h>
#include <gcrypt.h>
#include <errno.h> 
#include <pthread.h>


/* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
 * Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications and
 * http://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library
 * Also pupnp library is able to do this initialization, but it probably is the best 
 * if the main application does the initialization, not the libraries.
 */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

// Global variables
globals g_vars;

/**
 * Modify description document so that UDN of InternetGatewayDevice is uuid 
 * created from its X.509 certificate.
 * 
 * Modified file is written to disk.
 *
 * @param descDocFile Full path to file which is modifed
 * @return 0 on success, something else on error
 */
static int updateDescDocUuid(const char *descDocFile)
{
    int ret;
    char newValue[150];
    IXML_Node *tmpNode = NULL;

    IXML_Document *descDoc = ixmlLoadDocument(descDocFile);
    if (descDoc == NULL)
        return -1;

    // update uuid. According to the DeviceProtection, Device impelementing DP 
    // MUST have uuid created from it's certificate
    int cert_size = 10000;
    char *uuid = NULL;
    unsigned char cert[cert_size];
    unsigned char hash[cert_size];

    // get server certificate
    ret = UpnpGetHttpsServerCertificate(cert, &cert_size);
    if (ret != 0)
    {
        ixmlDocument_free(descDoc);
        return ret;
    }

    // create hash from certificate
    ret = crypt_calculate_sha256(cert, cert_size, hash);
    if (ret < 0)
    {
        ixmlDocument_free(descDoc);
        return ret;
    }

    // create uuid from certificate
    createUuidFromData(&uuid, NULL, NULL, hash, 16);
    if (uuid == NULL)
    {
        ixmlDocument_free(descDoc);
        return -2;
    }

    // replace existing uuid with new
    if ( (tmpNode = GetNode(descDoc, "UDN") ) )
    {
        snprintf(newValue, 150, "uuid:%s", uuid);
        ret = ixmlNode_setNodeValue(ixmlNode_getFirstChild(tmpNode), newValue);
    }

    free (uuid);

    if (ret != 0)
    {
        ixmlDocument_free(descDoc);
        return ret;
    }

    ret = writeDocumentToFile(descDoc, descDocFile);
    ixmlDocument_free(descDoc);

    return ret;
}

void trace_gnutls(int level, const char* str)
{
	printf("%d: %s", level, str);
}

int main (int argc, char** argv)
{
    char descDocUrl[7+15+1+5+1+sizeof(g_vars.descDocName)+1]; // http://ipaddr:port/docName<null>
    char secureDescDocUrl[8+15+1+5+1+sizeof(g_vars.descDocName)+1]; // https://ipaddr:port/docName<null>
    char intIpAddress[INET6_ADDRSTRLEN];     // Server internal ip address updated IPv6 address length 16 -> 46
    sigset_t sigsToCatch;
    int ret, signum, arg = 1, foreground = 0, non_secure = 0;

    if (!setlocale(LC_CTYPE, "")) {
      fprintf(stderr, "Can't set the specified locale! "
              "Check LANG, LC_CTYPE, LC_ALL.\n");
      return 1;
    }


    if (argc < 3 || argc > 5)
    {
        printf("Usage: upnpd [-f] [-s] <external ifname> <internal ifname>\n");
        printf("  -f\tdon't daemonize\n");
        printf("  -s\tdon't start HTTPS server\n");
        printf("Example: upnpd ppp0 eth0\n");
        exit(0);
    }

    if(parseConfigFile(&g_vars))
    {
        perror("Error parsing config file");
        exit(0);
    }

    // check for '-f' option
    if (strcmp(argv[arg], "-f") == 0)
    {
        foreground = 1;
        arg++;
    }

    // check for '-s' option
    if (strcmp(argv[arg], "-s") == 0)
    {
        non_secure = 1;
        arg++;
    }

    // uncomment the following lines, if you want gnutls traces
//    gnutls_global_set_log_level(9);
//    gnutls_global_set_log_function(trace_gnutls);

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

    // initialize libgcrypt library which is used by both pupnp (gnutls) and crypt.c
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        trace(3, "Initializing libgcrypt library ... ");
        /* Version check should be the very first call because it
          makes sure that important subsystems are intialized. */
        if (!gcry_check_version (GCRYPT_VERSION))
        {
            return -1;
        }

        /* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
           Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications */
        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

        /* to disallow usage of the blocking /dev/random  */
        gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

        /* Disable secure memory.  */
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

        /* Tell Libgcrypt that initialization has completed. */
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    }

    // Initialize UPnP SDK on the internal Interface
    trace(3, "Initializing UPnP SDK ... ");
    if ( (ret = UpnpInit(intIpAddress,g_vars.listenport) ) != UPNP_E_SUCCESS)
    {
        syslog (LOG_ERR, "Error Initializing UPnP SDK on IP %s port %d",intIpAddress,g_vars.listenport);
        syslog (LOG_ERR, "  UpnpInit returned %d", ret);
        UpnpFinish();
        exit(1);
    }
    trace(2, "UPnP SDK Successfully Initialized.");

    if (!non_secure)  // if HTTPS server is started and secure service served
    {
        trace(2, "Starting HTTPS server, this may take few seconds...");
        // start https server
        if ( (ret = UpnpStartHttpsServer(g_vars.httpsListenport, g_vars.certPath, NULL, NULL, NULL, NULL, "LinuxIGD 2.0") ) != UPNP_E_SUCCESS)
        {
            syslog (LOG_ERR, "Error Starting UPnP HTTPS server on IP %s port %d",intIpAddress,g_vars.httpsListenport);
            syslog (LOG_ERR, "  UpnpStartHttpsServer returned %d", ret);
            UpnpFinish();
            exit(1);
        }
        trace(2, "UPnP HTTPS Server Started Successfully.");

        // Modify description document on the fly so that the uuid is correct and created from certificate
        char descDocFile[sizeof(g_vars.xmlPath)+1+sizeof(g_vars.descDocName)+1];
        sprintf(descDocFile, "%s/%s", g_vars.xmlPath, g_vars.descDocName);
        if ( (ret = updateDescDocUuid(descDocFile) ) != 0)
        {
            syslog (LOG_ERR, "Error Updating UDN to Description document");
            UpnpFinish();
            exit(1);
        }
        trace(2, "UDN Updated Successfully to Description Document.");
    }

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

    // Form the Description Doc URL's to pass to RegisterRootDevice
    sprintf(descDocUrl, "http://%s:%d/%s", UpnpGetServerIpAddress(),
            UpnpGetServerPort(), g_vars.descDocName);
    if (!non_secure)
    {
        sprintf(secureDescDocUrl, "https://%s:%d/%s", UpnpGetServerIpAddress(),
                g_vars.httpsListenport, g_vars.descDocName);

        // Register our IGD as a valid UPnP Root device
        trace(3, "Registering the root device with descDocUrl %s and secureDescDocUrl %s for byebye sending", descDocUrl, secureDescDocUrl);
        if ( (ret = UpnpRegisterRootDeviceHTTPS(descDocUrl, secureDescDocUrl, EventHandler, &deviceHandle,
                                           &deviceHandle)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }

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
        trace(3, "Send initial sspd:byebye messages");
        UpnpUnRegisterRootDevice(deviceHandle); // this will send byebye's
        // Register our IGD as a valid UPnP Root device
        trace(3, "Registering the root device again with descDocUrl %s and secureDescDocUrl %s", descDocUrl, secureDescDocUrl);
        if ( (ret = UpnpRegisterRootDeviceHTTPS(descDocUrl, secureDescDocUrl, EventHandler, &deviceHandle,
                                           &deviceHandle)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
        //end of byebye
    }
    else // non-secure option. HTTPS server is not started and we don't want to advertise any HTTPS address
    {
        // Register our IGD as a valid UPnP Root device
        trace(3, "Registering the root device with descDocUrl %s for byebye sending", descDocUrl);
        if ( (ret = UpnpRegisterRootDevice(descDocUrl, EventHandler, &deviceHandle,
                                           &deviceHandle)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }

        trace(3, "Send initial sspd:byebye messages");
        UpnpUnRegisterRootDevice(deviceHandle); // this will send byebye's
        // Register our IGD as a valid UPnP Root device
        trace(3, "Registering the root device again with descDocUrl %s", descDocUrl);
        if ( (ret = UpnpRegisterRootDevice(descDocUrl, EventHandler, &deviceHandle,
                                           &deviceHandle)) != UPNP_E_SUCCESS )
        {
            syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
            syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
            UpnpFinish();
            exit(1);
        }
    }

    trace(2, "IGD root device successfully registered.");

    // Initialize the state variable table.
    StateTableInit(descDocUrl);

    // Initialize lanhostconfig module
    InitLanHostConfig();

    // Initialize DeviceProtection
    dp_device_info_t dp_dev_info;
    dp_dev_info.deviceHandle = GetDeviceHandle();
    dp_dev_info.udnList = GetUdnList();
    dp_dev_info.timerThread = GetTimerThread();
    InitDP(&dp_dev_info);

    // Send out initial advertisements of our device's services (with timeouts of 30 minutes, default value,can be changed from config file)
    if ( (ret = UpnpSendAdvertisement(deviceHandle, g_vars.advertisementInterval) != UPNP_E_SUCCESS ))
    {
        syslog(LOG_ERR, "Error Sending Advertisements. Exiting ...");
        UpnpFinish();
        exit(1);
    }
    trace(2, "Advertisements Sent. Advertisement sending interval set to %d seconds.  Listening for requests ...",g_vars.advertisementInterval);

    // Loop until program exit signals received
    do
    {
        sigemptyset(&sigsToCatch);
        sigaddset(&sigsToCatch, SIGINT);
        sigaddset(&sigsToCatch, SIGTERM);
        sigaddset(&sigsToCatch, SIGUSR1);
        sigaddset(&sigsToCatch, SIGUSR2);
        pthread_sigmask(SIG_SETMASK, &sigsToCatch, NULL);
        sigwait(&sigsToCatch, &signum);
        trace(3, "Caught signal %d...\n", signum);
        switch (signum)
        {
        case SIGUSR1:
            DeleteAllPortMappings();
            break;
        case SIGUSR2:
            DP_buttonPressed();
            break;
        default:
            break;
        }
    }
    while (signum!=SIGTERM && signum!=SIGINT);

    trace(2, "Shutting down on signal %d...\n", signum);

    // Cleanup UPnP SDK and free memory
    DeleteAllPortMappings();
    ExpirationTimerThreadShutdown();

    // Cleanup lanhostconfig module
    FreeLanHostConfig();

    // Cleanup deviceprotection module
    FreeDP();
    free(dp_dev_info.udnList);
    
    UpnpUnRegisterRootDevice(deviceHandle);
    UpnpFinish();

    // Exit normally
    return (0);
}
