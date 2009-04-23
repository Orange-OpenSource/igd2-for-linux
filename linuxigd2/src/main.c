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
#include <locale.h>



// Global variables
globals g_vars;

int main (int argc, char** argv)
{
    char descDocUrl[7+15+1+5+1+sizeof(g_vars.descDocName)+1]; // http://ipaddr:port/docName<null>
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
    if ( (ret = UpnpInit(intIpAddress,g_vars.listenport) ) != UPNP_E_SUCCESS)
    {
        syslog (LOG_ERR, "Error Initializing UPnP SDK on IP %s port %d",intIpAddress,g_vars.listenport);
        syslog (LOG_ERR, "  UpnpInit returned %d", ret);
        UpnpFinish();
        exit(1);
    }
    trace(2, "UPnP SDK Successfully Initialized.");
    
    // start https server
    if ( (ret = UpnpStartHttpsServer(443, g_vars.certPath, NULL, NULL, NULL, NULL, "LinuxIGD 2.0") ) != UPNP_E_SUCCESS)
    {
        syslog (LOG_ERR, "Error Starting UPnP HTTPS server on IP %s port %d",intIpAddress,443);
        syslog (LOG_ERR, "  UpnpStartHttpsServer returned %d", ret);
        UpnpFinish();
        exit(1);
    }
    trace(2, "UPnP HTTPS Server Started Successfully.");

    
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

    // Form the Description Doc URL to pass to RegisterRootDevice
    sprintf(descDocUrl, "http://%s:%d/%s", UpnpGetServerIpAddress(),
            UpnpGetServerPort(), g_vars.descDocName);

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
    //end of byebye

    trace(2, "IGD root device successfully registered.");

    // Initialize the state variable table.
    StateTableInit(descDocUrl);

    // Initialize lanhostconfig module
    InitLanHostConfig();

    // Record the startup time, for uptime
    startup_time = time(NULL);

    // Send out initial advertisements of our device's services (with timeouts of 30 minutes, default value,can be changed from config file)
    if ( (ret = UpnpSendAdvertisement(deviceHandle, g_vars.advertisementInterval) != UPNP_E_SUCCESS ))
    {
        syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
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
        pthread_sigmask(SIG_SETMASK, &sigsToCatch, NULL);
        sigwait(&sigsToCatch, &signum);
        trace(3, "Caught signal %d...\n", signum);
        switch (signum)
        {
        case SIGUSR1:
            DeleteAllPortMappings();
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

    UpnpUnRegisterRootDevice(deviceHandle);
    UpnpFinish();

    // Exit normally
    return (0);
}
