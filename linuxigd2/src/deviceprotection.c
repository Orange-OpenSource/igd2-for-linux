/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 * 
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU (Lesser) General Public License as 
 * published by the Free Software Foundation, version 2 of the License. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU (Lesser) General Public License for more details. 
 * 
 * You should have received a copy of the GNU (Lesser) General Public 
 * License along with this program. If not, see http://www.gnu.org/licenses/. 
 * 
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "deviceprotection.h"
#include "gatedevice.h"
#include "globals.h"
#include "util.h"
#include "crypt.h"
#include <hostap/wpa_supplicant_iface.h>
#include <upnp/upnptools.h>
#include <upnp/upnp.h>
#include <gcrypt.h>

static void message_received(struct Upnp_Action_Request *ca_event, int error, unsigned char *data, int len, int *status);
static int getSaltAndStoredForName(const char *user_name, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len);
static int createUserLoginChallengeResponse(struct Upnp_Action_Request *ca_event, const char *user_name);
static int getValuesFromPasswdFile(const char *user_name, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len, int max_size);
static int putValuesToPasswdFile(const char *name, const unsigned char *b64_salt, const unsigned char *b64_stored);
static int updateValuesToPasswdFile(const char *user_name, const unsigned char *b64_salt, const unsigned char *b64_stored, int delete_values);
static int getIdentifierOfCP(struct Upnp_Action_Request *ca_event, char **identifier, int *idLen, char **CN);
static int createAuthenticator(const char *b64_stored, const char *b64_challenge, unsigned char **bin_authenticator, const unsigned char *cp_uuid, int *auth_len);
static int startWPS();
static void stopWPS();

static void* enrollee_state_machine;
static unsigned char* Enrollee_send_msg;
static int Enrollee_send_msg_len;
static int gStopWPSJobId = -1;
static unsigned char *device_uuid;

// identifer of control point which is executing introduction process
static unsigned char prev_CP_id[40];

// Access Control List
static IXML_Document *ACLDoc = NULL;

// flag telling if WPS introduction process is going on
static int gWpsIntroductionRunning = 0;

static const char *admin_name = "Administrator";

static wpa_supplicant_wps_enrollee_config enrollee_config;

#define MAC_LEN               6
#define HASH_LEN              32

#define PSEUDO_RANDOM_UUID_TYPE 0x5
typedef struct {
    uint32_t  time_low;
    uint16_t  time_mid;
    uint16_t time_hi_and_version;
    uint8_t   clock_seq_hi_and_reserved;
    uint8_t   clock_seq_low;
    unsigned char   node[6];
} my_uuid_t;

/*
 * Document containing SSL session and username relationship. This in only for internal use of LinuxIGD.
 * Identity is either username or 20 bytes of certificate hash. It is trusted that no-one will never-ever
 * use username that could be some certificates hash. Value of identity corresponds in ACL to value of
 * "Name" under "User" or "Hash" under "CP" 
 * Active attribute tells if session is currently logged in as identity. If value is 0, it can be later 
 * used in session resumption.
 * 
 * If session contains "rolelist"-element, this is the current role for this session, not value from ACL.
 * 
 * 
 * Session may also contain data associated for user login process. Device must know what username/
 * accountname CP wishes to login and value of challenge which was send to CP. Because its certificate
 * is only somesort of unique identifer of Control point, SIR is only reasonable place to store these
 * values.
 * Value of "name" corresponds to the first word in passwordfile.
 * After UserLogin and UserLogout logindata is removed. 
 * 
 * loginattempts tells how many times this session has failed at UserLogin 
 *
 * <SIR>
 *  <session id="AHHuendfn372jsuGDS==" active="1">
 *      <identity>username</identity>
 *      <rolelist>Basic</rolelist>
 *      <logindata loginattempts="2">
 *          <name>Admin</name>
 *          <challenge>83h83288J7YGHGS778jsJJHGDn=</challenge>
 *      </logindata>
 *  </session>
 * </SIR>
 */
static IXML_Document *SIRDoc = NULL;

/**
 * Print contents of given IXML_Document as debug output to console.
 * 
 * @param debuglevel Debuglevel used for trace()-function
 * @param msg Message printed before printing XML
 * @param doc IXML_Document which is printed
 * @return void
 */
static void trace_ixml(int debuglevel, const char *msg, IXML_Document *doc)
{
    if (!msg || !doc)
        return;

    char *tmp = ixmlPrintDocument(doc);
    trace(3, "%s\n%s\n",msg, tmp);
    free(tmp);
}

/**
 * Initialize DeviceProtection StateVariables for their default values.
 * 
 * @return void
 */
void DPStateTableInit()
{
    // DeviceProtection is ready for introduction
    SetupReady = 1;
    strcpy(SupportedProtocols, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                               "<SupportedProtocols xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\" "
                               "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                               "xsi:schemaLocation=\"urn:schemas-upnp-org:gw:DeviceProtection "
                               "http://www.upnp.org/schemas/gw/DeviceProtection-v1.xsd\">"
                               "<Introduction><Name>WPS</Name></Introduction>"
                               "<Login><Name>PKCS5</Name></Login></SupportedProtocols>");
}

/**
 * Initialize DeviceProtection. Create input for WPS
 * 
 * @return int. 0 on success
 */
int InitDP()
{
    DP_loadDocuments();

    int ret = 0;
    char descDocFile[sizeof(g_vars.xmlPath)+sizeof(g_vars.descDocName)+2];
    unsigned char MAC[MAC_LEN];
    memset(MAC, 0x00, MAC_LEN);
    GetMACAddressStr(MAC, MAC_LEN, g_vars.intInterfaceName);

    // manufacturer and device info is read from device description XML
    sprintf(descDocFile, "%s/%s", g_vars.xmlPath, g_vars.descDocName);
    IXML_Document *descDoc = ixmlLoadDocument(descDocFile);

    if (descDoc)
    {
        // create the UUID
        int cert_size = 10000;
        size_t uuid_size;
        unsigned char cert[cert_size];
        unsigned char hash[cert_size];

        // get server certificate
        ret = UpnpGetHttpsServerCertificate(cert, &cert_size);
        if (ret != 0)
        {
            trace(1, "Failed to get server certificate");
            return ret;
        }

        // create hash from certificate
        ret = crypt_calculate_sha256(cert, cert_size, hash);
        if (ret < 0)
        {
            trace(1, "Failed to create hash from server certificate");
            return ret;
        }

        // create uuid from certificate
        createUuidFromData(NULL, &device_uuid, &uuid_size, hash, 16);
        if (device_uuid == NULL)
        {
            trace(1, "Failed to create uuid from server certificate");
            return -2;
        }

        enrollee_config.device_pin = g_vars.pinCode;
        //enrollee_config.mac_address = MAC; //TODO: check if this is needed
        enrollee_config.device_name = GetFirstDocumentItem(descDoc, "friendlyName");
        enrollee_config.manufacturer = GetFirstDocumentItem(descDoc, "manufacturer");
        enrollee_config.model_name = GetFirstDocumentItem(descDoc, "modelName");
        enrollee_config.model_number = GetFirstDocumentItem(descDoc, "modelNumber");
        enrollee_config.serial_number = GetFirstDocumentItem(descDoc, "serialNumber");
        enrollee_config.device_type = "1-0050F204-1"; //(Computer / PC)
        enrollee_config.config_methods = "label";
        memcpy(enrollee_config.uuid, device_uuid, uuid_size);
    }
    else return UPNP_E_FILE_NOT_FOUND;

    ixmlDocument_free(descDoc);
    return ret;
}


/**
 * Deinit DeviceProtection.
 * Free WPS input. Counterpart of InitDP()
 *
 * @return void
 */
void FreeDP()
{
    free(device_uuid);

    // Save possible changes done in DeviceProtection XML's 
    DP_finishDocuments();
}

/**
 * Initialize XML documents used in DeviceProtection.
 * Reads ACL from file, and creates an empty SIR
 * 
 * @return void
 */
void DP_loadDocuments()
{
    // init ACL
    ACLDoc = ixmlLoadDocument(ACL_XML);
    if (ACLDoc == NULL)
    {
        trace(1, "Couldn't load ACL (Access Control List) document which should locate here: %s\nExiting...\n",ACL_XML);
        UpnpFinish();
        exit(1);
    }

    // session-identity relationships are stored in this. Also user login data which is needed at UserLogin()
    SIRDoc = SIR_init();
    if (SIRDoc == NULL)
    {
        trace(1, "Couldn't load SIR document.\nSIR is LinuxIDG's internal structure for containing SSL-session-User relationships\nExiting...\n");
        UpnpFinish();
        exit(1);
    }
}

/**
 * Release XML documents used in DeviceProtection.
 * Writes ACL to file.
 * 
 * @return void
 */
void DP_finishDocuments()
{
    // write ACL to file
    writeDocumentToFile(ACLDoc, ACL_XML);
    ixmlDocument_free(ACLDoc);

    // should SIR stay or not. Probably not...?
    ixmlDocument_free(SIRDoc);
}


/**
 * Check if CP which send given action has required role to initiate this action.
 * First creates control point identifier based on certificate of control point. 
 * Second get username (or certificate hash) associated with identifier created previously (from SIR).
 * Third check if username (or hash) has desired role associated to (from ACL).
 * 
 * @param ca_event Upnp event struct.
 * @param targetRoles List of rolenames from which at least one control point or user must have assigned in ACL
 * @return 0 if rolename is found and everything is ok, 1 if CP doesn't have privileges. Something else if error
 */
int checkCPPrivileges(struct Upnp_Action_Request *ca_event, const char *targetRoles)
{
    int ret, len=0;
    char *identifier = NULL;
    char *commonName = NULL;
    char *name = NULL;
    char *rolelist = NULL;

    // get identity of CP 
    ret = getIdentifierOfCP(ca_event, &identifier, &len, &commonName);
    if (ret != 0 )
    {
        free(identifier);
        return ret;
    }

    // get "Name" of CP from ACL. It is possible that CP is not listed in ACL, 
    // in that case everything is OK. If CP is found from ACL, then "Name" from ACL must match 
    // "CommonName" value from the certificate of CP.
    ret = ACL_getCP(ACLDoc, identifier, &name, NULL, &rolelist);
    if (ret == 0 && commonName && name && (caseInsesitive_strcmp(commonName, name) != 0))
    {
        trace(1,"CommonName found from certificate of Control Point does not match Name of the same Control Point listed in ACL! Terminating connection...");
        // close SSL session on way out...
        UpnpTerminateSSLSession(ca_event->SSLSession, ca_event->Socket);
        // remove session from SIR
        SIR_removeSession(SIRDoc, (char *)identifier);

        free(identifier);
        free(commonName);
        free(name);

        return -1;
    }
    free(commonName);
    free(name);

    if (rolelist)
    {
        // Let's add new entry to SIR. RoleList value is either value fetched from ACL for this CP or Public.
        // Identity value is not inserted to SIR now.
        // If return value is -1, session was there already. If 0 CP was new and it was 
        // succesfully added to SIR.
        // Every action is checked through checkCPPrivileges, so that is why every session is found from SIR
        trace(3, "checkCPPrivileges: roles from ACL\n");
        ret = SIR_addSession(SIRDoc, identifier, 0, NULL, rolelist, NULL, NULL, NULL);
    }
    else
        ret = SIR_addSession(SIRDoc, identifier, 0, NULL, "Public", NULL, NULL, NULL);
    if (ret == 0)
    {
        trace(3, "New session was added to SIR. Id: '%s'",identifier);
        trace_ixml(3, "Contents of SIR:",SIRDoc);
    }
    else if (ret == -1)
    {
        // ok it was there already. Just continue   
    }
    else
    {
        trace(2,"SIR handling failed somehow when adding new session!");
        free(identifier);
        free(rolelist);
        return -1;
    }
    free(rolelist);

    /* Actual privileges checking takes place here */
    // SIR contains union of roles defined for contorl point in ACL and roles defined for username
    // which CP has logged in.
    // All we need to do is check that targetRole is found from "rolelist" of this session in SIR.

    // fetch contents of session for this session from SIR. All we actually need is the value of rolelist
    int active;
    char *roles = NULL;
    char *identity = SIR_getIdentityOfSession(SIRDoc, identifier, &active, &roles);
    free(identifier);
    free(identity);

    // check if targetRole is found from roles of this session
    if (roles)
    {
        trace(2, "checkCPPrivileges: session roles:'%s', target roles:'%s'\n", roles, targetRoles);
        // loop through all roles from targetRoles. If any of those match, then exit OK
        char *tmp = NULL;
        char *role = NULL;
        char list[strlen(targetRoles)];
        strcpy(list,targetRoles);

        // get the last role from the end of list and shorten rolelist
        while ((tmp = strrchr(list, ' ')))
        {
            role = tmp+1;
            *tmp = '\0';
            if ( tokenizeAndSearch(roles, " ", role, 1) )
            {
                // CP does have privileges
                return 0;
            }
        }
        // and remember to check the first item from the beginning of the list
        if (strlen(list) > 0 && tokenizeAndSearch(roles, " ", list, 1))
        {
            // CP does have privileges
            return 0;
        }
    }

    // so CP doesn't have privileges
    return 1;
}


/**
 * Create uuid string from given data. (In this case data is hash created from certificate)
 * 
 * "The CP Identity is a UUID derived from the first 128 bits of the SHA-256 hash of the 
 * CP’s X.509 certificate in accordance with the procedure given in Section 4.4 and Appendix A 
 * of RFC 4122."
 * 
 * @param uuid_str Pointer to string where uuid is created. User must release this with free()
 * @param uuid_bin Created uuid in binary form before it is converted to its string presentation
 * @param uuid_size Pointer to length of uuid_bin. (16 bytes)
 * @param hash Input data from which uuid is created
 * @param hashLen Length of input data. Or how much of it is used.
 * @return void
 */
void createUuidFromData(char **uuid_str, unsigned char **uuid_bin, size_t *uuid_bin_size, unsigned char *hash, int hashLen)
{
    size_t uuid_size = sizeof(my_uuid_t);
    my_uuid_t *uuid = malloc(uuid_size);

    memcpy(uuid, hash, uuid_size);
    uuid->time_low = ntohl(uuid->time_low);
    uuid->time_mid = ntohs(uuid->time_mid);
    uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);

    /* put in the variant and version bits */
    uuid->time_hi_and_version &= 0x0FFF;
    uuid->time_hi_and_version |= (PSEUDO_RANDOM_UUID_TYPE << 12);
    uuid->clock_seq_hi_and_reserved &= 0x3F;
    uuid->clock_seq_hi_and_reserved |= 0x80;

    if (uuid_bin && uuid_bin_size)
    {
        // copy uuid struct to uuid_bin
        *uuid_bin = (unsigned char*)malloc(uuid_size);
        memcpy(*uuid_bin, uuid, uuid_size);
        *uuid_bin_size = uuid_size;
    }

    if (uuid_str)
    {
        *uuid_str = malloc(37*sizeof(char));
        char tmp[3];
        int i;
        memset(*uuid_str, '\0', 37);

        // create string representation from binary
        snprintf(*uuid_str, 37, "%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", uuid->time_low, uuid->time_mid,
                uuid->time_hi_and_version, uuid->clock_seq_hi_and_reserved, uuid->clock_seq_low);

        for (i = 0; i < 6; i++)
        {
            snprintf(tmp, 3, "%2.2x", uuid->node[i]);
            strcat(*uuid_str,tmp);
        }
    }

    free(uuid);
}

/**
 * Get identity identifier of Control point based on certificate of Control Point.
 * Identifier is created like this:
 *  1. create sha-1 hash from CP certificate
 *  2. create uuid string from 16 first bytes of previously created hash
 * 
 * 
 * @param ca_event Upnp event struct.
 * @param identifier Pointer to char* where identifier is created. Caller should use free() for this.
 * @param idLen Length of created base64 identifier
 * @param CN Value of Common Name used in certificate is returned here. Use free() for this
 * @return 0 if succeeded to create identifier. Something else if error
 */
static int getIdentifierOfCP(struct Upnp_Action_Request *ca_event, char **identifier, int *idLen, char **CN)
{
    int ret;
    int cert_size = 1000;
    unsigned char cert[cert_size];
    unsigned char hash[cert_size];

    if (ca_event->SSLSession == NULL)
    {
        return 1;
    }

    // 1. get certificate of client
    ret = UpnpGetPeerClientCert(ca_event->SSLSession, cert, &cert_size, CN);
    if (ret != UPNP_E_SUCCESS)
        return ret;

    // 2. create hash from certificate
    ret = crypt_calculate_sha256(cert, cert_size, hash);
    if (ret < 0)
        return ret;

    createUuidFromData(identifier, NULL, NULL, hash, 16);
    *idLen = strlen(*identifier);

    return 0;
}

/**
 * Get identity identifier of Control point based on certificate of Control Point.
 * Identifier is created like this:
 *  1. create sha-1 hash from CP certificate
 *  2. create uuid string from 16 first bytes of previously created hash
 *
 *
 * @param ca_event Upnp event struct.
 * @param uuid Pointer to char* where uuid is created. Caller should use free() for this.
 * @return 0 if succeeded to create identifier. Something else if error
 */
static int get_cp_uuid(struct Upnp_Action_Request *ca_event, unsigned char **uuid)
{
    int ret;
    int cert_size = 1000;
    size_t uuid_size;
    char **CN = NULL;
    unsigned char cert[cert_size];
    unsigned char hash[cert_size];

    if (ca_event->SSLSession == NULL)
    {
        return 1;
    }

    // 1. get certificate of client
    ret = UpnpGetPeerClientCert(ca_event->SSLSession, cert, &cert_size, CN);
    if (ret != UPNP_E_SUCCESS)
        return ret;

    // 2. create hash from certificate
    ret = crypt_calculate_sha256(cert, cert_size, hash);
    if (ret < 0)
        return ret;

    createUuidFromData(NULL, uuid, &uuid_size, hash, 16);

    return 0;
}

/**
 * Get identity associated with SSL session used for sending given action.
 * 
 * @param ca_event Upnp event struct.
 * @param identity Pointer to char* where identity are put.
 * @return 0 if succeeded to fetch identity. Something else if error
 */
static int getIdentityOfSession(struct Upnp_Action_Request *ca_event, char **identity)
{
    int ret, len=0;
    char *identifier = NULL;

    // 1. get identifier of CP 
    ret = getIdentifierOfCP(ca_event, &identifier, &len, NULL);
    if (ret != 0 )
    {
        return ret;
    }

    // 2. fetch current identity of CP from SIR. Identity may be username or identifier created from certificate
    int active;
    char *role = NULL;
    *identity = SIR_getIdentityOfSession(SIRDoc, identifier, &active, &role);

    free(identifier);

    if (*identity == NULL)
        return -1;

    return 0;
}

/**
 * Get list of roles associated with SSL session used for sending given action.
 * 
 * @param ca_event Upnp event struct.
 * @param roles Pointer to char* where roles are put.
 * @return 0 if succeeded to fetch roles. Something else if error
 */
static int getRolesOfSession(struct Upnp_Action_Request *ca_event, char **roles)
{
    int ret, len=0;
    char *identifier;

    // 1. get identifier of CP 
    ret = getIdentifierOfCP(ca_event, &identifier, &len, NULL);
    if (ret != 0 )
    {
        return ret;
    }

    // 2. fetch current roles of CP from SIR.
    int active;
    char *identity = SIR_getIdentityOfSession(SIRDoc, identifier, &active, roles);

    free(identity);
    free(identifier);

    if (*roles == NULL)
        return -1;

    return 0;
}

/**
 * Create timer for stopping WPS setup process if it has been running over DP_MAX_WPS_SETUP_TIME
 * (60 seconds).
 * This way we release WPS for others to use if some client stays in error state for example.
 * 
 * @return Upnp error code.
 */
static int createStopWPSTimer(void)
{
    int result = 0;

    if (DP_MAX_WPS_SETUP_TIME > 0)
    {
        trace(3,"Create StopWPS timer to be executed after %d seconds",DP_MAX_WPS_SETUP_TIME);
        // schedule new autodisconnect job
        ThreadPoolJob job;
        // Add disconnect job
        TPJobInit( &job, ( start_routine ) stopWPS, NULL );
        result = TimerThreadSchedule( &gExpirationTimerThread,
                                        DP_MAX_WPS_SETUP_TIME,
                                        REL_SEC, &job, SHORT_TERM,
                                        &gStopWPSJobId );
    }
    return result;
}

/**
 * Start WPS enrollee.
 * Creates also timer which will automatically stop WPS introduction process if it takes too long.
 * Meaning that process is halted because of error.
 * 
 * @return 0 on success, negative value on error.
 */
static int startWPS()
{
    int err;
    trace(2,"startWPS");

    // create timer which will end introduction after 60 seconds if it is still runnning
    if ((err = createStopWPSTimer()) != 0)
    {
        trace(1, "Failed to create StopWPS timer! Error: %d",err);
        return err;
    }

    err = wpa_supplicant_iface_init( &enrollee_config );
    if (err != 0)
    {
        trace(1, "Failed to initialize WPS interface! Error: %d",err);
        return err;
    }
    
    // create enrollee state machine
    err = wpa_supplicant_create_enrollee_state_machine(&enrollee_state_machine);
    if (err != 0)
    {
        trace(1, "Failed to create WPS enrollee! Error: %d",err);
        return err;
    }

    gWpsIntroductionRunning = 1;

    return 0;
}

/**
 * Stop WPS enrollee.
 * Removes automatic WPS stop timer.
 * Events SetupReady state variable if needed.
 * 
 * @return void.
 */
static void stopWPS()
{
    int error;
    trace(2,"stopWPS(), Finished DeviceProtection pairwise introduction process\n");

    // cancel possible StopWPS thread job
    if (gStopWPSJobId != -1)
    {
        trace(3,"Cancel StopWPS timer");
        TimerThreadRemove(&gExpirationTimerThread, gStopWPSJobId, NULL);
        gStopWPSJobId = -1;
    }

    error = wpa_supplicant_stop_enrollee_state_machine(enrollee_state_machine);
    wpa_supplicant_iface_delete();

    gWpsIntroductionRunning = 0;

    // DP is free. SetupReady is evented only if old value is 0
    if (SetupReady == 0)
    {
        SetupReady = 1;
        IXML_Document *propSet = NULL;
        trace(3, "DeviceProtection SetupReady: %d", SetupReady);
        UpnpAddToPropertySet(&propSet, "SetupReady", "1");
        UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:DeviceProtection1", propSet);
        ixmlDocument_free(propSet);
    } 
}


/**
 * WPS introduction uses this function. SendSetupMessage calls this.
 * When message M2, M2D, M4, M6, M8 or Done ACK is received, enrollee state machine is updated here
 * 
 * Actual stopping of state machine must be done at the end of SendSetupMessage, because 
 * stopping will release Enrollee_send_msg which is needed at SendSetupMessage after returning from here.
 * 
 * @param error Error code is passed through this.
 * @param data Received WPS introduction binary message
 * @oaram len Length of binary message
 * @return void
 */
static void message_received(struct Upnp_Action_Request *ca_event, int error, unsigned char *data, int len, int *status)
{
    if (error)
    {
        trace(2,"DeviceProtection introduction message receive failure! Error = %d", error);
        return;
    }

    error = wpa_supplicant_update_enrollee_state_machine(enrollee_state_machine,
                                                         data,
                                                         len,
                                                         &Enrollee_send_msg,
                                                         &Enrollee_send_msg_len,
                                                         status);

    switch (*status)
    {
        case WPASUPP_SM_E_SUCCESS:
        {
            trace(3,"DeviceProtection introduction last message received!\n");
            // Add CP certificate hash into ACL
            int ret, len=0;
            char *identifier = NULL;
            char *CN = NULL;

            // get identity of CP 
            ret = getIdentifierOfCP(ca_event, &identifier, &len, &CN);
            if (ret != 0 )
            {
                trace(1,"Failed to get Identifier value from Certificate (%d)! Ignoring...",ret);
            }
            else
            {
                // Add CP to ACL with roles 'Public' and 'Basic'
                const char* pub_bas="Public Basic";
                ret = ACL_addCP(ACLDoc, CN, NULL, identifier, pub_bas, 1);
                if (ret != ACL_SUCCESS && ret != ACL_USER_ERROR)
                    trace(1,"Failed to add new CP into ACL! Ignoring...");
                else
                {
                    writeDocumentToFile(ACLDoc, ACL_XML);
                    // Update roles to SIR
                    if (SIR_updateSession(SIRDoc, identifier, NULL, NULL, pub_bas,
                                          NULL, NULL, NULL) != 0)
                    {
                        trace(1, "WARNING, SIR update failed!");
                    }
                }
            }
            free(identifier);
            free(CN);

            trace_ixml(3, "Contents of ACL:",ACLDoc);
            break;
        }
        case WPASUPP_SM_E_SUCCESSINFO:
        {
            trace(3,"DeviceProtection introduction last message received M2D!\n");
            break;
        }

        case WPASUPP_SM_E_FAILURE:
        {
            trace(3,"DeviceProtection introduction error in state machine (Peer gave wrong PIN?). Gracefully terminating and sending of NACK...\n");
            break;
        }

        case WPASUPP_SM_E_FAILUREEXIT:
        {
            trace(3,"Received NACK from peer. Terminating state machine...\n");
            break;
        }
        case WPASUPP_SM_E_PROCESS:
        {
            trace(3, "Continuing DeviceProtection introduction...\n");
            break;
        }
        default:
        {
            trace(2, "DeviceProtection introduction state machine in unknown error state. Terminating...\n");
        }
    }
}


/**
 * Get salt and stored values of user with user_name as username.
 * With getValuesFromPasswdFile(name, NULL, NULL, NULL, NULL, 0) it is possible to check 
 * if password file contains that specific username.
 * 
 * @param user_name User name.
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @param salt_len Pointer to integer where length of salt is inserted
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @param stored_len Pointer to integer where length of stored is inserted
 * @param max_size Maximum space available for salt and stored. If they are longer than max_size, error is returned
 * @return -1 if fail, -2 if username is not found, -3 if salt or stored is too long, 0 on success
 */
static int getValuesFromPasswdFile(const char *user_name, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len, int max_size)
{
    // file is formatted as this (every user in own row):
    // Username,base64(SALT),base64(STORED)
    char line[200];
    char *name;
    char *temp;

    FILE *stream = fopen(PASSWD_FILE, "r");
    if (!stream) return -1;

    while(fgets(line, 200, stream) != NULL) 
    {
        line[strlen(line)-1] = '\0';

        name = strtok(line, ",");
        if (name != NULL)
        {
            // if names match
            if ( strcmp(name,user_name) == 0 )
            {
                fclose(stream);

                if (b64_salt)
                {
                    memset(*b64_salt, '\0', max_size);
                    temp = strtok(NULL, ",");
                    *salt_len = strlen(temp);

                    if (*salt_len > max_size) return -3;

                    memcpy(*b64_salt, temp, *salt_len);
                }
                if (b64_stored)
                {
                    memset(*b64_stored, '\0', max_size);
                    temp = strtok(NULL, ",");
                    *stored_len = strlen(temp);

                    if (*stored_len > max_size) return -3;

                    memcpy(*b64_stored, temp, *stored_len);
                }
                return 0;
            }
        }
    }

    fclose(stream);
    return -2;
}

/**
 * Update username,salt,stored values in password file.
 * 
 * @param name User name
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @return -1 if fail -2 if username already exist, 0 on success
 */
static int putValuesToPasswdFile(const char *name, const unsigned char *b64_salt, const unsigned char *b64_stored)
{
    if (getValuesFromPasswdFile(name,NULL,NULL, NULL, NULL, 0) == 0)
        return -2;

    FILE *stream = fopen(PASSWD_FILE, "a");
    if (!stream) return -1;

    fprintf(stream, "%s,%s,%s\n", name, b64_salt, b64_stored);

    fclose(stream);
    return 0;
}

/**
 * Update username,salt,stored values in password file.
 * Username and values can also be removed totally from file by putting delete_values as 1.
 * 
 * @param name User name
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @param delete_values Use 0 to update existing values, 1 to delete.
 * @return -1 if fail, -2 if username is not found, 0 on success
 */
static int updateValuesToPasswdFile(const char *user_name, const unsigned char *b64_salt, const unsigned char *b64_stored, int delete_values)
{
    // file is formatted as this (every user in own row):
    // Username,base64(SALT),base64(STORED)
    char line[200];
    char temp[200];
    char *name;
    int ret = -2;

    char tempfile[strlen(PASSWD_FILE) + 6];
    strcpy(tempfile,PASSWD_FILE);
    strcat(tempfile,".temp");

    // open 2 files, passwordfile which is read and temp file where lines are written.
    // if usernames match write new values in temp file.
    // Finally remove original passwordfile and rename temp file as original.
    FILE *in = fopen(PASSWD_FILE, "r");
    if (!in) return -1;
    FILE *out = fopen(tempfile, "w");
    if (!out) 
    {
        fclose(in);
        return -1;
    }

    while(fgets(line, 200, in) != NULL) 
    {
        line[strlen(line)-1] = '\0';
        strcpy(temp,line); // copy line, strtok modifies it

        name = strtok(line, ",");

        if (name != NULL)
        {
            // if names match
            if ( strcmp(name,user_name) == 0 )
            {
                // if we want to remove user from passwd file, lets not add him to temp file
                if (!delete_values)
                    fprintf(out, "%s,%s,%s\n", user_name, b64_salt, b64_stored);

                ret = 0;
            }
            else
            {
                fprintf(out, "%s\n", temp);
            }
        }
    }

    fclose(in);
    fclose(out);

    // delete original password file
    remove(PASSWD_FILE);
    // rename temp file is original password file
    rename(tempfile, PASSWD_FILE);

    return ret;
}

/**
 * Get salt and stored values of user with user_name as username.
 * Username "Administrator" is an special case: if it is not found form password file, totally
 * new salt and stored values are creted for that username. Password used for creation 
 * of stored is stored in config file.
 *  
 * 
 * @param user_name User name
 * @param b64_salt Pointer to salt data read from file or newly created (base64 encoded)
 * @param salt_len Pointer to integer where length of salt is inserted
 * @oaram b64_stored Pointer to stored data read from file or newly created (base64 encoded)
 * @param stored_len Pointer to integer where length of stored is inserted
 * @return 0 on success
 */
static int getSaltAndStoredForName(const char *user_name, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len)
{
    int maxb64len = 2*DP_STORED_BYTES;
    *b64_salt = (unsigned char *)malloc(maxb64len);
    *b64_stored = (unsigned char *)malloc(maxb64len);

    int ret = getValuesFromPasswdFile(user_name, b64_salt, salt_len, b64_stored, stored_len, maxb64len);

    if (ret != 0)
    {
        if (strcmp(user_name, admin_name) == 0)
        {
            // create new salt and stored
            int name_len = strlen(user_name);
            int namesalt_len = name_len + DP_SALT_BYTES;
            unsigned char namesalt[namesalt_len];

            // create SALT
            unsigned char *salt = crypt_create_random_value(DP_SALT_BYTES);

            memcpy(namesalt, user_name, name_len);
            memcpy(namesalt+name_len, salt, DP_SALT_BYTES);

            /* Create STORED = first 160 bits of the key T1, with T1 computed according to [PKCS#5] algorithm PBKDF2

                T1 is defined as the exclusive-or sum of the first c iterates of PRF applied to the concatenation 
                of the Password, Name, Salt, and four-octet block index (0x00000001) in big-endian format.  
                For DeviceProtection, the value for c is 5,000.
                Password and Name MUST be encoded in UTF-8 format prior to invoking the PRF operation.  
                T1 = U1 \xor U2 \xor … \xor Uc
                where
                U1 = PRF(Password, Name || Salt || 0x0 || 0x0 || 0x0 || 0x1)
                U2 = PRF(Password, U1),
                …
                Uc = PRF(Password, Uc-1).

                NOTE1: SALT and STORED are created only if username is admin and passwordfile doesn't 

                NOTE2: crypt_pbkdf2 goes through whole PBKDF2 algorithm, even if in this case only first block
                       is needed for result. First 160 bits are the same if all the data is processed or just 
                       the first block. (block size should be defined to 160bits => DP_STORED_BYTES = 8)
             */
            unsigned char bin_stored[DP_STORED_BYTES];
            ret = crypt_pbkdf2(g_vars.adminPassword, strlen(g_vars.adminPassword), namesalt,
                               namesalt_len, DP_PRF_ROUNDS, DP_STORED_BYTES, bin_stored);

            if (ret != 0) return ret;

            // SALT and STORED to base 64
            *b64_salt = wpa_supplicant_base64_encode(salt, DP_SALT_BYTES, (size_t *)salt_len);
            *b64_stored = wpa_supplicant_base64_encode(bin_stored, DP_STORED_BYTES, (size_t *)stored_len);
            // write values to password file
            ret = putValuesToPasswdFile(user_name, *b64_salt, *b64_stored);
        }
    }

    return ret;
}

/**
 * Create userlogin challenge data and put it in upnp response struct.
 * GetUserLoginChallenge uses this.
 *
 * When Algorithm is the default value for DeviceProtection:1, the Salt and Challenge are derived as follows: 
 *  Salt = 16-octet random value used to hash Password into the STORED authentication value for each Name in the database.
 *  
 *  STORED = first 160 bits of the key T1, with T1 computed according to [PKCS#5] algorithm PBKDF2, with PRF=SHA-256.
 *  A separate value of STORED is kept in the Device’s password file for each specific Name. 
 *  T1 is defined as the exclusive-or sum of the first c iterates of PRF applied to the concatenation of
 *  the Password, Name, Salt, and four-octet block index (0x00000001) in big-endian format.
 *  For DeviceProtection, the value for c is 5,000. Password and Name MUST be encoded in UTF-8 format prior
 *  to invoking the PRF operation.  
 *  T1 = U1 \xor U2 \xor … \xor Uc
 *  where
 *  U1 = PRF(Password, Name || Salt || 0x0 || 0x0 || 0x0 || 0x1)
 *  U2 = PRF(Password, U1),
 *  …
 *  Uc = PRF(Password, Uc-1).
 * 
 *  Challenge = SHA-256(STORED || nonce).  Nonce is a fresh, random 128-bit value generated by the Device for each GetUserLoginChallenge() call.
 * 
 * @param ca_event Upnp event struct.
 * @param user_name User name
 * @return Upnp error code.
 */
static int createUserLoginChallengeResponse(struct Upnp_Action_Request *ca_event, const char *user_name)
{
    int result = 0;
    unsigned char *b64_salt = NULL;
    unsigned char *b64_stored = NULL;
    int b64_salt_len = 0;
    int b64_stored_len = 0;

    if (getSaltAndStoredForName(user_name, &b64_salt, &b64_salt_len, &b64_stored, &b64_stored_len) != 0)
    {
        trace(1, "Error creating/getting STORED value for user %s",user_name);
        result = 501;
        addErrorData(ca_event, result, "Action Failed");
    }
    else
    {
        // stored to binary format
        unsigned char *bin_stored;
        size_t outlen;
        bin_stored = wpa_supplicant_base64_decode(b64_stored, b64_stored_len, &outlen);

        // Create CHALLENGE = random 128-bit value
        unsigned char *challenge = crypt_create_nonce(DP_NONCE_BYTES);

        int b64len = 0;
        unsigned char *b64_challenge;
        b64_challenge = wpa_supplicant_base64_encode(challenge, DP_NONCE_BYTES, (size_t*)&b64len);

        IXML_Document *ActionResult = NULL;
        ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                    2,
                                    "Salt", b64_salt,
                                    "Challenge", b64_challenge);

        if (ActionResult)
        {
            ca_event->ActionResult = ActionResult;
            ca_event->ErrCode = UPNP_E_SUCCESS;
        }
        else
        {
            trace(1, "Error parsing Response to %s",ca_event->ActionName);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }

        // insert user login values to SIR document
        char *identifier = NULL;
        result = getIdentifierOfCP(ca_event, &identifier, &b64len, NULL);
        if (result == 0 )
        {
            trace(3,"Session with id '%s' is being updated in SIR. Add name '%s' and challenge '%s'",identifier,user_name,(char *)b64_challenge);
            result = SIR_updateSession(SIRDoc, identifier, NULL, NULL, NULL, NULL, user_name, (char *)b64_challenge);
            if (result == 0)
                trace_ixml(3, "Contents of SIR:",SIRDoc);
            else
                trace(2, "Failed to update session in SIR");
        }
        else
            trace(1, "Failure on inserting UserLoginChallenge values to SIR. Ignoring...");

        free(challenge);
        free(identifier);
        free(b64_challenge);
        free(bin_stored);
    }

    free(b64_salt);
    free(b64_stored);
    return result;
}


/**
 * Create authenticator value used in UserLogin
 * Authenticator contains the Base64 encoding of the first 20 bytes of SHA-256(STORED || Challenge).
 * 
 * @param b64_stored Base64 encoded value of STORED.
 * @param b64_challenge Base64 encoded value of Challenge.
 * @param bin_authenticator Pointer to allocated memory block where authenticator is created. User needs to use free() for this
 * @param auth_len Pointer to integer which is set to contain length of created authenticator
 * @return 0 if succeeded to create authenticato. Something else if error
 */
static int createAuthenticator(const char          *b64_stored,
                               const char          *b64_challenge,
                               unsigned char       **bin_authenticator,
                               const unsigned char *cp_uuid,
                               int                 *auth_len)
{
    // stored and challenge from base64 to binary
    size_t b64msglen = strlen(b64_stored);
    size_t bin_stored_len;
    unsigned char *bin_stored;
    bin_stored = wpa_supplicant_base64_decode((const unsigned char *)b64_stored,
                                              b64msglen, &bin_stored_len);
    if (bin_stored == NULL) 
    {
        return -1;
    }

    b64msglen = strlen(b64_challenge);
    size_t bin_challenge_len;
    unsigned char *bin_challenge;
    bin_challenge = wpa_supplicant_base64_decode((const unsigned char *)b64_challenge,
                                                 b64msglen, &bin_challenge_len);
    if (bin_challenge == NULL)
    {
        free(bin_stored);
        return -1;
    }
    

    // create ( Challenge || DeviceID || ControlPointID )
    int cdc_len = bin_challenge_len + 2*(DP_UUID_LEN);
    unsigned char *cdc = (unsigned char *) malloc ( cdc_len );
    memcpy( cdc, bin_challenge, bin_challenge_len );
    memcpy( cdc + bin_challenge_len, device_uuid, DP_UUID_LEN );
    memcpy( cdc + bin_challenge_len + DP_UUID_LEN, cp_uuid, DP_UUID_LEN );

    unsigned char hmac_result[HASH_LEN];
    wpa_supplicant_hmac_sha256( bin_stored, bin_stored_len, cdc, cdc_len, hmac_result );
    // release useless stuff
    free( bin_challenge );
    free( cdc );

    *bin_authenticator = malloc(DP_AUTH_BYTES);
    memcpy(*bin_authenticator, hmac_result, DP_AUTH_BYTES);
    *auth_len = DP_AUTH_BYTES;
    return 0;
}


/**
 * Validate input arguments for SetUserLoginPassword
 *
 * @param protocoltype,
 * @param name,
 * @param stored,
 * @param salt, 
 * @return 0 on success, -1 if operation fails.
 */
int validateArgsForSULP(const char *protocoltype, const char *name, const char *stored, const char *salt)
{
    if (strcmp(protocoltype, "PKCS5") != 0)
    {
        trace(1, "Login protocol type must be 'PKCS5': Invalid ProtocolType=%s\n",protocoltype);
        return -1; 
    }
    if (strlen(stored) < DP_STORED_BYTES)
    {
        trace(1, "Invalid length for Stored\n");
        return -1;
    }
    if (strlen(salt) < DP_SALT_BYTES)
    {
        trace(1, "Invalid length for Salt\n");
        return -1;
    }
    return 0;   
}

/**
 * Validate input arguments for UserLogin
 *
 * @param protocoltype,
 * @param challenge,
 * @param authenticator,
 * @return 0 on success, -1 if operation fails.
 */
int validateArgsForUL(const char *protocoltype, const char *challenge, const char *authenticator)
{
    if (strcmp(protocoltype, "PKCS5") != 0)
    {
        trace(1, "Login protocol type must be 'PKCS5': Invalid ProtocolType=%s\n",protocoltype);
        return -1; 
    }
    if (strlen(challenge) < DP_NONCE_BYTES)
    {
        trace(1, "Invalid length for Challenge\n");
        return -1;
    }
    if (strlen(authenticator) < DP_AUTH_BYTES)
    {
        trace(1, "Invalid length for Authenticator\n");
        return -1;
    }
    return 0;   
}


//-----------------------------------------------------------------------------
//
//                      DeviceProtection:1 Service Actions
//
//-----------------------------------------------------------------------------

/**
 * DeviceProtection:1 Action: SendSetupMessage
 * 
 * This action is used transport for pairwise introduction protocol messages.
 * Currently used protocol is WPS. Only one introduction process possible at same time.
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SendSetupMessage(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char resultStr[RESULT_LEN];
    char *protocoltype = NULL;
    char *inmessage = NULL;
    char IP_addr[INET6_ADDRSTRLEN];
    int id_len = 0;
    char *CP_id = NULL;
    int sm_status = 0;

    if ((protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "ProtocolType")) &&
            (inmessage = GetFirstDocumentItem(ca_event->ActionRequest, "InMessage")))
    {
        inet_ntop(AF_INET, &ca_event->CtrlPtIPAddr, IP_addr, INET6_ADDRSTRLEN);

        if (strcmp(protocoltype, "WPS") != 0)
        {
            trace(1, "Introduction protocol type must be 'WPS': Invalid ProtocolType=%s\n",protocoltype);
            if (gWpsIntroductionRunning)
                stopWPS();
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");

            free(inmessage);
            free(protocoltype);
            return ca_event->ErrCode;
        }

        // get identifier of CP 
        // this will tell if the same CP is doing all setup messages
        result = getIdentifierOfCP(ca_event, &CP_id, &id_len, NULL);

        if (result == 0 && !gWpsIntroductionRunning && strcmp(inmessage, "") == 0) // ready to start introduction. InMessage MUST be empty for M1
        {
            // store id of this CP to determine next time if still the same CP is using this.
            memcpy(prev_CP_id, CP_id, id_len);

            // begin introduction
            trace(2,"Begin DeviceProtection pairwise introduction process. IP %s\n",IP_addr);
            startWPS();
            // start the state machine and create M1
            result = wpa_supplicant_start_enrollee_state_machine(enrollee_state_machine,
                                                                 &Enrollee_send_msg,
                                                                 &Enrollee_send_msg_len);
            if (result != 0)
            {
                trace(1, "Failed to start WPS state machine. Returned %d\n",result);
                result = 704;
                addErrorData(ca_event, result, "Processing Error");
            }
        }
        else if (!gWpsIntroductionRunning && strcmp(inmessage, "") != 0)
        {
            trace(1, "Failure in SendSetupMessage: InMessage must be empty when fetching M1 message");
            result = 402;
            addErrorData(ca_event, result, "Invalid Args");
        }
        else if (gWpsIntroductionRunning && (memcmp(prev_CP_id, CP_id, id_len) == 0)) // continue started introduction
        {
            // to bin
            size_t b64msglen = strlen(inmessage);
            unsigned char *pBinMsg;
            size_t outlen;
            pBinMsg = wpa_supplicant_base64_decode((unsigned char *)inmessage, b64msglen, &outlen);

            // update state machine
            message_received(ca_event, 0, pBinMsg, outlen, &sm_status);
            free(pBinMsg);
        }
        else // must be busy doing someone else's introduction process 
        {
            trace(1, "Busy with someone else's introduction process. IP %s\n",IP_addr);
            result = 708;
            addErrorData(ca_event, result, "Busy");

            // set state variable SetupReady to false, meaning DP service is busy
            SetupReady = 0;
            IXML_Document *propSet = NULL;
            trace(3, "DeviceProtection SetupReady: %d", SetupReady);
            UpnpAddToPropertySet(&propSet, "SetupReady", "0");
            UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:DeviceProtection1", propSet);
            ixmlDocument_free(propSet);
        }
    }
    else
    {
        trace(1, "Failure in SendSetupMessage: Invalid Arguments!");
        result = 402;
        addErrorData(ca_event, result, "Invalid Args");
    }

    if (result == 0)
    {
        // response (next message) to base64
        size_t b64len = 0;
        unsigned char *pB64Msg;
        pB64Msg = wpa_supplicant_base64_encode(Enrollee_send_msg, Enrollee_send_msg_len, &b64len);

        trace(3,"Send response for SendSetupMessage request\n");

                //Handle invalid PIN case correctly
        if (sm_status == WPASUPP_SM_E_FAILURE)
        {
                trace(1, "return error 704\n");
                ca_event->ErrCode = 704;
        }
        else
                ca_event->ErrCode = UPNP_E_SUCCESS;
        
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<OutMessage>%s</OutMessage>\n</u:%sResponse>",
                 ca_event->ActionName, DP_SERVICE_TYPE, pB64Msg, ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
        free(pB64Msg);
    }

    // Any else state means that WPS is either ready or in error state and it must be terminated
    if (sm_status != WPASUPP_SM_E_PROCESS &&
        sm_status != WPASUPP_SM_E_SUCCESSINFO)
    {
        stopWPS();
    }

    // Send last ACK if success
    if (sm_status == WPASUPP_SM_E_SUCCESS)
    {
        // response (next message) to base64
        size_t b64len = 0;
        unsigned char *pB64Msg;
        pB64Msg = wpa_supplicant_base64_encode(Enrollee_send_msg, Enrollee_send_msg_len, &b64len);

        trace(3,"Send last ack in WPS\n");

        ca_event->ErrCode = UPNP_E_SUCCESS;
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<OutMessage>%s</OutMessage>\n</u:%sResponse>",
                 ca_event->ActionName, DP_SERVICE_TYPE, pB64Msg, ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
        free(pB64Msg);
    }

    free(CP_id);
    free(inmessage);
    free(protocoltype);
    return ca_event->ErrCode;
}


/**
 * DeviceProtection:1 Action: GetSupportedProtocols.
 *
 * Retrieve a list of setup protocols supported by the Device
 * 
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetSupportedProtocols(struct Upnp_Action_Request *ca_event)
{
    IXML_Document *ActionResult = NULL;
    ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                    1,
                                    "ProtocolList", SupportedProtocols);

    if (ActionResult)
    {
        ca_event->ActionResult = ActionResult;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetSupportedProtocols");
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 501;
    }

    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: GetUserLoginChallenge.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetUserLoginChallenge(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *protocoltype = NULL;
    char *name = NULL;
    int ret, len=0;
    char *identifier = NULL;

    // CP with same ID must be listed in ACL
    ret = getIdentifierOfCP(ca_event, &identifier, &len, NULL);
    if (identifier && (ACL_getRolesOfCP(ACLDoc, identifier) == NULL))
    {
        trace(1, "%s: ID '%s' of control point is not listed in ACL",ca_event->ActionName,identifier);
        // TODO: Check this error code!
        result = 606;
        addErrorData(ca_event, result, "Action not authorized");
        free(identifier);
        return ca_event->ErrCode;
    }

    if (( protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "ProtocolType") )
            && ( name = GetFirstDocumentItem(ca_event->ActionRequest, "Name") ))
    {
        if (strcmp(protocoltype, "PKCS5") != 0)
        {
            trace(1, "Login protocol type must be 'PKCS5': Invalid ProtocolType=%s\n",protocoltype);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");

            free(name);
            free(protocoltype);
            free(identifier);
            return ca_event->ErrCode;
        }

        // check if user exits in password file and also in ACL.
        // "Administrator" is an exception and it doesn't have to be in those files.
        if ((caseInsesitive_strcmp(name, admin_name) == 0) ||
            ((getValuesFromPasswdFile(name, NULL,NULL,NULL,NULL,0) == 0) &&
            (ACL_getRolesOfUser(ACLDoc, name) != NULL)))
        {
            // parameters OK
            if (result == 0)
            {
                createUserLoginChallengeResponse(ca_event, name);
            }
        }
        else
        {
            trace(1, "Unknown username %s",name);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
    }
    else
    {
        trace(1, "Failure in GetUserLoginChallenge: Invalid Arguments!");
        trace(1, "  ProtocolType: %s Name: %s",protocoltype,name);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(name);
    free(protocoltype);
    free(identifier);

    return ca_event->ErrCode;
}

void print_uuid( unsigned char *data )
{
    char tmp[120], uuid_str[120];
    int i;
    size_t uuid_size = sizeof( my_uuid_t );
    my_uuid_t *uuid = malloc( uuid_size );

    memcpy( uuid, data, uuid_size );

    snprintf( uuid_str, 37, "%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", uuid->time_low, uuid->time_mid,
               uuid->time_hi_and_version, uuid->clock_seq_hi_and_reserved, uuid->clock_seq_low );

    for ( i = 0; i < 6; i++ )
    {
        snprintf( tmp, 3, "%2.2x", uuid->node[i] );
        strcat( uuid_str, tmp );
    }

    printf("UUID: %s", uuid_str);
}

/**
 * DeviceProtection:1 Action: UserLogin.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int UserLogin(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *protocoltype = NULL;
    char *challenge = NULL;
    char *authenticator = NULL;
    int loginattempts = 0;
    char *loginName = NULL;
    char *loginChallenge = NULL;
    int active;

    char *id =NULL;
    int id_len = 0;

    char *identifier = NULL;
    int identifier_len;

    // CP with same ID must be listed in ACL
    getIdentifierOfCP(ca_event, &identifier, &identifier_len, NULL);
    if (identifier && (ACL_getRolesOfCP(ACLDoc, identifier) == NULL))
    {
        trace(1, "%s: ID '%s' of control point is not listed in ACL",ca_event->ActionName,identifier);
        result = 606;
        addErrorData(ca_event, result, "Action not authorized");
        free(identifier);
        return ca_event->ErrCode;
    }
    free(identifier);

    if (( protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "ProtocolType") )
            &&( challenge = GetFirstDocumentItem(ca_event->ActionRequest, "Challenge") )
            && ( authenticator = GetFirstDocumentItem(ca_event->ActionRequest, "Authenticator") ))
    {
        if (validateArgsForUL(protocoltype, challenge, authenticator) != 0)
        {
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");

            free(challenge);
            free(protocoltype);
            free(authenticator);
            return ca_event->ErrCode;
        }

        result = getIdentifierOfCP(ca_event, &id, &id_len, NULL);
        trace(3,"CP with identifier '%s' is logging in.",id);
        // here we could try "session resumption" by getting identity from SIR?
        // but not now, just continue as new login...
        result = SIR_getLoginDataOfSession(SIRDoc, (char *)id, &loginattempts, &loginName, &loginChallenge);

        if (result != 0 || !loginName || !loginChallenge)
        {
            trace(1, "%s: Failed to get login data for this session",ca_event->ActionName);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");

            // don't return yet, we need to check if CP has tried to login too many times
        }

        // has CP tried to login too many times already?
        if (++loginattempts >= DP_MAX_LOGIN_ATTEMPTS)
        {
            trace(1,"CP with identifier '%s' has tried unsuccesfully to login too many times. Closing connection...",id);
            // out and away!
            // close SSL session on way out...
            UpnpTerminateSSLSession(ca_event->SSLSession, ca_event->Socket);
            trace(3,"Cleaning SIR...");
            // remove session from SIR
            SIR_removeSession(SIRDoc, (char *)id);

            free(protocoltype);
            free(challenge);
            free(authenticator);
            free(loginName);
            free(loginChallenge);
            free(id);

            trace_ixml(3, "Contents of SIR:",SIRDoc);
            return ca_event->ErrCode;
        }

        // does our challenge stored in SIR match challenge received from control point
        if (result == 0 && strcmp(challenge, loginChallenge) != 0)
        {
            trace(1, "%s: Challenge value does not match value from SIR",ca_event->ActionName);
            trace(3, "Received challenge was '%s' and local challenge was '%s'",challenge, loginChallenge);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }

        if (result == 0)
        {
            // update loginattempts value
            result = SIR_updateSession(SIRDoc, (char *)id, NULL, NULL, NULL, &loginattempts, NULL, NULL);

            // get stored from passwd file
            int maxb64len = 2*DP_STORED_BYTES;
            unsigned char *b64_salt = (unsigned char *)malloc(maxb64len); 
            unsigned char *b64_stored = (unsigned char *)malloc(maxb64len);
            int salt_len, stored_len;

            result = getValuesFromPasswdFile(loginName, &b64_salt, &salt_len, &b64_stored, &stored_len, maxb64len);
            if (result != 0 || stored_len < 1)
            {
                // failure
                trace(2, "%s: Failed to get STORED and Challenge from passwd file. (username: '%s')",ca_event->ActionName,loginName);
                result = 600;
                addErrorData(ca_event, result, "Argument Value Invalid");
            }
            else
            {
                // first decode the received authenticator
                int bin_auth_1_len;
                unsigned char *bin_auth_1 = wpa_supplicant_base64_decode((unsigned char*)authenticator,
                                                                         strlen(authenticator),
                                                                         (size_t*)&bin_auth_1_len);
                    
                // create authenticator from the locally stored values
                int bin_auth_2_len = 0;
                unsigned char *bin_auth_2 = NULL;
                unsigned char *cp_uuid = NULL;
                if ( get_cp_uuid( ca_event, &cp_uuid ) != 0)
                {
                    // TODO: correct this
                    trace(2, "UserLogin: unable to get UUID",ca_event->ActionName,loginName);
                    result = 600;
                    addErrorData(ca_event, result, "Argument Value Invalid");
                    return ca_event->ErrCode;
                }
                print_uuid( cp_uuid );
                result = createAuthenticator((char *)b64_stored, loginChallenge, &bin_auth_2, cp_uuid, &bin_auth_2_len);

                // do the authenticators match?
                if (result != 0)
                {
                    trace(2, "%s: Failed to create authenticator",ca_event->ActionName);
                    result = 501;
                    addErrorData(ca_event, result, "Action Failed");
                }
                else if ((bin_auth_1_len != bin_auth_2_len) ||
                         (memcmp(bin_auth_1, bin_auth_2, bin_auth_1_len) != 0))
                {
                    trace(1, "%s: Authenticator values do not match!",ca_event->ActionName);
                    result = 701;
                    addErrorData(ca_event, result, "Authentication Failure");
                }
                else
                {
                    trace(2,"CP with id '%s' succeeded to log in as '%s'",id,loginName);
                    // Login is now succeeded
                    loginattempts = 0;
                    active = 1;

                    // fetch roles of logged in loginname and roles defined for CP and set those as parameter for SIR_updateSession
                    char *roles = createUnion(ACL_getRolesOfUser(ACLDoc, loginName), ACL_getRolesOfCP(ACLDoc, id));

                    // after updating SIR, login is official
                    result = SIR_updateSession(SIRDoc, (char *)id, &active, loginName, roles, &loginattempts, NULL, NULL);

                    free(roles);

                    // remove logindata from SIR
                    SIR_removeLoginDataOfSession(SIRDoc, (char *)id);
                    // create response SOAP message
                    IXML_Document *ActionResult = NULL;
                    ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                                    0, NULL);

                    if (ActionResult && result == 0)
                    {
                        ca_event->ActionResult = ActionResult;
                        ca_event->ErrCode = UPNP_E_SUCCESS;
                    }
                    else
                    {
                        trace(1, "Error parsing Response to %s (or failed to change identity of user in SIR)",ca_event->ActionName);
                        result = 501;
                        addErrorData(ca_event, result, "Action Failed");
                    } 
                }

                free(bin_auth_1);
                free(bin_auth_2);
            }
            free(b64_salt);
            free(b64_stored);
        }
    }

    else
    {
        trace(1, "Failure in %s: Invalid Arguments!",ca_event->ActionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(protocoltype);
    free(challenge);
    free(authenticator);
    free(loginName);
    free(loginChallenge);
    free(id);

    trace_ixml(3, "Contents of SIR:",SIRDoc);
    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: UserLogout.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int UserLogout(struct Upnp_Action_Request *ca_event)
{
    char *id =NULL;
    int id_len = 0;
    int result = 0;

    if (ca_event->SSLSession)
    {
        result = getIdentifierOfCP(ca_event, &id, &id_len, NULL);

        if (result != 0)
        {
            trace(1, "%s: Failed to get identifier from certificate",ca_event->ActionName);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        else
        {
            // Totally remove this session from SIR. No session resumption is supported.
            // When this same session next time calls an action, checkCPPrivileges function 
            // will add this session again to SIR with default roles (either with roles defined 
            // in ACL for that CP or "Public" if CP is not found from ACL). 
            result = SIR_removeSession(SIRDoc, id);

            if (result != 0)
            {
                trace(1, "%s: Failed to remove Session with ID '%s' from SIR",ca_event->ActionName,id);
                result = 501;
                addErrorData(ca_event, result, "Action Failed"); 
            }
        }
    }

    // success (or nothing was logged in or SSL connection was not used so nothing can be logged in)
    if (result == 0)
    {
        // create response SOAP message
        IXML_Document *ActionResult = NULL;
        ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        0, NULL);
        ca_event->ActionResult = ActionResult;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }

    free(id);

    trace_ixml(3, "Contents of SIR:",SIRDoc);
    return ca_event->ErrCode;
}


/**
 * DeviceProtection:1 Action: GetACLData.
 * 
 * Return the Device’s Access Control List (ACL).
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetACLData(struct Upnp_Action_Request *ca_event)
{
    char *ACL;
    IXML_Document *ActionResult = NULL;

    char *identifier = NULL;
    int identifier_len;

    // CP with same ID must be listed in ACL
    getIdentifierOfCP(ca_event, &identifier, &identifier_len, NULL);
    if (identifier && (ACL_getRolesOfCP(ACLDoc, identifier) == NULL))
    {
        trace(1, "%s: ID '%s' of control point is not listed in ACL",ca_event->ActionName,identifier);
        addErrorData(ca_event, 606, "Action not authorized");
        free(identifier);
        return ca_event->ErrCode;
    }
    free(identifier);

    ACL = ixmlDocumenttoString(ACLDoc);
    if (ACL)
    {
        ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        1,
                                        "ACL", ACL);
        free (ACL);
    }
    else
    {
        trace(1, "Error reading ACL value");
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 501;
        return ca_event->ErrCode;
    }

    if (ActionResult)
    {
        ca_event->ActionResult = ActionResult;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetSupportedProtocols");
        ca_event->ActionResult = NULL;
        ca_event->ErrCode = 501;
    }

    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: AddRolesForIdentity.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int AddRolesForIdentity(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *identity = NULL;
    char *rolelist = NULL;
    IXML_Document *identityDoc = NULL;

    if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") )
            && (rolelist = GetFirstDocumentItem(ca_event->ActionRequest, "RoleList") ))
    {
        // unescape identity
        char *unescValue = unescapeXMLString(identity);

        identityDoc = ixmlParseBuffer(unescValue);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, unescValue);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
            free(unescValue);
            free(identity);
            free(rolelist);

            return ca_event->ErrCode;
        }

        // add roles for identity which is found from identityDoc
        result = ACL_addRolesForIdentity(ACLDoc, identityDoc, rolelist);
        if (result == ACL_USER_ERROR)
        {
            // ok, identity wasn't username or hash
            trace(1, "AddRolesForIdentity: Unknown identity %s",identity);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        else if (result == ACL_ROLE_ERROR)
        {
            trace(1, "AddRolesForIdentity: Invalid rolelist received %s",rolelist);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        else if (result != ACL_SUCCESS)
        {
            trace(1, "AddRolesForIdentity: Failed to add roles '%s' for identity '%s'",rolelist,unescValue);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        free(unescValue);

        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);
            ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        0, NULL);
            ca_event->ErrCode = UPNP_E_SUCCESS;
        }

    }
    else
    {
        trace(1, "AddRolesForIdentity: Invalid Arguments!");
        trace(1, "  Identity: %s, RoleList: %s",identity,rolelist);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    ixmlDocument_free(identityDoc);
    free(identity);
    free(rolelist);

    trace_ixml(3, "Contents of ACL:",ACLDoc);

    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: RemoveRolesForIdentity.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int RemoveRolesForIdentity(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *identity = NULL;
    char *rolelist = NULL;
    IXML_Document *identityDoc = NULL;

    if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") )
            && (rolelist = GetFirstDocumentItem(ca_event->ActionRequest, "RoleList") ))
    {
        // unescape identity
        char *unescValue = unescapeXMLString(identity);

        identityDoc = ixmlParseBuffer(unescValue);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, unescValue);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
            free(unescValue);
            free(identity);
            free(rolelist);

            return ca_event->ErrCode;
        }

        // remove roles from identity which is found from identityDoc
        result = ACL_removeRolesFromIdentity(ACLDoc, identityDoc, rolelist);
        if (result == ACL_USER_ERROR)
        {
            // identity wasn't username or hash
            trace(1, "%s: Unknown identity %s",ca_event->ActionName,identity);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        else if (result == ACL_ROLE_ERROR)
        {
            trace(1, "%s: Invalid rolelist received %s",ca_event->ActionName,rolelist);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        else if (result != ACL_SUCCESS)
        {
            trace(1, "%s: Failed to remove roles '%s' from identity '%s'",ca_event->ActionName,rolelist,unescValue);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        free(unescValue);

        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);
            ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        0, NULL);
            ca_event->ErrCode = UPNP_E_SUCCESS;
        }

    }
    else
    {
        trace(1, "%s: Invalid Arguments!",ca_event->ActionName);
        trace(1, "  Identity: %s, RoleList: %s",identity,rolelist);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    ixmlDocument_free(identityDoc);
    free(identity);
    free(rolelist);

    trace_ixml(3, "Contents of ACL:",ACLDoc);

    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: GetAssignedRoles.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetAssignedRoles(struct Upnp_Action_Request *ca_event)
{
    IXML_Document *ActionResult = NULL;
    char *roles = NULL;
    int result = 0;

    // get the roles
    result = getRolesOfSession(ca_event, &roles);
    // if no roles is still NULL, this could mean two things: either action was not initiated over SSL
    // or certificate of Control Point is unknown for us. In both cases "Public" role must be returned
    if (roles == NULL)
    {
        roles = "Public";
        result = 0;
    }

    if (result == 0 && roles)
    {
        ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        1,
                                        "RoleList", roles);
    }
    else
    {
        trace(1, "Error getting roles of session");
        addErrorData(ca_event, 501, "Action Failed");
        return ca_event->ErrCode;
    }

    if (ActionResult)
    {
        ca_event->ActionResult = ActionResult;
        ca_event->ErrCode = UPNP_E_SUCCESS;
    }
    else
    {
        trace(1, "Error parsing Response to GetAssignedRoles");
        addErrorData(ca_event, 501, "Action Failed");
    }

    return ca_event->ErrCode;
}


/**
 * DeviceProtection:1 Action: GetRolesForAction.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetRolesForAction(struct Upnp_Action_Request *ca_event)
{
    int result = 0;

    char *deviceUDN = NULL;
    char *serviceId = NULL;
    char *actionName = NULL;
    char *roleList = NULL;
    char *restrictedRoleList = NULL;
    char *identifier = NULL;
    int identifier_len;

    // CP with same ID must be listed in ACL
    getIdentifierOfCP(ca_event, &identifier, &identifier_len, NULL);
    if (identifier && (ACL_getRolesOfCP(ACLDoc, identifier) == NULL))
    {
        trace(1, "%s: ID '%s' of control point is not listed in ACL",ca_event->ActionName,identifier);
        result = 606;
        addErrorData(ca_event, result, "Action not authorized");
        free(identifier);
        return ca_event->ErrCode;
    }
    free(identifier);

    if ( (deviceUDN = GetFirstDocumentItem(ca_event->ActionRequest, "DeviceUDN"))
        && (serviceId = GetFirstDocumentItem(ca_event->ActionRequest, "ServiceId"))
        && (actionName = GetFirstDocumentItem(ca_event->ActionRequest, "ActionName")) )
    {
        /* Here we are going to cheat a little. Instead of checking that ActionName is found from device
           with DeviceUDN, we just check that given DeviceUDN is valid. This IGD won't most probably 
           have two services with same id under different devices. */
        if ( (strcmp(deviceUDN, gateUDN) != 0) && (strcmp(deviceUDN, wanUDN) != 0) && (strcmp(deviceUDN, wanConnectionUDN) != 0) )
        {
            trace(1, "%s: Invalid DeviceUDN '%s'",
                  ca_event->ActionName, deviceUDN);
            trace(3, "compared to '%s', '%s', '%s'", gateUDN, wanUDN, wanConnectionUDN);
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");
        }
        else
        {
            trace(3, "Get roles for S:'%s', A:'%s'", serviceId, actionName);
            roleList = getAccessLevel(serviceId, actionName, 1, NULL);
            if (roleList)
            {
                // get restricted rolelist if it exists
                restrictedRoleList = getAccessLevel(serviceId,actionName, 0, NULL);
                if (restrictedRoleList)
                {
                    ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                                2,
                                                "RoleList", roleList,
                                                "RestrictedRoleList", restrictedRoleList);
                }
                else
                {
                    ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                                2,
                                                "RoleList", roleList,
                                                "RestrictedRoleList", "");
                }
                ca_event->ErrCode = UPNP_E_SUCCESS;
            }
            else
            {
                // invalid ActionName
                trace(1, "%s: Combination of ServiceId '%s' and ActionName '%s' is not found from %s",
                    ca_event->ActionName,serviceId,actionName,g_vars.accessLevelXml);
                result = 600;
                addErrorData(ca_event, result, "Argument Value Invalid");
            }
        }
    }
    else
    {
        trace(1, "GetRolesForAction: Invalid Arguments!");
        trace(1, "  ServiceId: %s, ActionName: %s  ", serviceId, actionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(deviceUDN);
    free(serviceId);
    free(actionName);
    free(roleList);
    free(restrictedRoleList);

    return ca_event->ErrCode;
}


/**
 * DeviceProtection:1 Action: SetUserLoginPassword.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int SetUserLoginPassword(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *protocoltype = NULL;
    char *name = NULL;
    char *stored = NULL;
    char *salt = NULL;
    char *identity = NULL;

    if ( (protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "ProtocolType") )
            && (name = GetFirstDocumentItem(ca_event->ActionRequest, "Name") )
            && (stored = GetFirstDocumentItem(ca_event->ActionRequest, "Stored") )
            && (salt = GetFirstDocumentItem(ca_event->ActionRequest, "Salt") ))
    {
        trace(3, "ProtocolType:'%s', Name:'%s', Stored:'%s', Salt:'%s'",
              protocoltype, name, stored, salt);
        if (validateArgsForSULP(protocoltype, name, stored, salt) != 0)
        {
            result = 600;
            addErrorData(ca_event, result, "Argument Value Invalid");

            free(protocoltype);
            free(name);
            free(stored);
            free(salt);
            return ca_event->ErrCode;
        }
        
        // First try to update existing username/password pair
        else
        {
            getIdentityOfSession(ca_event, &identity);
            if (identity == NULL)
            {
                trace(1, "%s: Failed to get session identity",ca_event->ActionName);
                result = 501;
                addErrorData(ca_event, result, "Action Failed");
            }
            // check from SIR that username received as parameter is current identity of this session
            // or has "Admin" privileges
            // TODO: This might be better to do by getting managed roles from acceslevels. But spec might change so let this be now... 
            else if ( (checkCPPrivileges(ca_event, "Admin") == 0) || (strcmp(identity, name) == 0))
            {
                result = updateValuesToPasswdFile(name, (unsigned char *)salt, (unsigned char *)stored, 0); // if this returns 0, all is well
                if (result == -2)
                {
                    // So we are after all adding new username! (Because username was not found from passwd-file)
                    // lets Add new
                    result = putValuesToPasswdFile(name, (unsigned char *)salt, (unsigned char *)stored);
                    if (result == -2)
                    {
                        trace(1, "%s: Same username '%s' exists in passwd file already",ca_event->ActionName,name);
                        result = 600;
                        addErrorData(ca_event, result, "Argument Value Invalid");
                    }
                    else if (result != 0)
                    {
                        trace(1, "%s: Failed to write login values to passwordfile",ca_event->ActionName);
                        result = 501;
                        addErrorData(ca_event, result, "Action Failed");

                        // if failed to add new logindata to file but reason wasn't that same username 
                        // existed in passwd file already, try to remove added data
                        updateValuesToPasswdFile(name, (unsigned char *)salt, (unsigned char *)stored, 1);
                    }
                    else
                    {
                        // add user to ACL also
                        result = ACL_addUser(ACLDoc, name, "Public");  // if this return 0, all is well
                        // user might have ben added through AddIdentityList previously
                        if (result == ACL_USER_ERROR) 
                            result = ACL_SUCCESS;

                        // if failed, try to clean up what have done so far
                        if (result != ACL_SUCCESS && result != ACL_USER_ERROR) 
                        {
                            trace(1, "%s: Failed to add username to ACL",ca_event->ActionName);
                            result = 501;
                            addErrorData(ca_event, result, "Action Failed");

                            // remove added username from passwdfile
                            updateValuesToPasswdFile(name, (unsigned char *)salt, (unsigned char *)stored, 1);
                            // try to remove username from ACL
                            ACL_removeUser(ACLDoc, name);
                        }
                    } // end of adding new

                }
                else if (result != 0)
                {
                    trace(1, "%s: Failed to update login values to passwordfile",ca_event->ActionName);
                    result = 501;
                    addErrorData(ca_event, result, "Action Failed");
                }
            }
            else
            {
                trace(1, "%s: Not enough privileges to do this, '%s' is required",ca_event->ActionName, "Admin");
                result = 606;
                addErrorData(ca_event, result, "Action not authorized");
            }
        }

        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);
            ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        0, NULL);
            ca_event->ErrCode = UPNP_E_SUCCESS;
        }
    }
    else
    {
        trace(1, "%s: Invalid Arguments!", ca_event->ActionName);
        trace(1, "   Name: %s, Stored: %s, Salt: %s",name,stored,salt);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    free(protocoltype);
    free(name);
    free(stored);
    free(salt);
    free(identity);

    trace_ixml(3, "Contents of ACL:",ACLDoc);

    return ca_event->ErrCode;
}


/**
 * DeviceProtection:1 Action: AddIdentityList.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int AddIdentityList(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *identitylist = NULL;
    IXML_Document *identitiesDoc = NULL;

    if ( (identitylist = GetFirstDocumentItem(ca_event->ActionRequest, "IdentityList") ))
    {
        // unescape identitylist
        char *unescValue = unescapeXMLString(identitylist);

        trace(3, "%s: Received IdentityList: \n%s",ca_event->ActionName,unescValue); 
        identitiesDoc = ixmlParseBuffer(unescValue);
        if (identitiesDoc == NULL)
        {
            trace(1, "%s: Failed to parse IdentityList '%s'",ca_event->ActionName, unescValue);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        else
        {
            // validate contents of list and add new identities to ACL
            result = ACL_validateListAndUpdateACL(ACLDoc, identitiesDoc);
            if (result == 600)
            {
                addErrorData(ca_event, result, "Argument Value Invalid");
            }
            else if (result != 0)
            {
                result = 501;
                addErrorData(ca_event, result, "Action Failed");
            }
        }
        free(unescValue);

        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);

            // get identities element from ACL and return it to CP
            char *responseIdentities = NodeWithNameToString(ACLDoc, "Identities");

            if (responseIdentities)
            {
                // replace <Identities> from beginning with <Identities xmlns="...>
                char responseIdentitiesWithNamespace[strlen(responseIdentities)+300]; // 300 is few chars more than text below
                strcpy(responseIdentitiesWithNamespace,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                                       "<Identities xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\" "
                                                       "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                                                       "xsi:schemaLocation=\"urn:schemas-upnp-org:gw:DeviceProtection "
                                                       "http://www.upnp.org/schemas/gw/DeviceProtection-v1.xsd\">");
                strcat(responseIdentitiesWithNamespace, responseIdentities+12);
                free(responseIdentities);

                // Succesfull end happens here, libupnp takes care of escaping the string for SOAP
                ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                            1, 
                                            "IdentityListResult", responseIdentitiesWithNamespace,
                                            NULL);
                ca_event->ErrCode = UPNP_E_SUCCESS;
            }
            else
            {
                trace(1, "%s: Failed to get IdentityListResult",ca_event->ActionName);
                result = 501;
                addErrorData(ca_event, result, "Action Failed");
            }
        }
        else
        {
            // erase all possible changes done
            ixmlDocument_free(ACLDoc);
            // init ACL
            ACLDoc = ixmlLoadDocument(ACL_XML);
            if (ACLDoc == NULL)
            {
                trace(1, "Couldn't load ACL (Access Control List) document which should locate here: %s\nExiting...\n",ACL_XML);
                UpnpFinish();
                exit(1);
            }
        }
    }
    else
    {
        trace(1, "%s: Invalid Arguments!", ca_event->ActionName);
        trace(1, "  IdentityList: %s",identitylist);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    ixmlDocument_free(identitiesDoc);
    free(identitylist);

    trace_ixml(3, "Contents of ACL:",ACLDoc);
    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: RemoveIdentity.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int RemoveIdentity(struct Upnp_Action_Request *ca_event)
{
    int result = 0;
    char *identity = NULL;
    IXML_Document *identityDoc = NULL;

    if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") ))
    {
        // unescape identity
        char *unescValue = unescapeXMLString(identity);

        identityDoc = ixmlParseBuffer(unescValue);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, unescValue);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        else
        {
            trace(3, "%s: Received Identity: \n%s",ca_event->ActionName,unescValue); 
            // validate input and remove CP/User
            result = ACL_validateAndRemoveIdentity(ACLDoc, identityDoc);

            if (result == 600)
            {
                addErrorData(ca_event, result, "Argument Value Invalid");
            }
            else if (result != 0)
            {
                result = 501;
                addErrorData(ca_event, result, "Action Failed");
            }
        }
        free(unescValue);

        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);
            ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        0, NULL);
            ca_event->ErrCode = UPNP_E_SUCCESS;
        }
        else
        {
            // erase all possible changes done
            ixmlDocument_free(ACLDoc);
            // init ACL
            ACLDoc = ixmlLoadDocument(ACL_XML);
            if (ACLDoc == NULL)
            {
                trace(1, "Couldn't load ACL (Access Control List) document which should locate here: %s\nExiting...\n",ACL_XML);
                UpnpFinish();
                exit(1);
            }
        }
    }
    else
    {
        trace(1, "%s: Invalid Arguments!", ca_event->ActionName);
        trace(1, "  Identity: %s",identity);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    ixmlDocument_free(identityDoc);
    free(identity);

    trace_ixml(3, "Contents of ACL:",ACLDoc);

    return ca_event->ErrCode;
}
