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
#include <wpsutil/enrollee_state_machine.h>
#include <wpsutil/base64mem.h>
#include <wpsutil/cryptoutil.h>
#include <upnp/upnptools.h>
#include <upnp/upnp.h>

static void message_received(struct Upnp_Action_Request *ca_event, int error, unsigned char *data, int len, int *status);
static int getSaltAndStoredForName(const char *nameUPPER, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len);
static int createUserLoginChallengeResponse(struct Upnp_Action_Request *ca_event, const char *nameUPPER);
static int getValuesFromPasswdFile(const char *nameUPPER, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len, int max_size);
static int putValuesToPasswdFile(const char *name, const unsigned char *b64_salt, const unsigned char *b64_stored);
static int updateValuesToPasswdFile(const char *nameUPPER, const unsigned char *b64_salt, const unsigned char *b64_stored, int delete_values);
static int getIdentifierOfCP(struct Upnp_Action_Request *ca_event, char **identifier, int *idLen, char **CN);
static int createAuthenticator(const char *b64_stored, const char *b64_challenge, char **b64_authenticator, int *auth_len);

// WPS state machine related stuff
static WPSuEnrolleeSM* esm;
static unsigned char* Enrollee_send_msg;
static int Enrollee_send_msg_len;
static WPSuStationInput *wpsu_input;

// identifer of control point which is executing introduction process
static unsigned char prev_CP_id[40];

// Access Control List
static IXML_Document *ACLDoc = NULL;

#define PSEUDO_RANDOM_UUID_TYPE 0x4
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
 * If session contains "role"-element, this is the current role for this sesseion, not value from ACL.
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
 *      <role>Basic</role>
 *      <logindata loginattempts="2">
 *          <name>Admin</name>
 *          <challenge>83h83288J7YGHGS778jsJJHGDn=</challenge>
 *      </logindata>
 *  </session>
 * </SIR>
 */
static IXML_Document *SIRDoc = NULL;


/**
 * Initialize DeviceProtection StateVariables for their default values.
 * 
 * @return void
 */
void DPStateTableInit()
{
    // DeviceProtection is ready for introduction
    SetupReady = 1;
    strcpy(SupportedProtocols, "<SupportedProtocols><Introduction><Name>WPS</Name></Introduction></SupportedProtocols>");   
}

/**
 * Initialize DeviceProtection. Create input for WPS
 * 
 * @return int. 0 on success
 */
int InitDP()
{   
    DP_loadDocuments();
    
    int err;
    char descDocFile[sizeof(g_vars.xmlPath)+sizeof(g_vars.descDocName)+2];
    unsigned char MAC[WPSU_MAC_LEN];
    memset(MAC, 0x00, WPSU_MAC_LEN);
    GetMACAddressStr(MAC, WPSU_MAC_LEN, g_vars.intInterfaceName);

    // manufacturer and device info is read from device description XML
    sprintf(descDocFile, "%s/%s", g_vars.xmlPath, g_vars.descDocName);
    IXML_Document *descDoc = ixmlLoadDocument(descDocFile);
    
    if (descDoc)
    {
        char *UUID = GetFirstDocumentItem(descDoc, "UDN");
        if (strlen(UUID) > 5)
        {
            UUID = UUID + 5; // remove text uuid: from beginning of string
        }
        if (strlen(UUID) > WPSU_MAX_UUID_LEN) // if uuid is too long, crop only allowed length from beginning
        {
            UUID[WPSU_MAX_UUID_LEN] = '\0';
        }
        
        wpsu_input = (WPSuStationInput *)malloc(sizeof(WPSuStationInput));
        memset(wpsu_input, 0, sizeof(*(wpsu_input)));
       
        err = wpsu_enrollee_station_input_add_device_info(wpsu_input, 
                                            g_vars.pinCode,
                                            GetFirstDocumentItem(descDoc, "manufacturer"),
                                            GetFirstDocumentItem(descDoc, "modelName"),
                                            GetFirstDocumentItem(descDoc, "modelNumber"),
                                            GetFirstDocumentItem(descDoc, "serialNumber"),
                                            GetFirstDocumentItem(descDoc, "friendlyName"),
                                            NULL,
                                            0,
                                            MAC,
                                            WPSU_MAC_LEN,
                                            (unsigned char*)UUID,
                                            strlen(UUID),
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                            WPSU_CONF_METHOD_LABEL, 
                                            WPSU_RFBAND_2_4GHZ);
        if (err != WPSU_E_SUCCESS)
            return err;                                                                             
    }
    else return UPNP_E_FILE_NOT_FOUND;
    
  
    return 0;
}


/**
 * Deinit DeviceProtection.
 * Free WPS input. Counterpart of InitDP()
 *
 * @return void
 */
void FreeDP()
{    
    wpsu_enrollee_station_input_free(wpsu_input);
    
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
    
    //fprintf(stderr,"\n\n\n%s\n",ixmlPrintDocument(ACLDoc));
    
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
 * @param targetRole Rolename that control point or user should have registerd in ACL
 * @return 0 if rolename is found and everything is ok, 1 if CP doesn't have privileges. Something else if error
 */
int checkCPPrivileges(struct Upnp_Action_Request *ca_event, const char *targetRole)
{
    int ret, len=0;
    char *identifier = NULL;

    // get identity of CP 
    ret = getIdentifierOfCP(ca_event, &identifier, &len, NULL);
    if (ret != 0 )
    {
        if (identifier) free(identifier);
        return ret;
    } 

    // Let's add new entry to SIR with role value "Public". Identity is not inserted.
    // If return value is -1, session was there already. If 0 CP was new and it was 
    // succesfully added to SIR.
    // Every action is checked through checkCPPrivileges, so that why every session is found from SIR
    ret = SIR_addSession(SIRDoc, identifier, 0, NULL, "Public", NULL, NULL, NULL);
    if (ret == 0)
    {
        trace(3, "New session was added to SIR. Id: '%s'",identifier);
        trace(3, "Contents of SIR:\n%s\n",ixmlPrintDocument(SIRDoc));
    }
    else if (ret == -1)
    {
        // ok it was there already. Just continue   
    }
    else
    {
        trace(2,"SIR handling failed somehow when adding new session!");
        if (identifier) free(identifier);
        return -1;
    }
    
    // fetch current identity of CP from SIR. Identity may be username or identity created from certificate
    int active;
    char *roles = NULL;
    char *identity = SIR_getIdentityOfSession(SIRDoc, identifier, &active, &roles);
    if (identifier) free(identifier);
    
    if (identity == NULL)
    {
        // So session doesn't have any identity yet. This means that CP is privileged only to Public actions            
        // check if targetrole is public
        if (strcmp(targetRole, "Public") == 0)
            return 0;
        else 
            return 1;
    }
// TODO Does this really go like this? Test this later. What if user is not logged in
//      but CP in ACL has Admin rights or something?
    if (active && roles == NULL) // this means that user is logged in as some username
    {
        //  check if target role is one of current roles of identity
        if ( ACL_doesIdentityHasRole(ACLDoc, identity, targetRole) )
            return 0;
    }
    else  // this means that user isn't logged in
    {
        if ( tokenizeAndSearch(roles, " ", targetRole) )
            return 0;
    }
    
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
 * @param hash Input data from which uuid is created
 * @param hashLen Length of input data. Or how much of it is used.
 * @return void
 */
void createUuidFromData(char **uuid_str, unsigned char *hash, int hashLen)
{
    my_uuid_t *uuid = malloc(sizeof *uuid);
    int i;
    *uuid_str = malloc(37*sizeof(char));
    char tmp[3];
    memset(*uuid_str, '\0', 37);
   
    memcpy(uuid, hash, sizeof *uuid);
    uuid->time_low = ntohl(uuid->time_low);
    uuid->time_mid = ntohs(uuid->time_mid);
    uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);

    /* put in the variant and version bits */
    uuid->time_hi_and_version &= 0x0FFF;
    uuid->time_hi_and_version |= (PSEUDO_RANDOM_UUID_TYPE << 12);
    uuid->clock_seq_hi_and_reserved &= 0x3F;
    uuid->clock_seq_hi_and_reserved |= 0x80;
    
    
    // create string representation from binary
    snprintf(*uuid_str, 37, "%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", uuid->time_low, uuid->time_mid,
            uuid->time_hi_and_version, uuid->clock_seq_hi_and_reserved, uuid->clock_seq_low);

    for (i = 0; i < 6; i++)
    {
        snprintf(tmp, 3, "%2.2x", uuid->node[i]);
        strcat(*uuid_str,tmp);
    }
    
    if (uuid) free(uuid);
}


/**
 * Get identity identifier of Control point based on certificate of Control Point.
 * Identifier is created like this:
 *  1. create sha-256 hash from CP certificate
 *  2. create uuid string from 16 first bytes of previously created hash
 * 
 * @param ca_event Upnp event struct.
 * @param identifier Pointer to char* where identifier is created. Caller should use free() for this.
 * @param idLen Length of created base64 identifier
 * @return 0 if succeeded to create identifier. Something else if error
 */
static int getIdentifierOfCP(struct Upnp_Action_Request *ca_event, char **identifier, int *idLen, char **CN)
{
    int ret;
    int cert_size = 1000;
    unsigned char cert[cert_size];
    unsigned char hash[cert_size];

    if (ca_event->SSLSession == NULL)
        return 1;

    // 1. get certificate of client
    ret = UpnpGetClientCert(ca_event->SSLSession, cert, &cert_size, CN);
    if (ret != UPNP_E_SUCCESS)
        return ret;

    // 2. create hash from certificate
    ret = wpsu_sha256(cert, cert_size, hash);
    if (ret < 0)
        return ret;

    createUuidFromData(identifier, hash, 16);
    *idLen = strlen(*identifier);
   
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
    char *identifier;
    
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
    
    if (*identity == NULL)
        return -1;
    
    if (identifier) free(identifier);
    
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
    
    // 2. fetch current identity of CP from SIR. Identity may be username or hash of certificate (== b64_identity)
    int active;
    char *role = NULL;
    char *identity = SIR_getIdentityOfSession(SIRDoc, identifier, &active, &role);
    if (identity == NULL)
    {
        // if identity is not defined in SIR, role should be
        if (role == NULL)
            return -1;
        
        *roles = (char *)malloc(strlen(role));
        strcpy(*roles, role);
        return 0;
    }
    
    // 3. get roles from ACL associated with identity fetched from SIR    
    *roles = ACL_getRolesOfUser(ACLDoc, identity);
    if (*roles == NULL)
        // is identity hash
        *roles = ACL_getRolesOfCP(ACLDoc, identity);
    if (*roles == NULL)
        return -1;
    
    if (identifier) free(identifier);    
    
    return 0;
}


static int startWPS()
{
    int err;
    // create enrollee state machine
    esm = wpsu_create_enrollee_sm_station(wpsu_input, &err);
    if (err != WPSU_E_SUCCESS)
    {
        return err;
    }

    // set state variable SetupReady to false, meaning DP service is busy
    SetupReady = 0;
    IXML_Document *propSet = NULL;
    trace(3, "DeviceProtection SetupReady: %d", SetupReady);
    UpnpAddToPropertySet(&propSet, "SetupReady", "0");
    UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:DeviceProtection1", propSet);
    ixmlDocument_free(propSet);
    
    return 0;
}

static void stopWPS()
{
    int error;    
    trace(2,"Finished DeviceProtection pairwise introduction process\n");    

    /*WPSuStationOutput *smOutput;
    smOutput = wpsu_get_enrollee_sm_station_output(esm, &error);
    
    printf("ConfigurationError: %d\n",smOutput->ConfigurationError);
    printf("DeviceName: %s\n",smOutput->RegistrarInfo.DeviceName);
    printf("Uuid: %s\n",smOutput->RegistrarInfo.Uuid);*/
    
    wpsu_cleanup_enrollee_sm(esm, &error);
    
    // DP is free
    SetupReady = 1;
    IXML_Document *propSet = NULL;
    trace(3, "DeviceProtection SetupReady: %d", SetupReady);
    UpnpAddToPropertySet(&propSet, "SetupReady", "1");
    UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:DeviceProtection1", propSet);
    ixmlDocument_free(propSet);    
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

    wpsu_update_enrollee_sm(esm, data, len, &Enrollee_send_msg, &Enrollee_send_msg_len, status, &error);

    switch (*status)
    {
        case WPSU_SM_E_SUCCESS:
        {
            trace(3,"DeviceProtection introduction last message received!\n");
            // Add CP certificate hash into ACL
            int ret, len=0;
            char *identifier;
            char *CN = NULL;
    
            // get identity of CP 
            ret = getIdentifierOfCP(ca_event, &identifier, &len, &CN);
            if (ret != 0 )
            {
                trace(1,"Failed to get Identifier value from Certificate (%d)! Ignoring...",ret);
            }
            else
            {       
                // Add CP to ACL with role Public 
                ret = ACL_addCP(ACLDoc, CN, NULL, identifier, "Public", 1);
                if (ret != ACL_SUCCESS && ret != ACL_USER_ERROR)
                    trace(1,"Failed to add new CP into ACL! Ignoring...");
            }
            trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));
            //stopWPS();
            break;
        }
        case WPSU_SM_E_SUCCESSINFO:
        {
            trace(3,"DeviceProtection introduction last message received M2D!\n");
            //stopWPS();
            break;
        }

        case WPSU_SM_E_FAILURE:
        {
            trace(3,"DeviceProtection introduction error in state machine (Peer gave wrong PIN?). Gracefully terminating and sending of NACK...\n");
            break;
        }

        case WPSU_SM_E_FAILUREEXIT:
        {
            trace(3,"Received NACK from peer. Terminating state machine...\n");
            //stopWPS();
            break;
        }
        case WPSU_SM_E_PROCESS:
        {
            trace(3, "Continuing DeviceProtection introduction...\n");
            break;
        }
        default:
        {
            trace(2, "DeviceProtection introduction state machine in unknown error state. Terminating...\n");
            //stopWPS();
        }
    }
}


/**
 * Get salt and stored values of user with nameUpper as username.
 * With getValuesFromPasswdFile(name, NULL, NULL, NULL, NULL, 0) it is possible to check 
 * if password file contains that specific username.
 * 
 * @param nameUPPER User name in upper case.
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @param salt_len Pointer to integer where length of salt is inserted
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @param stored_len Pointer to integer where length of stored is inserted
 * @param max_size Maximum space available for salt and stored. If they are longer than max_size, error is returned
 * @return -1 if fail, -2 if username is not found, -3 if salt or stored is too long, 0 on success
 */
static int getValuesFromPasswdFile(const char *nameUPPER, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len, int max_size)
{
    // file is formatted as this (every user in own row):
    // Username,base64(SALT),base64(STORED)
    char line[200];
    char *name;
    char *temp;

    FILE *stream = fopen(g_vars.passwdFile, "r");
    if (!stream) return -1;
    
    while(fgets(line, 200, stream) != NULL) 
    {
        line[strlen(line)-1] = '\0';
    
        name = strtok(line, ",");
        if (name != NULL)
        {        
            name = toUpperCase(name);
            if (name == NULL)
            {
                fclose(stream);
                return -1;             
            }
            // if names match
            if ( strcmp(name,nameUPPER) == 0 )
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
 * @param name User name in uppercase
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @return -1 if fail -2 if username already exist, 0 on success
 */
static int putValuesToPasswdFile(const char *name, const unsigned char *b64_salt, const unsigned char *b64_stored)
{
    if (getValuesFromPasswdFile(name,NULL,NULL, NULL, NULL, 0) == 0)
        return -2;
    
    FILE *stream = fopen(g_vars.passwdFile, "a");
    if (!stream) return -1;
    
    fprintf(stream, "%s,%s,%s\n", name, b64_salt, b64_stored);
    
    fclose(stream);
    return 0;     
}

/**
 * Update username,salt,stored values in password file.
 * Username and values can also be removed totally from file by putting delete_values as 1.
 * 
 * @param name User name in uppercase
 * @param b64_salt Pointer to salt data read from file (base64 encoded)
 * @oaram b64_stored Pointer to stored data read from file (base64 encoded)
 * @param delete_values Use 0 to update existing values, 1 to delete.
 * @return -1 if fail, -2 if username is not found, 0 on success
 */
static int updateValuesToPasswdFile(const char *nameUPPER, const unsigned char *b64_salt, const unsigned char *b64_stored, int delete_values)
{
    // file is formatted as this (every user in own row):
    // Username,base64(SALT),base64(STORED)
    char line[200];
    char temp[200];
    char *name;
    int ret = -2;
    
    char tempfile[strlen(g_vars.passwdFile) + 5];
    strcpy(tempfile,g_vars.passwdFile);
    strcat(tempfile,".temp");
    
    // open 2 files, passwordfile which is read and temp file where lines are written.
    // if usernames match write new values in temp file.
    // Finally remove original passwordfile and rename temp file as original.
    FILE *in = fopen(g_vars.passwdFile, "r");
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
            name = toUpperCase(name);
            if (name == NULL)
            {
                fclose(in);
                fclose(out);
                return -1;             
            }
            // if names match        
            if ( strcmp(name,nameUPPER) == 0 )
            {
                // if we want to remove user from passwd file, lets not add him to temp file
                if (!delete_values)
                    fprintf(out, "%s,%s,%s\n", nameUPPER, b64_salt, b64_stored);
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
    remove(g_vars.passwdFile);
    // rename temp file is original password file
    rename(tempfile, g_vars.passwdFile); 

    return ret; 
}

/**
 * Get salt and stored values of user with nameUPPER as username.
 * Username "ADMIN" is an special case: if it is not found form password file, totally
 * new salt and stored values are creted for that username. Password used for creation 
 * of stored is stored in config file.
 *  
 * 
 * @param nameUPPER User name in upper case.
 * @param b64_salt Pointer to salt data read from file or newly created (base64 encoded)
 * @param salt_len Pointer to integer where length of salt is inserted
 * @oaram b64_stored Pointer to stored data read from file or newly created (base64 encoded)
 * @param stored_len Pointer to integer where length of stored is inserted
 * @return 0 on success
 */
static int getSaltAndStoredForName(const char *nameUPPER, unsigned char **b64_salt, int *salt_len, unsigned char **b64_stored, int *stored_len)
{
    int maxb64len = 2*DP_STORED_BYTES;     
    *b64_salt = (unsigned char *)malloc(maxb64len); 
    *b64_stored = (unsigned char *)malloc(maxb64len);
    
    int ret = getValuesFromPasswdFile(nameUPPER, b64_salt, salt_len, b64_stored, stored_len, maxb64len);
    
    if (ret != 0)
    {
        if (strcmp(nameUPPER,"ADMIN") == 0)
        {
            // create new salt and stored
            int name_len = strlen(nameUPPER);
            int namesalt_len = name_len + DP_SALT_BYTES;
            unsigned char namesalt[namesalt_len];
        
            // create SALT   
            unsigned char *salt = wpsu_createRandomValue(DP_SALT_BYTES);
            
            memcpy(namesalt, nameUPPER, name_len);
            memcpy(namesalt+name_len, salt, DP_SALT_BYTES);
            
            /* Create STORED = first 160 bits of the key T1, with T1 computed according to [PKCS#5] algorithm PBKDF2
                
                T1 is defined as the exclusive-or sum of the first c iterates of PRF applied to the concatenation 
                of the Password, Name, Salt, and four-octet block index (0x00000001) in big-endian format.  
                For DeviceProtection, the value for c is 5,000.  Name MUST be converted to upper-case, and 
                Password and Name MUST be encoded in UTF-8 format prior to invoking the PRF operation.  
                T1 = U1 \xor U2 \xor … \xor Uc
                where
                U1 = PRF(Password, Name || Salt || 0x0 || 0x0 || 0x0 || 0x1)
                U2 = PRF(Password, U1),
                …
                Uc = PRF(Password, Uc-1).
              
                NOTE1: SALT and STORED are created only if username is admin and passwordfile doesn't 
                
                NOTE2: wpsu_pbkdf2 goes through whole PBKDF2 algorithm, even if in this case only first block
                       is needed for result. First 160 bits are the same if all the data is processed or just 
                       the first block. (block size should be defined to 160bits => DP_STORED_BYTES = 8)
             */
            unsigned char bin_stored[DP_STORED_BYTES];
            ret = wpsu_pbkdf2(g_vars.adminPassword, strlen(g_vars.adminPassword), namesalt,
                            namesalt_len, DP_PRF_ROUNDS, DP_STORED_BYTES, bin_stored);
                            
            if (ret != 0) return ret;
            
            // SALT and STORED to base 64
            wpsu_bin_to_base64(DP_SALT_BYTES, salt, salt_len, *b64_salt, maxb64len);                                                
            wpsu_bin_to_base64(DP_STORED_BYTES, bin_stored, stored_len, *b64_stored, maxb64len);             

            
            // write values to password file
            ret = putValuesToPasswdFile(nameUPPER, *b64_salt, *b64_stored);
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
 *  STORED = first 160 bits of the key T1, with T1 computed according to [PKCS#5] algorithm PBKDF2, with PRF=SHA-256.  A separate value of STORED is kept in the Device’s password file for each specific Name. 
 *  T1 is defined as the exclusive-or sum of the first c iterates of PRF applied to the concatenation of the Password, Name, Salt, and four-octet block index (0x00000001) in big-endian format.  For DeviceProtection, the value for c is 5,000.  Name MUST be converted to upper-case, and Password and Name MUST be encoded in UTF-8 format prior to invoking the PRF operation.  
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
 * @param nameUPPER Username in uppercase
 * @return Upnp error code.
 */
static int createUserLoginChallengeResponse(struct Upnp_Action_Request *ca_event, const char *nameUPPER)
{
    int result = 0;
    unsigned char *b64_salt = NULL;
    unsigned char *b64_stored = NULL;
    int b64_salt_len = 0;
    int b64_stored_len = 0;

    if (getSaltAndStoredForName(nameUPPER, &b64_salt, &b64_salt_len, &b64_stored, &b64_stored_len) != 0)
    {
        trace(1, "Error creating/getting STORED value for user %s",nameUPPER);
        result = 501;
        addErrorData(ca_event, result, "Action Failed");
    }
    else
    {
        // stored to binary format
        unsigned char *bin_stored = (unsigned char *)malloc(b64_stored_len);
        int outlen;        
        wpsu_base64_to_bin(b64_stored_len, b64_stored, &outlen, bin_stored, DP_STORED_BYTES);


        // Create NONCE
        unsigned char *nonce = wpsu_createNonce(DP_NONCE_BYTES);
        
        unsigned char storednonce[DP_STORED_BYTES+DP_NONCE_BYTES];
        memcpy(storednonce, bin_stored, DP_STORED_BYTES);
        memcpy(storednonce+DP_STORED_BYTES, nonce, DP_NONCE_BYTES);
             
        // Create CHALLENGE = SHA-256(STORED || nonce)
        unsigned char challenge[DP_STORED_BYTES+DP_NONCE_BYTES];
        if ( wpsu_sha256(storednonce, DP_STORED_BYTES+DP_NONCE_BYTES, challenge) < 0 )
        {
            trace(1, "Error creating CHALLENGE value for %s",ca_event->ActionName);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");                    
        }
        else
        {                
            // CHALLENGE to base64
            int maxb64len = 2*(DP_STORED_BYTES+DP_NONCE_BYTES); 
            int b64len = 0;        
    
            unsigned char *b64_challenge = (unsigned char *)malloc(maxb64len);
            wpsu_bin_to_base64(DP_STORED_BYTES+DP_NONCE_BYTES, challenge, &b64len, b64_challenge, maxb64len);               

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
                trace(3,"Session with id '%s' is being updated in SIR. Add name '%s' and challenge '%s'",identifier,nameUPPER,(char *)b64_challenge);
                result = SIR_updateSession(SIRDoc, identifier, NULL, NULL, NULL, NULL, nameUPPER, (char *)b64_challenge);
                if (result == 0) 
                    trace(3, "Contents of SIR:\n%s\n",ixmlPrintDocument(SIRDoc));
                else 
                    trace(2, "Failed to update session in SIR");
            } 
            else
                trace(1, "Failure on inserting UserLoginChallenge values to SIR. Ignoring...");
            
            if (identifier) free(identifier);
            if (b64_challenge) free(b64_challenge);
        }
        if (bin_stored) free(bin_stored);
    }
    
    if (b64_salt) free(b64_salt);
    if (b64_stored) free(b64_stored);
    return result;
}


/**
 * Create authenticator value used in UserLogin
 * Authenticator contains the Base64 encoding of the first 20 bytes of SHA-256(STORED || Challenge).
 * 
 * @param b64_stored Base64 encoded value of STORED.
 * @param b64_challenge Base64 encoded value of Challenge.
 * @param b64_authenticator Pointer to string where authenticator is created. User needs to use free() for this
 * @param auth_len Pointer to integer which is set to contain length of created authenticator
 * @return 0 if succeeded to create authenticato. Something else if error
 */
static int createAuthenticator(const char *b64_stored, const char *b64_challenge, char **b64_authenticator, int *auth_len)
{
    // stored and challenge from base64 to binary
    int b64msglen = strlen(b64_stored);
    unsigned char *bin_stored = (unsigned char *)malloc(b64msglen);
    if (bin_stored == NULL) 
    {
        return -1;
    }
    int bin_stored_len;    
    wpsu_base64_to_bin(b64msglen, (const unsigned char *)b64_stored, &bin_stored_len, bin_stored, b64msglen);    

    b64msglen = strlen(b64_challenge);
    unsigned char *bin_challenge = (unsigned char *)malloc(b64msglen);
    if (bin_challenge == NULL) 
    {
        if (bin_stored) free(bin_stored);
        return -1;
    }
    int bin_challenge_len;    
    wpsu_base64_to_bin(b64msglen, (const unsigned char *)b64_challenge, &bin_challenge_len, bin_challenge, b64msglen); 
   
    
    // concatenate stored || challenge
    int bin_concat_len = bin_stored_len + bin_challenge_len;
    unsigned char *bin_concat = (unsigned char *)malloc(bin_concat_len);    
    if (bin_concat == NULL) 
    {
        if (bin_stored) free(bin_stored);
        if (bin_challenge) free(bin_challenge);
        return -1;
    }
    memcpy(bin_concat, bin_stored, bin_stored_len);
    memcpy(bin_concat + bin_stored_len, bin_challenge, bin_challenge_len);

    // release useless stuff
    if (bin_stored) free(bin_stored);
    if (bin_challenge) free(bin_challenge);
 
    // crete hash from concatenation
    unsigned char hash[2*bin_concat_len];
    int hashlen = wpsu_sha256(bin_concat, bin_concat_len, hash);
    if (hashlen < 0)
    {
        if (bin_concat) free(bin_concat);
        *b64_authenticator = NULL;
        return hashlen;
    }

    // encode 16 first bytes of created hash as base64 authenticator
    int maxb64len = 2*DP_AUTH_BYTES; 
    *auth_len = 0;
    *b64_authenticator = (char *)malloc(maxb64len);
    wpsu_bin_to_base64(DP_AUTH_BYTES, hash, auth_len, (unsigned char *)*b64_authenticator, maxb64len);
    
    if (bin_concat) free(bin_concat);
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

// TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/ if ((protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "ProtocolType")) &&
            (inmessage = GetFirstDocumentItem(ca_event->ActionRequest, "InMessage")))
    {    
        inet_ntop(AF_INET, &ca_event->CtrlPtIPAddr, IP_addr, INET6_ADDRSTRLEN);
        
        if (strcmp(protocoltype, "WPS") != 0)
        {
            trace(1, "Introduction protocol type must be 'WPS': Invalid ProtocolType=%s\n",protocoltype);
            result = 703;
            addErrorData(ca_event, result, "Unknown Protocol Type");       
        } 
        
        // get identifier of CP 
        // this will tell if the same CP is doing all setup messages
        result = getIdentifierOfCP(ca_event, &CP_id, &id_len, NULL);
// TODO remove this!!!!!!!!!!!!!!!!!!!!!!!!     
result = 0;   
        
        if (result == 0 && SetupReady && strcmp(inmessage, "") == 0) // ready to start introduction. InMessage MUST be empty for M1
        {
            // store id of this CP to determine next time if still the same CP is using this.
            memcpy(prev_CP_id, CP_id, id_len);            
            
            // begin introduction
            trace(2,"Begin DeviceProtection pairwise introduction process. IP %s\n",IP_addr);
            startWPS();
            // start the state machine and create M1
            wpsu_start_enrollee_sm(esm, &Enrollee_send_msg, &Enrollee_send_msg_len, &result);
            if (result != WPSU_E_SUCCESS)
            {
                trace(1, "Failed to start WPS state machine. Returned %d\n",result);
                result = 704;
                addErrorData(ca_event, result, "Processing Error");               
            }
        }
        else if (SetupReady && strcmp(inmessage, "") != 0)
        {
            trace(1, "Failure in SendSetupMessage: InMessage must be empty when fetching M1 message");
            result = 402;
            addErrorData(ca_event, result, "Invalid Args");            
        }
// TODO: remove comment!!!!!        
        else if (!SetupReady )//&& (memcmp(prev_CP_id, CP_id, id_len) == 0)) // continue started introduction
        {
            // to bin
            int b64msglen = strlen(inmessage);            
            unsigned char *pBinMsg=(unsigned char *)malloc(b64msglen);
            int outlen;
            
            wpsu_base64_to_bin(b64msglen,(const unsigned char *)inmessage,&outlen,pBinMsg,b64msglen);

            // update state machine
            message_received(ca_event, 0, pBinMsg, outlen, &sm_status);
            if (pBinMsg) free(pBinMsg);
        }
        else // must be busy doing someone else's introduction process 
        {
            trace(1, "Busy with someone else's introduction process. IP %s\n",IP_addr);
            result = 708;
            addErrorData(ca_event, result, "Busy");         
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
        int maxb64len = 2*Enrollee_send_msg_len; 
        int b64len = 0;    
        unsigned char *pB64Msg = (unsigned char *)malloc(maxb64len);
        wpsu_bin_to_base64(Enrollee_send_msg_len,Enrollee_send_msg, &b64len, pB64Msg,maxb64len);
        
        trace(3,"Send response for SendSetupMessage request\n");
        
        ca_event->ErrCode = UPNP_E_SUCCESS;
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<OutMessage>%s</OutMessage>\n</u:%sResponse>",
                 ca_event->ActionName, DP_SERVICE_TYPE, pB64Msg, ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
        if (pB64Msg) free(pB64Msg);     
    }

    
    // Any else state means that WPS is either ready or in error state and it must be terminated
    if (sm_status != WPSU_SM_E_PROCESS)  
    {
        stopWPS();
    }
    
    if (CP_id) free(CP_id);
    if (inmessage) free(inmessage);
    if (protocoltype) free(protocoltype);
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
    char *name = NULL;
    char *nameUPPER = NULL;
    char *passwd = NULL;

    
    // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (name = GetFirstDocumentItem(ca_event->ActionRequest, "Name") ))
    {
        // name to uppercase
        nameUPPER = toUpperCase(name);
        if (nameUPPER == NULL)
        {
            trace(1, "Failed to convert name to upper case ");
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        // check if user exits
        if ((strcmp(nameUPPER, "ADMIN") != 0) && (getValuesFromPasswdFile(nameUPPER, NULL,NULL,NULL,NULL,0) != 0))
        {
            trace(1, "Unknown username %s",nameUPPER);
            result = 706;
            addErrorData(ca_event, result, "Invalid Name");                 
        }
        
        // parameters OK
        if (result == 0)
        {
            createUserLoginChallengeResponse(ca_event, nameUPPER);
        }
    }

    else
    {
        trace(1, "Failure in GetUserLoginChallenge: Invalid Arguments!");
        trace(1, "  Name: %s",name);
        addErrorData(ca_event, 402, "Invalid Args");
    }

    if (name) free(name);    
    if (nameUPPER) free(nameUPPER);
    if (passwd) free(passwd);
    
    return ca_event->ErrCode;
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
    char *challenge = NULL;
    char *authenticator = NULL;
    int loginattempts = 0;
    char *loginName = NULL;
    char *loginChallenge = NULL;
    int active;
    
    char *id =NULL;
    int id_len = 0;

    // what if user is already logged in?
    
    
    // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (challenge = GetFirstDocumentItem(ca_event->ActionRequest, "Challenge") )
            && (authenticator = GetFirstDocumentItem(ca_event->ActionRequest, "Authenticator") ))
    {
        result = getIdentifierOfCP(ca_event, &id, &id_len, NULL);
        trace(3,"CP with identifier '%s' is logging in",id);
        // here we could try "session resumption" by getting identity from SIR?
        // but not now, just continue as new login...
        result = SIR_getLoginDataOfSession(SIRDoc, (char *)id, &loginattempts, &loginName, &loginChallenge);
        
        if (result != 0 || !loginName || !loginChallenge)
        {
            trace(1, "%s: Failed to get login data for this session",ca_event->ActionName);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");            
        }
        
        // has CP tried to login too many times already?
        if (++loginattempts > DP_MAX_LOGIN_ATTEMPTS)
        {
            // out and away!
            // close SSL session on way out...
            UpnpTerminateSSLSession(ca_event->SSLSession, ca_event->Socket);
            
            // remove session from SIR
            SIR_removeSession(SIRDoc, (char *)id);
            
            if (challenge) free(challenge);
            if (authenticator) free(authenticator);
            if (loginName) free(loginName);
            if (loginChallenge) free(loginChallenge);
            if (id) free(id);
            
            return ca_event->ErrCode;            
        }
        
        // does our challenge stored in SIR match challenge received from control point
        if (result == 0 && strcmp(challenge, loginChallenge) != 0)
        {
            trace(1, "%s: Challenge value does not match value from SIR",ca_event->ActionName);
            trace(3, "Received challenge was '%s' and local challenge was '%s'",challenge, loginChallenge);
            result = 706;
            addErrorData(ca_event, result, "Invalid Context");
        }
        
        if (result == 0)
        {
            // update loginattempts value
            result = SIR_updateSession(SIRDoc, (char *)id, NULL, NULL, NULL, &loginattempts, NULL, NULL);
            
            // name to uppercase
            loginName = toUpperCase(loginName);
            
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
                result = 706;
                addErrorData(ca_event, result, "Invalid Context");
            }
            else
            {
                // create authenticator
                int auth_len = 0;
                char *b64_authenticator = NULL;
                result = createAuthenticator((char *)b64_stored, loginChallenge, &b64_authenticator, &auth_len);
                
                // do the authenticators match?
                if (result != 0)
                {
                    trace(2, "%s: Failed to create authenticator",ca_event->ActionName);
                    result = 501;
                    addErrorData(ca_event, result, "Action Failed");                
                }
                else if ( strcmp(authenticator, b64_authenticator) != 0 )
                {
                    trace(1, "%s: Authenticator values do not match!",ca_event->ActionName);
                    trace(3, "Received Authenticator was '%s' and local Authenticator was '%s'",authenticator, b64_authenticator);
                    result = 701;
                    addErrorData(ca_event, result, "Authentication Failure");                
                }
                else
                {
                    trace(2,"CP with id '%s' succeeded to log in as '%s'",id,loginName);
                    // Login is now succeeded
                    loginattempts = 0;
                    active = 1;
                    result = SIR_updateSession(SIRDoc, (char *)id, &active, loginName, NULL, &loginattempts, NULL, NULL);
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
            }
        }
    }

    else
    {
        trace(1, "Failure in %s: Invalid Arguments!",ca_event->ActionName);
        addErrorData(ca_event, 402, "Invalid Args");
    }
    
    if (challenge) free(challenge);
    if (authenticator) free(authenticator);
    if (loginName) free(loginName);
    if (loginChallenge) free(loginChallenge);
    if (id) free(id);
    
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
    int result, active;
    char *roles = NULL;  

    // what if user is not even logged in?
    // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");   
        return ca_event->ErrCode;     
    }
    else*/
        result = getIdentifierOfCP(ca_event, &id, &id_len, NULL);
    
    if (result != 0)
    {
        trace(1, "%s: Failed to get identifier from certificate",ca_event->ActionName);
        result = 501;
        addErrorData(ca_event, result, "Action Failed");            
    }
    else
    {
        // Fetch default role(s) for this CP from ACL
        roles = ACL_getRolesOfCP(ACLDoc, (char *)id);
        if (roles == NULL)
            roles = "Public";
        
        // Add value of role default roles of this CP, and active to 0
        active = 0;
        result = SIR_updateSession(SIRDoc, (char *)id, &active, NULL, roles, NULL, NULL, NULL);

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
            trace(1, "Error parsing Response to %s (add default roles (%s) for this session in SIR)",ca_event->ActionName,roles);
            result = 501;
            addErrorData(ca_event, result, "Action Failed"); 
        }
    }
    
    if (id) free(id);
    
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
    char *ACL = ixmlDocumenttoString(ACLDoc);
    IXML_Document *ActionResult = NULL;
    
    if (ACL)
    {
        ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                        1,
                                        "ACL", ACL);
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
    
        // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") )
            && (rolelist = GetFirstDocumentItem(ca_event->ActionRequest, "RoleList") ))
    {
        identityDoc = ixmlParseBuffer(identity);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, identity);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        
        // add roles for identity which is found from identityDoc
        result = ACL_addRolesForIdentity(ACLDoc, identityDoc, rolelist);        
        if (result == ACL_USER_ERROR)
        {
            // ok, identity wasn't username or hash
            trace(1, "AddRolesForIdentity: Unknown identity %s",identity);
            result = 706;
            addErrorData(ca_event, result, "Unknown Identity");
        }
        else if (result == ACL_ROLE_ERROR)
        {
            trace(1, "AddRolesForIdentity: Invalid rolelist received %s",rolelist);
            result = 707;
            addErrorData(ca_event, result, "Invalid RoleList");
        }
        else if (result != ACL_SUCCESS)
        {
            trace(1, "AddRolesForIdentity: Failed to add roles '%s' for identity '%s'",rolelist,identity);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
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
        trace(1, "AddRolesForIdentity: Invalid Arguments!");
        trace(1, "  Identity: %s, RoleList: %s",identity,rolelist);
        addErrorData(ca_event, 402, "Invalid Args");
    }
    
    if (identityDoc) ixmlDocument_free(identityDoc);
    if (identity) free(identity);
    if (rolelist) free(rolelist);
    
    trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));  
    
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
    
        // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") )
            && (rolelist = GetFirstDocumentItem(ca_event->ActionRequest, "RoleList") ))
    {       
        identityDoc = ixmlParseBuffer(identity);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, identity);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        
        // remove roles from identity which is found from identityDoc
        result = ACL_removeRolesFromIdentity(ACLDoc, identityDoc, rolelist);
        if (result == ACL_USER_ERROR)
        {
            // ok, identity wasn't username or hash
            trace(1, "RemoveRolesForIdentity: Unknown identity %s",identity);
            result = 706;
            addErrorData(ca_event, result, "Unknown Identity");
        }
        else if (result == ACL_ROLE_ERROR)
        {
            trace(1, "RemoveRolesForIdentity: Invalid rolelist received %s",rolelist);
            result = 707;
            addErrorData(ca_event, result, "Invalid RoleList");
        }
        else if (result != ACL_SUCCESS)
        {
            trace(1, "RemoveRolesForIdentity: Failed to add roles '%s' for identity '%s'",rolelist,identity);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
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
        trace(1, "RemoveRolesForIdentity: Invalid Arguments!");
        trace(1, "  Identity: %s, RoleList: %s",identity,rolelist);
        addErrorData(ca_event, 402, "Invalid Args");
    }
  
    if (identityDoc) ixmlDocument_free(identityDoc);
    if (identity) free(identity);
    if (rolelist) free(rolelist);
    
    trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));
    
    return ca_event->ErrCode;
}

/**
 * DeviceProtection:1 Action: GetCurrentRole.
 *
 * @param ca_event Upnp event struct.
 * @return Upnp error code.
 */
int GetCurrentRoles(struct Upnp_Action_Request *ca_event)
{    
    char *roles = NULL;
    int ret;

    // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");    
        return ca_event->ErrCode;   
    }
    */
    ret = getRolesOfSession(ca_event, &roles);
    IXML_Document *ActionResult = NULL;
    
    if (ret == 0 && roles)
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
        trace(1, "Error parsing Response to GetCurrentRoles");
        addErrorData(ca_event, 501, "Action Failed");
    }

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
    char *name = NULL;
    char *stored = NULL;
    char *salt = NULL;
    char *nameUPPER = NULL;
    char *identity = NULL;
    
        // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (name = GetFirstDocumentItem(ca_event->ActionRequest, "Name") )
            && (stored = GetFirstDocumentItem(ca_event->ActionRequest, "Stored") )
            && (salt = GetFirstDocumentItem(ca_event->ActionRequest, "Salt") ))
    {      
        // change name to uppercase, because usernames are not case sensitive
        nameUPPER = toUpperCase(name);
        if (nameUPPER == NULL)
        {
            trace(1, "%s: Failed to turn name '%s' to uppercase",ca_event->ActionName,name);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");            
        }
        // First try to update existing username/password pair
        else
        {
            getIdentityOfSession(ca_event, &identity);
            identity = toUpperCase(identity);
            if (identity == NULL)
            {
                trace(1, "%s: Failed to turn identity '%s' to uppercase",ca_event->ActionName,identity);
                result = 501;
                addErrorData(ca_event, result, "Action Failed");            
            }            
            // check from SIR that username received as parameter is current identity of this session
            // or has "Admin" privileges 
            else if ( (checkCPPrivileges(ca_event, "Admin") == 0) || (strcmp(identity, nameUPPER) == 0))
            {
                result = updateValuesToPasswdFile(nameUPPER, (unsigned char *)salt, (unsigned char *)stored, 0); // if this returns 0, all is well
                if (result == -2)
                {
                    // So we are after all adding new username! (Because username was not found from passwd-file)
                    // lets Add new
                    result = putValuesToPasswdFile(nameUPPER, (unsigned char *)salt, (unsigned char *)stored);
                    if (result == -2)
                    {
                        trace(1, "%s: Same username '%s' exists in passwd file already",ca_event->ActionName,name);
                        result = 706;
                        addErrorData(ca_event, result, "Invalid Name");                    
                    }
                    else if (result != 0)
                    {
                        trace(1, "%s: Failed to write login values to passwordfile",ca_event->ActionName);
                        result = 501;
                        addErrorData(ca_event, result, "Action Failed");
                        
                        // if failed to add new logindata to file but reason wasn't that same username 
                        // existed in passwd file already, try to remove added data
                        updateValuesToPasswdFile(nameUPPER, (unsigned char *)salt, (unsigned char *)stored, 1);          
                    } 
                    else
                    {
                        // add user to ACL also
                        result = ACL_addUser(ACLDoc, nameUPPER, "Public");  // if this return 0, all is well
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
                            updateValuesToPasswdFile(nameUPPER, (unsigned char *)salt, (unsigned char *)stored, 1);
                            // try to remove username from ACL
                            ACL_removeUser(ACLDoc, nameUPPER);
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
                result = 702;
                addErrorData(ca_event, result, "Authorization Failure");                
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

    if (name) free(name);
    if (stored) free(stored);
    if (salt) free(salt);
    if (nameUPPER) free(nameUPPER);
    if (identity) free(identity);

    trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));

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
    int admin_handling = 0;
    int len;
    char *identifier = NULL;
    char *identitylist = NULL;
    IXML_Document *identitiesDoc = NULL;
    
        // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (identitylist = GetFirstDocumentItem(ca_event->ActionRequest, "IdentityList") ))
    {    
        identitiesDoc = ixmlParseBuffer(identitylist);
        if (identitiesDoc == NULL)
        {
            trace(1, "%s: Failed to parse IdentityList '%s'",ca_event->ActionName, identitylist);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        else
        {
            // because how IdentityList is handled is based on role of CP sending this action
            // we need to check if CP has Admin rights. If Admin rights exist, RoleList and Alias
            // elements are used, else they are ignored 
            
            // get identifier of CP 
            result = getIdentifierOfCP(ca_event, &identifier, &len, NULL);
            if (result != 0 )
            {
                trace(1, "%s: Failed to get identifier of CP",ca_event->ActionName);
                result = 501;
                addErrorData(ca_event, result, "Action Failed");                
            }
            else
            {
                if ( ACL_doesIdentityHasRole(ACLDoc, identifier, "Admin") == 1 )
                {
                    admin_handling = 1;
                }
                else
                {
                    admin_handling = 0;
                }
            
                // validate contents of list and add new identities to ACL
                result = ACL_validateListAndUpdateACL(ACLDoc, identitiesDoc, admin_handling);
                if (result == 707)
                {
                    addErrorData(ca_event, result, "Invalid Parameter");
                } 
                else if (result != 0)
                {
                    result = 501;
                    addErrorData(ca_event, result, "Action Failed");
                }
            }    
        }
        
        
        // all is well
        if (result == 0)
        {
            // write ACL in filesystem
            writeDocumentToFile(ACLDoc, ACL_XML);
            
            // get identities element from ACL and return it to CP
            char *responseIdentities = NodeWithNameToString(ACLDoc, "Identities");
            if (responseIdentities)
            {
                // Succesfull end happens here
                ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, DP_SERVICE_TYPE,
                                            1, 
                                            "IdentityListResult", responseIdentities,
                                            NULL);                                        
                ca_event->ErrCode = UPNP_E_SUCCESS;
                free(responseIdentities);
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

    if (identitiesDoc) ixmlDocument_free(identitiesDoc);
    if (identitylist) free(identitylist);

    trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));
    
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
    
    // TODO should it be tested that there is only one CP element in Identity?
        // TODO remove this from comments
/*    if (ca_event->SSLSession == NULL)
    {
        // SSL must be used
        trace(1, "%s: SSL connection must be used for this",ca_event->ActionName);
        result = 701;
        addErrorData(ca_event, result, "Authentication Failure");        
    }
    else*/if ( (identity = GetFirstDocumentItem(ca_event->ActionRequest, "Identity") ))
    {    
        identityDoc = ixmlParseBuffer(identity);
        if (identityDoc == NULL)
        {
            trace(1, "%s: Failed to parse Identity xml '%s'",ca_event->ActionName, identity);
            result = 501;
            addErrorData(ca_event, result, "Action Failed");
        }
        else
        {
            // validate input and remove CP/User
            result = ACL_validateAndRemoveIdentity(ACLDoc, identityDoc);
            
            if (result == 707)
            {
                addErrorData(ca_event, result, "Invalid Parameter");               
            }
            else if (result != 0)
            {
                result = 501;
                addErrorData(ca_event, result, "Action Failed");
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
    
    if (identityDoc) ixmlDocument_free(identityDoc);
    if (identity) free(identity);
    
    trace(3, "Contents of ACL:\n%s\n",ixmlPrintDocument(ACLDoc));
    
    return ca_event->ErrCode;
}
