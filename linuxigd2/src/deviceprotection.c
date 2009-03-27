#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "deviceprotection.h"
#include "gatedevice.h"
#include "globals.h"
#include "util.h"
#include <wpsutil/enrollee_state_machine.h>
#include <wpsutil/base64mem.h>

static int InitDP();
static void FreeDP();
static int message_received(int error, unsigned char *data, int len, void* control);

// WPS state machine related stuff
WPSuEnrolleeSM* esm;
unsigned char* Enrollee_send_msg;
int Enrollee_send_msg_len;
WPSuStationInput input;

// address of control point which is executin introduction process
char prev_addr[INET6_ADDRSTRLEN];

static int InitDP()
{   
    // TODO these values. What those should be and move to config file 
    // TODO: Should start new thread for multiple simultanious registration processes?
    int err;
    
    unsigned char MAC[WPSU_MAC_LEN];
    memset(MAC, 0xAB, WPSU_MAC_LEN);

    err = wpsu_enrollee_station_input_add_device_info(&input, 
                                        "stasecret",
                                        "TestManufacturer", 
                                        "TestModelName",
                                        "TestModelNumber", 
                                        "TestSerialNumber", 
                                        "TestDeviceName", 
                                        NULL,
                                        0,
                                        MAC,
                                        WPSU_MAC_LEN,
                                        "TestUUID",
                                        8,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        WPSU_CONF_METHOD_LABEL, 
                                        WPSU_RFBAND_2_4GHZ);
                                        
    // station has applications A, B and C
    //input.Apps = 3;

    unsigned char UUID[WPSU_MAX_UUID_LEN];

    memset(UUID, 0xAA, WPSU_MAX_UUID_LEN);

    err =  wpsu_enrollee_station_input_add_app(&input,
        UUID,WPSU_MAX_UUID_LEN,
        NULL,0,
        NULL,0);
    
    memset(UUID, 0xBB, WPSU_MAX_UUID_LEN);

    err =  wpsu_enrollee_station_input_add_app(&input,
        UUID,WPSU_MAX_UUID_LEN,
        "B data from STA",strlen("B data from STA") + 1,
        NULL,0);

    memset(UUID, 0xCC, WPSU_MAX_UUID_LEN);
    

    err =  wpsu_enrollee_station_input_add_app(&input,
        UUID,WPSU_MAX_UUID_LEN,
        "C data from STA",strlen("C data from STA") + 1,
        NULL,0);

    // create enrollee state machine
    esm = wpsu_create_enrollee_sm_station(&input, &err);

    // set state variable SetupReady to false, meaning DP service is busy
    SetupReady = 0;
    IXML_Document *propSet = NULL;
    trace(3, "DeviceProtection SetupReady: %d", SetupReady);
    UpnpAddToPropertySet(&propSet, "SetupReady", "0");
    UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:DeviceProtection1", propSet);
    ixmlDocument_free(propSet);
    
    return 0;
}

static void FreeDP()
{
    int error;
    
    trace(2,"Finished DeviceProtection pairwise introduction process\n");
    wpsu_enrollee_station_input_free(&input);
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
 * When message M2, M2D, M4, M6, M8 or Done ACK is received, enrollee state machine is updated here
 */
static int message_received(int error, unsigned char *data, int len, void* control)
{
    int status;

    if (error)
    {
        trace(2,"DeviceProtection introduction message receive failure! Error = %d", error);
        return error;
    }

    wpsu_update_enrollee_sm(esm, data, len, &Enrollee_send_msg, &Enrollee_send_msg_len, &status, &error);

    switch (status)
    {
        case WPSU_SM_E_SUCCESS:
        {
            // Now we should create SSL Session or something
            trace(3,"DeviceProtection introduction last message received!\n");
            FreeDP();
            break;
        }
        case WPSU_SM_E_SUCCESSINFO:
        {
            trace(3,"DeviceProtection introduction last message received M2D!\n");
            FreeDP();
            break;
        }

        case WPSU_SM_E_FAILURE:
        {
            trace(3,"DeviceProtection introduction error in state machine. Terminating...\n");
            FreeDP();
            break;
        }

        case WPSU_SM_E_FAILUREEXIT:
        {
            trace(3,"DeviceProtection introduction error in state machine. Terminating...\n");
            FreeDP();
            break;
        }
        default:
        {

        }
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
 * Currently used protocol is WPS.
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
    char curr_addr[INET6_ADDRSTRLEN];
    
    if ((protocoltype = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocolType")) &&
            (inmessage = GetFirstDocumentItem(ca_event->ActionRequest, "NewInMessage")))
    {    
        if (strcmp(protocoltype, "DeviceProtection:1") != 0)
        {
            trace(1, "Introduction protocol type must be DeviceProtection:1: Invalid NewProtocolType=%s\n",protocoltype);
            result = 703;
            addErrorData(ca_event, result, "Unknown Protocol Type");       
        } 
        
        inet_ntop(AF_INET, &ca_event->CtrlPtIPAddr, curr_addr, INET6_ADDRSTRLEN);
        if (result == 0 && SetupReady) // ready to start introduction
        {
            strcpy(prev_addr, curr_addr);
            // begin introduction
            trace(2,"Begin DeviceProtection pairwise introduction process. IP %s\n",prev_addr);
            InitDP();
            // start the state machine and create M1
            wpsu_start_enrollee_sm(esm, &Enrollee_send_msg, &Enrollee_send_msg_len, &result);
            if (result != WPSU_E_SUCCESS)
            {
                trace(1, "Failed to start WPS state machine. Returned %d\n",result);
                result = 704;
                addErrorData(ca_event, result, "Processing Error");               
            }
        }
        else if (!SetupReady && (strcmp(prev_addr, curr_addr) == 0)) // continue started introduction
        {
            // to bin
            int b64msglen = strlen(inmessage);
            unsigned char *pBinMsg=(unsigned char *)malloc(b64msglen);
            int outlen;
            
            wpsu_base64_to_bin(b64msglen,(const unsigned char *)inmessage,&outlen,pBinMsg,b64msglen);

            // update state machine
            message_received(0, pBinMsg, outlen, NULL);
            if (pBinMsg) free(pBinMsg);
        }
        else // must be busy doing someone else's introduction process 
        {
            trace(1, "Busy with someone else's introduction process. IP %s\n",curr_addr);
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
        snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<NewOutMessage>%s</NewOutMessage>\n</u:%sResponse>",
                 ca_event->ActionName, "urn:schemas-upnp-org:service:DeviceProtection:1", pB64Msg, ca_event->ActionName);
        ca_event->ActionResult = ixmlParseBuffer(resultStr);
        if (pB64Msg) free(pB64Msg);     
    }
    else if (result != 708)
    {
        FreeDP();       
    }
    
    if (inmessage) free(inmessage);
    if (protocoltype) free(protocoltype);
    return ca_event->ErrCode;
}




/**
 * Action: GetSupportedProtocols.
 *
 */
int GetSupportedProtocols(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: GetSessionLoginChallenge.
 *
 */
int GetSessionLoginChallenge(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: SessionLogin.
 *
 */
int SessionLogin(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: SessionLogout.
 *
 */
int SessionLogout(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}


/**
 * Action: GetACLData.
 *
 */
int GetACLData(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: AddRolesForIdentity.
 *
 */
int AddRolesForIdentity(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: RemoveRolesForIdentity.
 *
 */
int RemoveRolesForIdentity(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: AddLoginData.
 *
 */
int AddLoginData(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}


/**
 * Action: RemoveLoginData.
 *
 */
int RemoveLoginData(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: AddIdentityData.
 *
 */
int AddIdentityData(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: RemoveIdentityData.
 *
 */
int RemoveIdentityData(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}
