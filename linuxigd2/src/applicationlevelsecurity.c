#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "lanhostconfig.h"
#include "globals.h"
#include "util.h"
#include <wpsutil/enrollee_state_machine.h>
#include <wpsutil/base64mem.h>

// TODO Should these be in main? Or somewhere else. 
WPSuEnrolleeSM* esm;
unsigned char* Enrollee_send_msg;
int Enrollee_send_msg_len;
WPSuStationInput input;

int reactor_loop = 1;

int InitALS()
{   
    // TODO these values. What those should be and move to config file 
    // TODO: Should start new thread for multiple simultanious registration processes?
    int err;
    
    unsigned char MAC[SC_MAC_LEN];
    memset(MAC, 0xAB, SC_MAC_LEN);

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
                                        SC_MAC_LEN,
                                        "TestUUID",
                                        8,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        SC_CONF_METHOD_LABEL | SC_CONF_METHOD_PUSHBUTTON, 
                                        SC_RFBAND_2_4GHZ);
                                        
                                
                                        
    /*
    strcpy(input.OwnInfo.Manufacturer, "TestManufacturer");
    strcpy(input.OwnInfo.ModelName, "TestModelName");
    strcpy(input.OwnInfo.ModelNumber, "TestModelNumber");
    strcpy(input.OwnInfo.SerialNumber, "TestSerialNumber");
    strcpy(input.OwnInfo.DeviceName, "TestDeviceName");
    strcpy(input.OwnInfo.Uuid, "TestUUID");
    memset(input.OwnInfo.MacAddress, 0xAB, SC_MAC_LEN);
    input.OwnInfo.ConfigMethods = SC_CONF_METHOD_LABEL | SC_CONF_METHOD_PUSHBUTTON;
    input.OwnInfo.RFBands = SC_RFBAND_2_4GHZ;
    strcpy(input.DevicePIN, "stasecret");
*/
    // station has applications A, B and C
    input.Apps = 3;

unsigned char UUID[SC_MAX_UUID_LEN];
unsigned char *DATA;

    memset(UUID, 0xAA, SC_MAX_UUID_LEN);
    //input.AppsList[0].DataLen = 0;

err =  wpsu_enrollee_station_input_add_app(&input,
    UUID,SC_MAX_UUID_LEN,
    NULL,0,
    NULL,0);

    //input.AppsList[1].Data = (unsigned char*) malloc(1000);
    //memset(input.AppsList[1].UUID, 0xBB, SC_MAX_UUID_LEN);
    //strcpy(input.AppsList[1].Data, "B data from STA");
    //input.AppsList[1].DataLen = strlen("B data from STA") + 1;
    
    memset(UUID, 0xBB, SC_MAX_UUID_LEN);

err =  wpsu_enrollee_station_input_add_app(&input,
    UUID,SC_MAX_UUID_LEN,
    "B data from STA",strlen("B data from STA") + 1,
    NULL,0);

    //input.AppsList[2].Data = (unsigned char*) malloc(1000);
    //memset(input.AppsList[2].UUID, 0xCC, SC_MAX_UUID_LEN);
    //strcpy(input.AppsList[2].Data, "C data from STA");
    //input.AppsList[2].DataLen = strlen("C data from STA") + 1;

    memset(UUID, 0xCC, SC_MAX_UUID_LEN);
    

err =  wpsu_enrollee_station_input_add_app(&input,
    UUID,SC_MAX_UUID_LEN,
    "C data from STA",strlen("C data from STA") + 1,
    NULL,0);

    // create enrollee state machine

    esm = wpsu_create_enrollee_sm_station(&input, &err);
    printf ("wpsu_create_enrollee_sm_station %d\n",err);
    
    return 0;
}

void FreeALS()
{
    int error;
    free(input.AppsList[1].Data);
    free(input.AppsList[2].Data);
    wpsu_cleanup_enrollee_sm(esm, &error);
}

/**
 * When message M2, M2D, M4, M6, M8 or Done ACK is received, enrollee state machine is updated here
 */
int message_received(int error, unsigned char *data, int len, void* control)
{
    int status;

    if (error)
    {
        trace(2,"Message receive failure! Error = %d", error);
        return error;
    }

    wpsu_update_enrollee_sm(esm, data, len, &Enrollee_send_msg, &Enrollee_send_msg_len, &status, &error);

    switch (status)
    {
        case SC_E_SUCCESS:
        {
            trace(3,"Last message received!\n");
            FreeALS();
            reactor_loop = 0;
            break;
        }
        case SC_E_SUCCESSINFO:
        {
            trace(3,"Last message received M2D!\n");
            FreeALS();
            reactor_loop = 0;
            break;
        }

        case SC_E_FAILURE:
        {
            trace(3,"Error in state machine. Terminating...\n");
            FreeALS();
            reactor_loop = 0;
            break;
        }

        case SC_E_FAILUREEXIT:
        {
            trace(3,"Error in state machine. Terminating...\n");
            FreeALS();
            reactor_loop = 0;
            break;
        }
        default:
        {

        }
    }
    return 0;
}


/**
 * Action: GetDeviceInfo.
 *
 * Return M1 message for sender of action.
 */
int GetDeviceInfo(struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];
    int error;
    
    // temporarly this is here. This should probably be somewhere else?
    InitALS();
    // start the state machine and create M1
    wpsu_start_enrollee_sm(esm, &Enrollee_send_msg, &Enrollee_send_msg_len, &error);
      
    // to base64   
    int maxb64len=2*Enrollee_send_msg_len; 
    int b64len=0;    
    unsigned char *pB64Msg=(unsigned char *)malloc(maxb64len); 

    wpsu_bin_to_base64(Enrollee_send_msg_len,Enrollee_send_msg, &b64len, pB64Msg,maxb64len);
    // return M1 as base64 encoded
    trace(3,"Send M1 as response for GetDeviceInfo request\n");
    //printf("M1 in base64: %s\n",pB64Msg);
    
    ca_event->ErrCode = UPNP_E_SUCCESS;
    snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<NewDeviceInfo>%s</NewDeviceInfo>\n</u:%sResponse>",
             ca_event->ActionName, "urn:schemas-upnp-org:service:WFAWLANConfig:1", pB64Msg, ca_event->ActionName);
    ca_event->ActionResult = ixmlParseBuffer(resultStr);    

    free(pB64Msg);
    return ca_event->ErrCode;
}

/**
 * Action: PutMessage.
 *
 * After sending M1 as response for GetDeviceInfo-action, messages M3, M5, M7 and Done
 * are send as response for this action.
 */
int PutMessage(struct Upnp_Action_Request *ca_event)
{
    char resultStr[RESULT_LEN];   
    char *message = NULL;
    
    message = GetFirstDocumentItem(ca_event->ActionRequest, "NewInMessage");

    // to bin
    int b64msglen=strlen(message);
    unsigned char *pBinMsg=(unsigned char *)malloc(b64msglen);
    int outlen;
    
    wpsu_base64_to_bin(b64msglen,(const unsigned char *)message,&outlen,pBinMsg,b64msglen);
    
    //printf("Message in bin: %s\n",pBinMsg);
    // update state machine
    message_received(0, pBinMsg, outlen, NULL); 

    // response (next message) to base64   
    int maxb64len=2*Enrollee_send_msg_len; 
    int b64len=0;    
    unsigned char *pB64Msg=(unsigned char *)malloc(maxb64len); 
    wpsu_bin_to_base64(Enrollee_send_msg_len,Enrollee_send_msg, &b64len, pB64Msg,maxb64len);
    
    trace(3,"Send response for PutMessage request\n");
    
    ca_event->ErrCode = UPNP_E_SUCCESS;
    snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n<NewOutMessage>%s</NewOutMessage>\n</u:%sResponse>",
             ca_event->ActionName, "urn:schemas-upnp-org:service:WFAWLANConfig:1", pB64Msg, ca_event->ActionName);
    ca_event->ActionResult = ixmlParseBuffer(resultStr);       
    
    free(pBinMsg);
    return ca_event->ErrCode;
}

/**
 * Action: RequestCert.
 *
 */
int RequestCert(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: GetRoles.
 *
 */
int GetRoles(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: GetCACert.
 *
 */
int GetCACert(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: GetKnownCAs.
 *
 */
int GetKnownCAs(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

// Admin interface

/**
 * Action: AddACLEntry.
 *
 */
int AddACLEntry(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}

/**
 * Action: AddCACertHash.
 *
 */
int AddCACertHash(struct Upnp_Action_Request *ca_event)
{
    return ca_event->ErrCode;
}
