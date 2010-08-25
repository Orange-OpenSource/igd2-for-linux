#ifndef WPA_SUPPLICANT_IFACE_H
#define WPA_SUPPLICANT_IFACE_H

#ifdef __cplusplus
extern "C" {
#endif

//values directly from wpsutil ##003
#define WPSU_MAC_LEN               6
#define WPSU_HASH_LEN              32 // if SHA1 is used then 20

typedef struct {
  char *devicePIN;
  char *manufacturer;
  char *modelName; 
  char *modelNumber;
  char *serialNumber;
  char *deviceName;
  unsigned char *primaryDeviceType;
  int primaryDeviceType_len;
  unsigned char *macAddress;
  int macAddress_len;
  unsigned char *uuid;
  int uuid_len;
  unsigned char *OSVersion;
  int OSVersion_len;
  unsigned char *pubKey;
  int pubKey_len;
  int configMethods; //##003 not needed??
  int RFBands; //##003 not needed??
} wpa_supplicant_wps_enrollee_info;


int wpa_supplicant_iface_init(wpa_supplicant_wps_enrollee_info *info);
int wpa_supplicant_iface_delete(void);

int wpa_supplicant_create_enrollee_state_machine(void **esm);
int wpa_supplicant_start_enrollee_state_machine(void *esm,
                                                unsigned char** next_message,
                                                int* next_message_len);
int wpa_supplicant_stop_enrollee_state_machine(void *esm);

//status values directly from wpsutil ##003
typedef enum {WPSU_SM_E_PROCESS,WPSU_SM_E_SUCCESS,WPSU_SM_E_SUCCESSINFO,WPSU_SM_E_FAILURE,WPSU_SM_E_FAILUREEXIT} wpsu_enrollee_sm_status; 
int wpa_supplicant_update_enrollee_state_machine(void* esm,
                                                 unsigned char* received_message,
                                                 int received_message_len,
                                                 unsigned char** next_message,
                                                 int* next_message_len,
                                                 int* ready);

unsigned char *wpa_supplicant_base64_encode(const unsigned char *src,
                                                   size_t len,
                                                   size_t *out_len);

unsigned char *wpa_supplicant_base64_decode(const unsigned char *src,
                                                   size_t len,
                                                   size_t *out_len);

void wpa_supplicant_hmac_sha256(const unsigned char *key, size_t key_len,
				const unsigned char *data, size_t data_len,
				unsigned char *mac);
#ifdef __cplusplus
}
#endif

#endif //WPA_SUPPLICANT_IFACE_H
