//TODO: insert header text, this is a new file
#ifndef WPA_SUPPLICANT_IFACE_H
#define WPA_SUPPLICANT_IFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * wpa_supplicant_iface configuration data
 *
 * This data structure is a subset of internal wpa_config structure,
 * plus device_pin
 */
typedef struct {
	char *device_pin;
	unsigned char uuid[16];
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	char *device_type;
	char *config_methods;
} wpa_supplicant_wps_enrollee_config;


int wpa_supplicant_iface_init(wpa_supplicant_wps_enrollee_config *config);
int wpa_supplicant_iface_delete(void);

int wpa_supplicant_create_enrollee_state_machine(void **esm);
int wpa_supplicant_start_enrollee_state_machine(void *esm,
                                                unsigned char** next_message,
                                                int* next_message_len);
int wpa_supplicant_stop_enrollee_state_machine(void *esm);

//status values for 'int *ready' output parameter
typedef enum {WPASUPP_SM_E_PROCESS,
	      WPASUPP_SM_E_SUCCESS,
	      WPASUPP_SM_E_SUCCESSINFO,
	      WPASUPP_SM_E_FAILURE,
	      WPASUPP_SM_E_FAILUREEXIT} wpasupp_enrollee_sm_status;
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
