#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <upnp/ixml.h>
#include <string.h>

#include "gatedevice.h"
#include "pmlist.h"
#include "globals.h"
#include "unittest.h"

// Global variables
globals g_vars;


char get_specific_portmapping_entry_request_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";
char get_specific_portmapping_entry_inv_args_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>HTTP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";
char get_specific_portmapping_entry_no_such_entry_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>UDP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";

int InitTestSuite(void)
{
    struct portMap *pm;

    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "21", "21", "TCP", "192.168.0.20", "FTP");
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "22", "22", "TCP", "192.168.0.20", "SSH");
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "80", "80", "TCP", "192.168.0.20", "Http");
    pmlist_PushBack(pm);

    ExpirationTimerThreadInit();

    return 0;
}

int CleanTestSuite(void)
{
    return 0;
}

void Test_AddAnyPortMapping(void)
{
    struct Upnp_Action_Request event;
    char *port = NULL;
    int result;

    strcpy(event.ActionName,"AddAnyPortMapping");
    strcpy(event.DevUDN,"00:22132:24324");
    strcpy(event.ServiceID,"99");

    // Add new port mapping 	
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_ok_xml);
 
    CU_ASSERT(AddAnyPortMapping(&event) == 0);
    port = GetFirstDocumentItem(event.ActionResult, "ReservedPort");
    CU_ASSERT(strcmp(port, "100") == 0);

    // Add it again
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_reserved_xml);
    result = AddAnyPortMapping(&event);
    CU_ASSERT(result == 0);

    port = GetFirstDocumentItem(event.ActionResult, "ReservedPort");
    CU_ASSERT(strcmp(port, "100") != 0);

    // Wildcard in remote host
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_wild_card_in_remote_host_xml);
    CU_ASSERT(AddAnyPortMapping(&event) == 715);

    // Wildcard in external port
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_wild_card_in_external_port_xml);
    result = AddAnyPortMapping(&event);
    CU_ASSERT(result == 716);

    // Different internal and external port values
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_different_port_values_xml);
    CU_ASSERT(AddAnyPortMapping(&event) == 724);

    // Missing parameter
    event.ActionRequest = ixmlParseBuffer(add_any_port_mapping_missing_parameter_xml);
    CU_ASSERT(AddAnyPortMapping(&event) == 402);
}
    
void Test_RetrieveListOfPortMappings(void)
{
    struct Upnp_Action_Request event;

    // Ok
    event.ActionRequest = ixmlParseBuffer(retrieve_port_list_request_xml);
    CU_ASSERT(RetrieveListOfPortmappings(&event) == 0);

    // Invalid arguments
    event.ActionRequest = ixmlParseBuffer(retrieve_port_list_inv_args_xml);
    CU_ASSERT(RetrieveListOfPortmappings(&event) == 402);

    // No results
    event.ActionRequest = ixmlParseBuffer(retrieve_port_list_no_results_xml);
    CU_ASSERT(RetrieveListOfPortmappings(&event) == 714);
}

void Test_GetSpecificPortMappingEntry(void)
{
    struct Upnp_Action_Request event;

    // Ok
    event.ActionRequest = ixmlParseBuffer(get_specific_portmapping_entry_request_xml);
    CU_ASSERT(GetSpecificPortMappingEntry(&event) == 0);
    
    // Invalid args
    event.ActionRequest = ixmlParseBuffer(get_specific_portmapping_entry_inv_args_xml);
    CU_ASSERT(GetSpecificPortMappingEntry(&event) == 402);
    
    // No such entry
    event.ActionRequest = ixmlParseBuffer(get_specific_portmapping_entry_no_such_entry_xml);
    CU_ASSERT(GetSpecificPortMappingEntry(&event) == 714);
}

int main(int argc, char** argv)
{
    CU_pSuite pSuite = NULL;
    int xml = 0, i;

    for(i=1; i < argc; i++)
    {
        if (strcmp(argv[i], "--xml") == 0 || strcmp(argv[i], "-x") == 0)
            xml = 1;
    }

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* add a suite to the registry */
    pSuite = CU_add_suite("Suite_1", InitTestSuite, CleanTestSuite);
    if (NULL == pSuite)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "test of RetrieveListOfPortMappings()", Test_RetrieveListOfPortMappings)) ||
        (NULL == CU_add_test(pSuite, "test of GetSpecificPortMappingEntry()", Test_GetSpecificPortMappingEntry)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test of AddAnyPortMapping()", Test_AddAnyPortMapping)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (xml)
    {
        CU_automated_run_tests();
    }
    else
    {
        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();
    }

    CU_cleanup_registry();

    return CU_get_error();
}
