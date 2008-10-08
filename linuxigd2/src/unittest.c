#include <CUnit/Basic.h>
#include <CUnit/Automated.h>

#include "gatedevice.h"
#include "pmlist.h"
#include "globals.h"

// Global variables
globals g_vars;

char retrieve_port_list_request_xml[] = "<?xml version=\"1.0\"?>\n<u:RetrieveListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>100</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n<Manage>1</Manage>\n</u:RetrieveListOfPortmappings>";
char retrieve_port_list_inv_args_xml[] = "<?xml version=\"1.0\"?>\n<u:RetrieveListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>100</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n</u:RetrieveListOfPortmappings>";
char retrieve_port_list_no_results_xml[] = "<?xml version=\"1.0\"?>\n<u:RetrieveListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>10</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n<Manage>1</Manage>\n</u:RetrieveListOfPortmappings>";

int InitTestSuite(void)
{
    struct portMap *pm;

    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "21", "21", "TCP", "192.168.0.20", "FTP");
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "22", "22", "TCP", "192.168.0.20", "SSH");
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "80", "80", "TCP", "192.168.0.20", "Http");
    pmlist_PushBack(pm);

    return 0;
}

int CleanTestSuite(void)
{
    return 0;
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
    if ((NULL == CU_add_test(pSuite, "test of RetrieveListOfPortMappings()", Test_RetrieveListOfPortMappings)))
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
