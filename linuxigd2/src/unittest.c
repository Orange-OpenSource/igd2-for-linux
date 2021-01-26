/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
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

/*
    THESE ARE, AT LEAST FOR SOME PARTS, OUTDATED!!!
*/

#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <upnp/ixml.h>
#include "threadutil/TimerThread.h"
#include <string.h>

#include "gatedevice.h"
#include "pmlist.h"
#include "globals.h"
#include "util.h"
#include "unittest.h"
#include "util.h"
#include <arpa/inet.h>

// Global variables
globals g_vars;

int InitTestSuite(void)
{
    struct portMap *pm;

    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "21", "21", "TCP", "192.168.0.20", "FTP", 0);
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "22", "22", "TCP", "192.168.0.20", "SSH", 0);
    pmlist_PushBack(pm);
    pm = pmlist_NewNode(1, 604800, "130.234.180.200", "80", "80", "TCP", "192.168.0.20", "Http", 0);
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
    UpnpActionRequest* event;
    char *port = NULL;
    int result;

    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_ActionName(event, "AddAnyPortMapping");
    UpnpActionRequest_strcpy_DevUDN(event, "00:22132:24324");
    UpnpActionRequest_strcpy_ServiceID(event, "99");

    // Add new port mapping
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_ok_xml));

    CU_ASSERT(AddAnyPortMapping(event) == 0);
    port = GetFirstDocumentItem(UpnpActionRequest_get_ActionResult(event), "NewReservedPort");
    CU_ASSERT(strcmp(port, "100") == 0);

    // Add it again
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_reserved_xml));
    result = AddAnyPortMapping(event);
    CU_ASSERT(result == 0);

    port = GetFirstDocumentItem(UpnpActionRequest_get_ActionResult(event), "NewReservedPort");
    CU_ASSERT(strcmp(port, "100") != 0);

    // Wildcard in internal client
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_wild_card_in_internal_client_xml));
    CU_ASSERT(AddAnyPortMapping(event) == 715);

    // Wildcard in external port
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_wild_card_in_external_port_xml));
    result = AddAnyPortMapping(event);
    CU_ASSERT(result == 716);

    // Different internal and external port values
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_different_port_values_xml));
    CU_ASSERT(AddAnyPortMapping(event) == 724);

    // Missing parameter
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_any_port_mapping_missing_parameter_xml));
    CU_ASSERT(AddAnyPortMapping(event) == 402);

    UpnpActionRequest_delete(event);
}

void Test_RetrieveListOfPortMappings(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANIPConn1");
    UpnpActionRequest_strcpy_ActionName(event, "RetrieveListOfPortmappings");

    // Ok
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(retrieve_port_list_request_xml));
    CU_ASSERT(GetListOfPortmappings(event) == 0);

    // Invalid arguments
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(retrieve_port_list_inv_args_xml));
    CU_ASSERT(GetListOfPortmappings(event) == 402);

    // No results
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(retrieve_port_list_no_results_xml));
    CU_ASSERT(GetListOfPortmappings(event) == 714);

    UpnpActionRequest_delete(event);
}

void Test_GetSpecificPortMappingEntry(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANIPConn1");
    UpnpActionRequest_strcpy_ActionName(event, "GetSpecificPortMappingEntry");

    // Ok
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(get_specific_portmapping_entry_request_xml));
    CU_ASSERT(GetSpecificPortMappingEntry(event) == 0);

    // Invalid args
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(get_specific_portmapping_entry_inv_args_xml));
    CU_ASSERT(GetSpecificPortMappingEntry(event) == 402);

    // No such entry
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(get_specific_portmapping_entry_no_such_entry_xml));
    CU_ASSERT(GetSpecificPortMappingEntry(event) == 714);

    UpnpActionRequest_delete(event);
}

void Test_AddPortMapping(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANIPConn1");
    UpnpActionRequest_strcpy_ActionName(event, "AddPortMapping");

    // Add with remotehost
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_xml));
    CU_ASSERT(AddPortMapping(event) == 0);

    // Add with wildcarded remotehost
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_wildcard_remotehost_xml));
    CU_ASSERT(AddPortMapping(event) == 0);

    // Add with wildcarded internalclient
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_wildcard_internalclient_xml));
    CU_ASSERT(AddPortMapping(event) == 715);

    // Add with wildcarded external port
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_wildcard_extport_xml));
    CU_ASSERT(AddPortMapping(event) == 716);

    // Add with wildcarded internal port
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_wildcard_intport_xml));
    CU_ASSERT(AddPortMapping(event) == 732);

    // Add with different port values
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_diff_ports_xml));
    CU_ASSERT(AddPortMapping(event) == 724);

    // Invalid args
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(add_portmapping_request_missing_parameter_xml));
    CU_ASSERT(AddPortMapping(event) == 402);

    UpnpActionRequest_delete(event);
}

void Test_DeletePortMapping(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANIPConn1");
    UpnpActionRequest_strcpy_ActionName(event, "DeletePortMapping");

    // add required portmappings
    Test_AddPortMapping();

    // Delete with remotehost
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_request_xml));
    CU_ASSERT(DeletePortMapping(event) == 0);

    // Delete with wildcarded remotehost
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_request_wildcard_remotehost_xml));
    CU_ASSERT(DeletePortMapping(event) == 0);

    // Invalid args
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_request_missing_parameter_xml));
    CU_ASSERT(DeletePortMapping(event) == 402);

    // Try to delete non-existent portmapping
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_request_xml));
    CU_ASSERT(DeletePortMapping(event) == 714);

    // Try to delete with invalid IP address as remotehost
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_request_invalid_IP_xml));
    CU_ASSERT(DeletePortMapping(event) == 402);
}

void Test_DeletePortMappingRange(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANIPConn1");
    UpnpActionRequest_strcpy_ActionName(event, "DeletePortMappingRange");

    // add required portmappings
    Test_AddPortMapping();

    // Missing argument
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_range_request_missing_parameter_xml));
    CU_ASSERT(DeletePortMappingRange(event) == 402);

    // Invalid protocol
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_range_request_invalid_protocol_xml));
    CU_ASSERT(DeletePortMappingRange(event) == 402);

    // Delete range
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_range_request_xml));
    CU_ASSERT(DeletePortMappingRange(event) == 0);

    // Try to delete non-existent portmappings
    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(delete_portmapping_range_request_xml));
    CU_ASSERT(DeletePortMappingRange(event) == 714);

    UpnpActionRequest_delete(event);
}

void Test_ControlPointIP_equals_InternalClientIP(void)
{
    struct in_addr cpIP;
    int TestResult;
    char ICAddress[INET_ADDRSTRLEN];

    strcpy(ICAddress,"255.255.255.255"); // InternalClient test IP

    // Control point IP same as InternalClient
    inet_pton(AF_INET,"255.255.255.255", &cpIP);
    TestResult = ControlPointIP_equals_InternalClientIP(ICAddress, &cpIP);
    // Check the compare result InternalClient IP address is same than Control Point
    CU_ASSERT(TestResult == 1);

    // Control point IP is different than InternalClient
    inet_pton(AF_INET,"255.255.255.250", &cpIP);
    TestResult = ControlPointIP_equals_InternalClientIP(ICAddress, &cpIP);
    // Check the result that InternalClient IP address is NOT same as Control Point
    CU_ASSERT(TestResult == 0);

}

void Test_GetEthernetLinkStatus(void)
{
    UpnpActionRequest* event;
    event = UpnpActionRequest_new();
    UpnpActionRequest_strcpy_DevUDN(event, "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e");
    UpnpActionRequest_strcpy_ServiceID(event, "urn:upnp-org:serviceId:WANEthLinkC1");
    UpnpActionRequest_strcpy_ActionName(event, "GetEthernetLinkStatus");

    UpnpActionRequest_set_ActionRequest(event, ixmlParseBuffer(get_ethernet_link_status_request_xml));

    // Up
    strcpy(g_vars.extInterfaceName,"eth0");
    CU_ASSERT(GetEthernetLinkStatus(event) == 0);
    CU_ASSERT(strcmp(GetFirstDocumentItem(UpnpActionRequest_get_ActionResult(event), "EthernetLinkStatus"), "Up") == 0);

    // Down
    strcpy(g_vars.extInterfaceName,"eth7");
    CU_ASSERT(GetEthernetLinkStatus(event) == 0);
    CU_ASSERT(strcmp(GetFirstDocumentItem(UpnpActionRequest_get_ActionResult(event), "EthernetLinkStatus"), "Down") == 0);

    UpnpActionRequest_delete(event);
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
    // WANIPConn1 tests
    if ((NULL == CU_add_test(pSuite, "test of RetrieveListOfPortMappings()", Test_RetrieveListOfPortMappings)) ||
        (NULL == CU_add_test(pSuite, "test of GetSpecificPortMappingEntry()", Test_GetSpecificPortMappingEntry)) ||
        (NULL == CU_add_test(pSuite, "test of AddPortMapping()", Test_AddPortMapping)) ||
        (NULL == CU_add_test(pSuite, "test of DeletePortMapping()", Test_DeletePortMapping)) ||
        (NULL == CU_add_test(pSuite, "test of DeletePortMappingRange()", Test_DeletePortMappingRange)) ||
        (NULL == CU_add_test(pSuite, "test of Test_ControlPointIP_equals_InternalClientIP()", Test_ControlPointIP_equals_InternalClientIP)) ||
        (NULL == CU_add_test(pSuite, "test of AddAnyPortMapping()", Test_AddAnyPortMapping)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // WANEthLinkC1 tests
    if ((NULL == CU_add_test(pSuite, "test of GetEthernetLinkStatus()", Test_GetEthernetLinkStatus)))
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
