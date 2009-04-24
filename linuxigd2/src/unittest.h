/* 
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation 
 * Copyright © 2009 Nokia Corporation and/or its subsidiary(-ies).* 
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

// RetrieveListOfPortMappings
// SOAP requests
char retrieve_port_list_request_xml[] = "<?xml version=\"1.0\"?>\n<u:GetListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>100</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n<NewManage>1</NewManage>\n</u:GetListOfPortmappings>";
char retrieve_port_list_inv_args_xml[] = "<?xml version=\"1.0\"?>\n<u:GetListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>100</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n</u:GetListOfPortmappings>";
char retrieve_port_list_no_results_xml[] = "<?xml version=\"1.0\"?>\n<u:GetListOfPortmappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>10</NewEndPort>\n<NewNumberOfPorts>0</NewNumberOfPorts>\n<NewProtocol>TCP</NewProtocol>\n<NewStartPort>10</NewStartPort>\n<NewManage>1</NewManage>\n</u:GetListOfPortmappings>";

//AddAnyPortMapping 
// SOAP requests
char add_any_port_mapping_ok_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>100</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>100</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>mapping port 100</NewPortMappingDescription>\n<NewLeaseDuration>40500</NewLeaseDuration>\n</u:AddAnyPortMapping>";
char add_any_port_mapping_reserved_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>100</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>100</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>again tries to map port 100</NewPortMappingDescription><NewLeaseDuration>40500</NewLeaseDuration></u:AddAnyPortMapping>";
char add_any_port_mapping_wild_card_in_internal_client_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>100</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>100</NewInternalPort>\n<NewInternalClient></NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>again tries to map port 100</NewPortMappingDescription><NewLeaseDuration>40500</NewLeaseDuration></u:AddAnyPortMapping>";
char add_any_port_mapping_wild_card_in_external_port_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>*</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>100</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>again tries to map port 100</NewPortMappingDescription><NewLeaseDuration>40500</NewLeaseDuration></u:AddAnyPortMapping>";
char add_any_port_mapping_different_port_values_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>100</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>99</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>again tries to map port 100</NewPortMappingDescription><NewLeaseDuration>40500</NewLeaseDuration></u:AddAnyPortMapping>";
char add_any_port_mapping_missing_parameter_xml[]= "<?xml version=\"1.0\"?>\n<u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>100</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>again tries to map port 100</NewPortMappingDescription><NewLeaseDuration>40500</NewLeaseDuration></u:AddAnyPortMapping>";

// GetSpecificPortMappingEntry
// SOAP requests
char get_specific_portmapping_entry_request_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";
char get_specific_portmapping_entry_inv_args_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>HTTP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";
char get_specific_portmapping_entry_no_such_entry_xml[] = "<?xml version=\"1.0\"?>\n<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>21</NewExternalPort>\n<NewProtocol>UDP</NewProtocol>\n</u:GetSpecificPortMappingEntry>";

// AddPortMapping
// SOAP requests
char add_portmapping_request_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2000</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_wildcard_remotehost_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost></NewRemoteHost>\n<NewExternalPort>2001</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2001</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_wildcard_internalclient_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost></NewRemoteHost>\n<NewExternalPort>2001</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2001</NewInternalPort>\n<NewInternalClient></NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_wildcard_extport_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>0</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2000</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_wildcard_intport_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>0</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_diff_ports_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2001</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n<NewPortMappingDescription>Desc</NewPortMappingDescription>\n</u:AddPortMapping>";
char add_portmapping_request_missing_parameter_xml[] = "<?xml version=\"1.0\"?>\n<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n<NewInternalPort>2000</NewInternalPort>\n<NewInternalClient>192.168.0.20</NewInternalClient>\n<NewLeaseDuration>220</NewLeaseDuration>\n<NewEnabled>1</NewEnabled>\n</u:AddPortMapping>";

// DeletePortMapping
// SOAP requests
char delete_portmapping_request_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>130.234.180.200</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:DeletePortMapping>";
char delete_portmapping_request_wildcard_remotehost_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost></NewRemoteHost>\n<NewExternalPort>2001</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:DeletePortMapping>";
char delete_portmapping_request_missing_parameter_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:DeletePortMapping>";
char delete_portmapping_request_invalid_IP_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewRemoteHost>Not an IP</NewRemoteHost>\n<NewExternalPort>2000</NewExternalPort>\n<NewProtocol>TCP</NewProtocol>\n</u:DeletePortMapping>";

// DeletePortMappingRange
// SOAP requests
char delete_portmapping_range_request_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMappingRange xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewStartPort>1990</NewStartPort>\n<NewEndPort>2000</NewEndPort>\n<NewProtocol>TCP</NewProtocol>\n<NewManage>1</NewManage>\n</u:DeletePortMappingRange>";
char delete_portmapping_range_request_invalid_protocol_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMappingRange xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewStartPort>2000</NewStartPort>\n<NewEndPort>2005</NewEndPort>\n<NewProtocol>FTP</NewProtocol>\n<NewManage>1</NewManage>\n</u:DeletePortMappingRange>";
char delete_portmapping_range_request_missing_parameter_xml[] = "<?xml version=\"1.0\"?>\n<u:DeletePortMappingRange xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n<NewEndPort>2000</NewEndPort>\n<NewProtocol>TCP</NewProtocol>\n<NewManage>1</NewManage>\n</u:DeletePortMappingRange>";

// GetEthernetLinkStatus
// SOAP requests
char get_ethernet_link_status_request_xml[] = "<?xml version=\"1.0\"?>\n<u:GetEthernetLinkStatus xmlns:u=\"urn:schemas-upnp-org:service:WANEthernetLinkConfig:1\">\n</u:GetEthernetLinkStatus>";
