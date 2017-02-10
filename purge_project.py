#!/usr/bin/python
"""
Sequentiial K5 Project Purge script

Author: Graham Land
Date: 08/12/16
Twitter: @allthingsclowd
Github: https://github.com/allthingscloud
Blog: https://allthingscloud.eu


"""
from k5contractsettingsV10 import *
from k5APIwrappersV19 import *


def purge_project(projectid, projectidB):
    k5token = get_scoped_token(adminUser, adminPassword, contract, projectid, region).headers['X-Subject-Token']
    print k5token

    PBK5token = get_rescoped_token(k5token, projectidB, region).headers['X-Subject-Token']
    print PBK5token

    for snapshot in list_snapshots(k5token, projectid, region).json()['snapshots']:
        print snapshot
        result = delete_snapshot(k5token, snapshot.get('id'), projectid, region)
        if result.status_code == 204:
            print "Snapshot removed - ", snapshot.get('id')
        else:
            print "Snap delete error: ", result.json()

    for server in list_servers(k5token, projectid, region).json()['servers']:
        print server
        if "BUILD" not in server.get('status'):
            result = delete_server(k5token, server.get('id'), projectid, region)
            if result.status_code == 204:
                print "Server removed - ", server.get('id')
            else:
                print "Server delete error: ", result.json()
        else:
            print "Server still buliding..try again in 5 minutes.. - ", server.get('id')

    for volume in list_volumes(k5token, projectid, region).json()['volumes']:
        print volume
        result = delete_volume(k5token, volume.get('id'), projectid, region)
        if result.status_code == 204:
            print "Volume removed - ", volume.get('id')
        else:
            print "Volume delete error: ", result

    for global_ip in list_global_ips(k5token, region).json()['floatingips']:
        print global_ip
        result = delete_global_ip(k5token, global_ip.get('id'), region)
        if result.status_code == 204:
            print "Global ip removed - ", global_ip.get('id')
        else:
            print "Global ip delete error: ", result.json()

    for vpncon in list_ipsec_site_connections(k5token, region).json()['ipsec_site_connections']:
        print "\nVPN connections:  ", vpncon.get('name'),  vpncon.get('id')
        print show_ipsec_site_connection(k5token, vpncon.get('id'), region).json()
        result = delete_ipsec_site_connection(k5token, vpncon.get('id'), region)
        if result.status_code == 204:
            print "VPN connection removed - ", vpncon.get('id')
        else:
            print "VPN connection delete error: ", result.json()

    for vpnservice in list_vpn_services(k5token, region).json()['vpnservices']:
        print vpnservice.get('name'), vpnservice.get('id')
        print show_vpn_service(k5token, vpnservice.get('id'), region).json()
        result = delete_vpn_service(k5token, vpnservice.get('id'), region)
        if result.status_code == 204:
            print "VPN service removed - ", vpnservice.get('id')
        else:
            print "VPN service delete error: ", result.json()

    for secpol in list_ipsec_policies(k5token, region).json()['ipsecpolicies']:
        print "\nIPSec Policy: ", secpol.get('name'), secpol.get('id')
        print show_ipsec_policy(k5token, secpol.get('id'), region).json()
        result = delete_ipsec_policy(k5token, secpol.get('id'), region)
        if result.status_code == 204:
            print "IPSec policy removed - ", secpol.get('id')
        else:
            print "IPSec policy delete error: ", result.json()

    for router in list_routers(k5token, region).json()['routers']:
        if len(router['routes']) > 0:
            print update_router_routes(k5token, router.get('id'), None, region)

        for interface in show_router_interfaces(k5token, router.get('id'), region).json()['ports']:
            result = remove_interface_from_router(k5token, router.get('id'), interface.get('id'), region)
            if result.status_code == 200:
                print "Router interface removed - ", interface.get('id')
            else:
                print "Router interface delete error: ", result.json()
        #print list_device_ports(k5token, router.get('id'), region).json()
        for port in list_ports(PBK5token, region).json()['ports']:
            print port, router.get('id')
            if port.get('device_owner') == "network:router_interface":
                print "you need to remove me"
                result = inter_project_connection_remove(k5token, port.get('device_id'), port.get('id'), region)
                print "Take 1 ", result.json()
                if result.status_code == 403:
                    result = inter_project_connection_remove(PBK5token, port.get('device_id'), port.get('id'), region)
                    print "Take 2: ", result.json()

        result = delete_router(k5token, router.get('id'), region)
        if result.status_code == 204:
            print "Router removed - ", router.get('id')
        else:
            print "Router delete error: ", result.json()

    for port in list_ports(k5token, region).json()['ports']:
        print port.get('name'), "\t", port.get('id')
        result = delete_port(k5token, port.get('id'), region)
        if result.status_code == 204:
            print "Port removed - ", port.get('id')
        else:
            # check for interproject route

            print "Port delete error: ", result.json()

    for sg in list_security_groups(k5token, region).json()['security_groups']:
        #if "created by API" in sg.get('description'):
        if "Demo Security Group Allows RDP, SSH and ICMP" in sg.get('description'):
            result = delete_security_group(k5token, sg.get('id'), region)
            if result.status_code == 204:
                print "Security group removed - ", sg.get('id')
            else:
                print "Security group delete error: ", result.json()

    #print list_keypairs(k5token, projectid, region).json()
    for kp in list_keypairs(k5token, projectid, region).json()['keypairs']:

        if "kp-loadtest" in kp['keypair'].get('name'):
            result = delete_keypair(k5token, kp['keypair'].get('name'), projectid, region)
            print result
            if result.status_code == 202:
                print "SSH KP removed - ", kp['keypair'].get('name')
            else:
                print "SSH KP delete error: ", result.json()

    for subnet in list_subnets(k5token, region).json()['subnets']:
        if "inf" not in subnet.get('name'):
            print subnet
            result = delete_subnet(k5token, subnet.get('id'), region)
            if result.status_code == 204:
                print "Subnet removed - ", subnet.get('id')
            else:
                print "Subnet delete error: ", result.json()

    for network in list_networks(k5token, region).json()['networks']:
        if "ext-net" not in network.get('name'):
            result = delete_network(k5token, network.get('id'), region)
            if result.status_code == 204:
                print "Network removed - ", network.get('id')
            else:
                print "Network delete error: ", result.json()


def main():

    purge_project(demoProjectAid, demoProjectBid)


if __name__ == "__main__":
    main()
