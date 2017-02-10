#!/usr/bin/python
"""Threaded version of the purge script
This script attempts to obliterate/destroy/delete all resources in the supplied project along with fixed security groups and fixed ssh key pairs.

Don't run this as a CLOUD ADMIN as you could end up in big trouble!!!!!

Note 1 : If only purging a single project please pass this project id in the first and second parameters
Note 2 : This may take two attempts before successfully purging all resources
Note 3 : Certain newer Killer Wifi modules collapse when the network is saturated if there are many parallel calls, used a wired LAN if possible



Author: Graham Land
Date: 09/02/17
Twitter: @allthingsclowd
Github: https://github.com/allthingscloud
Blog: https://allthingscloud.eu


"""
from k5contractsettingsV10 import *
from k5APIwrappersV19 import *
# Gevent magic!
import gevent
import gevent.monkey




def purge_project(projectid, projectidB):
    k5token = get_scoped_token(adminUser, adminPassword, contract, projectid, region).headers['X-Subject-Token']
    print k5token

    PBK5token = get_rescoped_token(k5token, projectidB, region).headers['X-Subject-Token']
    print PBK5token

    gevent.monkey.patch_all()
    print "Deleting Snapshots"
    jobs = [gevent.spawn(delete_snapshot, k5token, snapshot.get('id'), projectid, region) for snapshot in list_snapshots(k5token, projectid, region).json()['snapshots']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting Servers"
    jobs = [gevent.spawn(delete_server, k5token, server.get('id'), projectid, region) for server in list_servers(k5token, projectid, region).json()['servers']]
    result = gevent.joinall(jobs, timeout=3600)

    print "Deleting Volumes"
    jobs = [gevent.spawn(delete_volume, k5token, volume.get('id'), projectid, region) for volume in list_volumes(k5token, projectid, region).json()['volumes']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting Floating IPs"
    jobs = [gevent.spawn(delete_global_ip, k5token, global_ip.get('id'), region) for global_ip in list_global_ips(k5token, region).json()['floatingips']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting VPN Connections"
    jobs = [gevent.spawn(delete_ipsec_site_connection, k5token, vpncon.get('id'), region) for vpncon in list_ipsec_site_connections(k5token, region).json()['ipsec_site_connections']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting VPN Services"
    jobs = [gevent.spawn(delete_vpn_service, k5token, vpnservice.get('id'), region) for vpnservice in list_vpn_services(k5token, region).json()['vpnservices']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting VPN IPSec Policies"
    jobs = [gevent.spawn(delete_ipsec_policy, k5token, secpol.get('id'), region) for secpol in list_ipsec_policies(k5token, region).json()['ipsecpolicies']]
    result = gevent.joinall(jobs, timeout=1200)

    for router in list_routers(k5token, region).json()['routers']:
        if len(router['routes']) > 0:
            print update_router_routes(k5token, router.get('id'), None, region)

        print "Deleting Router Interfaces"
        jobs = [gevent.spawn(remove_interface_from_router, k5token, router.get('id'), interface.get('id'), region) for interface in show_router_interfaces(k5token, router.get('id'), region).json()['ports']]
        result = gevent.joinall(jobs, timeout=1200)

        print "Deleting InterProject Ports"
        jobs = [gevent.spawn(inter_project_connection_remove, k5token, port.get('device_id'), port.get('id'), region) for port in list_ports(PBK5token, region).json()['ports']]
        result = gevent.joinall(jobs, timeout=1200)

        print "Deleting InterProject Ports - take2 "
        jobs = [gevent.spawn(inter_project_connection_remove, PBK5token, port.get('device_id'), port.get('id'), region) for port in list_ports(PBK5token, region).json()['ports']]
        result = gevent.joinall(jobs, timeout=1200)

    print "Deleting Routers"
    jobs = [gevent.spawn(delete_router, k5token, router.get('id'), region) for router in list_routers(k5token, region).json()['routers']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting Ports"
    jobs = [gevent.spawn(delete_port, k5token, port.get('id'), region) for port in list_ports(k5token, region).json()['ports']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Only purging very specific security groups - modify this to Purge ALL SGs"
    for sg in list_security_groups(k5token, region).json()['security_groups']:
        #if "created by API" in sg.get('description'):
        if "Demo Security Group Allows RDP, SSH and ICMP" in sg.get('description'):
            result = delete_security_group(k5token, sg.get('id'), region)
            if result.status_code == 204:
                print "Security group removed - ", sg.get('id')
            else:
                print "Security group delete error: ", result.json()

    print "Only purging very specific key pairs - modify this to Purge ALL key pairs"
    for kp in list_keypairs(k5token, projectid, region).json()['keypairs']:

        if "kp-loadtest" in kp['keypair'].get('name'):
            result = delete_keypair(k5token, kp['keypair'].get('name'), projectid, region)
            print result
            if result.status_code == 202:
                print "SSH KP removed - ", kp['keypair'].get('name')
            else:
                print "SSH KP delete error: ", result.json()

    print "Deleting Subnets"
    jobs = [gevent.spawn(delete_subnet, k5token, subnet.get('id'), region) for subnet in list_subnets(k5token, region).json()['subnets']]
    result = gevent.joinall(jobs, timeout=1200)

    print "Deleting Networks"
    jobs = [gevent.spawn(delete_network, k5token, network.get('id'), region) for network in list_networks(k5token, region).json()['networks']]
    result = gevent.joinall(jobs, timeout=1200)


def main():

    purge_project(demoProjectAid, demoProjectBid)


if __name__ == "__main__":
    main()
