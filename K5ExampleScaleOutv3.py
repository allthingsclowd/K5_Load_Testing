#!/usr/bin/python
"""The following script demonstrates how to deploy  large volumes of virtual machines balanced evenly across  a  region.


Author: Graham Land
Date: 09/02/17
Twitter: @allthingsclowd
Github: https://github.com/allthingscloud
Blog: https://allthingscloud.eu


"""

import requests
import sys
import json
import pprint
import datetime
import time
import random
import string
import copy
from multiprocessing import Process, Queue


def randomword(length):
    """Generate a random string
    Args:
        length (int): length of random string required

    Returns:
        TYPE: random string of length supplied
    """
    return ''.join(random.choice(string.lowercase) for i in range(length))


def verify_servers_active(queue, k5token, testResults, errorOffset):
    """
    Monitor the progress of the server builds from the control plane
    Log the results when changes are detected
    Runs in it's own queue

    Args:
        k5token (object): valid project scoped k5 token
        testResults (list): list to hold the current test results
        errorOffset (int): existing errors to be ignored in project

    Returns:
        TYPE: a list containing the test results
    """
    # initialise vars
    server = {"activecount": None, "timestamp": None, "errorcount": None, "average": None}
    currentts = str(datetime.datetime.utcnow())
    serverBuildTotal = testResults['servercount']
    current_server_total = len(list_servers(k5token).json()['servers'])
    print list_servers_with_filter(k5token,"status=ACTIVE").json()
    current_active_servers = len(list_servers_with_filter(k5token,"status=ACTIVE").json()['servers'])
    print list_servers_with_filter(k5token,"status=ERROR").json()
    current_errored_servers = len(list_servers_with_filter(k5token,"status=ERROR").json()['servers']) - errorOffset
    duration = (datetime.datetime.strptime(currentts, "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(testResults['testplanbuildstart'], "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
    timeout = testResults['timeout']

    previousas = 0
    previouses = 0
    try:
        while (serverBuildTotal > (current_active_servers + current_errored_servers)) :

            if current_active_servers > 0:
                print "Total requested : ", serverBuildTotal,  "\tActive : ", current_active_servers, "\tError : ", current_errored_servers, "\tAverage : ", duration/current_active_servers
                server['average'] = duration/current_active_servers
                server['activecount'] = current_active_servers
                server['errorcount'] = current_errored_servers
                server['timestamp'] = currentts

            if (previouses != current_errored_servers) or (previousas != current_active_servers):
                testResults['servers'].append(copy.deepcopy(server))


            previousas = current_active_servers
            previouses = current_errored_servers
            current_active_servers = len(list_servers_with_filter(k5token,"status=ACTIVE").json()['servers'])
            current_errored_servers = len(list_servers_with_filter(k5token,"status=ERROR").json()['servers']) - errorOffset
            currentts = str(datetime.datetime.utcnow())
            duration = (datetime.datetime.strptime(currentts, "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(testResults['testplanbuildstart'], "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
            if duration > timeout:
                break

            print "\n\n...waiting for all servers to become ACTIVE or timeout....\n\n"
            # check results every second
            queue9 = Queue()
            sleepp = Process(target=QueuedSleep, args=(queue9, (1)))
            sleepp.start()
            sleepp.join()
    except KeyboardInterrupt:
        pass

    print serverBuildTotal,  current_active_servers, current_errored_servers
    server['activecount'] = current_active_servers
    server['errorcount'] = current_errored_servers
    server['timestamp'] = currentts
    server['average'] = duration/current_active_servers
    testResults['servers'].append(copy.deepcopy(server))

    queue.put(testResults)


def create_demo_security_group(k5token, name):
    """Create a security group

    Args:
        k5token (TYPE): valid K5 token object
        name (TYPE): security group name

    Returns:
        TYPE: a tuple containing  security group name and id
    """
    # Create a new security group
    security_group = create_security_group(k5token, "demosecuritygroup", "Demo Security Group Allows RDP, SSH and ICMP")

    print security_group

    print security_group.json()

    security_group_id = security_group.json()['security_group'].get('id')

    print security_group_id

    security_group_name = security_group.json()['security_group'].get('name')

    # Create security group rules
    # allow rdp
    rdp_rule = create_security_group_rule(k5token, security_group_id, "ingress", "3389", "3389", "tcp")

    print rdp_rule

    print rdp_rule.json()

    # allow ssh # allow rdp
    ssh_rule = create_security_group_rule(k5token, security_group_id, "ingress", "22", "22", "tcp")

    print ssh_rule

    print ssh_rule.json()

    # allow icmp
    icmp_rule = create_security_group_rule(k5token, security_group_id, "ingress", "0", "0", "icmp")

    print icmp_rule

    print icmp_rule.json()

    return (security_group_id, security_group_name)


def create_demo_keypair(k5token, name, availability_zone):
    """Create a SSH Key Pair

    Args:
        k5token (TYPE): Description
        name (TYPE): Description
        availability_zone (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Create ssh key pair that can be injected into the servers in az1
    server_key = create_keypair(k5token, name, availability_zone)

    print server_key

    print server_key.json()

    server_key_id = server_key.json()['keypair'].get('id')

    print server_key_id

    server_key_private = server_key.json()['keypair'].get('private_key')

    print server_key_private

    server_key_public = server_key.json()['keypair'].get('public_key')

    print server_key_public

    server_key_name = server_key.json()['keypair'].get('name')

    return (server_key_id, server_key_name, server_key_private, server_key_public)


def create_test_network(k5token, number_of_networks, router_id, availability_zone, cidr_prefix, partial_network):
        """Create the test network infrastructure

        Args:
            k5token (TYPE): valid K5 token object
            number_of_networks (TYPE): number of networks to be created
            router_id (TYPE): the id of the router to be joined to the network
            availability_zone (TYPE): az
            cidr_prefix (TYPE): CIDR prefix
            partial_network (TYPE): boolean - iset True f this is a partial network (i.e. not fully loaded with VMs like the other networks)

        Returns:
            TYPE: Returns a list of all the networks created
        """
        networks = []
        while number_of_networks > 0:
            print "Creating network ", number_of_networks
            networkname = unicode(availability_zone) + unicode("-net-") + unicode(number_of_networks)
            network = create_network(k5token, networkname, availability_zone)
            network_id = network.json()['network'].get('id')
            subnetworkname = unicode(availability_zone) + unicode("-subnet-") + unicode(number_of_networks)
            # assumption that there'll never be more than 100 fully loaded networks
            if partial_network:
                cidr = unicode(cidr_prefix) + unicode("101") + unicode(".0/24")
            else:
                cidr = unicode(cidr_prefix) + unicode(number_of_networks) + unicode(".0/24")
            print "Creating subnet", cidr
            subnet = create_subnet(k5token, subnetworkname, network_id, cidr, availability_zone)
            subnet_id = subnet.json()['subnet'].get('id')
            router_interface = add_interface_to_router(k5token, router_id, subnet_id)
            networks.append(network_id)
            number_of_networks = number_of_networks - 1
        return networks


def get_endpoint(k5token, endpoint_type):
    """Extract the appropriate endpoint URL from the K5 token object body
    Args:
        k5token (TYPE): K5 token object
        endpoint_type (TYPE): trype of endpoint required - e.g. compute, network...

    Returns:
        TYPE: string - contain the endpoint url
    """
    # list the endpoints
    for ep in k5token.json()['token']['catalog']:
        if len(ep['endpoints'])>0:
            # if this is the endpoint that  I'm looking for return the url
            if endpoint_type == ep['endpoints'][0].get('name'):
                #pprint.pprint(ep)
                return ep['endpoints'][0].get('url')


def get_scoped_token(adminUser, adminPassword, contract, projectid, region):
    """Ket a K5 project scoped token

    Args:
        adminUser (TYPE): k5 username
        adminPassword (TYPE): K5 password
        contract (TYPE): K5 contract name
        projectid (TYPE): K5 project id to scope to
        region (TYPE): K5 region

    Returns:
        TYPE: K5 token object
    """
    identityURL = 'https://identity.' + region + \
        '.cloud.global.fujitsu.com/v3/auth/tokens'

    try:
        response = requests.post(identityURL,
                                 headers={'Content-Type': 'application/json',
                                          'Accept': 'application/json'},
                                 json={"auth":
                                         {"identity":
                                          {"methods": ["password"], "password":
                                           {"user":
                                           {"domain":
                                               {"name": contract},
                                            "name": adminUser,
                                            "password": adminPassword
                                            }}},
                                          "scope":
                                          {"project":
                                           {"id": projectid
                                            }}}})

        return response
    except:
        return 'Regional Project Token Scoping Failure'


def list_servers_with_filter(k5token, filter):
    """Summary - list  K5 projects

    Args:
        k5token (TYPE): valid regional domain scoped token
        filter (TYPE): ACTIVE, ERROR  etc...

    Returns:
        TYPE: http response object
    """
    computeURL = unicode(get_endpoint(k5token, "compute")) + unicode('/servers?') + unicode(filter)
    print computeURL
    token = k5token.headers['X-Subject-Token']
    try:

        response = requests.get(computeURL,
                                headers={
                                     'X-Auth-Token': token,
                                     'Content-Type': 'application/json',
                                     'Accept': 'application/json'})
        return response
    except:
        return 'Failed to list servers'


def list_servers(k5token):
    """Summary - list  K5 servers in scoped project token

    Args:
        k5token (TYPE): valid regional domain scoped token

    Returns:
        TYPE: http response object

    """
    computeURL = unicode(get_endpoint(k5token, "compute")) + unicode('/servers/detail')
    print computeURL
    token = k5token.headers['X-Subject-Token']
    try:

        response = requests.get(computeURL,
                                headers={
                                     'X-Auth-Token': token,
                                     'Content-Type': 'application/json',
                                     'Accept': 'application/json'})
        return response
    except:
        return 'Failed to list servers'


def create_network(k5token, name, availability_zone):
    """Summary

    Args:
        k5token (TYPE): K5 token object
        name (TYPE): network name
        availability_zone (TYPE): az

    Returns:
        TYPE: http response object
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/networks')
    print networkURL
    token = k5token.headers['X-Subject-Token']
    try:
        response = requests.post(networkURL,
                                 headers={'X-Auth-Token': token,
                                         'Content-Type': 'application/json'},
                                 json={
                                            "network":
                                            {
                                              "name": name,
                                              "admin_state_up": True,
                                              "availability_zone": availability_zone
                                             }
                                        })
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def create_subnet(k5token, name, netid, cidr, availability_zone):
    """Create a subnet

    Args:
        k5token (TYPE): token object
        name (TYPE): new subnet name
        netid (TYPE): K5 network id
        cidr (TYPE): CIDR of new subnet
        availability_zone (TYPE): az

    Returns:
        TYPE: http response object
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/subnets')
    print networkURL
    token = k5token.headers['X-Subject-Token']
    try:

        response = requests.post(networkURL,
                                headers={'X-Auth-Token': token,
                                         'Content-Type': 'application/json'},
                                json={
                                             "subnet": {
                                                 "name": name,
                                                 "network_id": netid,
                                                 "ip_version": 4,
                                                 "cidr": cidr,
                                                 "availability_zone": availability_zone
                                             }
                                            })
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def create_router(k5token, name, availability_zone):
    """Create a K5 router

    Args:
        k5token (TYPE): Description
        name (TYPE): Description
        availability_zone (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/routers')
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.post(networkURL,
                                headers={'X-Auth-Token': token,
                                         'Content-Type': 'application/json'},
                                json={
                                          "router": {
                                               "name": name,
                                               "admin_state_up": True,
                                               "availability_zone": availability_zone
                                          }})
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def update_router_gateway(k5token, router_id, network_id):
    """Summary

    Args:
        k5token (TYPE): Description
        router_id (TYPE): Description
        network_id (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/routers/') + router_id
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.put(networkURL,
                                headers={'X-Auth-Token': token,
                                         'Content-Type': 'application/json'},
                                json={
                                         "router": {
                                                     "external_gateway_info": {
                                                                                    "network_id": network_id
                                                     }
                                         }})
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def add_interface_to_router(k5token, router_id, subnet_id):
    """Summary

    Args:
        k5token (TYPE): Description
        router_id (TYPE): Description
        subnet_id (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/routers/') + router_id + '/add_router_interface'
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.put(networkURL,
                                headers={'X-Auth-Token': token,
                                         'Content-Type': 'application/json'},
                                json={
                                    "subnet_id": subnet_id})
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def create_security_group(k5token, name, description):
    """Summary

    Args:
        k5token (TYPE): Description
        name (TYPE): Description
        description (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/security-groups')
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.post(networkURL,
                                headers={'X-Auth-Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'},
                                json={
                                        "security_group": {
                                            "name": name,
                                            "description": description
                                            }
                                        })
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def create_security_group_rule(k5token, security_group_id, direction, portmin, portmax, protocol):
    """Summary

    Args:
        k5token (TYPE): Description
        security_group_id (TYPE): Description
        direction (TYPE): Description
        portmin (TYPE): Description
        portmax (TYPE): Description
        protocol (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/security-group-rules')
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.post(networkURL,
                                headers={'X-Auth-Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'},
                                json={
                                        "security_group_rule": {
                                            "direction": direction,
                                            "port_range_min": portmin,
                                            "ethertype": "IPv4",
                                            "port_range_max": portmax,
                                            "protocol": protocol,
                                            "security_group_id": security_group_id
                                            }
                                        })
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())

def create_port(k5token, name, network_id, security_group_id, availability_zone):
    """Summary

    Args:
        k5token (TYPE): Description
        name (TYPE): Description
        network_id (TYPE): Description
        security_group_id (TYPE): Description
        availability_zone (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/ports')
    print networkURL
    token = k5token.headers['X-Subject-Token']
    try:
        response = requests.post(networkURL,
                                 headers={
                                     'X-Auth-Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'},
                                 json={"port":
                                       {"network_id": network_id,
                                        "name": name,
                                        "admin_state_up": True,
                                        "availability_zone": availability_zone,
                                        "security_groups":
                                        [security_group_id]}})
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def create_keypair(k5token, keypair_name, availability_zone):
    """Summary

    Args:
        k5token (TYPE): Description
        keypair_name (TYPE): Description
        availability_zone (TYPE): Description

    Returns:
        TYPE: Description
    """
    computeURL = unicode(get_endpoint(k5token, "compute")) + unicode('/os-keypairs')
    print computeURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.post(computeURL,
                                headers={
                                     'X-Auth-Token': token,
                                     'Content-Type': 'application/json',
                                     'Accept': 'application/json'},
                                json={
                                    "keypair": {
                                        "name": keypair_name,
                                        "availability_zone": availability_zone
                                        }})
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())

def create_server_with_port(k5token, name, imageid, flavorid, sshkey_name, security_group_name, availability_zone, volsize,  port_id):
    """Summary

    Args:
        k5token (TYPE): Description
        name (TYPE): Description
        imageid (TYPE): Description
        flavorid (TYPE): Description
        sshkey_name (TYPE): Description
        security_group_name (TYPE): Description
        availability_zone (TYPE): Description
        volsize (TYPE): Description
        port_id (TYPE): Description

    Returns:
        TYPE: Description
    """
    computeURL = unicode(get_endpoint(k5token, "compute")) + unicode('/servers')
    print computeURL
    token = k5token.headers['X-Subject-Token']
    try:
        response = requests.post(computeURL,
                                headers={'X-Auth-Token':token,'Content-Type': 'application/json','Accept':'application/json'},
                                json={"server": {

                                                 "name": name,
                                                 "security_groups":[{"name": security_group_name }],
                                                 "availability_zone":availability_zone,
                                                 "imageRef": imageid,
                                                 "flavorRef": flavorid,
                                                 "key_name": sshkey_name,
                                                 "block_device_mapping_v2": [{
                                                                               "uuid": imageid,
                                                                               "boot_index": "0",
                                                                               "device_name": "/dev/vda",
                                                                               "source_type": "image",
                                                                               "volume_size": volsize,
                                                                               "destination_type": "volume",
                                                                               "delete_on_termination": True
                                                                            }],
                                                 "networks": [{"port": port_id}],
                                                 "metadata": {"Example Custom Tag": "Finance Department"}
                                                }})

        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())

def create_multiple_servers(k5token, name, imageid, flavorid, sshkey_name, security_group_name, availability_zone, volsize,  network_id, max_count):
    """This function will deploy multiple K5 servers with a single K5 API call

    Args:
        k5token (TYPE): K5 token object
        name (TYPE): server base name
        imageid (TYPE): image id of server to be built
        flavorid (TYPE): K5 flavor id to be used (t-shirt size)
        sshkey_name (TYPE): ssh public key name to be injected into the servers (if linux)
        security_group_name (TYPE): K5 security group name
        availability_zone (TYPE): az
        volsize (TYPE): OS disk size in GB
        network_id (TYPE): Network ID where server is to be attached
        max_count (TYPE): Number of servers to be deployed

    Returns:
        TYPE: http response object
    """
    computeURL = unicode(get_endpoint(k5token, "compute")) + unicode('/servers')
    print computeURL
    token = k5token.headers['X-Subject-Token']
    try:
        response = requests.post(computeURL,
                                headers={'X-Auth-Token':token,'Content-Type': 'application/json','Accept':'application/json'},
                                json={"server": {

                                                 "name": name,
                                                 "security_groups":[{"name": security_group_name }],
                                                 "availability_zone":availability_zone,
                                                 "imageRef": imageid,
                                                 "max_count": max_count,
                                                 "return_reservation_id": True,
                                                 "flavorRef": flavorid,
                                                 "key_name": sshkey_name,
                                                 "block_device_mapping_v2": [{
                                                                               "uuid": imageid,
                                                                               "boot_index": "0",
                                                                               "device_name": "/dev/vda",
                                                                               "source_type": "image",
                                                                               "volume_size": volsize,
                                                                               "destination_type": "volume",
                                                                               "delete_on_termination": True
                                                                            }],
                                                 "networks": [{"uuid": network_id}],
                                                 "metadata": {"Example Custom Tag": "Multiple Server Build"}
                                                }})

        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())

def create_global_ip(k5token, ext_network_id, port_id, availability_zone):
    """Summary

    Args:
        k5token (TYPE): Description
        ext_network_id (TYPE): Description
        port_id (TYPE): Description
        availability_zone (TYPE): Description

    Returns:
        TYPE: Description
    """
    networkURL = unicode(get_endpoint(k5token, "networking")) + unicode('/v2.0/floatingips')
    print networkURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.post(networkURL,
                                headers={
                                     'X-Auth-Token': token,
                                     'Content-Type': 'application/json',
                                     'Accept': 'application/json'},
                                json={
                                             "floatingip": {
                                                     "floating_network_id": ext_network_id,
                                                     "port_id": port_id,
                                                     "availability_zone": availability_zone
                                                     },
                                            })
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())

# create a container
def create_new_storage_container(k5token, container_name):
    """
    Create a publically accessible k5 object storage container

    Args:
        container_name (TYPE): Description

    Returns:
        The URL to the new container
    """
    objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name)
    print objectURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.put(objectURL,
                                 headers={'X-Auth-Token':token,'Content-Type': 'application/json','X-Container-Read': '.r:*'})

        return objectURL
    except:
        return ("\nUnexpected error:", sys.exc_info())

# download item in a container
def download_item_in_storage_container(k5token, container_name, object_name):
    """Download item from K5 object storage

    Args:
        k5token (TYPE): Description
        container_name (TYPE): Description
        object_name (TYPE): Description

    Returns:
        TYPE: Description
    """
    objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name) + '/' + unicode(object_name)
    print objectURL
    token = k5token.headers['X-Subject-Token']

    response = requests.get(objectURL,
                             headers={'X-Auth-Token':token,'Content-Type': 'application/json'})

    return response

# upload a list to a container
def upload_object_to_container(k5token, container_name, storage_object, object_name):
    """Upload an  object to a K5 container

    Args:
        k5token (TYPE): Description
        container_name (TYPE): Description
        storage_object (TYPE): Description
        object_name (TYPE): Description

    Returns:
        TYPE: Description
    """
    data = storage_object

    objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name) + '/' + unicode(object_name)
    print objectURL
    token = k5token.headers['X-Subject-Token']

    response = requests.put(objectURL,
                              data=data,
                              headers={'X-Auth-Token':token,'Content-Type': 'application/octet-stream','X-Container-Read': '.r:*'})

    return response


def QueuedSleep(myqueue, mytime):
    time.sleep(mytime)


def BuildAZ(k5token, loadednetwork, partialnetwork, routerid, az, cidrprefix, image_id, flavor_id, ssh_key, security_group, average_server_build_time, partialServerCount, servers_per_network, queue):

    if loadednetwork > 0:
        fullnetworklist = create_test_network(k5token, loadednetwork, routerid, az, cidrprefix, False)
        for net in fullnetworklist:
            name = unicode("loaded-") + unicode(randomword(5))
            print create_multiple_servers(k5token, name, image_id, flavor_id, ssh_key, security_group, az, 3,  net, servers_per_network)
            # delay added to ensure consistent deployment during busy hours - don't overload message queue
            queue6 = Queue()
            sleepp = Process(target=QueuedSleep, args=(queue6, (int(average_server_build_time*servers_per_network))))
            sleepp.start()
            sleepp.join()
    if partialnetwork > 0:
        partialnetworklist = create_test_network(k5token, partialnetwork, routerid, az, cidrprefix, True)
        for net in partialnetworklist:
            name = unicode("partial-") + unicode(randomword(5))
            print create_multiple_servers(k5token, name, image_id, flavor_id, ssh_key, security_group, az, 3,  net, partialServerCount)
            # delay added to ensure consistent deployment during busy hours - don't overload message queue
            queue7 = Queue()
            sleepp = Process(target=QueuedSleep, args=(queue7, (int(average_server_build_time*partialServerCount))))
            sleepp.start()
            sleepp.join()
    result = unicode(az) + unicode(' Server Deployment Complete')
    queue.put(result)


def main():
    """Summary

    Returns:
        TYPE: Description
    """

    # Initialise environment parameters
    # ENSURE TO ADD YOUR K5 DETAILS HERE
    adminUser = 'username' # k5/openstack user login name
    adminPassword = 'password' # k5/openstack user password
    contract = 'contract name' # k5 contract name or openstack domain name
    defaultProject = 'contract name-prj' # default project id - on k5 it's the project name that starts with contract name and ends with -prj
    demoProjectA = 'target project name' # k5/openstack demo target project name
    demoProjectAid = 'target project id' # k5/openstack demo target project id
    region = 'uk-1' # target region
    az1 = 'uk-1a' # availability zone 1
    az2 = 'uk-1b' # availability zone 2

    # parameters for K5 object storage container to hold current results and historical results
    k5resultcontainer = "K5_Deployment_Results"
    k5currenttest = "k5current.json"
    k5testrecords = "k5testrecords.json"

    # this is the id of the K5 ubuntu image
    image_id = "ffa17298-537d-40b2-a848-0a4d22b49df5"
    # the is the id of a small flavor size (S-2)
    flavor_id = "1102"

    # number of servers deploy to region
    total_servers = 20
    servers_per_network = 50

    # delay used to calculate timeouts and set delays between batch API server calls - tuned
    average_server_build_time = 1.61
    # delay necessary for very small test runs under 4 servers
    minimumBuildTime = 240

    # Get a project scoped token
    k5token = get_scoped_token(adminUser, adminPassword, contract, demoProjectAid, region)

    # list used to remove debris from historical runs that don't purge cleanly
    existingProjectservers = []

    # ignore historical run data/resources in project
    existing_project_servers = list_servers(k5token).json()['servers']
    print "\n\nExisting Project Servers", existing_project_servers
    for preServer in existing_project_servers:
            existingProjectservers.append(preServer.get('id'))

    # error offset to compensate for existing errors within a project
    errorOffset = len(list_servers_with_filter(k5token,"status=ERROR").json()['servers'])
    print "\n\nExisting Error Count ", errorOffset

    # Toggle for each AZ - when set to True the AZ will be included in the test runs
    testAZ1 = True
    testAZ2 = True

    testResults = {"id": None, "timeout": None, "testplantime": None, "averageperserver": None, "testplanbuildstart": None, "testplanbuildfinish": None, "testplanverifystart": None, "testplanverifyfinish": None, "servercount": None, "flavor": None, "image": None, "testplanbuildtime": None, "testplanverifytime": None, "servers": [], "errors": []}

    # calculate the number of servers in each AZ
    if testAZ1:
        az1ServerCount = total_servers/2 + total_servers%2
    else:
        az1ServerCount = 0

    if testAZ2:
        az2ServerCount = total_servers/2
    else:
        az2ServerCount = 0

    # calculate the number of fully loaded networks required  in each az
    az1fullnetwork = az1ServerCount/servers_per_network
    az2fullnetwork = az2ServerCount/servers_per_network

    # calculate the number of partially loaded networks
    if az1ServerCount % servers_per_network:
        az1partialnetwork = 1
        az1partialServerCount = az1ServerCount % servers_per_network
    else:
        az1partialnetwork = 0
        az1partialServerCount = 0

    if az2ServerCount % servers_per_network:
        az2partialnetwork = 1
        az2partialServerCount = az2ServerCount % servers_per_network
    else:
        az2partialnetwork = 0
        az2partialServerCount = 0

    total_servers = az1ServerCount + az2ServerCount

    testResults['id'] = str(datetime.datetime.utcnow())

    # if the testing goes beyond this time then something has gone wrong with the K5 deployment
    timeout = ((total_servers * average_server_build_time) * 1.1) + minimumBuildTime

    # capture data in results file
    testResults['servercount'] = total_servers
    testResults['timeout'] = timeout
    testResults['flavor'] = flavor_id
    testResults['image'] = image_id
    testResults['testplanbuildstart'] = str(datetime.datetime.utcnow())

    print "\nTotal Servers - ", total_servers
    print "The region will have ", (az1partialnetwork + az2partialnetwork + az1fullnetwork + az2fullnetwork), " networks"
    print "AZ 1 have ", az1fullnetwork, servers_per_network, " node networks and ", az1partialnetwork, " network with ", az1partialServerCount, " servers"
    print "AZ 2 have ", az2fullnetwork, servers_per_network," node networks and ", az2partialnetwork, " network with ", az2partialServerCount, " servers\n"

    # create router in az1 to link all networks
    if testAZ1:
        az1Router = create_router(k5token, "az1Router", "uk-1a")
        az1Router_id = az1Router.json()['router'].get('id')
        az1_ssh_key_pair = create_demo_keypair(k5token, "az1-kp-loadtest", az1)

    # create router in az2 to link all networks
    if testAZ2:
        az2Router = create_router(k5token, "az2Router", "uk-1b")
        az2Router_id = az2Router.json()['router'].get('id')
        az2_ssh_key_pair = create_demo_keypair(k5token, "az2-kp-loadtest", az2)

    security_group = create_demo_security_group(k5token, "loadtest")

    az1fullnetworklist = []
    az2fullnetworklist = []
    az1partialnetworklist = []
    az2partialnetworklist = []

    queue = Queue()
    p = Process(target=verify_servers_active, args=(queue, k5token, testResults, errorOffset))
    p.start()
    startMonitoring = str(datetime.datetime.utcnow())

    queue2 = Queue()
    p2 = Process(target=BuildAZ, args=(k5token, az1fullnetwork, az1partialnetwork, az1Router_id, az1, "192.168.", image_id, flavor_id, az1_ssh_key_pair[1], security_group[1], average_server_build_time, az1partialServerCount, servers_per_network, queue2))
    p2.start()

    queue3 = Queue()
    p3 = Process(target=BuildAZ, args=(k5token, az2fullnetwork, az2partialnetwork, az2Router_id, az2, "10.10.", image_id, flavor_id, az2_ssh_key_pair[1], security_group[1], average_server_build_time, az2partialServerCount, servers_per_network, queue3))
    p3.start()

    # wait here until all the servers have been deployed - each AZ is deployed using a separate thread
    p2.join()
    p3.join()

    print queue2.get()
    print queue3.get()


    print "\n\n\n\nFinished all server BUILDS \n\n\n"
    print "\n\n...waiting for all servers to become ACTIVE....\n\n"

    # wait for all servers to be verified active before proceeding - running inseparate thread
    p.join()

    testResults = queue.get()
    print testResults
    testResults['testplanverifystart'] = startMonitoring
    testResults['testplanbuildfinish'] = str(datetime.datetime.utcnow())
    testResults['testplanbuildtime'] = (datetime.datetime.strptime(testResults['testplanbuildfinish'], "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(testResults['testplanbuildstart'], "%Y-%m-%d %H:%M:%S.%f")).total_seconds()

    testResults['testplanverifyfinish'] = str(datetime.datetime.utcnow())
    testResults['testplanverifytime'] = (datetime.datetime.strptime(testResults['testplanverifyfinish'], "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(testResults['testplanverifystart'], "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
    testResults['testplantime'] = (datetime.datetime.strptime(testResults['testplanverifyfinish'], "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(testResults['testplanbuildstart'], "%Y-%m-%d %H:%M:%S.%f")).total_seconds()

    # calculate average build time for active servers
    current_active_servers = len(list_servers_with_filter(k5token,"status=ACTIVE").json()['servers'])
    testResults['averageperserver'] = testResults['testplantime']/current_active_servers

    # capture all the new errors in the log file
    current_servers = list_servers(k5token).json()['servers']
    print "\n\nLATEST SERVERS LIST\n\n", current_servers

    print "\n\nExisting Server List\n\n", existingProjectservers
    for new_server in current_servers:
        if new_server.get('status') != 'ACTIVE':
            if new_server.get('id') not in existingProjectservers:
                print "\n\nAddind new errored server\n", new_server
                testResults['errors'].append(copy.deepcopy(new_server))

    # download the previous set of results from k5 object storage so that the current results can be appended and re-uploaded
    try:
        #result = download_item_in_storage_container(k5tokenA, demoProjectAid, k5resultcontainer, k5testrecords, region).json()
        storedResults = download_item_in_storage_container(k5token, k5resultcontainer, k5testrecords).json()
    except:
        # if this is the first run the create the K5 object storage container
        print "Creating new object storage container for results"
        result = create_new_storage_container(k5token, k5resultcontainer)
        storedResults = []

    # append current results to historical test results
    storedResults.append(testResults)

    # convert them back to JSON for upload to storage container
    currentResults = json.dumps(testResults)
    storedResults = json.dumps(storedResults)

    # upload results
    result = upload_object_to_container(k5token, k5resultcontainer, storedResults, k5testrecords)
    print "^^^^^^ Navigate to this URL to locate current and historical test run results ^^^^^^^\n\n"
    result = upload_object_to_container(k5token, k5resultcontainer, currentResults, k5currenttest)
    print "^^^^^^ Navigate to this URL to locate current test run results ^^^^^^^"


if __name__ == "__main__":
    main()
