import testtools
from oslo_log import log
import netaddr
import base64
from six import moves

import tempest.api.compute.servers.test_attach_interfaces as test_attach_interfaces
import tempest.api.compute.servers.test_availability_zone as test_availability_zone
import tempest.api.compute.servers.test_create_server as test_create_server
import tempest.api.compute.servers.test_delete_server as test_delete_server
import tempest.api.compute.servers.test_instance_actions as test_instance_actions
import tempest.api.compute.servers.test_instance_actions_negative as test_instance_actions_negative
import tempest.api.compute.servers.test_list_server_filters as test_list_server_filters
import tempest.api.compute.servers.test_list_servers_negative as test_list_servers_negative
import tempest.api.compute.servers.test_multiple_create as test_multiple_create
import tempest.api.compute.servers.test_multiple_create_negative as test_multiple_create_negative
import tempest.api.compute.servers.test_server_actions as test_server_actions
import tempest.api.compute.servers.test_server_addresses as test_server_addresses
import tempest.api.compute.servers.test_server_addresses_negative as test_server_addresses_negative
import tempest.api.compute.servers.test_server_metadata as test_server_metadata
import tempest.api.compute.servers.test_server_metadata_negative as test_server_metadata_negative
import tempest.api.compute.servers.test_server_password as test_server_password
import tempest.api.compute.servers.test_server_personality as test_server_personality
import tempest.api.compute.servers.test_servers as test_servers
import tempest.api.compute.servers.test_servers_negative as test_servers_negative
import tempest.api.compute.servers.test_virtual_interfaces_negative as test_virtual_interfaces_negative
from tempest.common.utils import data_utils
from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest.common import fixed_network
from tempest.lib import exceptions as lib_exc
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridAttachInterfacesVCloudTestJSON(test_attach_interfaces.AttachInterfacesTestJSON):
    """Test attach interfaces"""

    def _create_server_get_interfaces(self):
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        ifs = (self.client.list_interfaces(server['id'])
               ['interfaceAttachments'])
        body = self.wait_for_interface_status(
            server['id'], ifs[0]['port_id'], 'ACTIVE')
        ifs[0]['port_state'] = body['port_state']
        return server, ifs


class HybridAttachInterfacesAWSTestJSON(test_attach_interfaces.AttachInterfacesTestJSON):
    """Test attach interfaces"""

    def _create_server_get_interfaces(self):
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        ifs = (self.client.list_interfaces(server['id'])
               ['interfaceAttachments'])
        body = self.wait_for_interface_status(
            server['id'], ifs[0]['port_id'], 'ACTIVE')
        ifs[0]['port_state'] = body['port_state']
        return server, ifs

class HybridAZV2TestJSON(test_availability_zone.AZV2TestJSON):
    """Test AZ"""

class HybridCreateVCloudServersTestJSON(test_create_server.ServersTestJSON):
    """Test create servers"""

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(test_create_server.ServersTestJSON, cls).resource_setup()
        cls.meta = {'hello': 'world'}
        cls.accessIPv4 = '1.1.1.1'
        cls.accessIPv6 = '0000:0000:0000:0000:0000:babe:220.12.22.2'
        cls.name = data_utils.rand_name('server')
        cls.password = data_utils.rand_password()
        disk_config = cls.disk_config
        cls.server_initial = cls.create_test_server(
            validatable=True,
            wait_until='ACTIVE',
            name=cls.name,
            metadata=cls.meta,
            accessIPv4=cls.accessIPv4,
            accessIPv6=cls.accessIPv6,
            disk_config=disk_config,
            adminPass=cls.password,
            availability_zone=CONF.compute.vcloud_availability_zone)
        cls.server = (cls.client.show_server(cls.server_initial['id'])
                      ['server'])

    @test.attr(type='smoke')
    @test.idempotent_id('5de47127-9977-400a-936f-abcfbec1218f')
    def test_verify_server_details(self):
        # Verify the specified server attributes are set correctly
        self.assertEqual(self.accessIPv4, self.server['accessIPv4'])
        # NOTE(maurosr): See http://tools.ietf.org/html/rfc5952 (section 4)
        # Here we compare directly with the canonicalized format.
        self.assertEqual(self.server['accessIPv6'],
                         str(netaddr.IPAddress(self.accessIPv6)))
        self.assertEqual(self.name, self.server['name'])
        self.assertEqual(self.image_ref, self.server['image']['id'])
        self.assertEqual(self.flavor_ref, self.server['flavor']['id'])
        self.assertTrue(cmp(self.server['metadata'], self.meta) > 0)

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('ed20d3fb-9d1f-4329-b160-543fbd5d9811')
    def test_create_server_with_scheduler_hint_group(self):
        # Create a server with the scheduler hint "group".
        name = data_utils.rand_name('server_group')
        policies = ['affinity']
        body = self.server_groups_client.create_server_group(
            name=name, policies=policies)['server_group']
        group_id = body['id']
        self.addCleanup(self.server_groups_client.delete_server_group,
                        group_id)

        hints = {'group': group_id}
        server = self.create_test_server(scheduler_hints=hints,
                                         wait_until='ACTIVE')

        # Check a server is in the group
        server_group = (self.server_groups_client.show_server_group(group_id)
                        ['server_group'])
        self.assertIn(server['id'], server_group['members'])

    @test.idempotent_id('0578d144-ed74-43f8-8e57-ab10dbf9b3c2')
    @testtools.skipUnless(CONF.service_available.neutron,
                          'Neutron service must be available.')
    def test_verify_multiple_nics_order(self):
        # Verify that the networks order given at the server creation is
        # preserved within the server.
        net1 = self._create_net_subnet_ret_net_from_cidr('19.80.0.0/24')
        net2 = self._create_net_subnet_ret_net_from_cidr('19.86.0.0/24')

        networks = [{'uuid': net1['network']['id']},
                    {'uuid': net2['network']['id']}]

        server_multi_nics = self.create_test_server(
            networks=networks, wait_until='ACTIVE',availability_zone=CONF.compute.vcloud_availability_zone)

        # Cleanup server; this is needed in the test case because with the LIFO
        # nature of the cleanups, if we don't delete the server first, the port
        # will still be part of the subnet and we'll get a 409 from Neutron
        # when trying to delete the subnet. The tear down in the base class
        # will try to delete the server and get a 404 but it's ignored so
        # we're OK.
        def cleanup_server():
            self.client.delete_server(server_multi_nics['id'])
            waiters.wait_for_server_termination(self.client,
                                                server_multi_nics['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(server_multi_nics['id'])
                     ['addresses'])

        # We can't predict the ip addresses assigned to the server on networks.
        # Sometimes the assigned addresses are ['19.80.0.2', '19.86.0.2'], at
        # other times ['19.80.0.3', '19.86.0.3']. So we check if the first
        # address is in first network, similarly second address is in second
        # network.
        addr = [addresses[net1['network']['name']][0]['addr'],
                addresses[net2['network']['name']][0]['addr']]
        networks = [netaddr.IPNetwork('19.80.0.0/24'),
                    netaddr.IPNetwork('19.86.0.0/24')]
        for address, network in zip(addr, networks):
            self.assertIn(address, network)

    @test.idempotent_id('1678d144-ed74-43f8-8e57-ab10dbf9b3c2')
    @testtools.skipUnless(CONF.service_available.neutron,
                          'Neutron service must be available.')
    # The below skipUnless should be removed once Kilo-eol happens.
    @testtools.skipUnless(CONF.compute_feature_enabled.
                          allow_duplicate_networks,
                          'Duplicate networks must be allowed')
    def test_verify_duplicate_network_nics(self):
        # Verify that server creation does not fail when more than one nic
        # is created on the same network.
        net1 = self._create_net_subnet_ret_net_from_cidr('19.80.0.0/24')
        net2 = self._create_net_subnet_ret_net_from_cidr('19.86.0.0/24')

        networks = [{'uuid': net1['network']['id']},
                    {'uuid': net2['network']['id']},
                    {'uuid': net1['network']['id']}]

        server_multi_nics = self.create_test_server(
            networks=networks, wait_until='ACTIVE',availability_zone=CONF.compute.vcloud_availability_zone)

        def cleanup_server():
            self.client.delete_server(server_multi_nics['id'])
            waiters.wait_for_server_termination(self.client,
                                                server_multi_nics['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(server_multi_nics['id'])
                     ['addresses'])

        addr = [addresses[net1['network']['name']][0]['addr'],
                addresses[net2['network']['name']][0]['addr'],
                addresses[net1['network']['name']][1]['addr']]
        networks = [netaddr.IPNetwork('19.80.0.0/24'),
                    netaddr.IPNetwork('19.86.0.0/24'),
                    netaddr.IPNetwork('19.80.0.0/24')]
        for address, network in zip(addr, networks):
            self.assertIn(address, network)

    @test.idempotent_id('c25a6b9c-764d-4254-b782-e56074987daf')
    def test_create_server_with_user_data(self):
        name = data_utils.rand_name('server_with_user_data')
        rand_data = data_utils.random_bytes()
        password = self.password
        created_server = self.create_test_server(wait_until='ACTIVE',
                                         name=name,
                                         adminPass=password,
                                         user_data=base64.b64encode(rand_data),
                                         #validatable=bool(CONF.validation.run_validation),
                                         availability_zone=CONF.compute.vcloud_availability_zone)

        server = self.client.show_server(created_server['id'])['server']

        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            self.assertEqual(rand_data,
                             linux_client.exec_command(
                                 'curl http://169.254.169.254/user-data'))

    @test.idempotent_id('57318d1e-67ec-4889-b42d-e7874366ce4c')
    def test_create_server_with_network_port(self):
        name = data_utils.rand_name('server_with_network_port')
        net = self._create_net_subnet_ret_net_from_cidr('19.90.5.0/24')
        port = self.os.ports_client.create_port(network_id=net['network']['id'])
        self.addCleanup(self.os.ports_client.delete_port, port['port']['id'])
        created_server = self.create_test_server(wait_until='ACTIVE', name=name,
                                         networks = [{"port": port['port']['id']}],
                                         availability_zone=CONF.compute.vcloud_availability_zone)

        server = self.client.show_server(created_server['id'])['server']

    @test.idempotent_id('0828112b-d873-435f-8798-6eafdbf363f4')
    def test_create_server_with_network_v4_fixed_ip(self):
        name = data_utils.rand_name('server_with_network_fixed')
        ip = "19.90.8.50"
        net = self._create_net_subnet_ret_net_from_cidr('19.90.8.0/24')
        created_server = self.create_test_server(wait_until='ACTIVE', name=name,
                                         networks=[{"uuid": net['network']['id'], "fixed_ip":ip}],
                                         availability_zone=CONF.compute.vcloud_availability_zone)

        def cleanup_server():
            self.client.delete_server(created_server['id'])
            waiters.wait_for_server_termination(self.client,
                                                created_server['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(created_server['id'])
                     ['addresses'])
        addr = addresses[net['network']['name']][0]['addr']
        self.assertEqual(addr, ip)

class HybridCreateAwsServersTestJSON(test_create_server.ServersTestJSON):
    """Test create servers"""

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(test_create_server.ServersTestJSON, cls).resource_setup()
        cls.meta = {'hello': 'world'}
        cls.accessIPv4 = '1.1.1.1'
        cls.accessIPv6 = '0000:0000:0000:0000:0000:babe:220.12.22.2'
        cls.name = data_utils.rand_name('server')
        cls.password = data_utils.rand_password()
        disk_config = cls.disk_config
        cls.server_initial = cls.create_test_server(
            validatable=True,
            wait_until='ACTIVE',
            name=cls.name,
            metadata=cls.meta,
            accessIPv4=cls.accessIPv4,
            accessIPv6=cls.accessIPv6,
            disk_config=disk_config,
            adminPass=cls.password,
            availability_zone=CONF.compute.aws_availability_zone)
        cls.server = (cls.client.show_server(cls.server_initial['id'])
                      ['server'])

    @test.attr(type='smoke')
    @test.idempotent_id('5de47127-9977-400a-936f-abcfbec1218f')
    def test_verify_server_details(self):
        # Verify the specified server attributes are set correctly
        self.assertEqual(self.accessIPv4, self.server['accessIPv4'])
        # NOTE(maurosr): See http://tools.ietf.org/html/rfc5952 (section 4)
        # Here we compare directly with the canonicalized format.
        self.assertEqual(self.server['accessIPv6'],
                         str(netaddr.IPAddress(self.accessIPv6)))
        self.assertEqual(self.name, self.server['name'])
        self.assertEqual(self.image_ref, self.server['image']['id'])
        self.assertEqual(self.flavor_ref, self.server['flavor']['id'])
        self.assertTrue(cmp(self.server['metadata'], self.meta) > 0)

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('ed20d3fb-9d1f-4329-b160-543fbd5d9811')
    def test_create_server_with_scheduler_hint_group(self):
        # Create a server with the scheduler hint "group".
        name = data_utils.rand_name('server_group')
        policies = ['affinity']
        body = self.server_groups_client.create_server_group(
            name=name, policies=policies)['server_group']
        group_id = body['id']
        self.addCleanup(self.server_groups_client.delete_server_group,
                        group_id)

        hints = {'group': group_id}
        server = self.create_test_server(scheduler_hints=hints,
                                         wait_until='ACTIVE')

        # Check a server is in the group
        server_group = (self.server_groups_client.show_server_group(group_id)
                        ['server_group'])
        self.assertIn(server['id'], server_group['members'])

    @test.idempotent_id('0578d144-ed74-43f8-8e57-ab10dbf9b3c2')
    @testtools.skipUnless(CONF.service_available.neutron,
                          'Neutron service must be available.')
    def test_verify_multiple_nics_order(self):
        # Verify that the networks order given at the server creation is
        # preserved within the server.
        net1 = self._create_net_subnet_ret_net_from_cidr('19.80.0.0/24')
        net2 = self._create_net_subnet_ret_net_from_cidr('19.86.0.0/24')

        networks = [{'uuid': net1['network']['id']},
                    {'uuid': net2['network']['id']}]

        server_multi_nics = self.create_test_server(
            networks=networks, wait_until='ACTIVE',availability_zone=CONF.compute.aws_availability_zone)

        # Cleanup server; this is needed in the test case because with the LIFO
        # nature of the cleanups, if we don't delete the server first, the port
        # will still be part of the subnet and we'll get a 409 from Neutron
        # when trying to delete the subnet. The tear down in the base class
        # will try to delete the server and get a 404 but it's ignored so
        # we're OK.
        def cleanup_server():
            self.client.delete_server(server_multi_nics['id'])
            waiters.wait_for_server_termination(self.client,
                                                server_multi_nics['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(server_multi_nics['id'])
                     ['addresses'])

        # We can't predict the ip addresses assigned to the server on networks.
        # Sometimes the assigned addresses are ['19.80.0.2', '19.86.0.2'], at
        # other times ['19.80.0.3', '19.86.0.3']. So we check if the first
        # address is in first network, similarly second address is in second
        # network.
        addr = [addresses[net1['network']['name']][0]['addr'],
                addresses[net2['network']['name']][0]['addr']]
        networks = [netaddr.IPNetwork('19.80.0.0/24'),
                    netaddr.IPNetwork('19.86.0.0/24')]
        for address, network in zip(addr, networks):
            self.assertIn(address, network)

    @test.idempotent_id('1678d144-ed74-43f8-8e57-ab10dbf9b3c2')
    @testtools.skipUnless(CONF.service_available.neutron,
                          'Neutron service must be available.')
    # The below skipUnless should be removed once Kilo-eol happens.
    @testtools.skipUnless(CONF.compute_feature_enabled.
                          allow_duplicate_networks,
                          'Duplicate networks must be allowed')
    def test_verify_duplicate_network_nics(self):
        # Verify that server creation does not fail when more than one nic
        # is created on the same network.
        net1 = self._create_net_subnet_ret_net_from_cidr('19.80.0.0/24')
        net2 = self._create_net_subnet_ret_net_from_cidr('19.86.0.0/24')

        networks = [{'uuid': net1['network']['id']},
                    {'uuid': net2['network']['id']},
                    {'uuid': net1['network']['id']}]

        server_multi_nics = self.create_test_server(
            networks=networks, wait_until='ACTIVE',availability_zone=CONF.compute.aws_availability_zone)

        def cleanup_server():
            self.client.delete_server(server_multi_nics['id'])
            waiters.wait_for_server_termination(self.client,
                                                server_multi_nics['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(server_multi_nics['id'])
                     ['addresses'])

        addr = [addresses[net1['network']['name']][0]['addr'],
                addresses[net2['network']['name']][0]['addr'],
                addresses[net1['network']['name']][1]['addr']]
        networks = [netaddr.IPNetwork('19.80.0.0/24'),
                    netaddr.IPNetwork('19.86.0.0/24'),
                    netaddr.IPNetwork('19.80.0.0/24')]
        for address, network in zip(addr, networks):
            self.assertIn(address, network)

    @test.idempotent_id('1c4b805d-3147-437b-b28c-a0ef32279bb8')
    def test_create_server_with_user_data(self):
        name = data_utils.rand_name('server_with_user_data')
        rand_data = data_utils.random_bytes()
        password = self.password
        created_server = self.create_test_server(wait_until='ACTIVE',
                                         name=name,
                                         adminPass=password,
                                         user_data=base64.b64encode(rand_data),
                                         #validatable=bool(CONF.validation.run_validation),
                                         availability_zone=CONF.compute.aws_availability_zone)

        server = self.client.show_server(created_server['id'])['server']

        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            self.assertEqual(rand_data,
                             linux_client.exec_command(
                                 'curl http://169.254.169.254/user-data'))

    @test.idempotent_id('3aed0802-db0f-46e1-ae20-07ead366c0e1')
    def test_create_server_with_network_port(self):
        name = data_utils.rand_name('server_with_network_port')
        net = self._create_net_subnet_ret_net_from_cidr('19.90.5.0/24')
        port = self.os.ports_client.create_port(network_id=net['network']['id'])
        self.addCleanup(self.os.ports_client.delete_port, port['port']['id'])
        created_server = self.create_test_server(wait_until='ACTIVE', name=name,
                                         networks = [{"port": port['port']['id']}],
                                         availability_zone=CONF.compute.aws_availability_zone)

        server = self.client.show_server(created_server['id'])['server']

    @test.idempotent_id('d25de144-339e-47d4-9885-081a6437529d')
    def test_create_server_with_network_v4_fixed_ip(self):
        name = data_utils.rand_name('server_with_network_fixed')
        ip = "19.90.8.50"
        net = self._create_net_subnet_ret_net_from_cidr('19.90.8.0/24')
        created_server = self.create_test_server(wait_until='ACTIVE', name=name,
                                         networks=[{"uuid": net['network']['id'], "fixed_ip":ip}],
                                         availability_zone=CONF.compute.aws_availability_zone)

        def cleanup_server():
            self.client.delete_server(created_server['id'])
            waiters.wait_for_server_termination(self.client,
                                                created_server['id'])

        self.addCleanup(cleanup_server)

        addresses = (self.client.list_addresses(created_server['id'])
                     ['addresses'])
        addr = addresses[net['network']['name']][0]['addr']
        self.assertEqual(addr, ip)

class HybridDeleteVCloudServersTestJSON(test_delete_server.DeleteServersTestJSON):
    """Test delete server"""

    @test.idempotent_id('9e6e0c87-3352-42f7-9faf-5d6210dbd159')
    def test_delete_server_while_in_building_state(self):
        # Delete a server while it's VM state is Building
        server = self.create_test_server(wait_until='BUILD', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('925fdfb4-5b13-47ea-ac8a-c36ae6fddb05')
    def test_delete_active_server(self):
        # Delete a server while it's VM state is Active
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('546d368c-bb6c-4645-979a-83ed16f3a6be')
    def test_delete_server_while_in_shutoff_state(self):
        # Delete a server while it's VM state is Shutoff
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.stop_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SHUTOFF')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('943bd6e8-4d7a-4904-be83-7a6cc2d4213b')
    @testtools.skipUnless(CONF.compute_feature_enabled.pause,
                          'Pause is not available.')
    def test_delete_server_while_in_pause_state(self):
        # Delete a server while it's VM state is Pause
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.pause_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'PAUSED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('1f82ebd3-8253-4f4e-b93f-de9b7df56d8b')
    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          'Suspend is not available.')
    def test_delete_server_while_in_suspended_state(self):
        # Delete a server while it's VM state is Suspended
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.suspend_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SUSPENDED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('bb0cb402-09dd-4947-b6e5-5e7e1cfa61ad')
    @testtools.skipUnless(CONF.compute_feature_enabled.shelve,
                          'Shelve is not available.')
    def test_delete_server_while_in_shelved_state(self):
        # Delete a server while it's VM state is Shelved
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.shelve_server(server['id'])

        offload_time = CONF.compute.shelved_offload_time
        if offload_time >= 0:
            waiters.wait_for_server_status(self.client, server['id'],
                                           'SHELVED_OFFLOADED',
                                           extra_timeout=offload_time)
        else:
            waiters.wait_for_server_status(self.client, server['id'],
                                           'SHELVED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('ab0c38b4-cdd8-49d3-9b92-0cb898723c01')
    @testtools.skipIf(not CONF.compute_feature_enabled.resize,
                      'Resize not available.')
    def test_delete_server_while_in_verify_resize_state(self):
        # Delete a server while it's VM state is VERIFY_RESIZE
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.resize_server(server['id'], self.flavor_ref_alt)
        waiters.wait_for_server_status(self.client, server['id'],
                                       'VERIFY_RESIZE')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @testtools.skip('Volume test support this operation')
    @test.idempotent_id('d0f3f0d6-d9b6-4a32-8da4-23015dcab23c')
    @test.services('volume')
    def test_delete_server_while_in_attached_volume(self):
        # Delete a server while a volume is attached to it
        volumes_client = self.volumes_extensions_client
        device = '/dev/%s' % CONF.compute.volume_device_name
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)

        volume = (volumes_client.create_volume(size=CONF.volume.volume_size,
                                               availability_zone=CONF.compute.vcloud_availability_zone)
                  ['volume'])
        self.addCleanup(volumes_client.delete_volume, volume['id'])
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'available')
        self.client.attach_volume(server['id'],
                                  volumeId=volume['id'],
                                  device=device)
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'in-use')

        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'available')

class HybridDeleteAwsServersTestJSON(test_delete_server.DeleteServersTestJSON):
    """Test delete server"""

    @test.idempotent_id('9e6e0c87-3352-42f7-9faf-5d6210dbd159')
    def test_delete_server_while_in_building_state(self):
        # Delete a server while it's VM state is Building
        server = self.create_test_server(wait_until='BUILD', availability_zone=CONF.compute.aws_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('925fdfb4-5b13-47ea-ac8a-c36ae6fddb05')
    def test_delete_active_server(self):
        # Delete a server while it's VM state is Active
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('546d368c-bb6c-4645-979a-83ed16f3a6be')
    def test_delete_server_while_in_shutoff_state(self):
        # Delete a server while it's VM state is Shutoff
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.stop_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SHUTOFF')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('943bd6e8-4d7a-4904-be83-7a6cc2d4213b')
    @testtools.skipUnless(CONF.compute_feature_enabled.pause,
                          'Pause is not available.')
    def test_delete_server_while_in_pause_state(self):
        # Delete a server while it's VM state is Pause
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.pause_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'PAUSED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('1f82ebd3-8253-4f4e-b93f-de9b7df56d8b')
    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          'Suspend is not available.')
    def test_delete_server_while_in_suspended_state(self):
        # Delete a server while it's VM state is Suspended
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.suspend_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SUSPENDED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('bb0cb402-09dd-4947-b6e5-5e7e1cfa61ad')
    @testtools.skipUnless(CONF.compute_feature_enabled.shelve,
                          'Shelve is not available.')
    def test_delete_server_while_in_shelved_state(self):
        # Delete a server while it's VM state is Shelved
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.shelve_server(server['id'])

        offload_time = CONF.compute.shelved_offload_time
        if offload_time >= 0:
            waiters.wait_for_server_status(self.client, server['id'],
                                           'SHELVED_OFFLOADED',
                                           extra_timeout=offload_time)
        else:
            waiters.wait_for_server_status(self.client, server['id'],
                                           'SHELVED')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('ab0c38b4-cdd8-49d3-9b92-0cb898723c01')
    @testtools.skipIf(not CONF.compute_feature_enabled.resize,
                      'Resize not available.')
    def test_delete_server_while_in_verify_resize_state(self):
        # Delete a server while it's VM state is VERIFY_RESIZE
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.resize_server(server['id'], self.flavor_ref_alt)
        waiters.wait_for_server_status(self.client, server['id'],
                                       'VERIFY_RESIZE')
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

    @test.idempotent_id('d0f3f0d6-d9b6-4a32-8da4-23015dcab23c')
    @test.services('volume')
    def test_delete_server_while_in_attached_volume(self):
        # Delete a server while a volume is attached to it
        volumes_client = self.volumes_extensions_client
        device = '/dev/%s' % CONF.compute.volume_device_name
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)

        volume = (volumes_client.create_volume(size=CONF.volume.volume_size,
                                               availability_zone=CONF.compute.aws_availability_zone)
                  ['volume'])
        self.addCleanup(volumes_client.delete_volume, volume['id'])
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'available')
        self.client.attach_volume(server['id'],
                                  volumeId=volume['id'],
                                  device=device)
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'in-use')

        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])
        waiters.wait_for_volume_status(volumes_client,
                                       volume['id'], 'available')

class HybridDeleteVCloudServersAdminTestJSON(test_delete_server.DeleteServersAdminTestJSON):
    """Test delete admin servers"""

    @test.idempotent_id('99774678-e072-49d1-9d2a-49a59bc56063')
    def test_delete_server_while_in_error_state(self):
        # Delete a server while it's VM state is error
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.admin_client.reset_state(server['id'], state='error')
        # Verify server's state
        server = self.non_admin_client.show_server(server['id'])['server']
        self.assertEqual(server['status'], 'ERROR')
        self.non_admin_client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.servers_client,
                                            server['id'],
                                            ignore_error=True)

    @test.idempotent_id('73177903-6737-4f27-a60c-379e8ae8cf48')
    def test_admin_delete_servers_of_others(self):
        # Administrator can delete servers of others
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.admin_client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.servers_client, server['id'])

class HybridDeleteAwsServersAdminTestJSON(test_delete_server.DeleteServersAdminTestJSON):
    """Test delete admin servers"""

    @test.idempotent_id('99774678-e072-49d1-9d2a-49a59bc56063')
    def test_delete_server_while_in_error_state(self):
        # Delete a server while it's VM state is error
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.admin_client.reset_state(server['id'], state='error')
        # Verify server's state
        server = self.non_admin_client.show_server(server['id'])['server']
        self.assertEqual(server['status'], 'ERROR')
        self.non_admin_client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.servers_client,
                                            server['id'],
                                            ignore_error=True)

    @test.idempotent_id('73177903-6737-4f27-a60c-379e8ae8cf48')
    def test_admin_delete_servers_of_others(self):
        # Administrator can delete servers of others
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.admin_client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.servers_client, server['id'])

class HybridVCloudInstanceActionsTestJSON(test_instance_actions.InstanceActionsTestJSON):
    """Test instance action"""

    @classmethod
    def resource_setup(cls):
        super(test_instance_actions.InstanceActionsTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        cls.request_id = server.response['x-compute-request-id']
        cls.server_id = server['id']

class HybridAwsInstanceActionsTestJSON(test_instance_actions.InstanceActionsTestJSON):
    """Test instance action"""

    @classmethod
    def resource_setup(cls):
        super(test_instance_actions.InstanceActionsTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        cls.request_id = server.response['x-compute-request-id']
        cls.server_id = server['id']

class HybridVCloudInstanceActionsNegativeTestJSON(test_instance_actions_negative.InstanceActionsNegativeTestJSON):
    """Test instance negative action"""

    @classmethod
    def resource_setup(cls):
        super(test_instance_actions_negative.InstanceActionsNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        cls.server_id = server['id']

class HybridAwsInstanceActionsNegativeTestJSON(test_instance_actions_negative.InstanceActionsNegativeTestJSON):
    """Test instance negative action"""

    @classmethod
    def resource_setup(cls):
        super(test_instance_actions_negative.InstanceActionsNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        cls.server_id = server['id']

class HybridListServerFiltersTestJSON(test_list_server_filters.ListServerFiltersTestJSON):
    """Test list server filters"""

    @classmethod
    def resource_setup(cls):
        super(test_list_server_filters.ListServerFiltersTestJSON, cls).resource_setup()

        # Check to see if the alternate image ref actually exists...
        images_client = cls.compute_images_client
        images = images_client.list_images()['images']

        if cls.image_ref != cls.image_ref_alt and \
            any([image for image in images
                 if image['id'] == cls.image_ref_alt]):
            cls.multiple_images = True
        else:
            cls.image_ref_alt = cls.image_ref

        # Do some sanity checks here. If one of the images does
        # not exist, fail early since the tests won't work...
        try:
            cls.compute_images_client.show_image(cls.image_ref)
        except lib_exc.NotFound:
            raise RuntimeError("Image %s (image_ref) was not found!" %
                               cls.image_ref)

        try:
            cls.compute_images_client.show_image(cls.image_ref_alt)
        except lib_exc.NotFound:
            raise RuntimeError("Image %s (image_ref_alt) was not found!" %
                               cls.image_ref_alt)

        network = cls.get_tenant_network()
        if network:
            cls.fixed_network_name = network.get('name')
        else:
            cls.fixed_network_name = None
        network_kwargs = fixed_network.set_networks_kwarg(network)
        cls.s1_name = data_utils.rand_name(cls.__name__ + '-instance')
        cls.s1 = cls.create_test_server(name=cls.s1_name,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone,
                                        **network_kwargs)

        cls.s2_name = data_utils.rand_name(cls.__name__ + '-instance')
        cls.s2 = cls.create_test_server(name=cls.s2_name,
                                        image_id=cls.image_ref_alt,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)

        cls.s3_name = data_utils.rand_name(cls.__name__ + '-instance')
        cls.s3 = cls.create_test_server(name=cls.s3_name,
                                        flavor=cls.flavor_ref_alt,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)

class HybridListServersNegativeTestJSON(test_list_servers_negative.ListServersNegativeTestJSON):
    """Test list servers negative"""

    @classmethod
    def resource_setup(cls):
        super(test_list_servers_negative.ListServersNegativeTestJSON, cls).resource_setup()

        # The following servers are created for use
        # by the test methods in this class. These
        # servers are cleaned up automatically in the
        # tearDownClass method of the super-class.
        cls.existing_fixtures = []
        cls.deleted_fixtures = []
        for x in moves.xrange(2):
            srv = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.default_availability_zone)
            cls.existing_fixtures.append(srv)

        srv = cls.create_test_server(availability_zone=CONF.compute.default_availability_zone)
        cls.client.delete_server(srv['id'])
        # We ignore errors on termination because the server may
        # be put into ERROR status on a quick spawn, then delete,
        # as the compute node expects the instance local status
        # to be spawning, not deleted. See LP Bug#1061167
        waiters.wait_for_server_termination(cls.client, srv['id'],
                                            ignore_error=True)
        cls.deleted_fixtures.append(srv)

class HybridMultipleCreateVCloudTestJSON(test_multiple_create.MultipleCreateTestJSON):
    """Test multiple create servers"""

    def _create_multiple_servers(self, name=None, wait_until=None, **kwargs):
        # NOTE: This is the right way to create_multiple servers and manage to
        # get the created servers into the servers list to be cleaned up after
        # all.
        kwargs['name'] = name if name else self._generate_name()
        if wait_until:
            kwargs['wait_until'] = wait_until
        body = self.create_test_server(availability_zone=CONF.compute.vcloud_availability_zone, **kwargs)

        return body

class HybridMultipleCreateAwsTestJSON(test_multiple_create.MultipleCreateTestJSON):
    """Test multiple create servers"""

    def _create_multiple_servers(self, name=None, wait_until=None, **kwargs):
        # NOTE: This is the right way to create_multiple servers and manage to
        # get the created servers into the servers list to be cleaned up after
        # all.
        kwargs['name'] = name if name else self._generate_name()
        if wait_until:
            kwargs['wait_until'] = wait_until
        body = self.create_test_server(availability_zone=CONF.compute.aws_availability_zone, **kwargs)

        return body

class HybridMultipleCreateVCloudNegativeTestJSON(test_multiple_create_negative.MultipleCreateNegativeTestJSON):
    """Test multiple create negative"""

    def _create_multiple_servers(self, name=None, wait_until=None, **kwargs):
        # This is the right way to create_multiple servers and manage to get
        # the created servers into the servers list to be cleaned up after all.
        kwargs['name'] = kwargs.get('name', self._generate_name())
        body = self.create_test_server(availability_zone=CONF.compute.vcloud_availability_zone, **kwargs)

        return body

class HybridMultipleCreateAwsNegativeTestJSON(test_multiple_create_negative.MultipleCreateNegativeTestJSON):
    """Test multiple create negative"""

    def _create_multiple_servers(self, name=None, wait_until=None, **kwargs):
        # This is the right way to create_multiple servers and manage to get
        # the created servers into the servers list to be cleaned up after all.
        kwargs['name'] = kwargs.get('name', self._generate_name())
        body = self.create_test_server(availability_zone=CONF.compute.aws_availability_zone, **kwargs)

        return body

class HybridVCloudServerActionsTestJSON(test_server_actions.ServerActionsTestJSON):
    """Test server actions"""

    def setUp(self):
        # NOTE(afazekas): Normally we use the same server with all test cases,
        # but if it has an issue, we build a new one
        super(test_server_actions.ServerActionsTestJSON, self).setUp()
        # Check if the server is in a clean state after test
        try:
            waiters.wait_for_server_status(self.client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # The server was deleted by previous test, create a new one
            server = self.create_test_server(
                validatable=True,
                wait_until='ACTIVE',
                availability_zone=CONF.compute.vcloud_availability_zone)
            self.__class__.server_id = server['id']
        except Exception:
            # Rebuild server if something happened to it during a test
            self.__class__.server_id = self.rebuild_server(
                self.server_id, validatable=True)

    @classmethod
    def rebuild_server(cls, server_id, validatable=False, **kwargs):
        # Destroy an existing server and creates a new one
        if server_id:
            try:
                cls.servers_client.delete_server(server_id)
                waiters.wait_for_server_termination(cls.servers_client,
                                                    server_id)
            except Exception:
                LOG.exception('Failed to delete server %s' % server_id)

        cls.password = data_utils.rand_password()
        server = cls.create_test_server(
            validatable,
            wait_until='ACTIVE',
            adminPass=cls.password,
            availability_zone=CONF.compute.vcloud_availability_zone,
            **kwargs)
        return server['id']

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('80a8094c-211e-440a-ab88-9e59d556c7ee')
    def test_lock_unlock_server(self):
        # Lock the server,try server stop(exceptions throw),unlock it and retry
        self.client.lock_server(self.server_id)
        self.addCleanup(self.client.unlock_server, self.server_id)
        server = self.client.show_server(self.server_id)['server']
        self.assertEqual(server['status'], 'ACTIVE')
        # Locked server is not allowed to be stopped by non-admin user
        self.assertRaises(lib_exc.Conflict,
                          self.client.stop_server, self.server_id)
        self.client.unlock_server(self.server_id)
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'SHUTOFF')
        self.client.start_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'ACTIVE')

    @testtools.skip("HybridCloud Bug:after rebulding, vxlan tunnel can't set up")
    @test.idempotent_id('aaa6cdf3-55a7-461a-add9-1c8596b9a07c')
    def test_rebuild_server(self):
        # The server should be rebuilt using the provided image and data
        meta = {'rebuild': 'server'}
        new_name = data_utils.rand_name('server')
        password = 'rebuildPassw0rd'
        rebuilt_server = self.client.rebuild_server(
            self.server_id,
            self.image_ref_alt,
            name=new_name,
            metadata=meta,
            adminPass=password)['server']

        # If the server was rebuilt on a different image, restore it to the
        # original image once the test ends
        if self.image_ref_alt != self.image_ref:
            self.addCleanup(self._rebuild_server_and_check, self.image_ref)

        # Verify the properties in the initial response are correct
        self.assertEqual(self.server_id, rebuilt_server['id'])
        rebuilt_image_id = rebuilt_server['image']['id']
        self.assertTrue(self.image_ref_alt.endswith(rebuilt_image_id))
        self.assertEqual(self.flavor_ref, rebuilt_server['flavor']['id'])

        # Verify the server properties after the rebuild completes
        waiters.wait_for_server_status(self.client,
                                       rebuilt_server['id'], 'ACTIVE')
        server = self.client.show_server(rebuilt_server['id'])['server']
        rebuilt_image_id = server['image']['id']
        self.assertTrue(self.image_ref_alt.endswith(rebuilt_image_id))
        self.assertEqual(new_name, server['name'])

        if CONF.validation.run_validation:
            # Authentication is attempted in the following order of priority:
            # 1.The key passed in, if one was passed in.
            # 2.Any key we can find through an SSH agent (if allowed).
            # 3.Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in
            #   ~/.ssh/ (if allowed).
            # 4.Plain username/password auth, if a password was given.
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(rebuilt_server),
                self.ssh_user,
                password,
                self.validation_resources['keypair']['private_key'])
            linux_client.validate_authentication()


    @test.idempotent_id('30449a88-5aff-4f9b-9866-6ee9b17f906d')
    def test_rebuild_server_in_stop_state(self):
        # The server in stop state  should be rebuilt using the provided
        # image and remain in SHUTOFF state
        server = self.client.show_server(self.server_id)['server']
        old_image = server['image']['id']
        new_image = (self.image_ref_alt
                     if old_image == self.image_ref else self.image_ref)
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'SHUTOFF')
        rebuilt_server = (self.client.rebuild_server(self.server_id, new_image)
                          ['server'])
        # If the server was rebuilt on a different image, restore it to the
        # original image once the test ends
        if self.image_ref_alt != self.image_ref:
            self.addCleanup(self._rebuild_server_and_check, old_image)

        # Verify the properties in the initial response are correct
        self.assertEqual(self.server_id, rebuilt_server['id'])
        rebuilt_image_id = rebuilt_server['image']['id']
        self.assertEqual(new_image, rebuilt_image_id)
        self.assertEqual(self.flavor_ref, rebuilt_server['flavor']['id'])

        # Verify the server properties after the rebuild completes
        waiters.wait_for_server_status(self.client,
                                       rebuilt_server['id'], 'SHUTOFF')
        server = self.client.show_server(rebuilt_server['id'])['server']
        rebuilt_image_id = server['image']['id']
        self.assertEqual(new_image, rebuilt_image_id)

        self.client.start_server(self.server_id)

        #If not so, teardown report no container exception
        waiters.wait_for_server_status(self.client, self.server_id, 'ACTIVE')

    @testtools.skip("HybridCloud Bug:after reboot, boot_time can't change")
    @test.attr(type='smoke')
    @test.idempotent_id('2cb1baf6-ac8d-4429-bf0d-ba8a0ba53e32')
    def test_reboot_server_hard(self):
        # The server should be power cycled
        self._test_reboot_server('HARD')

    @testtools.skip("HybridCloud:cascading project not support now")
    @test.idempotent_id('b963d4f1-94b3-4c40-9e97-7b583f46e470')
    @testtools.skipUnless(CONF.compute_feature_enabled.snapshot,
                          'Snapshotting not available, backup not possible.')
    @test.services('image')
    def test_create_backup(self):
        pass

class HybridAwsServerActionsTestJSON(test_server_actions.ServerActionsTestJSON):
    """Test server actions"""

    def setUp(self):
        # NOTE(afazekas): Normally we use the same server with all test cases,
        # but if it has an issue, we build a new one
        super(test_server_actions.ServerActionsTestJSON, self).setUp()
        # Check if the server is in a clean state after test
        try:
            waiters.wait_for_server_status(self.client,
                                           self.server_id, 'ACTIVE')
        except lib_exc.NotFound:
            # The server was deleted by previous test, create a new one
            server = self.create_test_server(
                validatable=True,
                wait_until='ACTIVE',
                availability_zone=CONF.compute.aws_availability_zone)
            self.__class__.server_id = server['id']
        except Exception:
            # Rebuild server if something happened to it during a test
            self.__class__.server_id = self.rebuild_server(
                self.server_id, validatable=True)

    @classmethod
    def rebuild_server(cls, server_id, validatable=False, **kwargs):
        # Destroy an existing server and creates a new one
        if server_id:
            try:
                cls.servers_client.delete_server(server_id)
                waiters.wait_for_server_termination(cls.servers_client,
                                                    server_id)
            except Exception:
                LOG.exception('Failed to delete server %s' % server_id)

        cls.password = data_utils.rand_password()
        server = cls.create_test_server(
            validatable,
            wait_until='ACTIVE',
            adminPass=cls.password,
            availability_zone=CONF.compute.aws_availability_zone,
            **kwargs)
        return server['id']

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('80a8094c-211e-440a-ab88-9e59d556c7ee')
    def test_lock_unlock_server(self):
        # Lock the server,try server stop(exceptions throw),unlock it and retry
        self.client.lock_server(self.server_id)
        self.addCleanup(self.client.unlock_server, self.server_id)
        server = self.client.show_server(self.server_id)['server']
        self.assertEqual(server['status'], 'ACTIVE')
        # Locked server is not allowed to be stopped by non-admin user
        self.assertRaises(lib_exc.Conflict,
                          self.client.stop_server, self.server_id)
        self.client.unlock_server(self.server_id)
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'SHUTOFF')
        self.client.start_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'ACTIVE')

    @testtools.skip("HybridCloud Bug:after rebulding, vxlan tunnel can't set up")
    @test.idempotent_id('aaa6cdf3-55a7-461a-add9-1c8596b9a07c')
    def test_rebuild_server(self):
        # The server should be rebuilt using the provided image and data
        meta = {'rebuild': 'server'}
        new_name = data_utils.rand_name('server')
        password = 'rebuildPassw0rd'
        rebuilt_server = self.client.rebuild_server(
            self.server_id,
            self.image_ref_alt,
            name=new_name,
            metadata=meta,
            adminPass=password)['server']

        # If the server was rebuilt on a different image, restore it to the
        # original image once the test ends
        if self.image_ref_alt != self.image_ref:
            self.addCleanup(self._rebuild_server_and_check, self.image_ref)

        # Verify the properties in the initial response are correct
        self.assertEqual(self.server_id, rebuilt_server['id'])
        rebuilt_image_id = rebuilt_server['image']['id']
        self.assertTrue(self.image_ref_alt.endswith(rebuilt_image_id))
        self.assertEqual(self.flavor_ref, rebuilt_server['flavor']['id'])

        # Verify the server properties after the rebuild completes
        waiters.wait_for_server_status(self.client,
                                       rebuilt_server['id'], 'ACTIVE')
        server = self.client.show_server(rebuilt_server['id'])['server']
        rebuilt_image_id = server['image']['id']
        self.assertTrue(self.image_ref_alt.endswith(rebuilt_image_id))
        self.assertEqual(new_name, server['name'])

        if CONF.validation.run_validation:
            # Authentication is attempted in the following order of priority:
            # 1.The key passed in, if one was passed in.
            # 2.Any key we can find through an SSH agent (if allowed).
            # 3.Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in
            #   ~/.ssh/ (if allowed).
            # 4.Plain username/password auth, if a password was given.
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(rebuilt_server),
                self.ssh_user,
                password,
                self.validation_resources['keypair']['private_key'])
            linux_client.validate_authentication()

    @test.idempotent_id('30449a88-5aff-4f9b-9866-6ee9b17f906d')
    def test_rebuild_server_in_stop_state(self):
        # The server in stop state  should be rebuilt using the provided
        # image and remain in SHUTOFF state
        server = self.client.show_server(self.server_id)['server']
        old_image = server['image']['id']
        new_image = (self.image_ref_alt
                     if old_image == self.image_ref else self.image_ref)
        self.client.stop_server(self.server_id)
        waiters.wait_for_server_status(self.client, self.server_id, 'SHUTOFF')
        rebuilt_server = (self.client.rebuild_server(self.server_id, new_image)
                          ['server'])
        # If the server was rebuilt on a different image, restore it to the
        # original image once the test ends
        if self.image_ref_alt != self.image_ref:
            self.addCleanup(self._rebuild_server_and_check, old_image)

        # Verify the properties in the initial response are correct
        self.assertEqual(self.server_id, rebuilt_server['id'])
        rebuilt_image_id = rebuilt_server['image']['id']
        self.assertEqual(new_image, rebuilt_image_id)
        self.assertEqual(self.flavor_ref, rebuilt_server['flavor']['id'])

        # Verify the server properties after the rebuild completes
        waiters.wait_for_server_status(self.client,
                                       rebuilt_server['id'], 'SHUTOFF')
        server = self.client.show_server(rebuilt_server['id'])['server']
        rebuilt_image_id = server['image']['id']
        self.assertEqual(new_image, rebuilt_image_id)

        self.client.start_server(self.server_id)

        #If not so, teardown report no container exception
        waiters.wait_for_server_status(self.client, self.server_id, 'ACTIVE')

    @testtools.skip("HybridCloud Bug:after reboot, boot_time can't change")
    @test.attr(type='smoke')
    @test.idempotent_id('2cb1baf6-ac8d-4429-bf0d-ba8a0ba53e32')
    def test_reboot_server_hard(self):
        # The server should be power cycled
        self._test_reboot_server('HARD')

    @testtools.skip("HybridCloud:cascading project not support now")
    @test.idempotent_id('b963d4f1-94b3-4c40-9e97-7b583f46e470')
    @testtools.skipUnless(CONF.compute_feature_enabled.snapshot,
                          'Snapshotting not available, backup not possible.')
    @test.services('image')
    def test_create_backup(self):
        pass

class HybridServerAddressesTestJSON(test_server_addresses.ServerAddressesTestJSON):
    """Test server address"""

    @classmethod
    def resource_setup(cls):
        super(test_server_addresses.ServerAddressesTestJSON, cls).resource_setup()

        cls.server = cls.create_test_server(wait_until='ACTIVE',
                                            availability_zone=CONF.compute.default_availability_zone)

class HybridServerAddressesNegativeTestJSON(test_server_addresses_negative.ServerAddressesNegativeTestJSON):
    """Test server address negative"""

    @classmethod
    def resource_setup(cls):
        super(test_server_addresses_negative.ServerAddressesNegativeTestJSON, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE',
                                            availability_zone=CONF.compute.default_availability_zone)

class HybridServerMetadataTestJSON(test_server_metadata.ServerMetadataTestJSON):
    """Test server metadata"""

    @classmethod
    def resource_setup(cls):
        super(test_server_metadata.ServerMetadataTestJSON, cls).resource_setup()
        server = cls.create_test_server(metadata={}, wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)
        cls.server_id = server['id']

class HybridServerMetadataNegativeTestJSON(test_server_metadata_negative.ServerMetadataNegativeTestJSON):
    """Test server metadata negative"""

    @classmethod
    def resource_setup(cls):
        super(test_server_metadata_negative.ServerMetadataNegativeTestJSON, cls).resource_setup()
        cls.tenant_id = cls.client.tenant_id
        server = cls.create_test_server(metadata={}, wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)

        cls.server_id = server['id']

class HybridVCloudServerPasswordTestJSON(test_server_password.ServerPasswordTestJSON):
    """Test server password"""

    @classmethod
    def resource_setup(cls):
        super(test_server_password.ServerPasswordTestJSON, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until="ACTIVE",
                                            availability_zone=CONF.compute.vcloud_availability_zone)

class HybridAwsServerPasswordTestJSON(test_server_password.ServerPasswordTestJSON):
    """Test server password"""

    @classmethod
    def resource_setup(cls):
        super(test_server_password.ServerPasswordTestJSON, cls).resource_setup()
        cls.server = cls.create_test_server(wait_until="ACTIVE",
                                            availability_zone=CONF.compute.aws_availability_zone)

class HybridVCloudServerPersonalityTestJSON(test_server_personality.ServerPersonalityTestJSON):
    """Test server personality"""

    @testtools.skip("HybridCloud Bug:when exec this testcase individual will sucess, exec in class will failed")
    @test.idempotent_id('3cfe87fd-115b-4a02-b942-7dc36a337fdf')
    def test_create_server_with_personality(self):
        file_contents = 'This is a test file.'
        file_path = '/test.txt'
        personality = [{'path': file_path,
                        'contents': base64.b64encode(file_contents)}]
        password = data_utils.rand_password()
        created_server = self.create_test_server(personality=personality,
                                                 adminPass=password,
                                                 wait_until='ACTIVE',
                                                 validatable=True,
                                                 availability_zone=CONF.compute.vcloud_availability_zone)
        server = self.client.show_server(created_server['id'])['server']
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            self.assertEqual(file_contents,
                             linux_client.exec_command(
                                 'cat %s' % file_path))

    @test.idempotent_id('128966d8-71fc-443c-8cab-08e24114ecc9')
    def test_rebuild_server_with_personality(self):
        server = self.create_test_server(wait_until='ACTIVE', validatable=True,
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        server_id = server['id']
        file_contents = 'Test server rebuild.'
        personality = [{'path': 'rebuild.txt',
                        'contents': base64.b64encode(file_contents)}]
        rebuilt_server = self.client.rebuild_server(server_id,
                                                    self.image_ref_alt,
                                                    personality=personality)
        waiters.wait_for_server_status(self.client, server_id, 'ACTIVE')
        self.assertEqual(self.image_ref_alt,
                         rebuilt_server['server']['image']['id'])

    @test.idempotent_id('176cd8c9-b9e8-48ee-a480-180beab292bf')
    def test_personality_files_exceed_limit(self):
        # Server creation should fail if greater than the maximum allowed
        # number of files are injected into the server.
        file_contents = 'This is a test file.'
        personality = []
        limits = self.user_client.show_limits()['limits']
        max_file_limit = limits['absolute']['maxPersonality']
        if max_file_limit == -1:
            raise self.skipException("No limit for personality files")
        for i in range(0, int(max_file_limit) + 1):
            path = 'etc/test' + str(i) + '.txt'
            personality.append({'path': path,
                                'contents': base64.b64encode(file_contents)})
        # A 403 Forbidden or 413 Overlimit (old behaviour) exception
        # will be raised when out of quota
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                          self.create_test_server, personality=personality,
                          availability_zone=CONF.compute.vcloud_availability_zone)

    @test.idempotent_id('52f12ee8-5180-40cc-b417-31572ea3d555')
    def test_can_create_server_with_max_number_personality_files(self):
        # Server should be created successfully if maximum allowed number of
        # files is injected into the server during creation.
        file_contents = 'This is a test file.'
        limits = self.user_client.show_limits()['limits']
        max_file_limit = limits['absolute']['maxPersonality']
        if max_file_limit == -1:
            raise self.skipException("No limit for personality files")
        person = []
        for i in range(0, int(max_file_limit)):
            path = '/etc/test' + str(i) + '.txt'
            person.append({
                'path': path,
                'contents': base64.b64encode(file_contents),
            })
        password = data_utils.rand_password()
        created_server = self.create_test_server(personality=person,
                                                 adminPass=password,
                                                 wait_until='ACTIVE',
                                                 validatable=True,
                                                 availability_zone=CONF.compute.vcloud_availability_zone)
        server = self.client.show_server(created_server['id'])['server']
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            for i in person:
                self.assertEqual(base64.b64decode(i['contents']),
                                 linux_client.exec_command(
                                     'cat %s' % i['path']))


class HybridAwsServerPersonalityTestJSON(test_server_personality.ServerPersonalityTestJSON):
    """Test server personality"""

    @testtools.skip("HybridCloud Bug:when exec this testcase individual will sucess, exec in class will failed")
    @test.idempotent_id('3cfe87fd-115b-4a02-b942-7dc36a337fdf')
    def test_create_server_with_personality(self):
        file_contents = 'This is a test file.'
        file_path = '/test.txt'
        personality = [{'path': file_path,
                        'contents': base64.b64encode(file_contents)}]
        password = data_utils.rand_password()
        created_server = self.create_test_server(personality=personality,
                                                 adminPass=password,
                                                 wait_until='ACTIVE',
                                                 validatable=True,
                                                 availability_zone=CONF.compute.aws_availability_zone)
        server = self.client.show_server(created_server['id'])['server']
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            self.assertEqual(file_contents,
                             linux_client.exec_command(
                                 'cat %s' % file_path))

    @test.idempotent_id('128966d8-71fc-443c-8cab-08e24114ecc9')
    def test_rebuild_server_with_personality(self):
        server = self.create_test_server(wait_until='ACTIVE', validatable=True,
                                         availability_zone=CONF.compute.aws_availability_zone)
        server_id = server['id']
        file_contents = 'Test server rebuild.'
        personality = [{'path': 'rebuild.txt',
                        'contents': base64.b64encode(file_contents)}]
        rebuilt_server = self.client.rebuild_server(server_id,
                                                    self.image_ref_alt,
                                                    personality=personality)
        waiters.wait_for_server_status(self.client, server_id, 'ACTIVE')
        self.assertEqual(self.image_ref_alt,
                         rebuilt_server['server']['image']['id'])

    @test.idempotent_id('176cd8c9-b9e8-48ee-a480-180beab292bf')
    def test_personality_files_exceed_limit(self):
        # Server creation should fail if greater than the maximum allowed
        # number of files are injected into the server.
        file_contents = 'This is a test file.'
        personality = []
        limits = self.user_client.show_limits()['limits']
        max_file_limit = limits['absolute']['maxPersonality']
        if max_file_limit == -1:
            raise self.skipException("No limit for personality files")
        for i in range(0, int(max_file_limit) + 1):
            path = 'etc/test' + str(i) + '.txt'
            personality.append({'path': path,
                                'contents': base64.b64encode(file_contents)})
        # A 403 Forbidden or 413 Overlimit (old behaviour) exception
        # will be raised when out of quota
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                          self.create_test_server, personality=personality,
                          availability_zone=CONF.compute.aws_availability_zone)

    @test.idempotent_id('52f12ee8-5180-40cc-b417-31572ea3d555')
    def test_can_create_server_with_max_number_personality_files(self):
        # Server should be created successfully if maximum allowed number of
        # files is injected into the server during creation.
        file_contents = 'This is a test file.'
        limits = self.user_client.show_limits()['limits']
        max_file_limit = limits['absolute']['maxPersonality']
        if max_file_limit == -1:
            raise self.skipException("No limit for personality files")
        person = []
        for i in range(0, int(max_file_limit)):
            path = '/etc/test' + str(i) + '.txt'
            person.append({
                'path': path,
                'contents': base64.b64encode(file_contents),
            })
        password = data_utils.rand_password()
        created_server = self.create_test_server(personality=person,
                                                 adminPass=password,
                                                 wait_until='ACTIVE',
                                                 validatable=True,
                                                 availability_zone=CONF.compute.aws_availability_zone)
        server = self.client.show_server(created_server['id'])['server']
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.ssh_user, password,
                self.validation_resources['keypair']['private_key'])
            for i in person:
                self.assertEqual(base64.b64decode(i['contents']),
                                 linux_client.exec_command(
                                     'cat %s' % i['path']))

class HybridVCloudServersTestJSON(test_servers.ServersTestJSON):
    """Test servers"""

    @test.idempotent_id('b92d5ec7-b1dd-44a2-87e4-45e888c46ef0')
    @testtools.skipUnless(CONF.compute_feature_enabled.
                          enable_instance_password,
                          'Instance password not available.')
    def test_create_server_with_admin_password(self):
        # If an admin password is provided on server creation, the server's
        # root password should be set to that password.
        server = self.create_test_server(adminPass='testpassword', availability_zone=CONF.compute.vcloud_availability_zone)

        # Verify the password is set correctly in the response
        self.assertEqual('testpassword', server['adminPass'])

    @test.idempotent_id('8fea6be7-065e-47cf-89b8-496e6f96c699')
    def test_create_with_existing_server_name(self):
        # Creating a server with a name that already exists is allowed

        # TODO(sdague): clear out try, we do cleanup one layer up
        server_name = data_utils.rand_name('server')
        server = self.create_test_server(name=server_name,
                                         wait_until='ACTIVE',
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        id1 = server['id']
        server = self.create_test_server(name=server_name,
                                         wait_until='ACTIVE',
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        id2 = server['id']
        self.assertNotEqual(id1, id2, "Did not create a new server")
        server = self.client.show_server(id1)['server']
        name1 = server['name']
        server = self.client.show_server(id2)['server']
        name2 = server['name']
        self.assertEqual(name1, name2)

    @test.idempotent_id('f9e15296-d7f9-4e62-b53f-a04e89160833')
    def test_create_specify_keypair(self):
        # Specify a keypair while creating a server

        key_name = data_utils.rand_name('key')
        self.keypairs_client.create_keypair(name=key_name)
        self.addCleanup(self.keypairs_client.delete_keypair, key_name)
        self.keypairs_client.list_keypairs()
        server = self.create_test_server(key_name=key_name, availability_zone=CONF.compute.vcloud_availability_zone)
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')
        server = self.client.show_server(server['id'])['server']
        self.assertEqual(key_name, server['key_name'])

    def _update_server_name(self, server_id, status, prefix_name='server'):
        # The server name should be changed to the the provided value
        new_name = data_utils.rand_name(prefix_name)

        # Update the server with a new name
        self.client.update_server(server_id,
                                  name=new_name)
        waiters.wait_for_server_status(self.client, server_id, status)

        # Verify the name of the server has changed
        server = self.client.show_server(server_id)['server']
        self.assertEqual(new_name, server['name'])
        return server

    @test.idempotent_id('5e6ccff8-349d-4852-a8b3-055df7988dd2')
    def test_update_server_name(self):
        # The server name should be changed to the the provided value
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        # Update instance name with non-ASCII characters
        prefix_name = u'\u00CD\u00F1st\u00E1\u00F1c\u00E9'
        self._update_server_name(server['id'], 'ACTIVE', prefix_name)

    @test.idempotent_id('6ac19cb1-27a3-40ec-b350-810bdc04c08e')
    def test_update_server_name_in_stop_state(self):
        # The server name should be changed to the the provided value
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.stop_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SHUTOFF')
        # Update instance name with non-ASCII characters
        prefix_name = u'\u00CD\u00F1st\u00E1\u00F1c\u00E9'
        updated_server = self._update_server_name(server['id'],
                                                  'SHUTOFF',
                                                  prefix_name)
        self.assertNotIn('progress', updated_server)

    @test.idempotent_id('89b90870-bc13-4b73-96af-f9d4f2b70077')
    def test_update_access_server_address(self):
        # The server's access addresses should reflect the provided values
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)

        # Update the IPv4 and IPv6 access addresses
        self.client.update_server(server['id'],
                                  accessIPv4='1.1.1.1',
                                  accessIPv6='::babe:202:202')
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')

        # Verify the access addresses have been updated
        server = self.client.show_server(server['id'])['server']
        self.assertEqual('1.1.1.1', server['accessIPv4'])
        self.assertEqual('::babe:202:202', server['accessIPv6'])

    @test.idempotent_id('38fb1d02-c3c5-41de-91d3-9bc2025a75eb')
    def test_create_server_with_ipv6_addr_only(self):
        # Create a server without an IPv4 address(only IPv6 address).
        server = self.create_test_server(accessIPv6='2001:2001::3',
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')
        server = self.client.show_server(server['id'])['server']
        self.assertEqual('2001:2001::3', server['accessIPv6'])

class HybridAwsServersTestJSON(test_servers.ServersTestJSON):
    """Test servers"""

    @test.idempotent_id('b92d5ec7-b1dd-44a2-87e4-45e888c46ef0')
    @testtools.skipUnless(CONF.compute_feature_enabled.
                          enable_instance_password,
                          'Instance password not available.')
    def test_create_server_with_admin_password(self):
        # If an admin password is provided on server creation, the server's
        # root password should be set to that password.
        server = self.create_test_server(adminPass='testpassword', availability_zone=CONF.compute.aws_availability_zone)

        # Verify the password is set correctly in the response
        self.assertEqual('testpassword', server['adminPass'])

    @test.idempotent_id('8fea6be7-065e-47cf-89b8-496e6f96c699')
    def test_create_with_existing_server_name(self):
        # Creating a server with a name that already exists is allowed

        # TODO(sdague): clear out try, we do cleanup one layer up
        server_name = data_utils.rand_name('server')
        server = self.create_test_server(name=server_name,
                                         wait_until='ACTIVE',
                                         availability_zone=CONF.compute.aws_availability_zone)
        id1 = server['id']
        server = self.create_test_server(name=server_name,
                                         wait_until='ACTIVE',
                                         availability_zone=CONF.compute.aws_availability_zone)
        id2 = server['id']
        self.assertNotEqual(id1, id2, "Did not create a new server")
        server = self.client.show_server(id1)['server']
        name1 = server['name']
        server = self.client.show_server(id2)['server']
        name2 = server['name']
        self.assertEqual(name1, name2)

    @test.idempotent_id('f9e15296-d7f9-4e62-b53f-a04e89160833')
    def test_create_specify_keypair(self):
        # Specify a keypair while creating a server

        key_name = data_utils.rand_name('key')
        self.keypairs_client.create_keypair(name=key_name)
        self.addCleanup(self.keypairs_client.delete_keypair, key_name)
        self.keypairs_client.list_keypairs()
        server = self.create_test_server(key_name=key_name, availability_zone=CONF.compute.aws_availability_zone)
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')
        server = self.client.show_server(server['id'])['server']
        self.assertEqual(key_name, server['key_name'])

    def _update_server_name(self, server_id, status, prefix_name='server'):
        # The server name should be changed to the the provided value
        new_name = data_utils.rand_name(prefix_name)

        # Update the server with a new name
        self.client.update_server(server_id,
                                  name=new_name)
        waiters.wait_for_server_status(self.client, server_id, status)

        # Verify the name of the server has changed
        server = self.client.show_server(server_id)['server']
        self.assertEqual(new_name, server['name'])
        return server

    @test.idempotent_id('5e6ccff8-349d-4852-a8b3-055df7988dd2')
    def test_update_server_name(self):
        # The server name should be changed to the the provided value
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        # Update instance name with non-ASCII characters
        prefix_name = u'\u00CD\u00F1st\u00E1\u00F1c\u00E9'
        self._update_server_name(server['id'], 'ACTIVE', prefix_name)

    @test.idempotent_id('6ac19cb1-27a3-40ec-b350-810bdc04c08e')
    def test_update_server_name_in_stop_state(self):
        # The server name should be changed to the the provided value
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        self.client.stop_server(server['id'])
        waiters.wait_for_server_status(self.client, server['id'], 'SHUTOFF')
        # Update instance name with non-ASCII characters
        prefix_name = u'\u00CD\u00F1st\u00E1\u00F1c\u00E9'
        updated_server = self._update_server_name(server['id'],
                                                  'SHUTOFF',
                                                  prefix_name)
        self.assertNotIn('progress', updated_server)

    @test.idempotent_id('89b90870-bc13-4b73-96af-f9d4f2b70077')
    def test_update_access_server_address(self):
        # The server's access addresses should reflect the provided values
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)

        # Update the IPv4 and IPv6 access addresses
        self.client.update_server(server['id'],
                                  accessIPv4='1.1.1.1',
                                  accessIPv6='::babe:202:202')
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')

        # Verify the access addresses have been updated
        server = self.client.show_server(server['id'])['server']
        self.assertEqual('1.1.1.1', server['accessIPv4'])
        self.assertEqual('::babe:202:202', server['accessIPv6'])

    @test.idempotent_id('38fb1d02-c3c5-41de-91d3-9bc2025a75eb')
    def test_create_server_with_ipv6_addr_only(self):
        # Create a server without an IPv4 address(only IPv6 address).
        server = self.create_test_server(accessIPv6='2001:2001::3',
                                         availability_zone=CONF.compute.aws_availability_zone)
        waiters.wait_for_server_status(self.client, server['id'], 'ACTIVE')
        server = self.client.show_server(server['id'])['server']
        self.assertEqual('2001:2001::3', server['accessIPv6'])

class HybridVCloudServersNegativeTestJSON(test_servers_negative.ServersNegativeTestJSON):
    """Test servers negative"""

    @classmethod
    def resource_setup(cls):
        super(test_servers_negative.ServersNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE',
                                        availability_zone=CONF.compute.vcloud_availability_zone)
        cls.server_id = server['id']

    @classmethod
    def rebuild_server(cls, server_id, validatable=False, **kwargs):
        # Destroy an existing server and creates a new one
        if server_id:
            try:
                cls.servers_client.delete_server(server_id)
                waiters.wait_for_server_termination(cls.servers_client,
                                                    server_id)
            except Exception:
                LOG.exception('Failed to delete server %s' % server_id)

        cls.password = data_utils.rand_password()
        server = cls.create_test_server(
            validatable,
            wait_until='ACTIVE',
            adminPass=cls.password,
            availability_zone=CONF.compute.vcloud_availability_zone,
            **kwargs)
        return server['id']

    @test.attr(type=['negative'])
    @test.idempotent_id('98fa0458-1485-440f-873b-fe7f0d714930')
    def test_rebuild_deleted_server(self):
        # Rebuild a deleted server
        server = self.create_test_server(wait_until='ACTIVE',
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

        self.assertRaises(lib_exc.NotFound,
                          self.client.rebuild_server,
                          server['id'], self.image_ref_alt)

    @test.attr(type=['negative'])
    @test.idempotent_id('581a397d-5eab-486f-9cf9-1014bbd4c984')
    def test_reboot_deleted_server(self):
        # Reboot a deleted server
        server = self.create_test_server(wait_until='ACTIVE',
                                         availability_zone=CONF.compute.vcloud_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

        self.assertRaises(lib_exc.NotFound, self.client.reboot_server,
                          server['id'], type='SOFT')


class HybridAwsServersNegativeTestJSON(test_servers_negative.ServersNegativeTestJSON):
    """Test servers negative"""

    @classmethod
    def resource_setup(cls):
        super(test_servers_negative.ServersNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE',
                                        availability_zone=CONF.compute.aws_availability_zone)
        cls.server_id = server['id']

    @classmethod
    def rebuild_server(cls, server_id, validatable=False, **kwargs):
        # Destroy an existing server and creates a new one
        if server_id:
            try:
                cls.servers_client.delete_server(server_id)
                waiters.wait_for_server_termination(cls.servers_client,
                                                    server_id)
            except Exception:
                LOG.exception('Failed to delete server %s' % server_id)

        cls.password = data_utils.rand_password()
        server = cls.create_test_server(
            validatable,
            wait_until='ACTIVE',
            adminPass=cls.password,
            availability_zone=CONF.compute.aws_availability_zone,
            **kwargs)
        return server['id']

    @test.attr(type=['negative'])
    @test.idempotent_id('98fa0458-1485-440f-873b-fe7f0d714930')
    def test_rebuild_deleted_server(self):
        # Rebuild a deleted server
        server = self.create_test_server(wait_until='ACTIVE',
                                         availability_zone=CONF.compute.aws_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

        self.assertRaises(lib_exc.NotFound,
                          self.client.rebuild_server,
                          server['id'], self.image_ref_alt)

    @test.attr(type=['negative'])
    @test.idempotent_id('581a397d-5eab-486f-9cf9-1014bbd4c984')
    def test_reboot_deleted_server(self):
        # Reboot a deleted server
        server = self.create_test_server(wait_until='ACTIVE',
                                         availability_zone=CONF.compute.aws_availability_zone)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])

        self.assertRaises(lib_exc.NotFound, self.client.reboot_server,
                          server['id'], type='SOFT')


class HybridVirtualInterfacesNegativeTestJSON(test_virtual_interfaces_negative.VirtualInterfacesNegativeTestJSON):
    """Test virtual interfaces negative"""
