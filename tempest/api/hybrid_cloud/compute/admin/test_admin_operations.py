import datetime
import testtools
from oslo_log import log

from tempest.api.compute import base
from tempest.common import compute
from tempest.common import fixed_network

import tempest.api.compute.admin.test_agents as AgentsAdminTest
import tempest.api.compute.admin.test_aggregates as AggregatesAdminTest
import tempest.api.compute.admin.test_aggregates_negative as AggregatesAdminNegativeTest
import tempest.api.compute.admin.test_availability_zone as AZAdminV2Test
import tempest.api.compute.admin.test_availability_zone_negative as AZAdminNegativeTest
import tempest.api.compute.admin.test_baremetal_nodes as BaremetalNodesAdminTest
import tempest.api.compute.admin.test_fixed_ips as FixedIPsTest
import tempest.api.compute.admin.test_fixed_ips_negative as FixedIPsNegativeTest
import tempest.api.compute.admin.test_flavors as FlavorsAdminTest
import tempest.api.compute.admin.test_flavors_access as FlavorsAccessTest
import tempest.api.compute.admin.test_flavors_access_negative as FlavorsAccessNegativeTest
import tempest.api.compute.admin.test_flavors_extra_specs as FlavorsExtraSpecsTest
import tempest.api.compute.admin.test_flavors_extra_specs_negative as FlavorsExtraSpecsNegativeTest
import tempest.api.compute.admin.test_floating_ips_bulk as FloatingIPsBulkAdminTest
import tempest.api.compute.admin.test_hosts as HostsAdminTest
import tempest.api.compute.admin.test_hosts_negative as HostsAdminNegativeTest
import tempest.api.compute.admin.test_hypervisor as HypervisorAdminTest
import tempest.api.compute.admin.test_hypervisor_negative as HypervisorAdminNegativeTest
import tempest.api.compute.admin.test_instance_usage_audit_log as InstanceUsageAuditLogTest
import tempest.api.compute.admin.test_instance_usage_audit_log_negative as InstanceUsageAuditLogNegativeTest
import tempest.api.compute.admin.test_keypairs_v210 as KeyPairsV210Test
import tempest.api.compute.admin.test_live_migration as LiveBlockMigrationTest
import tempest.api.compute.admin.test_migrations as MigrationsAdminTest
import tempest.api.compute.admin.test_networks as NetworksTest
import tempest.api.compute.admin.test_quotas as QuotaClassesAdminTest
import tempest.api.compute.admin.test_quotas as QuotasAdminTest
import tempest.api.compute.admin.test_quotas_negative as QuotasAdminNegativeTest
import tempest.api.compute.admin.test_security_group_default_rules as SecurityGroupDefaultRulesTest
import tempest.api.compute.admin.test_security_groups as SecurityGroupsTestAdmin
import tempest.api.compute.admin.test_servers as ServersAdminTest
import tempest.api.compute.admin.test_servers_negative as ServersAdminNegativeTest
import tempest.api.compute.admin.test_servers_on_multinodes as ServersOnMultiNodesTest
import tempest.api.compute.admin.test_services as ServicesAdminTest
import tempest.api.compute.admin.test_services_negative as ServicesAdminNegativeTest
import tempest.api.compute.admin.test_simple_tenant_usage as TenantUsagesTest
import tempest.api.compute.admin.test_simple_tenant_usage_negative as TenantUsagesNegativeTest
from tempest.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.lib import decorators
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridAgentsAdminTestJSON(AgentsAdminTest.AgentsAdminTestJSON):
    """Tests Agents API"""

class HybridAggregatesAdminTestJSON(AggregatesAdminTest.AggregatesAdminTestJSON):
    """Tests Aggregates API that require admin privileges"""
    @testtools.skip('Do not support now')    
    @test.idempotent_id('96be03c7-570d-409c-90f8-e4db3c646996')
    def test_aggregate_add_host_create_server_with_az(self):
        # Add a host to the given aggregate and create a server.
        self.useFixture(fixtures.LockFixture('availability_zone'))
        aggregate_name = data_utils.rand_name(self.aggregate_name_prefix)
        az_name = data_utils.rand_name(self.az_name_prefix)
        aggregate = self.client.create_aggregate(
            name=aggregate_name, availability_zone=az_name)['aggregate']
        self.addCleanup(self.client.delete_aggregate, aggregate['id'])
        self.client.add_host(aggregate['id'], host=self.host)
        self.addCleanup(self.client.remove_host, aggregate['id'],
                        host=self.host)
        server_name = data_utils.rand_name('test_server')
        admin_servers_client = self.os_adm.servers_client
        server = self.create_test_server(name=server_name,
                                         availability_zone=az_name,
                                         wait_until='ACTIVE')
        body = admin_servers_client.show_server(server['id'])['server']
        self.assertEqual(self.host, body[self._host_key])

class HybridAggregatesAdminNegativeTestJSON(AggregatesAdminNegativeTest.AggregatesAdminNegativeTestJSON):
    """Tests Aggregates API that require admin privileges"""

class HybridAZAdminV2TestJSON(AZAdminV2Test.AZAdminV2TestJSON):
    """Tests Availability Zone API List"""

class HybridAZAdminNegativeTestJSON(AZAdminNegativeTest.AZAdminNegativeTestJSON):
    """Tests Availability Zone API List"""

class HybridBaremetalNodesAdminTestJSON(BaremetalNodesAdminTest.BaremetalNodesAdminTestJSON):
    """Tests Baremetal API"""

class HybridFixedIPsTestJson(FixedIPsTest.FixedIPsTestJson):
    """Tests FixedIPs API"""

class HybridFixedIPsNegativeTestJson(FixedIPsNegativeTest.FixedIPsNegativeTestJson):
    """Tests FixedIPs API"""

class HybridFlavorsAdminTestJSON(FlavorsAdminTest.FlavorsAdminTestJSON):
    """Tests Flavors API Create and Delete that require admin privileges"""
    @testtools.skip('Do not support now')
    @test.idempotent_id('63dc64e6-2e79-4fdf-868f-85500d308d66')
    def test_create_list_flavor_without_extra_data(self):
        # Create a flavor and ensure it is listed
        # This operation requires the user to have 'admin' role

        def verify_flavor_response_extension(flavor):
            # check some extensions for the flavor create/show/detail response
            self.assertEqual(flavor['swap'], '')
            self.assertEqual(int(flavor['rxtx_factor']), 1)
            self.assertEqual(int(flavor['OS-FLV-EXT-DATA:ephemeral']), 0)
            self.assertEqual(flavor['os-flavor-access:is_public'], True)

        flavor_name = data_utils.rand_name(self.flavor_name_prefix)
        new_flavor_id = data_utils.rand_int_id(start=1000)

        # Create the flavor
        flavor = self.client.create_flavor(name=flavor_name,
                                           ram=self.ram, vcpus=self.vcpus,
                                           disk=self.disk,
                                           id=new_flavor_id)['flavor']
        self.addCleanup(self.flavor_clean_up, flavor['id'])
        self.assertEqual(flavor['name'], flavor_name)
        self.assertEqual(flavor['ram'], self.ram)
        self.assertEqual(flavor['vcpus'], self.vcpus)
        self.assertEqual(flavor['disk'], self.disk)
        self.assertEqual(int(flavor['id']), new_flavor_id)
        verify_flavor_response_extension(flavor)

        # Verify flavor is retrieved
        flavor = self.client.show_flavor(new_flavor_id)['flavor']
        self.assertEqual(flavor['name'], flavor_name)
        verify_flavor_response_extension(flavor)

        # Check if flavor is present in list
        flavors = self.user_client.list_flavors(detail=True)['flavors']
        for flavor in flavors:
            if flavor['name'] == flavor_name:
                verify_flavor_response_extension(flavor)
                flag = True
        self.assertTrue(flag)

class HybridFlavorsAccessTestJSON(FlavorsAccessTest.FlavorsAccessTestJSON):
    """Tests Flavor Access API extension.

    Add and remove Flavor Access require admin privileges.
    """
class HybridFlavorsAccessNegativeTestJSON(FlavorsAccessNegativeTest.FlavorsAccessNegativeTestJSON):
    """Tests Flavor Access API extension.

    Add and remove Flavor Access require admin privileges.
    """
class HybridFlavorsExtraSpecsTestJSON(FlavorsExtraSpecsTest.FlavorsExtraSpecsTestJSON):
    """Tests Flavor Extra Spec API extension.

    SET, UNSET, UPDATE Flavor Extra specs require admin privileges.
    GET Flavor Extra specs can be performed even by without admin privileges.
    """
    @test.idempotent_id('a99dad88-ae1c-4fba-aeb4-32f898218bd0')
    def test_flavor_non_admin_get_all_keys(self):
        specs = {"key1": "value1", "key2": "value2"}
        self.client.set_flavor_extra_spec(self.flavor['id'], **specs)
        body = (self.flavors_client.list_flavor_extra_specs(self.flavor['id'])
                ['extra_specs'])

        for key in specs:
            self.assertEqual(body[key], specs[key])

    @testtools.skip('Do not support now')
    @test.idempotent_id('12805a7f-39a3-4042-b989-701d5cad9c90')
    def test_flavor_non_admin_get_specific_key(self):
            body = self.client.set_flavor_extra_spec(self.flavor['id'],
                                                     key1="value1",
                                                     key2="value2")['extra_specs']
            self.assertEqual(body['key1'], 'value1')
            self.assertIn('key2', body)
            body = self.flavors_client.show_flavor_extra_spec(
                self.flavor['id'], 'key1')
            self.assertEqual(body['key1'], 'value1')
            self.assertNotIn('key2', body)

class HybridFlavorsExtraSpecsNegativeTestJSON(FlavorsExtraSpecsNegativeTest.FlavorsExtraSpecsNegativeTestJSON):
    """Negative Tests Flavor Extra Spec API extension.

    SET, UNSET, UPDATE Flavor Extra specs require admin privileges.
    """
    @testtools.skip('Do not support now')
    @test.attr(type=['negative'])
    @test.idempotent_id('329a7be3-54b2-48be-8052-bf2ce4afd898')
    def test_flavor_get_nonexistent_key(self):
        self.assertRaises(lib_exc.NotFound,
                          self.flavors_client.show_flavor_extra_spec,
                          self.flavor['id'],
                          "nonexistent_key")

class HybridFloatingIPsBulkAdminTestJSON(FloatingIPsBulkAdminTest.FloatingIPsBulkAdminTestJSON):
    """Tests Floating IPs Bulk APIs that require admin privileges.

    API documentation - http://docs.openstack.org/api/openstack-compute/2/
    content/ext-os-floating-ips-bulk.html
    """

class HybridHostsAdminTestJSON(HostsAdminTest.HostsAdminTestJSON):
    """Tests hosts API using admin privileges."""

class HybridHostsAdminNegativeTestJSON(HostsAdminNegativeTest.HostsAdminNegativeTestJSON):
    """Tests hosts API using admin privileges."""

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('e40c72b1-0239-4ed6-ba21-81a184df1f7c')
    def test_update_host_with_non_admin_user(self):
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.Forbidden,
                          self.non_admin_client.update_host,
                          hostname,
                          status='enable',
                          maintenance_mode='enable')

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('fbe2bf3e-3246-4a95-a59f-94e4e298ec77')
    def test_update_host_with_invalid_status(self):
        # 'status' can only be 'enable' or 'disable'
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_host,
                          hostname,
                          status='invalid',
                          maintenance_mode='enable')

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('ab1e230e-5e22-41a9-8699-82b9947915d4')
    def test_update_host_with_invalid_maintenance_mode(self):
        # 'maintenance_mode' can only be 'enable' or 'disable'
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_host,
                          hostname,
                          status='enable',
                          maintenance_mode='invalid')

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('0cd85f75-6992-4a4a-b1bd-d11e37fd0eee')
    def test_update_host_without_param(self):
        # 'status' or 'maintenance_mode' needed for host update
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_host,
                          hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('23c92146-2100-4d68-b2d6-c7ade970c9c1')
    def test_update_nonexistent_host(self):
        nonexitent_hostname = data_utils.rand_name('rand_hostname')

        self.assertRaises(lib_exc.NotFound,
                          self.client.update_host,
                          nonexitent_hostname,
                          status='enable',
                          maintenance_mode='enable')

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('0d981ac3-4320-4898-b674-82b61fbb60e4')
    def test_startup_nonexistent_host(self):
        nonexitent_hostname = data_utils.rand_name('rand_hostname')

        self.assertRaises(lib_exc.NotFound,
                          self.client.startup_host,
                          nonexitent_hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('9f4ebb7e-b2ae-4e5b-a38f-0fd1bb0ddfca')
    def test_startup_host_with_non_admin_user(self):
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.Forbidden,
                          self.non_admin_client.startup_host,
                          hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('9e637444-29cf-4244-88c8-831ae82c31b6')
    def test_shutdown_nonexistent_host(self):
        nonexitent_hostname = data_utils.rand_name('rand_hostname')

        self.assertRaises(lib_exc.NotFound,
                          self.client.shutdown_host,
                          nonexitent_hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('a803529c-7e3f-4d3c-a7d6-8e1c203d27f6')
    def test_shutdown_host_with_non_admin_user(self):
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.Forbidden,
                          self.non_admin_client.shutdown_host,
                          hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('f86bfd7b-0b13-4849-ae29-0322e83ee58b')
    def test_reboot_nonexistent_host(self):
        nonexitent_hostname = data_utils.rand_name('rand_hostname')

        self.assertRaises(lib_exc.NotFound,
                          self.client.reboot_host,
                          nonexitent_hostname)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('02d79bb9-eb57-4612-abf6-2cb38897d2f8')
    def test_reboot_host_with_non_admin_user(self):
        hostname = self._get_host_name()

        self.assertRaises(lib_exc.Forbidden,
                          self.non_admin_client.reboot_host,
                          hostname)

class HybridHypervisorAdminTestJSON(HypervisorAdminTest.HypervisorAdminTestJSON):
    """Tests Hypervisors API that require admin privileges"""

class HybridHypervisorAdminNegativeTestJSON(HypervisorAdminNegativeTest.HypervisorAdminNegativeTestJSON):
    """Tests Hypervisors API that require admin privileges"""

class HybridInstanceUsageAuditLogTestJSON(InstanceUsageAuditLogTest.InstanceUsageAuditLogTestJSON):
    """Tests InstanceUsageAuditLogTestJSON API"""

class HybridInstanceUsageAuditLogNegativeTestJSON(InstanceUsageAuditLogNegativeTest.InstanceUsageAuditLogNegativeTestJSON):
    """Tests InstanceUsageAuditLogTestJSON API"""

class HybridKeyPairsV210TestJSON(KeyPairsV210Test.KeyPairsV210TestJSON):
    """Tests KeyPairsV210TestJSON API"""

class HybridNetworksTest(NetworksTest.NetworksTest):
    """Tests Nova Networks API that usually requires admin privileges.

    API docs:
    http://developer.openstack.org/api-ref-compute-v2-ext.html#ext-os-networks
    """

class HybridQuotaClassesAdminTestJSON(QuotaClassesAdminTest.QuotaClassesAdminTestJSON):
    """Tests the os-quota-class-sets API to update default quotas."""
    
class HybridQuotasAdminTestJSON(QuotasAdminTest.QuotasAdminTestJSON):
    """Test Quotas API that require admin privileges"""

class HybridQuotasAdminNegativeTestJSON(QuotasAdminNegativeTest.QuotasAdminNegativeTestJSON):
    """Test Quotas API that require admin privileges"""

    @test.attr(type=['negative'])
    @test.idempotent_id('91058876-9947-4807-9f22-f6eb17140d9b')
    def test_create_server_when_cpu_quota_is_full(self):
        # Disallow server creation when tenant's vcpu quota is full
        quota_set = (self.adm_client.show_quota_set(self.demo_tenant_id)
                     ['quota_set'])
        default_vcpu_quota = quota_set['cores']
        vcpu_quota = 0  # Set the quota to zero to conserve resources

        self.adm_client.update_quota_set(self.demo_tenant_id,
                                         force=True,
                                         cores=vcpu_quota)

        self.addCleanup(self.adm_client.update_quota_set, self.demo_tenant_id,
                        cores=default_vcpu_quota)
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                          self.create_test_server, availability_zone=CONF.compute.default_availability_zone)

    @test.attr(type=['negative'])
    @test.idempotent_id('6fdd7012-584d-4327-a61c-49122e0d5864')
    def test_create_server_when_memory_quota_is_full(self):
        # Disallow server creation when tenant's memory quota is full
        quota_set = (self.adm_client.show_quota_set(self.demo_tenant_id)
                     ['quota_set'])
        default_mem_quota = quota_set['ram']
        mem_quota = 0  # Set the quota to zero to conserve resources

        self.adm_client.update_quota_set(self.demo_tenant_id,
                                         force=True,
                                         ram=mem_quota)

        self.addCleanup(self.adm_client.update_quota_set, self.demo_tenant_id,
                        ram=default_mem_quota)
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                          self.create_test_server, availability_zone=CONF.compute.default_availability_zone)

    @test.attr(type=['negative'])
    @test.idempotent_id('7c6be468-0274-449a-81c3-ac1c32ee0161')
    def test_create_server_when_instances_quota_is_full(self):
        # Once instances quota limit is reached, disallow server creation
        quota_set = (self.adm_client.show_quota_set(self.demo_tenant_id)
                     ['quota_set'])
        default_instances_quota = quota_set['instances']
        instances_quota = 0  # Set quota to zero to disallow server creation

        self.adm_client.update_quota_set(self.demo_tenant_id,
                                         force=True,
                                         instances=instances_quota)
        self.addCleanup(self.adm_client.update_quota_set, self.demo_tenant_id,
                        instances=default_instances_quota)
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                          self.create_test_server, availability_zone=CONF.compute.default_availability_zone)


class HybridSecurityGroupDefaultRulesTest(SecurityGroupDefaultRulesTest.SecurityGroupDefaultRulesTest):
    """Test SecurityGroupDefaultRulesTest API"""

class HybridServersAdminTestJSON(ServersAdminTest.ServersAdminTestJSON):
    """Tests Servers API using admin privileges"""

    @classmethod
    def resource_setup(cls):
        super(ServersAdminTest.ServersAdminTestJSON, cls).resource_setup()

        cls.s1_name = data_utils.rand_name('server')
        server = cls.create_test_server(name=cls.s1_name,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)
        cls.s1_id = server['id']

        cls.s2_name = data_utils.rand_name('server')
        server = cls.create_test_server(name=cls.s2_name,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)
        cls.s2_id = server['id']

    @test.idempotent_id('86c7a8f7-50cf-43a9-9bac-5b985317134f')
    def test_list_servers_filter_by_exist_host(self):
        # Filter the list of servers by existent host
        name = data_utils.rand_name('server')
        network = self.get_tenant_network()
        network_kwargs = fixed_network.set_networks_kwarg(network)
        # We need to create the server as an admin, so we can't use
        # self.create_test_server() here as this method creates the server
        # in the "primary" (i.e non-admin) tenant.
        test_server, _ = compute.create_test_server(
            self.os_adm, wait_until="ACTIVE", availability_zone=CONF.compute.default_availability_zone,
            name=name, **network_kwargs)
        self.addCleanup(self.client.delete_server, test_server['id'])
        server = self.client.show_server(test_server['id'])['server']
        self.assertEqual(server['status'], 'ACTIVE')
        hostname = server[self._host_key]
        params = {'host': hostname}
        body = self.client.list_servers(**params)
        servers = body['servers']
        nonexistent_params = {'host': 'nonexistent_host'}
        nonexistent_body = self.client.list_servers(**nonexistent_params)
        nonexistent_servers = nonexistent_body['servers']
        self.assertIn(test_server['id'], map(lambda x: x['id'], servers))
        self.assertNotIn(test_server['id'],
                         map(lambda x: x['id'], nonexistent_servers))

    @test.idempotent_id('7a1323b4-a6a2-497a-96cb-76c07b945c71')
    def test_reset_network_inject_network_info(self):
        # Reset Network of a Server
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.default_availability_zone)
        self.client.reset_network(server['id'])
        # Inject the Network Info into Server
        self.client.inject_network_info(server['id'])

    @testtools.skip('Do not support host operation')
    @test.idempotent_id('fdcd9b33-0903-4e00-a1f7-b5f6543068d6')
    def test_create_server_with_scheduling_hint(self):
        # Create a server with scheduler hints.
        hints = {
            'same_host': self.s1_id
        }
        self.create_test_server(scheduler_hints=hints,
                                wait_until='ACTIVE')

    @testtools.skip('HybridCloud Bug:Do not support host operation')
    @test.idempotent_id('682cb127-e5bb-4f53-87ce-cb9003604442')
    def test_rebuild_server_in_error_state(self):
        # The server in error state should be rebuilt using the provided
        # image and changed to ACTIVE state

        # resetting vm state require admin privilege
        self.client.reset_state(self.s1_id, state='error')
        rebuilt_server = self.non_admin_client.rebuild_server(
            self.s1_id, self.image_ref_alt)['server']
        self.addCleanup(waiters.wait_for_server_status, self.non_admin_client,
                        self.s1_id, 'ACTIVE')
        self.addCleanup(self.non_admin_client.rebuild_server, self.s1_id,
                        self.image_ref)

        # Verify the properties in the initial response are correct
        self.assertEqual(self.s1_id, rebuilt_server['id'])
        rebuilt_image_id = rebuilt_server['image']['id']
        self.assertEqual(self.image_ref_alt, rebuilt_image_id)
        self.assertEqual(self.flavor_ref, rebuilt_server['flavor']['id'])
        waiters.wait_for_server_status(self.non_admin_client,
                                       rebuilt_server['id'], 'ACTIVE',
                                       raise_on_error=False)
        # Verify the server properties after rebuilding
        server = (self.non_admin_client.show_server(rebuilt_server['id'])
                  ['server'])
        rebuilt_image_id = server['image']['id']
        self.assertEqual(self.image_ref_alt, rebuilt_image_id)

class HybridServersAdminNegativeTestJSON(ServersAdminNegativeTest.ServersAdminNegativeTestJSON):
    """Tests Servers API using admin privileges"""

    @classmethod
    def resource_setup(cls):
        super(ServersAdminNegativeTest.ServersAdminNegativeTestJSON, cls).resource_setup()
        cls.tenant_id = cls.client.tenant_id

        cls.s1_name = data_utils.rand_name('server')
        server = cls.create_test_server(name=cls.s1_name,
                                        wait_until='ACTIVE',
                                        availability_zone=CONF.compute.default_availability_zone)
        cls.s1_id = server['id']

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('e84e2234-60d2-42fa-8b30-e2d3049724ac')
    def test_get_server_diagnostics_by_non_admin(self):
        # Non-admin user can not view server diagnostics according to policy
        self.assertRaises(lib_exc.Forbidden,
                          self.non_adm_client.show_server_diagnostics,
                          self.s1_id)

    @testtools.skip('Do not support host operation')
    @test.attr(type=['negative'])
    @test.idempotent_id('46a4e1ca-87ae-4d28-987a-1b6b136a0221')
    def test_migrate_non_existent_server(self):
        # migrate a non existent server
        self.assertRaises(lib_exc.NotFound,
                          self.client.migrate_server,
                          str(uuid.uuid4()))

class HybridServicesAdminTestJSON(ServicesAdminTest.ServicesAdminTestJSON):
    """Tests Services API. List and Enable/Disable require admin privileges."""

class HybridServicesAdminNegativeTestJSON(ServicesAdminNegativeTest.ServicesAdminNegativeTestJSON):
    """Tests Services API. List and Enable/Disable require admin privileges."""

class HybridTenantUsagesTestJSON(TenantUsagesTest.TenantUsagesTestJSON):
    """Tests TenantUsage API. require admin privileges."""
    @classmethod
    def resource_setup(cls):
        super(TenantUsagesTest.TenantUsagesTestJSON, cls).resource_setup()
        cls.tenant_id = cls.client.tenant_id

        # Create a server in the demo tenant
        cls.create_test_server(wait_until='ACTIVE',
                    availability_zone=CONF.compute.default_availability_zone)

        now = datetime.datetime.now()
        cls.start = cls._parse_strtime(now - datetime.timedelta(days=1))
        cls.end = cls._parse_strtime(now + datetime.timedelta(days=1))

    @testtools.skip('Do not support with origin policy')
    @test.idempotent_id('9d00a412-b40e-4fd9-8eba-97b496316116')
    def test_get_usage_tenant_with_non_admin_user(self):
        # Get usage for a specific tenant with non admin user
        tenant_usage = self.call_until_valid(
            self.client.show_tenant_usage, VALID_WAIT,
            self.tenant_id, start=self.start, end=self.end)['tenant_usage']
        self.assertEqual(len(tenant_usage), 8)

class HybridTenantUsagesNegativeTestJSON(TenantUsagesNegativeTest.TenantUsagesNegativeTestJSON):
    """Tests TenantUsage API. require admin privileges."""
