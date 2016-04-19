# Copyright 2014 NEC Corporation. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.api.baremetal.admin import base
from tempest import config
from tempest import test

CONF = config.CONF


class TestDrivers(base.BaseBaremetalTest):
    """Tests for drivers."""
    @classmethod
    def resource_setup(cls):
        super(TestDrivers, cls).resource_setup()
        cls.driver_name = CONF.baremetal.driver

    @test.idempotent_id('5aed2790-7592-4655-9b16-99abcc2e6ec5')
    def test_list_drivers(self):
        _, drivers = self.client.list_drivers()
        self.assertIn(self.driver_name,
                      [d['name'] for d in drivers['drivers']])

    @test.idempotent_id('fb3287a3-c4d7-44bf-ae9d-1eef906d78ce')
    def test_show_driver(self):
        _, driver = self.client.show_driver(self.driver_name)
        self.assertEqual(self.driver_name, driver['name'])
