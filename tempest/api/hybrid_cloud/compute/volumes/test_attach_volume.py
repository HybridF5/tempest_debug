# Copyright 2013 IBM Corp.
# All Rights Reserved.
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

import testtools

from tempest.common import waiters
from tempest import config
import tempest.api.compute.volumes.test_attach_volume as VolumeAttachTest

CONF = config.CONF


class HybridVCloudAttachVolumeTestJSON(VolumeAttachTest.AttachVolumeTestJSON):

    def _create_and_attach(self):
        # Start a server and wait for it to become ready
        self.admin_pass = self.image_ssh_password
        self.server = self.create_test_server(
            validatable=True,
            wait_until='ACTIVE',
            adminPass=self.admin_pass, availability_zone=CONF.compute.vcloud_availability_zone)

        # Record addresses so that we can ssh later
        self.server['addresses'] = self.servers_client.list_addresses(
            self.server['id'])['addresses']

        # Create a volume and wait for it to become ready
        self.volume = self.volumes_client.create_volume(
            size=CONF.volume.volume_size, display_name='test', availability_zone=CONF.compute.vcloud_availability_zone)['volume']
        self.addCleanup(self._delete_volume)
        waiters.wait_for_volume_status(self.volumes_client,
                                       self.volume['id'], 'available')

        # Attach the volume to the server
        self.attachment = self.servers_client.attach_volume(
            self.server['id'],
            volumeId=self.volume['id'],
            device='/dev/%s' % self.device)['volumeAttachment']
        waiters.wait_for_volume_status(self.volumes_client,
                                       self.volume['id'], 'in-use')

        self.addCleanup(self._detach, self.server['id'], self.volume['id'])

class HybridAWSAttachVolumeTestJSON(VolumeAttachTest.AttachVolumeTestJSON):

    def _create_and_attach(self):
        # Start a server and wait for it to become ready
        self.admin_pass = self.image_ssh_password
        self.server = self.create_test_server(
            validatable=True,
            wait_until='ACTIVE',
            adminPass=self.admin_pass, availability_zone=CONF.compute.aws_availability_zone)

        # Record addresses so that we can ssh later
        self.server['addresses'] = self.servers_client.list_addresses(
            self.server['id'])['addresses']

        # Create a volume and wait for it to become ready
        self.volume = self.volumes_client.create_volume(
            size=CONF.volume.volume_size, display_name='test', availability_zone=CONF.compute.aws_availability_zone)['volume']
        self.addCleanup(self._delete_volume)
        waiters.wait_for_volume_status(self.volumes_client,
                                       self.volume['id'], 'available')

        # Attach the volume to the server
        self.attachment = self.servers_client.attach_volume(
            self.server['id'],
            volumeId=self.volume['id'],
            device='/dev/%s' % self.device)['volumeAttachment']
        waiters.wait_for_volume_status(self.volumes_client,
                                       self.volume['id'], 'in-use')

        self.addCleanup(self._detach, self.server['id'], self.volume['id'])

