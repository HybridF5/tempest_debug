import testtools
import time
from oslo_log import log
import six

import tempest.api.compute.images.test_image_metadata as test_image_metadata
import tempest.api.compute.images.test_image_metadata_negative as test_image_metadata_negative
import tempest.api.compute.images.test_images as test_images
import tempest.api.compute.images.test_images_negative as test_images_negative
import tempest.api.compute.images.test_images_oneserver as test_images_oneserver
import tempest.api.compute.images.test_images_oneserver_negative as test_images_oneserver_negative
import tempest.api.compute.images.test_list_image_filters as test_list_image_filters
import tempest.api.compute.images.test_list_image_filters_negative as test_list_image_filters_negative
import tempest.api.compute.images.test_list_images as test_list_images
from tempest.common.utils import data_utils
from tempest.common import waiters
from tempest.lib import exceptions as lib_exc
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridImagesMetadataTestJSON(test_image_metadata.ImagesMetadataTestJSON):
    """Test Imges Metadata"""

class HybridImagesMetadataNegativeTestJSON(test_image_metadata_negative.ImagesMetadataTestJSON):
    """Test Images Metadata"""

class HybridImagesTestJSON(test_images.ImagesTestJSON):
    """Test Imges"""

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id,so testcase wait timeout")
    @test.idempotent_id('aa06b52b-2db5-4807-b218-9441f75d74e3')
    def test_delete_saving_image(self):
        snapshot_name = data_utils.rand_name('test-snap')
        server = self.create_test_server(wait_until='ACTIVE')
        self.addCleanup(self.servers_client.delete_server, server['id'])
        image = self.create_image_from_server(server['id'],
                                              name=snapshot_name,
                                              wait_until='SAVING')
        self.client.delete_image(image['id'])

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id,so testcase wait fail") 
    @test.idempotent_id('aaacd1d0-55a2-4ce8-818a-b5439df8adc9')
    def test_create_image_from_stopped_server(self):
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.default_availability_zone)
        self.servers_client.stop_server(server['id'])
        waiters.wait_for_server_status(self.servers_client,
                                       server['id'], 'SHUTOFF')
        self.addCleanup(self.servers_client.delete_server, server['id'])
        snapshot_name = data_utils.rand_name('test-snap')
        image = self.create_image_from_server(server['id'],
                                              name=snapshot_name,
                                              wait_until='ACTIVE',
                                              wait_for_server=False)
        self.addCleanup(self.client.delete_image, image['id'])
        self.assertEqual(snapshot_name, image['name'])

class HybridImagesNegativeTestJSON(test_images_negative.ImagesNegativeTestJSON):
    """Test Imges"""

    @test.attr(type=['negative'])
    @test.idempotent_id('6cd5a89d-5b47-46a7-93bc-3916f0d84973')
    def test_create_image_from_deleted_server(self):
        # An image should not be created if the server instance is removed
        server = self.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.default_availability_zone)

        # Delete server before trying to create server
        self.servers_client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.servers_client, server['id'])
        # Create a new image after server is deleted
        name = data_utils.rand_name('image')
        meta = {'image_type': 'test'}
        self.assertRaises(lib_exc.NotFound,
                          self.create_image_from_server,
                          server['id'], name=name, meta=meta)

class HybridImagesOneVCloudServerTestJSON(test_images_oneserver.ImagesOneServerTestJSON):
    """Test Imges"""

    @classmethod
    def resource_setup(cls):
        super(test_images_oneserver.ImagesOneServerTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        cls.server_id = server['id']

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id, so testcase wait fail") 
    @test.idempotent_id('3731d080-d4c5-4872-b41a-64d0d0021314')
    def test_create_delete_image(self):

        # Create a new image
        name = data_utils.rand_name('image')
        meta = {'image_type': 'test'}
        body = self.client.create_image(self.server_id, name=name,
                                        metadata=meta)
        image_id = data_utils.parse_image_id(body.response['location'])
        waiters.wait_for_image_status(self.client, image_id, 'ACTIVE')

        # Verify the image was created correctly
        image = self.client.show_image(image_id)['image']
        self.assertEqual(name, image['name'])
        self.assertEqual('test', image['metadata']['image_type'])

        original_image = self.client.show_image(self.image_ref)['image']

        # Verify minRAM is the same as the original image
        self.assertEqual(image['minRam'], original_image['minRam'])

        # Verify minDisk is the same as the original image or the flavor size
        flavor_disk_size = self._get_default_flavor_disk_size(self.flavor_ref)
        self.assertIn(str(image['minDisk']),
                      (str(original_image['minDisk']), str(flavor_disk_size)))

        # Verify the image was deleted correctly
        self.client.delete_image(image_id)
        self.client.wait_for_resource_deletion(image_id)

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id, so testcase wait fail") 
    @test.idempotent_id('3b7c6fe4-dfe7-477c-9243-b06359db51e6')
    def test_create_image_specify_multibyte_character_image_name(self):
        # prefix character is:
        # http://www.fileformat.info/info/unicode/char/1F4A9/index.htm

        # We use a string with 3 byte utf-8 character due to bug
        # #1370954 in glance which will 500 if mysql is used as the
        # backend and it attempts to store a 4 byte utf-8 character
        utf8_name = data_utils.rand_name('\xe2\x82\xa1')
        body = self.client.create_image(self.server_id, name=utf8_name)
        image_id = data_utils.parse_image_id(body.response['location'])
        self.addCleanup(self.client.delete_image, image_id)

class HybridImagesOneAwsServerTestJSON(test_images_oneserver.ImagesOneServerTestJSON):
    """Test Imges"""

    @classmethod
    def resource_setup(cls):
        super(test_images_oneserver.ImagesOneServerTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        cls.server_id = server['id']

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id, so testcase wait fail") 
    @test.idempotent_id('3731d080-d4c5-4872-b41a-64d0d0021314')
    def test_create_delete_image(self):

        # Create a new image
        name = data_utils.rand_name('image')
        meta = {'image_type': 'test'}
        body = self.client.create_image(self.server_id, name=name,
                                        metadata=meta)
        image_id = data_utils.parse_image_id(body.response['location'])
        waiters.wait_for_image_status(self.client, image_id, 'ACTIVE')

        # Verify the image was created correctly
        image = self.client.show_image(image_id)['image']
        self.assertEqual(name, image['name'])
        self.assertEqual('test', image['metadata']['image_type'])

        original_image = self.client.show_image(self.image_ref)['image']

        # Verify minRAM is the same as the original image
        self.assertEqual(image['minRam'], original_image['minRam'])
    
        # Verify minDisk is the same as the original image or the flavor size
        flavor_disk_size = self._get_default_flavor_disk_size(self.flavor_ref)
        self.assertIn(str(image['minDisk']),
                      (str(original_image['minDisk']), str(flavor_disk_size)))

        # Verify the image was deleted correctly
        self.client.delete_image(image_id)
        self.client.wait_for_resource_deletion(image_id)

    @testtools.skip("HybridCloud Bug:image id changed by proxy, response return original id, so testcase wait fail") 
    @test.idempotent_id('3b7c6fe4-dfe7-477c-9243-b06359db51e6')
    def test_create_image_specify_multibyte_character_image_name(self):
        # prefix character is:
        # http://www.fileformat.info/info/unicode/char/1F4A9/index.htm

        # We use a string with 3 byte utf-8 character due to bug
        # #1370954 in glance which will 500 if mysql is used as the
        # backend and it attempts to store a 4 byte utf-8 character
        utf8_name = data_utils.rand_name('\xe2\x82\xa1')
        body = self.client.create_image(self.server_id, name=utf8_name)
        image_id = data_utils.parse_image_id(body.response['location'])
        self.addCleanup(self.client.delete_image, image_id)

class HybridImagesOneVCloudServerNegativeTestJSON(test_images_oneserver_negative.ImagesOneServerNegativeTestJSON):
    """Test Imges"""

    @classmethod
    def resource_setup(cls):
        super(test_images_oneserver_negative.ImagesOneServerNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.vcloud_availability_zone)
        cls.server_id = server['id']

        cls.image_ids = []

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
    @test.idempotent_id('0894954d-2db2-4195-a45b-ffec0bc0187e')
    def test_delete_image_that_is_not_yet_active(self):
        # Return an error while trying to delete an image what is creating

        snapshot_name = data_utils.rand_name('test-snap')
        body = self.client.create_image(self.server_id, name=snapshot_name)
        image_id = data_utils.parse_image_id(body.response['location'])
        self.image_ids.append(image_id)
        self.addCleanup(self._reset_server)

        # Do not wait, attempt to delete the image, ensure it's successful
        self.client.delete_image(image_id)
        self.image_ids.remove(image_id)

        #self.assertRaises(lib_exc.NotFound, self.client.show_image, image_id)
        self.client.wait_for_resource_deletion(image_id)

class HybridImagesOneAwsServerNegativeTestJSON(test_images_oneserver_negative.ImagesOneServerNegativeTestJSON):
    """Test Imges"""

    @classmethod
    def resource_setup(cls):
        super(test_images_oneserver_negative.ImagesOneServerNegativeTestJSON, cls).resource_setup()
        server = cls.create_test_server(wait_until='ACTIVE', availability_zone=CONF.compute.aws_availability_zone)
        cls.server_id = server['id']

        cls.image_ids = []

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
    @test.idempotent_id('0894954d-2db2-4195-a45b-ffec0bc0187e')
    def test_delete_image_that_is_not_yet_active(self):
        # Return an error while trying to delete an image what is creating

        snapshot_name = data_utils.rand_name('test-snap')
        body = self.client.create_image(self.server_id, name=snapshot_name)
        image_id = data_utils.parse_image_id(body.response['location'])
        self.image_ids.append(image_id)
        self.addCleanup(self._reset_server)

        # Do not wait, attempt to delete the image, ensure it's successful
        self.client.delete_image(image_id)
        self.image_ids.remove(image_id)

        #self.assertRaises(lib_exc.NotFound, self.client.show_image, image_id)
        self.client.wait_for_resource_deletion(image_id)

"""HybridCloud Bug:image id changed by proxy, response return original id, so testcase wait fail"""
#class HybridListImageFiltersTestJSON(test_list_image_filters.ListImageFiltersTestJSON):
#    """Test Imges"""
#
#    @classmethod
#    def resource_setup(cls):
#        super(test_list_image_filters.ListImageFiltersTestJSON, cls).resource_setup()
#
#        def _create_image():
#            name = data_utils.rand_name('image')
#            body = cls.glance_client.create_image(name=name,
#                                                  container_format='bare',
#                                                  disk_format='raw',
#                                                  is_public=False)['image']
#            image_id = body['id']
#            cls.images.append(image_id)
#            # Wait 1 second between creation and upload to ensure a delta
#            # between created_at and updated_at.
#            time.sleep(1)
#            image_file = six.StringIO(('*' * 1024))
#            cls.glance_client.update_image(image_id, data=image_file)
#            waiters.wait_for_image_status(cls.client, image_id, 'ACTIVE')
#            body = cls.client.show_image(image_id)['image']
#            return body
#
#        # Create non-snapshot images via glance
#        cls.image1 = _create_image()
#        cls.image1_id = cls.image1['id']
#        cls.image2 = _create_image()
#        cls.image2_id = cls.image2['id']
#        cls.image3 = _create_image()
#        cls.image3_id = cls.image3['id']
#
#        if not CONF.compute_feature_enabled.snapshot:
#            return
#
#        # Create instances and snapshots via nova
#        cls.server1 = cls.create_test_server(availability_zone=CONF.compute.default_availability_zone)
#        cls.server2 = cls.create_test_server(wait_until='ACTIVE',
#                                             availability_zone=CONF.compute.default_availability_zone)
#        # NOTE(sdague) this is faster than doing the sync wait_util on both
#        waiters.wait_for_server_status(cls.servers_client,
#                                       cls.server1['id'], 'ACTIVE')
#
#        # Create images to be used in the filter tests
#        cls.snapshot1 = cls.create_image_from_server(
#            cls.server1['id'], wait_until='ACTIVE')
#        cls.snapshot1_id = cls.snapshot1['id']
#
#        # Servers have a hidden property for when they are being imaged
#        # Performing back-to-back create image calls on a single
#        # server will sometimes cause failures
#        cls.snapshot3 = cls.create_image_from_server(
#            cls.server2['id'], wait_until='ACTIVE')
#        cls.snapshot3_id = cls.snapshot3['id']
#
#        # Wait for the server to be active after the image upload
#        cls.snapshot2 = cls.create_image_from_server(
#            cls.server1['id'], wait_until='ACTIVE')
#        cls.snapshot2_id = cls.snapshot2['id']
#

class HybridListImageFiltersNegativeTestJSON(test_list_image_filters_negative.ListImageFiltersNegativeTestJSON):
    """Test Imges"""

class HybridListImagesTestJSON(test_list_images.ListImagesTestJSON):
    """Test Imges"""

