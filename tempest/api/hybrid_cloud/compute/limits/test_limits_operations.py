import testtools
from oslo_log import log

from tempest.api.compute import base
import tempest.api.compute.limits.test_absolute_limits as AbsoluteLimitsTest
import tempest.api.compute.limits.test_absolute_limits_negative as AbsoluteLimitsNegativeTest
from tempest.common.utils import data_utils
from tempest.common import waiters
from tempest.lib import exceptions as lib_exc
from tempest.lib import decorators
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridAbsoluteLimitsTestJSON(AbsoluteLimitsTest.AbsoluteLimitsTestJSON):
    """Test absolute limits"""

class HybridAbsoluteLimitsNegativeTestJSON(AbsoluteLimitsNegativeTest.AbsoluteLimitsNegativeTestJSON):
    """Test absolute limits negative"""

    @test.attr(type=['negative'])
    @test.idempotent_id('215cd465-d8ae-49c9-bf33-9c911913a5c8')
    def test_max_image_meta_exceed_limit(self):
        # We should not create vm with image meta over maxImageMeta limit
        # Get max limit value
        limits = self.client.show_limits()['limits']
        max_meta = limits['absolute']['maxImageMeta']

        # No point in running this test if there is no limit.
        if int(max_meta) == -1:
            raise self.skipException('no limit for maxImageMeta')

        # Create server should fail, since we are passing > metadata Limit!
        max_meta_data = int(max_meta) + 1

        meta_data = {}
        for xx in range(max_meta_data):
            meta_data[str(xx)] = str(xx)

        # A 403 Forbidden or 413 Overlimit (old behaviour) exception
        # will be raised when out of quota
        self.assertRaises((lib_exc.Forbidden, lib_exc.OverLimit),
                            self.create_test_server, metadata=meta_data,
                            availability_zone=CONF.compute.default_availability_zone)

