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
