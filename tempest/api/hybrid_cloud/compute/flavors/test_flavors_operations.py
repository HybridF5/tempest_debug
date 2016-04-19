import testtools
from oslo_log import log

from tempest.api.compute import base
import tempest.api.compute.flavors.test_flavors as FlavorsV2Test
import tempest.api.compute.flavors.test_flavors_negative as FlavorsListWithDetailsNegativeTest
import tempest.api.compute.flavors.test_flavors_negative as FlavorDetailsNegativeTest
from tempest.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.lib import decorators
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridFlavorsV2TestJSON(FlavorsV2Test.FlavorsV2TestJSON):
    """Test flavors"""

@test.SimpleNegativeAutoTest
class HybridFlavorsListWithDetailsNegativeTestJSON(FlavorsListWithDetailsNegativeTest.FlavorsListWithDetailsNegativeTestJSON):
    """Test FlavorsListWithDetails"""

@test.SimpleNegativeAutoTest
class HybridFlavorDetailsNegativeTestJSON(FlavorDetailsNegativeTest.FlavorDetailsNegativeTestJSON):
    """Test FlavorsListWithDetails"""