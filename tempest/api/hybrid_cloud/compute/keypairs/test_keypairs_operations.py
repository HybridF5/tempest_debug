import testtools
from oslo_log import log

from tempest.api.compute import base
import tempest.api.compute.keypairs.test_keypairs as KeyPairsV2Test
import tempest.api.compute.keypairs.test_keypairs_negative as KeyPairsNegativeTest
import tempest.api.compute.keypairs.test_keypairs_v22 as KeyPairsV22Test
from tempest.common.utils import data_utils
from tempest.common import waiters
from tempest.lib import exceptions as lib_exc
from tempest.lib import decorators
from tempest import test
from tempest import config

CONF = config.CONF

LOG = log.getLogger(__name__)

class HybridKeyPairsV2TestJSON(KeyPairsV2Test.KeyPairsV2TestJSON):
    """Test Keypairs v2"""

class HybridKeyPairsNegativeTestJSON(KeyPairsNegativeTest.KeyPairsNegativeTestJSON):
    """Test Keypairs negative"""

class HybridKeyPairsV22TestJSON(KeyPairsV22Test.KeyPairsV22TestJSON):
    """Test Keypairs v22"""