from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from gravel_spec.click_common import *
from gravel_spec.click_api import *
import unittest

import os

class ElementVerifyTest(unittest.TestCase):
    def setUp(self):
        build_dir = os.environ.get("GRAVEL_BUILD_DIR", "./build")
        self.lib = load_lib(os.path.join(build_dir, "libcobbleso.so"))

    def test_proxyrewriter(self):
        ele = ProxyRewriter()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="ProxyRewriter") 
        self.assertTrue(result.verified)
