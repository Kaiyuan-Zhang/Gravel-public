from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from gravel_spec.click_common import *
from gravel_spec.click_api import *
import unittest


class ElementVerifyTest(unittest.TestCase):
    def setUp(self):
        self.lib = load_lib("./build/libcobbleso.so")

    def test_my_ip_rewriter(self):
        rw = MyIPRewriterMod(0)
        result = rw.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="MyIPRewriterMod") 
        self.assertTrue(result.verified)
