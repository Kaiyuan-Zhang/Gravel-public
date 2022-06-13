from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from gravel_spec.click_common import *
from gravel_spec.click_api import *
import unittest


import os
import sys
sys.path.append(os.path.realpath(__file__ + '/../'))
from fw import IPFilter, IPClassifier, TCPFW


class ElementVerifyTest(unittest.TestCase):
    def setUp(self):
        build_dir = os.environ.get("GRAVEL_BUILD_DIR", "./build")
        self.lib = load_lib(os.path.join(build_dir, "libcobbleso.so"))

    def test_fw_ipfilter(self):
        ele = IPFilter()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="SimpleIPFilter") 
        self.assertTrue(result.verified)

    def test_fw_tcpfilter(self):
        ele = IPClassifier()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="SimpleTCPFilter") 
        self.assertTrue(result.verified)

    def test_fw_tcpfw(self):
        ele = TCPFW()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="SimpleTCPFW") 
        self.assertTrue(result.verified)
