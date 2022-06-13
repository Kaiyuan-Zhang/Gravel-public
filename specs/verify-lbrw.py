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
from lb_rw import LBStorage, Scheduler, IPFilter, TcpFilter


class ElementVerifyTest(unittest.TestCase):
    def setUp(self):
        build_dir = os.environ.get("GRAVEL_BUILD_DIR", "./build")
        self.lib = load_lib(os.path.join(build_dir, "libcobbleso.so"))

    def test_lb_storage(self):
        ele = LBStorage()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="LBStorage") 
        self.assertTrue(result.verified)

    def test_lb_scheduler(self):
        ele = Scheduler()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="LBScheduler") 
        self.assertTrue(result.verified)

    def test_lb_ipfilter(self):
        ele = IPFilter()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="SimpleIPFilter") 
        self.assertTrue(result.verified)

    def test_lb_tcpfilter(self):
        ele = TcpFilter()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="SimpleTCPFilter") 
        self.assertTrue(result.verified)
