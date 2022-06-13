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
from lb_rw import Scheduler


class ElementVerifyTest(unittest.TestCase):
    def setUp(self):
        self.lib = load_lib("./build/libcobbleso.so")

    def test_lb_scheduler(self):
        ele = Scheduler()
        result = ele.verify_pkt_handler(self.lib, "./ir-dir/all.ll", COMMON_PKT, element_name="LBScheduler") 
        self.assertTrue(result.verified)
