from .bindings import *
from functools import reduce
from .click_element import *

def ip2num(ip):
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))

def ether2num(addr):
    byte_list = addr
    if type(addr) == str:
        byte_list = list(map(lambda s: int(s, 16), addr.split(':')))
    assert type(byte_list) == list, byte_list
    return reduce(lambda x, y: (x << 8) + y, byte_list)

class ClickMap(ElementField):
    def __init__(self, key_type, val_type):
        self.key_type = key_type
        self.val_type = val_type

    @staticmethod
    def get_size(t):
        if isinstance(t, int):
            return (t,)
        elif 'size_tuple' in dir(t):
            return t.size_tuple()
        elif 'num_bytes' in dir(t):
            return (t.num_bytes(),)
        else:
            try:
                return (sizeof(t),)
            except TypeError as e:
                assert False, e

    def instance(self, name):
        key_size = self.get_size(self.key_type)
        val_size = self.get_size(self.val_type)
        return ExactMap(name, key_size, val_size)

    def cobble_instance(self, name, lib):
        key_size = list(map(lambda x: x * 8, self.get_size(self.key_type)))
        val_size = list(map(lambda x: x * 8, self.get_size(self.val_type)))
        return CobbleMap(lib, name, key_size, val_size)


class ClickVal(ElementField):
    def __init__(self, key_type):
        self.size = None
        if isinstance(key_type, int):
            self.size = key_type
        else:
            try:
                self.size = sizeof(key_type)
            except TypeError as e:
                assert False, e

    def instance(self, name):
        return fresh_bv(name, self.size * 8)

    def cobble_instance(self, name, lib):
        return CobbleSymVal(lib, lib.mk_bv_var(fresh_name(name).encode('utf-8'), self.size * 8))


class IPFlowID(SpecStruct):
    _fields = [('saddr', sizeof(c_int)),
               ('daddr', sizeof(c_int)),
               ('sport', sizeof(c_short)),
               ('dport', sizeof(c_short))]
    _struct_name = 'IPFlowID'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def get_flowid(p):
    flow = IPFlowID()
    is_tcp = (p.ip.proto == 6)
    flow.saddr = p.ip.src
    flow.daddr = p.ip.dst
    flow.sport = If(is_tcp, p.tcp.src, p.udp.src)
    flow.dport = If(is_tcp, p.tcp.dst, p.udp.dst)
    return flow

def get_pkt_conds(ps):
    result = []
    for k, v in ps.items():
        if 'get_num_cond' in dir(v):
            result.append(v.get_num_cond())

def get_state_num_conds(s):
    return len(s.states)
