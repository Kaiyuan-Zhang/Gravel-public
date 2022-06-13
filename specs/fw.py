from gravel_spec.utils import *
from gravel_spec.ops import *
from gravel_spec.element import *
from gravel_spec.click_api import *
from gravel_spec.click_element import *
from gravel_spec.graph import *
from gravel_spec.config import *


EXTERNAL = 0
INTERNAL = 1

def is_tcp(p, se=z3):
    return se.And(p.ether.ether_type == 0x0800,
                  p.ip.proto == 6)

def is_tcp_syn(p, se=z3):
    return (p.tcp.flags & 0x02) != 0


def is_tcp_fin(p, se=z3):
    return (p.tcp.flags & 0x01) != 0

def is_tcp_rst(p, se=z3):
    return (p.tcp.flags & 0x04) != 0


class IPFilter(ClickElement):
    ele_name = 'IPFilter'
    num_in_ports = 1
    num_out_ports = 1

    def process_packet(self, old, p, in_port, se=z3):
        ether_type = p.ether.ether_type
        return [{ 'pre_cond' : ether_type == 0x0800,
                  'packets' : { 0 : p },
                  'new_state' : old }]
    def impl_state_equiv(self, lib, spec_state, impl_state):
        se = CobbleSymGen(lib)
        return se.BoolVal(True).inner()


class IPClassifier(ClickElement):
    ele_name = 'udp_tcp_filter'
    num_in_ports = 1
    num_out_ports = 1

    def process_packet(self, old, p, in_port, se=z3):
        proto = p.ip.proto
        return [{ 'pre_cond' : proto == 6,
                  'packets' : { 0 : p },
                  'new_state' : old }]
    def impl_state_equiv(self, lib, spec_state, impl_state):
        se = CobbleSymGen(lib)
        return se.BoolVal(True).inner()


class TCPFW(ClickElement):
    ele_name = 'TCP_firewall'
    num_in_ports = 2
    num_out_ports = 2

    # private_state_type = [('flows', 'map', (4, 2, 4, 2), (1,))]
    flows = ClickMap(IPFlowID, 1)

    def process_packet(self, old, p, in_port, se=z3):
        actions = []
        ext_flow_id = IPFlowID()
        ext_flow_id.saddr = p.ip.src
        ext_flow_id.daddr = p.ip.dst
        ext_flow_id.sport = p.tcp.src
        ext_flow_id.dport = p.tcp.dst

        int_flow_id = IPFlowID()
        int_flow_id.saddr = p.ip.dst
        int_flow_id.daddr = p.ip.src
        int_flow_id.sport = p.tcp.dst
        int_flow_id.dport = p.tcp.src

        is_external = in_port == EXTERNAL

        has_mapping = old.flows.has_key(ext_flow_id.to_tuple())

        should_remove = se.Or(is_tcp_fin(p, se), is_tcp_rst(p, se))
        should_add = is_tcp_syn(p, se)

        removed = old.copy()
        removed.flows.delete(ext_flow_id.to_tuple())
        # new_ext = se.If(se.Or(is_tcp_fin(p, se), is_tcp_rst(p, se)), removed, old)

        # actions += Action(se.And(is_external, has_mapping, should_remove),
        #         {1 : p}, removed)
        actions += Action(se.And(is_external, has_mapping), #, se.Not(should_remove)),
                {1 : p}, old)

        flow_added = old.copy()
        flow_added.flows[int_flow_id.to_tuple()] = se.BitVecVal(1, 8)
        flow_removed = old.copy()
        flow_removed.flows.delete(int_flow_id.to_tuple())

        # new = se.If(is_tcp_syn(p, se), flow_added,
        #             se.If(se.Or(is_tcp_fin(p, se), is_tcp_rst(p, se)), flow_removed, old))

        actions += Action(se.And(se.Not(is_external), should_add), {0 : p}, flow_added)
        actions += Action(se.And(se.Not(is_external), se.Not(should_add), should_remove), {0 : p}, flow_removed)
        actions += Action(se.And(se.Not(is_external), se.Not(should_add), se.Not(should_remove)),
                {0 : p}, old)

        return actions

    def impl_state_equiv(self, lib, spec_state, impl_state):
        se = CobbleSymGen(lib)
        flows = lib.get_obj_handle_by_off(impl_state, 112)
        def flow_id_eq(spec_id, impl_id):
            impl_saddr = se.bv_bswap(se.bv_extract_from_top(impl_id[0], 0, 32))
            impl_daddr = se.bv_bswap(se.bv_extract_from_top(impl_id[0], 32, 64))
            impl_sport = se.bv_bswap(se.bv_extract_from_top(impl_id[0], 64, 80))
            impl_dport = se.bv_bswap(se.bv_extract_from_top(impl_id[0], 80, 96))
            # impl_fields = [impl_saddr, impl_daddr, impl_sport, impl_dport]
            # spec_bv = se.Concat(*spec_id)
            # impl_bv = se.Concat(*impl_fields)
            # return spec_bv == impl_bv
            return se.And(impl_saddr == spec_id[0], impl_daddr == spec_id[1],
                          impl_sport == spec_id[2], impl_dport == spec_id[3])
        return spec_state.flows.map_eq(flows, impl_key_sz=[96],
                key_eq_func=flow_id_eq, vals_eq_func=lambda s, i: s[0] == i[0])


def flow_id_ext(p):
    return (p.ip.src, p.tcp.src, p.ip.dst, p.tcp.dst)

def flow_id_int(p):
    return (p.ip.dst, p.tcp.dst, p.ip.src, p.tcp.src)

def is_flow_end(p):
    return Or(is_tcp_fin(p), is_tcp_rst(p))

class FWTasks(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        parser = HeaderParser()
        parser.add_header('ether', ETHER_HDR)
        parser.add_header('ip', IPv4_HDR)
        parser.add_header('tcp', TCP_HDR)
        parser.add_header('payload', [('data', 1500)])

        path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0800), 'ip') \
               >> (('proto', 'eq', 6), 'tcp')  >> (('always'), 'payload')
        parser.add_edges(path)

        elements = [('ext_in', Source),
                    ('ext_out', Sink),
                    ('int_in', Source),
                    ('int_out', Sink),
                    ('ip_filter_ext', IPFilter),
                    ('ip_mux_ext', IPClassifier),
                    ('ip_filter_int', IPFilter),
                    ('ip_mux_int', IPClassifier),
                    ('tcp_fw', TCPFW)]

        path_tcp_ext = Path('ext_in', 0) >> (0, 'ip_filter_ext', 0) \
                       >> (0, 'ip_mux_ext', 0) >> (0, 'tcp_fw', 0) >> (0, 'ext_out')
        path_tcp_int = Path('int_in', 0) >> (0, 'ip_filter_int', 0) \
                       >> (0, 'ip_mux_int', 0) >> (1, 'tcp_fw', 1) >> (0, 'int_out')
        edges = (path_tcp_ext + path_tcp_int).edges()
        return Config(elements, edges, parser)

    def test_tcp_only(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()
        o, _ = c.process_packet(s, 'ext_in', p)
        self.verify(Implies(Not(o['int_out'].is_empty()),
                            is_tcp(p)))

    def test_memorize_step_ext(self):
        c = self.conf()
        p0, s0 = c.sym_pkt(), c.sym_state()
        o0, _ = c.process_packet(s0, 'ext_in', p0)
        p_other = c.sym_pkt()
        p1 = c.sym_pkt()
        _, s_prime_1 = c.process_packet(s0, 'ext_in', p_other)
        o1, _ = c.process_packet(s_prime_1, 'ext_in', p1)
        self.verify(Implies(And(Not(o0['int_out'].is_empty()),
                                is_tcp(p1),
                                Eq(flow_id_ext(p0), flow_id_ext(p1)),
                                Not(And(Eq(flow_id_ext(p0), flow_id_ext(p_other)),
                                        is_flow_end(p_other)))),
                            Not(o1['int_out'].is_empty())))

        _, s_prime_2 = c.process_packet(s0, 'int_in', p_other)
        o2, _ = c.process_packet(s_prime_2, 'ext_in', p1)
        self.verify(Implies(And(Not(o0['int_out'].is_empty()),
                                is_tcp(p1),
                                Eq(flow_id_ext(p0), flow_id_ext(p1)),
                                Not(And(Eq(flow_id_ext(p0), flow_id_int(p_other)),
                                        is_flow_end(p_other)))),
                            Not(o2['int_out'].is_empty())))

    def test_memorize_step_int(self):
        c = self.conf()
        p0, s0 = c.sym_pkt(), c.sym_state()
        o0, _ = c.process_packet(s0, 'int_in', p0)
        p_other = c.sym_pkt()
        p1 = c.sym_pkt()
        _, s_prime_1 = c.process_packet(s0, 'ext_in', p_other)
        o1, _ = c.process_packet(s_prime_1, 'int_in', p1)
        self.verify(Implies(And(Not(o0['ext_out'].is_empty()),
                                is_tcp(p1),
                                Eq(flow_id_int(p0), flow_id_int(p1)),
                                Not(And(Eq(flow_id_int(p0), flow_id_ext(p_other)),
                                        is_flow_end(p_other)))),
                            Not(o1['ext_out'].is_empty())))

        _, s_prime_2 = c.process_packet(s0, 'int_in', p_other)
        o2, _ = c.process_packet(s_prime_2, 'int_in', p1)
        self.verify(Implies(And(Not(o0['ext_out'].is_empty()),
                                is_tcp(p1),
                                Eq(flow_id_int(p0), flow_id_int(p1)),
                                Not(And(Eq(flow_id_int(p0), flow_id_int(p_other)),
                                        is_flow_end(p_other)))),
                            Not(o2['ext_out'].is_empty())))

    def test_block_step(self):
        c = self.conf()
        p0, s0 = c.sym_pkt(), c.sym_state()
        o0, _ = c.process_packet(s0, 'ext_in', p0)
        p_other = c.sym_pkt()
        p1 = c.sym_pkt()
        _, s_prime_1 = c.process_packet(s0, 'ext_in', p_other)
        o1, _ = c.process_packet(s_prime_1, 'ext_in', p1)
        self.verify(Implies(And(is_tcp(p0),
                                o0['int_out'].is_empty(),
                                Eq(flow_id_ext(p0), flow_id_ext(p1))),
                            o1['int_out'].is_empty()))

        _, s_prime_2 = c.process_packet(s0, 'int_in', p_other)
        o2, _ = c.process_packet(s_prime_2, 'ext_in', p1)
        self.verify(Implies(And(o0['int_out'].is_empty(),
                                is_tcp(p0),
                                Eq(flow_id_ext(p0), flow_id_ext(p1)),
                                Not(And(Eq(flow_id_ext(p0), flow_id_int(p_other)),
                                        is_tcp_syn(p_other)))),
                            o2['int_out'].is_empty()))
