from gravel_spec.utils import *
from gravel_spec.ops import *
from gravel_spec.element import *
from gravel_spec.click_api import *
from gravel_spec.click_element import *
from gravel_spec.graph import *
from gravel_spec.config import *


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


class TcpFilter(ClickElement):
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


class LBStorage(ClickElement):
    '''
    private_state_type = [('decisions', 'map', (4, 2), (4,)),
                          ('timestamps', 'map', (4, 2), (8,)),
                          ('curr_time', 'bitvec', 8)]
    '''
    ele_name = 'lb_storage'
    num_in_ports = 2
    num_out_ports = 2

    class LBFlowId(SpecStruct):
        _fields = [('ip_addr', sizeof(c_int)),
                   ('port', sizeof(c_short))]
        _struct_name = "LBFlowId"
    public_ip = ClickVal(c_int)
    decisions = ClickMap(LBFlowId, 4)
    timestamps = ClickMap(LBFlowId, 8)
    curr_time = ClickVal(c_ulonglong)

    def process_packet(self, old, p, in_port, se=z3):
        flow_id = p.ip.src, p.tcp.src
        is_known_flow = se.And(in_port == 0, old.decisions.has_key(flow_id))
        new_p = p.copy()
        new_p.ip.dst = old.decisions[flow_id][0]
        timestamp_updated = old.copy()
        timestamp_updated.timestamps[flow_id] = old.curr_time
        
        is_unknown_flow = se.And(in_port == 0, se.Not(old.decisions.has_key(flow_id)))

        register_new_flow = in_port == 1
        new = old.copy()
        flow_id = p.ip.src, p.tcp.src
        new.decisions[flow_id] = p.ip.dst
        new.timestamps[flow_id] = new.curr_time
        
        return [{ 'pre_cond' : is_known_flow, 
                  'packets' : { 0 : new_p },
                  'new_state' : timestamp_updated },
                { 'pre_cond' : register_new_flow,
                  'packets' : { 0 : p },
                  'new_state' : new },
                { 'pre_cond' : is_unknown_flow,
                  'packets' : { 1 : p },
                  'new_state' : old }]

    def handle_event(self, s, event, *params):
        new = s.copy()
        new.curr_time = params[0]
        expire_filter = lambda ks, vs: And(s.timestamps.has_key(ks),
                                           z3.ULT(s.timestamps[ks][0], -1 - 600), 
                                           z3.UGE(new.curr_time, 600 + s.timestamps[ks][0]))
        new.decisions = new.decisions.filter(expire_filter)
        new.timestamps = new.timestamps.filter(expire_filter)
        return [{ 'pre_cond' : z3.BoolVal(True),
                  'packets' : {},
                  'new_state' : new }]

    def impl_state_equiv(self, lib, spec_state, impl_state):
        se = CobbleSymGen(lib)
        conds = []
        decision_map = lib.get_obj_handle_by_off(impl_state, 112)
        timestamp_map = lib.get_obj_handle_by_off(impl_state, 160)
        currtime_buf = CobbleBuffer(lib, ptr=lib.get_obj_handle_by_off(impl_state, 208))
        def lb_flow_id_eq(spec_k, impl_k):
            spec_bv = lib.bv_concat(spec_k[0], spec_k[1])
            impl_fields = []
            impl_fields.append(se.bv_bswap(se.bv_extract_from_top(impl_k[0], 0, 32)))
            impl_fields.append(se.bv_bswap(se.bv_extract_from_top(impl_k[0], 32, 32 + 16)))
            impl_v = se.Concat(*impl_fields)
            return se.And(spec_k[0] == impl_fields[0], spec_k[1] == impl_fields[1])
        conds.append(spec_state.decisions.map_eq(decision_map, impl_key_sz=[32 + 16],
            key_eq_func=lb_flow_id_eq, vals_eq_func=lambda s, i: se.bv_bswap(i[0]) == s[0]))
        conds.append(spec_state.timestamps.map_eq(timestamp_map, impl_key_sz=[32 + 16],
            key_eq_func=lb_flow_id_eq, vals_eq_func=lambda s, i: se.bv_bswap(i[0]) == s[0]))
        conds.append(spec_state.curr_time == currtime_buf.load(0, 8))
        return reduce(lib.bool_and, map(get_inner, conds))


class Scheduler(ClickElement):
    '''
    private_state_type = [('addr_map', 'map', (4,), (4,)),
                          ('cnt', 'bitvec', 4), 
                          ('num_dsts', 'bitvec', 4)]
    '''
    ele_name = 'scheduler'
    num_in_ports = 1
    num_out_ports = 1

    addr_map = ClickMap(4, 4)
    cnt = ClickVal(c_int)
    num_dsts = ClickVal(c_int)

    def process_packet(self, old, p, in_port, se=z3):
        dst_ip = old.addr_map[old.cnt][0]
        new = old.copy()
        new.cnt = se.URem(old.cnt + 1, old.num_dsts)
        has_bked = old.addr_map.has_key(old.cnt)
        new_packet = p.copy()
        new_packet.ip.dst = dst_ip
        return [{ 'pre_cond' : se.And(is_tcp(p, se), has_bked), 
                  'packets' : { 0 : new_packet },
                  'new_state' : new },
                { 'pre_cond' : se.Not(se.And(is_tcp(p, se), has_bked)),
                  'packets' : {},
                  'new_state' : new }]

    def state_inv(self, s, se=z3):
        conds = []
        k = fresh_bv('k', 32)
        conds.append(se.ULT(0, s.num_dsts))
        conds.append(ForAll([k], Implies(se.ULT(k, s.num_dsts), s.addr_map.has_key(k))))
        conds.append(se.ULT(s.cnt, s.num_dsts))
        return se.And(*conds)

    def impl_state_equiv(self, lib, spec_state, impl_state):
        se = CobbleSymGen(lib)
        conds = []
        impl_addr_map = lib.get_obj_handle_by_off(impl_state, 112)
        impl_cnt = CobbleBuffer(lib, ptr=lib.get_obj_handle_by_off(impl_state, 160))
        impl_n_dsts = CobbleBuffer(lib, ptr=lib.get_obj_handle_by_off(impl_state, 164))
        conds.append(spec_state.addr_map.map_eq(impl_addr_map, impl_key_sz=[32],
            key_eq_func=lambda s, i: se.bv_bswap(i[0]) == s[0],
            vals_eq_func = lambda s, i: se.bv_bswap(i[0]) == s[0]))
        conds.append(impl_cnt.load(0, 4) == spec_state.cnt)
        conds.append(impl_n_dsts.load(0, 4) == spec_state.num_dsts)
        return reduce(lib.bool_and, map(get_inner, conds))

class Maglev(Element):
    ele_name = 'maglev_selector'
    num_in_ports = 1
    num_out_ports = 1

    private_state_type = [('lookup_table', 'map', (4,), (4,)),
                          ('hash_func', 'uf', (12,), 4)]

    def process_packet(self, old, p, in_port):
        flow_id = p.ip.src, p.tcp.src, p.ip.dst, p.tcp.dst
        hash_val = old.hash_func(Concat(*flow_id))
        dst_ip = old.lookup_table[hash_val][0]
        new_packet = p.copy()
        new_packet.ip.dst = dst_ip
        return [{ 'pre_cond' : z3.BoolVal(True),
                  'packets' : { 0 : new_packet },
                  'new_state' : old }]

    def state_inv(self, s):
        k = fresh_bv('k', 32)
        return ForAll([k], s.lookup_table.has_key(k))

def get_flow_id(p):
    flow_id = p.ip.src, p.tcp.src, p.ip.dst, p.tcp.dst
    return flow_id

def from_same_flow(p1, p2):
    return And(is_tcp(p1), is_tcp(p2),
               p2.ip.src == p1.ip.src, 
               p2.ip.dst == p1.ip.dst,
               p2.tcp.src == p1.tcp.src, 
               p2.tcp.dst == p1.tcp.dst)

def is_tcp(p, se=z3):
    return se.And(p.ether.ether_type == 0x0800,
                  p.ip.proto == 6)

def steer_to(c, s, p, dst_ip, t=None):
    s_n = s
    if t is not None:
        _, s_n = c.handle_event(s, 'cache', '', t)
    o, _ = c.process_packet(s_n, 'in', p)
    return And(Not(o['out'].is_empty()),
               o['out'].ip.dst == dst_ip,
               o['__edges']['cache'][1].is_empty())

class LBTasks(ConfigVerifyTask, unittest.TestCase):
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
        
        elements = [('in', Source),
                    ('out', Sink),
                    ('ip_filter', IPFilter),
                    ('tcp_filter', TcpFilter),
                    ('cache', LBStorage),
                    ('lb', Scheduler)]

        path = Path('in', 0) >> (0, 'ip_filter', 0) >> (0, 'tcp_filter', 0) \
               >> (0, 'cache', 1) >> (0, 'lb', 0) >> (1, 'cache', 0) >> (0, 'out')

        return Config(elements, path.edges(), parser)

    def test_tcp_only(self):
        c = self.conf()
        p, old_states = c.fresh_packet(), c.fresh_states()
        out, _ = c.process_packet(old_states, 'in', p)
        self.verify(Implies(Not(out['out'].is_empty()),
                            is_tcp(p)))

    def test_always_steer(self):
        c = self.conf()
        p, s = c.fresh_packet(), c.fresh_states()
        out, s2 = c.process_packet(s, 'in', p)
        self.verify(Implies(And(c.state_invs(s),
                                p.ether.ether_type == 0x0800,
                                p.ip.proto == 6),
                            Not(out['out'].is_empty())),
                    lambda m: [m.eval(out['__edges']['cache'][1].is_empty()),
                               m.eval(out['__edges']['lb'][0].is_empty())])

    def test_persistency(self):
        c = self.conf()
        p1, p2, old_states = c.fresh_packet(), c.fresh_packet(), c.fresh_states()
        out1, new_s = c.process_packet(old_states, 'in', p1)

        p2.ip.src, p2.ip.dst = p1.ip.src, p1.ip.dst
        p2.tcp.src, p2.tcp.dst = p1.tcp.src, p1.tcp.dst
        out2, _ = c.process_packet(new_s, 'in', p2)
        self.verify(Implies(And(Not(out1['out'].is_empty()),
                                Not(out2['out'].is_empty())),
                            out1['out'].ip.dst == out2['out'].ip.dst))

    def test_step_init(self):
        c = self.conf()
        dst_ip = fresh_bv('dst_ip', 32)
        p0, p1, s0 = c.fresh_packet(), c.fresh_packet(), c.fresh_state()
        o, s1 = c.process_packet(s0, 'in', p0)
        dst_ip = o['out'].ip.dst
        t = s0['cache'].curr_time
        self.verify(Implies(And(c.state_invs(s0),
                                p0.ether.ether_type == 0x0800,
                                p0.ip.proto == 6),
                            steer_to(c, s1, p0, dst_ip, t)))

    def test_step_packet(self):
        c = self.conf()
        dst_ip = fresh_bv('dst_ip', 32)
        p0, p1, s0 = c.fresh_packet(), c.fresh_packet(), c.fresh_state()
        t = fresh_bv('time', 64)

        p_diff = c.fresh_packet()
        _, s1 = c.process_packet(s0, 'in', p_diff)

        out, s2 = c.process_packet(s1, 'in', p1)

        self.verify(Implies(And(steer_to(c, s0, p0, dst_ip, t),
                                And(p_diff.ip.src != p1.ip.src,
                                    p_diff.tcp.src != p1.tcp.src),
                                from_same_flow(p0, p1)),
                            steer_to(c, s1, p1, dst_ip, t)),
                    lambda m: [m.eval(s1['cache'].timestamps[p1.ip.src, p1.tcp.src][0]),
                               m.eval(dst_ip),
                               m.eval(t),
                               m.eval(s0['cache'].timestamps[p1.ip.src, p1.tcp.src][0]),
                               m.eval(out['__edges']['cache'][0].is_empty())])

    def test_step_time(self):
        c = self.conf()
        dst_ip = fresh_bv('dst_ip', 32)
        p0, p1, s0 = c.fresh_packet(), c.fresh_packet(), c.fresh_state()
        #t0 = s0['cache'].timestamps[get_flow_id(p0)][0]
        t0 = fresh_bv('time0', 64)

        t1 = fresh_bv('time1', 64)
        _, s1 = c.handle_event(s0, 'cache', '', t1)
        flow_id = get_flow_id(p0)
        self.verify(Implies(And(steer_to(c, s0, p0, dst_ip, t0),
                                z3.ULT(t1, t0),
                                from_same_flow(p0, p1)),
                            steer_to(c, s1, p1, dst_ip, t0)))
