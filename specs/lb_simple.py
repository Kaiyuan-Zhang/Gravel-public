from gravel_spec.utils import *
from gravel_spec.ops import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *


WINDOW = 600


class IPFilter(Element):
    ele_name = 'IPFilter'
    num_in_ports = 1
    num_out_ports = 1
    
    def process_packet(self, old, p, in_port):
        ether_type = p.ether.ether_type
        return [{ 'pre_cond' : ether_type == 0x0800, 
                  'packets' : { 0 : p }, 
                  'new_state' : old }]


class TcpFilter(Element):
    ele_name = 'udp_tcp_filter'
    num_in_ports = 1
    num_out_ports = 1
    
    def process_packet(self, old, p, in_port):
        proto = p.ip4.proto
        return [{ 'pre_cond' : proto == 6,
                  'packets' : { 0 : p },
                  'new_state' : old }]


class LBStorage(Element):
    ele_name = 'lb_storage'
    num_in_ports = 2
    num_out_ports = 2

    private_state_type = [('decisions', 'map', (4, 2, 4, 2), (4,)),
                          ('timestamps', 'map', (4, 2, 4, 2), (8,)),
                          ('curr_time', 'bitvec', 8)]

    def process_packet(self, old, p, in_port):
        flow_id = p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst
        is_known_flow = And(in_port == 0, old.decisions.has_key(flow_id))
        new_p = p.copy()
        new_p.inner_ip = new_p.ip4.copy()
        new_p.ip4.dst = old.decisions[flow_id][0]
        new_p.ip4.length = new_p.inner_ip.length + 20
        new_p.ip4.proto = 0x4
        timestamp_updated = old.copy()
        timestamp_updated.timestamps[flow_id] = If(old.timestamps.has_key(flow_id), 
                                                   If(z3.UGT(old.curr_time, old.timestamps[flow_id][0]), 
                                                      old.curr_time, old.timestamps[flow_id][0]),
                                                   old.curr_time)
        
        is_unknown_flow = And(in_port == 0, Not(old.decisions.has_key(flow_id)))

        register_new_flow = in_port == 1
        new = old.copy()
        flow_id = p.inner_ip.src, p.tcp.src, p.inner_ip.dst, p.tcp.dst
        new.decisions[flow_id] = p.ip4.dst
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
                                           z3.ULT(s.timestamps[ks][0], -1 - WINDOW), 
                                           z3.UGE(new.curr_time, WINDOW + s.timestamps[ks][0]))
        new.decisions = new.decisions.filter(expire_filter)
        new.timestamps = new.timestamps.filter(expire_filter)
        return [{ 'pre_cond' : z3.BoolVal(True),
                  'packets' : {},
                  'new_state' : new }]

class Scheduler(Element):
    ele_name = 'scheduler'
    num_in_ports = 1
    num_out_ports = 1

    private_state_type = [('addr_map', 'map', (4,), (4,)),
                          ('cnt', 'bitvec', 4), 
                          ('num_dsts', 'bitvec', 4)]

    def process_packet(self, old, p, in_port):
        dst_ip = old.addr_map[old.cnt % old.num_dsts][0]
        new = old.copy()
        new.cnt = (old.cnt + 1) % old.num_dsts
        new_packet = p.copy()
        new_packet.inner_ip = new_packet.ip4.copy()
        new_packet.ip4.dst = dst_ip
        new_packet.ip4.length = new_packet.inner_ip.length + 20
        new_packet.ip4.proto = 0x4
        return [{ 'pre_cond' : z3.BoolVal(True),
                  'packets' : { 0 : new_packet },
                  'new_state' : new }]

class Maglev(Element):
    ele_name = 'maglev_selector'
    num_in_ports = 1
    num_out_ports = 1
    
    private_state_type = [('lookup_table', 'map', (4,), (4,)),
                          ('hash_func', 'uf', (12,), 4)]

    def process_packet(self, old, p, in_port):
        flow_id = p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst
        hash_val = old.hash_func(Concat(*flow_id))
        dst_ip = old.lookup_table[hash_val][0]
        new_packet = p.copy()
        new_packet.inner_ip = new_packet.ip4.copy()
        new_packet.ip4.dst = dst_ip
        new_packet.ip4.length = new_packet.inner_ip.length + 20
        new_packet.ip4.proto = 0x4
        return [{ 'pre_cond' : z3.BoolVal(True),
                  'packets' : { 0 : new_packet },
                  'new_state' : old }]

    def state_inv(self, s):
        k = fresh_bv('k', 32)
        return ForAll([k], s.lookup_table.has_key(k))


def has_inner_ip(p):
    return (p.ip4.proto == 0x4)

def get_flow_id(p):
    flow_id = p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst
    return flow_id

def from_same_flow(p1, p2):
    return And(is_tcp(p1), is_tcp(p2),
               Not(has_inner_ip(p1)),
               Not(has_inner_ip(p2)),
               p2.ip4.src == p1.ip4.src, 
               p2.ip4.dst == p1.ip4.dst,
               p2.tcp.src == p1.tcp.src, 
               p2.tcp.dst == p1.tcp.dst)

def is_tcp(p):
    return And(p.ether.ether_type == 0x0800,
               If(has_inner_ip(p),
                  p.inner_ip.proto == 6,
                  p.ip4.proto == 6))

def steer_to(c, s, p, dst_ip, ddl):
    s_n = s
    t = fresh_bv('t', 64)
    _, s_n = c.handle_event(s, 'cache', '', t)
    o, _ = c.process_packet(s_n, 'in', p)
    return ForAll([t], Implies(And(z3.UGT(ddl, t)),
                               And(Not(o['out'].is_empty()),
                                   o['out'].ip4.dst == dst_ip,
                                   o['__edges']['cache'][1].is_empty())))

def get_flow_id(p):
    return p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst

class LBTasks(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        parser = HeaderParser()
        parser.add_header('ether', ETHER_HDR)
        parser.add_header('ip4', IPv4_HDR)
        parser.add_header('inner_ip', IPv4_HDR)
        parser.add_header('tcp', TCP_HDR)
        parser.add_header('payload', [('data', 1500)])
        
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
        out, _ = c.process_packet(s, 'in', p)
        self.verify(Implies(And(p.ether.ether_type == 0x0800,
                                p.ip4.proto == 6),
                            Not(out['out'].is_empty())))

    def test_is_l3(self):
        c = self.conf()
        p, old_states = c.fresh_packet(), c.fresh_states()
        out, _ = c.process_packet(old_states, 'in', p)
        self.verify(Implies(Not(out['out'].is_empty()),
                            has_inner_ip(out['out'])))

    def test_persistency(self):
        c = self.conf()
        p1, p2, old_states = c.fresh_packet(), c.fresh_packet(), c.fresh_states()
        out1, new_s = c.process_packet(old_states, 'in', p1)

        p2.ip4.src, p2.ip4.dst = p1.ip4.src, p1.ip4.dst
        p2.tcp.src, p2.tcp.dst = p1.tcp.src, p1.tcp.dst
        out2, _ = c.process_packet(new_s, 'in', p2)
        self.verify(Implies(And(Not(out1['out'].is_empty()),
                                Not(out2['out'].is_empty())),
                            out1['out'].ip4.dst == out2['out'].ip4.dst))

    def test_step_init(self):
        c = self.conf()
        dst_ip = fresh_bv('dst_ip', 32)
        p0, p1, s0 = c.fresh_packet(), c.fresh_packet(), c.fresh_state()
        o, s1 = c.process_packet(s0, 'in', p0)
        dst_ip = o['out'].ip4.dst
        t = s0['cache'].curr_time
        ddl = t + WINDOW
        t0 = fresh_bv('time', 64)
        self.verify(Implies(And(p0.ether.ether_type == 0x0800,
                                p0.ip4.proto == 6),
                            steer_to(c, s1, p0, dst_ip, ddl)))

    def test_step_packet(self):
        c = self.conf()
        dst_ip = fresh_bv('dst_ip', 32)
        p0, p1, s0 = c.fresh_packet(), c.fresh_packet(), c.fresh_state()
        t = fresh_bv('time', 64)

        p_diff = c.fresh_packet()
        _, s1 = c.process_packet(s0, 'in', p_diff)
        flow_id = get_flow_id(p0)
        _, ss = c.handle_event(s0, 'cache', '', z3.BitVecVal(0, 64))
        self.verify(Implies(And(steer_to(c, s0, p0, dst_ip, t),
                                Not(from_same_flow(p0, p_diff)),
                                from_same_flow(p0, p1)),
                            steer_to(c, s1, p0, dst_ip, t)),
                    lambda m: [m, m.eval(ss['cache'].timestamps.has_key(flow_id)), m.eval(s0['cache'].timestamps.has_key(flow_id)), m.eval(s1['cache'].timestamps[flow_id][0]), m.eval(t), m.eval(s0['cache'].curr_time)])

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
