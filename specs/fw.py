from gravel_spec.utils import *
from gravel_spec.ops import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *


EXTERNAL = 0
INTERNAL = 1


class IPFilter(Element):
    ele_name = 'IPFilter'
    num_in_ports = 1
    num_out_ports = 1
    
    def process_packet(self, old, p, in_port):
        ether_type = p.ether.ether_type
        return [{ 'pre_cond' : ether_type == 0x0800, 
                  'packets' : { 0 : p }, 
                  'new_state' : old }]


class IPClassifier(Element):
    ele_name = 'udp_tcp_filter'
    num_in_ports = 1
    num_out_ports = 1
    
    def process_packet(self, old, p, in_port):
        proto = p.ip4.proto
        return [{ 'pre_cond' : proto == 6,
                  'packets' : { 0 : p },
                  'new_state' : old }]
    

class TCPFW(Element):
    ele_name = 'TCP_firewall'
    num_in_ports = 2
    num_out_ports = 2

    private_state_type = [('flows', 'map', (4, 2, 4, 2), (1,))]
    
    def process_packet(self, old, p, in_port):
        actions = []
        ext_flow_id = (p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst)
        int_flow_id = (p.ip4.dst, p.tcp.dst, p.ip4.src, p.tcp.src)
        is_external = in_port == EXTERNAL

        removed = old.copy()
        removed.flows.delete(ext_flow_id)
        new_ext = If(Or(is_tcp_fin(p), is_tcp_rst(p)), removed, old)
        
        actions.append({ 'pre_cond' : And(is_tcp(p), is_external,
                                          old.flows.has_key(ext_flow_id)),
                         'packets' : { 1 : p },
                         'new_state' : new_ext })

        flow_added = old.copy()
        flow_added.flows[int_flow_id] = 1
        flow_removed = old.copy()
        flow_removed.flows.delete(int_flow_id)
        
        new = If(is_tcp_syn(p), flow_added,
                 If(Or(is_tcp_fin(p), is_tcp_rst(p)), flow_removed, old))
        actions.append({ 'pre_cond' : And(is_tcp(p), Not(is_external)),
                         'packets' : { 0 : p },
                         'new_state' : new })
                                              

        return actions


def flow_id_ext(p):
    return (p.ip4.src, p.tcp.src, p.ip4.dst, p.tcp.dst)

def flow_id_int(p):
    return (p.ip4.dst, p.tcp.dst, p.ip4.src, p.tcp.src)

def is_flow_end(p):
    return Or(is_tcp_fin(p), is_tcp_rst(p))

class FWTasks(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        parser = HeaderParser()
        parser.add_header('ether', ETHER_HDR)
        parser.add_header('ip4', IPv4_HDR)
        parser.add_header('tcp', TCP_HDR)
        parser.add_header('payload', [('data', 1500)])

        path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0800), 'ip4') \
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
        p, s = c.fresh_packet(), c.fresh_states()
        o, _ = c.process_packet(s, 'ext_in', p)
        self.verify(Implies(Not(o['int_out'].is_empty()),
                            is_tcp(p)))

    def test_memorize_step_ext(self):
        c = self.conf()
        p0, s0 = c.fresh_packet(), c.fresh_states()
        o0, _ = c.process_packet(s0, 'ext_in', p0)
        p_other = c.fresh_packet()
        p1 = c.fresh_packet()
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
        p0, s0 = c.fresh_packet(), c.fresh_states()
        o0, _ = c.process_packet(s0, 'int_in', p0)
        p_other = c.fresh_packet()
        p1 = c.fresh_packet()
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
        p0, s0 = c.fresh_packet(), c.fresh_states()
        o0, _ = c.process_packet(s0, 'ext_in', p0)
        p_other = c.fresh_packet()
        p1 = c.fresh_packet()
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
