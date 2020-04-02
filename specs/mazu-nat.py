from graphviz import Digraph
from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from gravel_spec.click_common import *
from gravel_spec.click_api import *


def is_tcp(p):
    return And(p.ether.ether_type == 0x0800,
               p.ip.proto == 6)

def is_tcp_or_udp(p):
    return And(p.ether.ether_type == 0x0800,
               Or(p.ip.proto == 6, p.ip.proto == 17))

def src_port(p):
    return If(is_tcp(p), p.tcp.src, p.udp.src)

def from_same_flow(p1, p2):
    is_tcp = (p1.ip.proto == 6)
    return And(p1.ip.proto == p2.ip.proto,
               p1.ether.ether_type == 0x0800,
               p2.ether.ether_type == 0x0800,
               p1.ip.src == p2.ip.src,
               p1.ip.dst == p2.ip.dst,
               If(is_tcp,
                  And(p1.tcp.src == p2.tcp.src,
                      p1.tcp.dst == p2.tcp.dst),
                  And(p1.udp.src == p2.udp.src,
                      p1.udp.dst == p2.udp.dst)))

def steer_to(c, state, pkt, port, time=None):
    s_n = state
    if time is not None:
        _, s_n = c.handle_event(state, 'rw', 'time', time)
    o, _ = c.process_packet(s_n, 'from_intern', pkt)
    sport = If(o['to_extern'].ip.proto == 6,
               o['to_extern'].tcp.src,
               o['to_extern'].udp.src)
    ext_id = MyIPRewriterMod.NatExternKey()
    ext_id.port = port
    ext_id.protocol = pkt.ip.proto
    int_id = MyIPRewriterMod.NatInternKey()
    int_id.addr = pkt.ip.src
    int_id.port = src_port(pkt)
    int_id.protocol = pkt.ip.proto
    return And(o['to_extern'].not_empty(),
               #s_n['rw'].map_extern.has_key(ext_id.to_tuple()),
               s_n['rw'].map_intern.has_key(int_id.to_tuple()),
               sport == port)


class Mazunat(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        intern_ether = ether2num("00:50:ba:85:84:a9")
        extern_ether = ether2num("00:e0:98:09:ab:af")
        next_hop_ether = ether2num("02:00:0a:11:22:1f")
        intern_ip = ip2num("10.0.0.1")
        extern_ip = ip2num("209.6.198.213")
        elements = {'from_extern': Source(),
                    'from_intern': Source(), 
                    'to_extern': Sink(),
                    'to_intern': Sink(),
                    'to_host': Sink(),
                    'ip_to_host': EtherEncap(0x0800, ether2num([1,1,1,1,1,1]), intern_ether),
                    'extern_arp_class': Classifier([[("ether.ether_type", 0x0806), ("arp.op", 0x0001)],
                                                    [("ether.ether_type", 0x0806), ("arp.op", 0x0002)],
                                                    ("ether.ether_type", 0x0800), "-"]),
                    'intern_arp_class': Classifier([[("ether.ether_type", 0x0806), ("arp.op", 0x0001)],
                                                    [("ether.ether_type", 0x0806), ("arp.op", 0x0002)],
                                                    ("ether.ether_type", 0x0800), "-"]),
                    'intern_arpq': ARPQuerier(intern_ether),
                    'extern_arpr': ARPResponder(extern_ether, 0),
                    'intern_arpr': ARPResponder(intern_ether, 0),
                    'discard': Discard(),
                    'tee01': Tee(),
                    'rw': MyIPRewriterMod(extern_ip),
                    'tcprw': TCPRewriter(),
                    'ip2extern': GetIPAddress(16),
                    'ip2intern': GetIPAddress(16),
                    'checkip1': CheckIPHeader(),
                    'checkip2': CheckIPHeader(),
                    'encap01': EtherEncap(0x0800, extern_ether, next_hop_ether),
                    'ip2extern_class': IPClassifier([lambda p, _: p.ip.dst == intern_ip,
                                                     lambda p, _: True]),
                    'ip2host_class': IPClassifier([lambda p, _: p.ip.dst == extern_ip]),
                    'extern2ip_class': IPClassifier([lambda p, _: p.ip.dst == extern_ip,
                                                     lambda p, _: True]),
                    'extern2ip2_class': IPClassifier([lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 22),
                                                      lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 80,
                                                                           p.tcp.dst == 443),
                                                      lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 21),
                                                      lambda p, se: se.Or(p.ip.proto == 6,
                                                                          p.ip.proto == 17),
                                                      lambda p, _: True]),
                    'intern2ip_class': IPClassifier([lambda p, _: p.ip.dst == intern_ip,
                                                     lambda p, _: (p.ip.dst & 0xff000000) \
                                                     == (intern_ip & 0xff000000),
                                                     lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 21),
                                                     lambda p, _: True]),
                    'intern2ip2_class': IPClassifier([lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 22),
                                                      lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 80,
                                                                       p.tcp.dst == 443),
                                                      lambda p, se: se.Or(se.And(p.ip.proto == 6,
                                                                             se.Or(p.tcp.dst == 53, p.tcp.src == 53)),
                                                                      se.And(p.ip.proto == 17,
                                                                             se.Or(p.udp.dst == 53, p.udp.src == 53))),
                                                      lambda p, se: se.And(p.ip.proto == 6, p.tcp.dst == 113),
                                                      lambda p, se: se.Or(p.ip.proto == 6,
                                                                          p.ip.proto == 17),
                                                      lambda p, _: True]),
                    'strip1': Strip(14),
                    'strip2': Strip(14),
                    'checkip3': CheckIPHeader(),
                    'checkip4': CheckIPHeader(),
                    'ftpmapper': FTPPortMapper(),
        }

        paths = Path('from_extern', 0) >> (0, 'extern_arp_class')
        paths += Path('extern_arp_class', 0) >> (0, 'extern_arpr', 0) >> (0, 'to_extern')
        paths += Path('extern_arp_class', 1) >> (0, 'to_host')
        paths += Path('extern_arp_class', 3) >> (0, 'discard')

        paths += Path('from_intern', 0) >> (0, 'intern_arp_class')
        paths += Path('intern_arp_class', 0) >> (0, 'intern_arpr', 0) >> (0, 'to_intern')
        paths += Path('intern_arp_class', 1) >> (0, 'tee01', 0) >> (0, 'to_host')
        paths += Path('tee01', 1) >> (1, 'intern_arpq')
        paths += Path('intern_arp_class', 3) >> (0, 'discard')

        paths += Path('ip2extern', 0) >> (0, 'checkip1', 0) >> (0, 'encap01', 0) >> (0, 'to_extern')
        paths += Path('ip2intern', 0) >> (0, 'checkip2', 0) >> (0, 'intern_arpq', 0) >> (0, 'to_intern')

        paths += Path('rw', 0) >> (0, 'ip2extern_class', 0) >> (0, 'ip_to_host', 0) >> (0, 'to_host')
        paths += Path('ip2extern_class', 1) >> (0, 'ip2extern')
        paths += Path('rw', 1) >> (0, 'ip2intern')
        paths += Path('rw', 2) >> (0, 'ip2host_class', 0) >> (0, 'ip_to_host')
        paths += Path('tcprw', 0) >> (0, 'ip2extern')
        paths += Path('tcprw', 1) >> (0, 'ip2intern')

        paths += Path('extern_arp_class', 2) >> (0, 'strip1', 0) >> (0, 'checkip3', 0) >> (0, 'extern2ip_class')
        paths += Path('extern2ip_class', 0) >> (0, 'extern2ip2_class', 0) >> (1, 'rw')
        paths += Path('extern2ip2_class', 1) >> (1, 'rw')
        paths += Path('extern2ip2_class', 2) >> (1, 'tcprw')
        paths += Path('extern2ip2_class', 3) >> (4, 'rw')
        paths += Path('extern2ip2_class', 4) >> (0, 'discard')
        paths += Path('extern2ip_class', 1) >> (0, 'discard')
        
        paths += Path('intern_arp_class', 2) >> (0, 'strip2', 0) >> (0, 'checkip4', 0) >> (0, 'intern2ip_class')
        paths += Path('intern2ip_class', 0) >> (0, 'intern2ip2_class', 0) >> (0, 'ip_to_host')
        paths += Path('intern2ip2_class', 1) >> (2, 'rw')
        paths += Path('intern2ip2_class', 2) >> (0, 'discard')
        paths += Path('intern2ip2_class', 3) >> (0, 'ip_to_host')
        paths += Path('intern2ip2_class', 4) >> (3, 'rw')
        paths += Path('intern2ip2_class', 5) >> (0, 'ip_to_host')

        paths += Path('intern2ip_class', 1) >> (0, 'ip_to_host')
        paths += Path('intern2ip_class', 2) >> (0, 'ftpmapper', 0) >> (0, 'tcprw')

        paths += Path('intern2ip_class', 3) >> (0, 'rw')

        
        cfg = Digraph('cfg', node_attr={'shape': 'record'})

        paths.get_diagram(cfg)
        #cfg.view()

        parser = HeaderParser()
        parser.add_header('ether', ETHER_HDR)
        parser.add_header('ip', IPv4_HDR)
        parser.add_header('tcp', TCP_HDR)
        parser.add_header('udp', UDP_HDR)
        parser.add_header('arp', ARP_HDR)
        parser.add_header('ftp', [('cmd', 4),
                                  ('mapping', 30)])
        parser.add_header('payload', [('data', 1500)])

        tcp_path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0800), 'ip4') \
                   >> (('proto', 'eq', 6), 'tcp')  >> (('always'), 'ftp') >> (('always'), 'payload')
        arp_path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0806), 'arp')
        udp_path = ParserEdge('ip4') >> (('proto', 'eq', 17), 'udp')  >> (('always'), 'payload')

        return ClickConfig(elements, paths.edges(), parser)

    def test_payload_unchanged(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()

        for source in c.sources:
            ps, _ = c.process_packet(s, source, p)

            for sink in c.sinks:
                self.verify(Implies(Not(ps[sink].is_empty()),
                                    ps[sink].payload == p.payload))

    def test_ep_independent(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()
        ps1, _ = c.process_packet(s, 'from_extern', p)

        p.ip.src = fresh_bv('addr', 32)
        p.tcp.src = fresh_bv('port', 16)
        p.udp.src = fresh_bv('port', 16)
        ps2, _ = c.process_packet(s, 'from_extern', p)

        for sink in c.sinks:
            self.verify(Implies(Not(ps1[sink].is_empty()),
                                And(Not(ps2[sink].is_empty()),
                                    ps1[sink].ip.dst == ps2[sink].ip.dst,
                                    ps1[sink].tcp.dst == ps2[sink].tcp.dst,
                                    ps1[sink].udp.dst == ps2[sink].udp.dst)))

    def test_no_ext2ext(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()
        ps, _ = c.process_packet(s, 'from_extern', p)
        self.verify(ps['to_extern'].is_empty())

    def test_independent_filter(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()
        ps1, _ = c.process_packet(s, 'from_extern', p)

        p.ip.src = fresh_bv('addr', 32)
        p.tcp.src = fresh_bv('port', 16)
        p.udp.src = fresh_bv('port', 16)
        ps2, _ = c.process_packet(s, 'from_extern', p)
        for sink in c.sinks:
            self.verify(ps1[sink].is_empty() == ps2[sink].is_empty())

    def test_no_port_overloading(self):
        def get_src_port(p):
            return If(p.ip.proto == 6, p.tcp.src, p.udp.src)
        c = self.conf()
        p1, p2, s = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        out1, new_s = c.process_packet(s, 'from_intern', p1)
        out2, _ = c.process_packet(new_s, 'from_intern', p2)
        self.verify(Implies(And(Not(out1['to_extern'].is_empty()),
                                Not(out2['to_extern'].is_empty()),
                                c.state_invs(s),
                                p1.ip.proto == 6,
                                p2.ip.proto == 6,
                                get_src_port(out1['to_extern']) == get_src_port(out2['to_extern'])),
                            And(p1.ip.src == p2.ip.src,
                                get_src_port(p1) == get_src_port(p2))),
                    lambda m: [m.eval(p1.ip.src), m.eval(p2.ip.src)])

    def test_ep_independent_map(self):
        intern_ip = ip2num("10.0.0.1")
        extern_ip = ip2num("209.6.198.213")
        def have_mapping(pkt, s):
            int_id = MyIPRewriterMod.NatInternKey()
            int_id.addr = pkt.ip.src
            int_id.port = src_port(pkt)
            int_id.protocol = pkt.ip.proto
            return (s['rw'].map_intern.has_key(int_id.to_tuple()))
        def get_src_port(p):
            return If(p.ip.proto == 6, p.tcp.src, p.udp.src)
        def to_external(p, s):
            return And(is_tcp(p),
                       p.ip.dst != extern_ip,
                       p.ip.dst != intern_ip,
                       p.ip.dst != s['rw'].public_ip,
                       p.ip.dst & 0xff000000 != intern_ip & 0xff000000,
                       p.tcp.dst != 21)
        c = self.conf()
        p1, p2, s = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        port1, port2 = fresh_bv('port', 16), fresh_bv('port', 16)

        def same_src(p1, p2):
            return And(is_tcp_or_udp(p1), is_tcp_or_udp(p2),
                       p1.ip.src == p2.ip.src,
                       get_src_port(p1) == get_src_port(p2))
        out1, _ = c.process_packet(s, 'from_intern', p1)
        out2, _ = c.process_packet(s, 'from_intern', p2)
        self.verify(Implies(And(to_external(p1, s),
                                to_external(p2, s),
                                same_src(p1, p2),
                                have_mapping(p1, s)),
                            same_src(out1['to_extern'], out2['to_extern'])))


    def test_hairpinning(self):
        c = self.conf()
        p1, p2, s = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        out1, _ = c.process_packet(s, 'from_extern', p1)
        out2, _ = c.process_packet(s, 'from_intern', p2)
        self.verify(Implies(And(p2.ether.ether_type == 0x0800,
                                p1.ip.proto == 6,
                                p2.ip.proto == 6,
                                p1.ip.dst == p2.ip.dst,
                                p1.tcp.dst == p2.tcp.dst,
                                p1.tcp.dst != 21,
                                Not(out1['to_intern'].is_empty())),
                            And(Not(out2['to_intern'].is_empty()),
                                out1['to_intern'].ip.dst == out2['to_intern'].ip.dst,
                                out1['to_intern'].tcp.dst == out2['to_intern'].tcp.dst)))

    def test_memorize_init(self):
        c = self.conf()
        p0, p1, s0 = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        o, s1 = c.process_packet(s0, 'from_intern', p0)
        ext_port = o['to_extern'].tcp.src
        t = s0['rw'].curr_time
        WINDOW = 600
        ddl = t + WINDOW
        intern_ip = ip2num("10.0.0.1")
        _, s2 = c.handle_event(s1, 'rw', 'time', ddl)
        o2, _ = c.process_packet(s2, 'from_intern', p0)
        int_id = MyIPRewriterMod.NatInternKey()
        int_id.addr = p0.ip.src
        int_id.port = p0.tcp.src
        int_id.protocol = p0.ip.proto
        self.verify(Implies(And(is_tcp(p0),
                                o['to_extern'].not_empty(),
                                p0.ip.dst != intern_ip,
                                p0.ip.dst & 0xff000000 != intern_ip & 0xff000000,
                                p0.tcp.dst != 21),
                            steer_to(c, s1, p0, ext_port, ddl)))


    def test_memorize_step_pkt(self):
        c = self.conf()
        p0, p1, s0 = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        t = fresh_bv('time', 64)

        p_diff = c.fresh_packet()
        ext_port = fresh_bv('port', 16)
        _, s1 = c.process_packet(s0, 'from_intern', p_diff)
        self.verify(Implies(And(steer_to(c, s0, p0, ext_port, t),
                                from_same_flow(p0, p1)),
                            steer_to(c, s1, p0, ext_port, t)))

    def test_memorize_step_time(self):
        c = self.conf()
        ext_port = fresh_bv('port', 16)
        p0, p1, s0 = c.sym_pkt(), c.sym_pkt(), c.sym_state()
        t0, t1 = fresh_bv('time', 64), fresh_bv('time', 64)
        _, s1 = c.handle_event(s0, 'rw', 'time', t1)
        self.verify(Implies(And(steer_to(c, s0, p0, ext_port, t0),
                                z3.ULT(t1, t0),
                                from_same_flow(p0, p1)),
                            steer_to(c, s1, p1, ext_port, t0)))
