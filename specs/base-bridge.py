from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from gravel_spec.click_common import *
from gravel_spec.click_api import *


class Bridge(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        my_ether0 = ether2num("1:1:1:1:1:0")
        my_ether1 = ether2num("1:1:1:1:1:1")
        left_ether = ether2num("90:e2:ba:55:14:10")
        right_ether = ether2num("90:e2:ba:55:14:11")
        
        iface0 = 0
        iface1 = 1
        
        elements = {'nicIn0' : Source(),
                    'nicOut0' : Sink(),
                    'nicIn1' : Source(),
                    'nicOut1' : Sink(),
                    'br' : EtherSwitch(2, 2)}

        paths = Path('nicIn0', 0) >> (0, 'br', 0) >> (0, 'nicOut0')

        paths += Path('nicIn1', 0) >> (1, 'br', 1) >> (0, 'nicOut1')

        parser = HeaderParser()
        parser.add_header('ether', ETHER_HDR)
        parser.add_header('ip', IPv4_HDR)
        parser.add_header('tcp', TCP_HDR)
        parser.add_header('udp', UDP_HDR)
        parser.add_header('arp', ARP_HDR)
        parser.add_header('ftp', [('cmd', 4),
                                  ('mapping', 30)])
        parser.add_header('payload', [('data', 1500)])

        tcp_path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0800), 'ip') \
                   >> (('proto', 'eq', 6), 'tcp')  >> (('always'), 'ftp') >> (('always'), 'payload')
        arp_path = ParserEdge('ether') >> (('ether_type', 'eq', 0x0806), 'arp')
        udp_path = ParserEdge('ip') >> (('proto', 'eq', 17), 'udp')  >> (('always'), 'payload')

        return ClickConfig(elements, paths.edges(), parser)

    def test_payload_unchanged(self):
        c = self.conf()
        p, s = c.sym_pkt(), c.sym_state()

        for source in c.sources:
            ps, _ = c.process_packet(s, source, p)

            for sink in c.sinks:
                self.verify(Implies(Not(ps[sink].is_empty()), 
                                    ps[sink].payload == p.payload))

    def test_memorize(self):
        c = self.conf()
        p1, p2 = c.sym_pkt(), c.sym_pkt()
        s_init = c.sym_state()

        def is_broadcast(ps):
            conds = []
            for sink in c.sinks:
                conds.append(Not(ps[sink].is_empty()))
            return And(*conds)

        in_out_map = {'nicIn0': 'nicOut0',
                      'nicIn1': 'nicOut1'}

        for source in c.sources:
            ps, s = c.process_packet(s_init, source, p1)
            ps2, _ = c.process_packet(s, source, p2)

            sink = in_out_map[source]
            self.verify(Implies(And(c.state_invs(s_init),
                                    p1.ether.src == p2.ether.dst),
                                And(Not(is_broadcast(ps2)),
                                    Not(ps2[sink].is_empty()))))

    def test_memorize_NI(self):
        c = self.conf()

        def is_broadcast(ps):
            conds = []
            for sink in c.sinks:
                conds.append(Not(ps[sink].is_empty()))
            return And(*conds)

        def steer_to(p, s, sink):
            conds = []
            for source in c.sources:
                ps, _ = c.process_packet(s, source, p)
                conds.append(And(Not(is_broadcast(ps)),
                                 Not(ps[sink].is_empty())))
            return And(*conds)

        p1, p2, p_other = c.sym_packets(3)
        s1 = c.sym_state()
        
        addr_cond = And(p1.ether.dst == p2.ether.dst,
                        p_other.ether.src != p1.ether.dst)

        for source in c.sources:
            for sink in c.sinks:
                _, s2 = c.process_packet(s1, source, p_other)

                self.verify(Implies(And(addr_cond,
                                        steer_to(p1, s1, sink)),
                                    steer_to(p2, s2, sink)))

    def test_always_broadcast_if_unknown(self):
        c = self.conf()
        
        def is_broadcast(ps):
            conds = []
            for sink in c.sinks:
                conds.append(Not(ps[sink].is_empty()))
            return And(*conds)

        def do_broadcast(p, s):
            conds = []
            for source in c.sources:
                ps, _ = c.process_packet(s, source, p)
                conds.append(is_broadcast(ps))
            return And(*conds)

        p1, p2, p_other = c.sym_packets(3)
        s1 = c.sym_state()
        
        addr_cond = And(p1.ether.dst == p2.ether.dst,
                        p_other.ether.src != p1.ether.dst)

        for source in c.sources:
            _, s2 = c.process_packet(s1, source, p_other)
            self.verify(Implies(And(addr_cond,
                                    do_broadcast(p1, s1)),
                                do_broadcast(p2, s2)))
