from gravel_spec.utils import *
from gravel_spec.element import *
from gravel_spec.graph import *
from gravel_spec.config import *
from gravel_spec.ops import *
from graphviz import Digraph
from gravel_spec.click_common import *
from gravel_spec.click_api import *


def is_tcp(p):
    return And(p.ether.ether_type == 0x0800,
               p.ip.proto == 6)


class Proxy(ConfigVerifyTask, unittest.TestCase):
    @classmethod
    def build_conf(cls):
        cls.fake_ip = fresh_bv('fakeIP', 32)
        cls.local_ip = fresh_bv('localIP', 32)
        
        elements = {
            'from_net' : Source(),
            'from_linux' : Source(),
            'net_ip_class' : IPClassifier([lambda p, se: And(p.ether.ether_type == 0x0800,
                                                             p.ip.proto == 6, 
                                                             p.tcp.dst == 80),
                                           lambda p, se: True]),
            'proxy_rw' : ProxyRewriter(),
            'linux_class' : Classifier([[("ether.ether_type", 0x0806), ("arp.op", 0x0001)],
                                        ("ether.ether_type", 0x0800), "-"]),
            'strip' : Strip(14),
            'checkip' : CheckIPHeader(),
            'ether_encap': EtherEncap(0x0800, ether2num([1,1,1,1,1,1]), ether2num([2,2,2,2,2,2])),
            'to_linux' : Sink(),
            'to_net' : Sink(),
            'discard' : Discard(),
        }

        paths = Path('from_net', 0) >> (0, 'net_ip_class', 0) >> (0, 'proxy_rw', 0) \
                >> (0, 'ether_encap', 0) >> (0, 'to_linux')
        paths += Path('from_linux', 0) >> (0, 'linux_class', 0) >> (0, 'discard')
        paths += Path('linux_class', 1) >> (0, 'strip', 0) >> (0, 'checkip', 0) >> (1, 'proxy_rw', 1) \
                 >> (0, 'to_net')
        paths += Path('net_ip_class', 1) >> (0, 'discard')
        paths += Path('linux_class', 2) >> (0, 'discard')

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

    # def test_no_filtering(self):
    #     c = self.conf()
    #     s, p = c.sym_state(), c.sym_pkt()
    #     ps, _ = c.process_packet(s, 'from_net', p)
    #     conds = []
    #     for sink in c.sinks:
    #         conds.append(ps[sink].not_empty())
    #     self.verify(Implies(And(p.ether.ether_type == 0x0800, 
    #                             p.ip.proto == 6,
    #                             p.tcp.dst == 80),
    #                         Or(*conds)))

    def test_bijection(self):
        c = self.conf()
        s, p = c.sym_state(), c.sym_pkt()
        p_rev = c.sym_pkt()
        o, ns = c.process_packet(s, 'from_net', p)
        o_rev, ns = c.process_packet(s, 'from_linux', p_rev)
        def is_rev_flow(p1, p2):
            return And(p1.ip.src == p2.ip.dst,
                       p1.ip.dst == p2.ip.src,
                       p1.tcp.src == p2.tcp.dst,
                       p1.tcp.dst == p2.tcp.src)
        self.verify(Implies(And(is_tcp(p), is_tcp(p_rev),
                                is_rev_flow(o['to_linux'], p_rev),
                                o['to_linux'].not_empty(),
                                c.state_invs(s)),
                            o_rev['to_net'].not_empty()))
