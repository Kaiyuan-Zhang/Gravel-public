from .element import *
from .graph import *
import unittest
from . import utils
from . import ops
import z3


class Config(object):
    def __init__(self, element_types, edges, packet_parser):
        packet_format = packet_parser.spec_format()
        self.parser = packet_parser
        elements = {}
        l = []
        self.sources = []
        self.sinks = []
        self.element_types = element_types
        for entry in element_types:
            name = entry[0]
            cls = entry[1]
            assert name not in elements
            e = cls(name)
            elements[name] = e
            l.append(elements[name])
            if e.num_in() == 0:
                self.sources.append(name)
            if e.num_out() == 0:
                self.sinks.append(name)

        self.graph = Graph(l, edges)
        self.packet_format = packet_format
        for e in self.graph.elements:
            self.graph.elements[e].packet_format = packet_format

    def sym_pkt(self):
        return self.fresh_packet()

    def sym_packets(self, n):
        results = []
        for i in range(n):
            results.append(self.sym_pkt())
        return tuple(results)

    def fresh_packet(self):
        return Packet(self.packet_format)

    def sym_state(self):
        return self.fresh_state()

    def fresh_state(self):
        return self.fresh_states()

    def fresh_states(self):
        states = {}
        for e in self.graph.elements:
            states[e] = self.graph.elements[e].fresh_state()
        return states

    def state_invs(self, states):
        invs = {}
        for name, e in self.graph.elements.items():
            try:
                invs[name] = e.state_inv(states[name])
            except NotImplementedError:
                continue
        if len(invs) == 0:
            return z3.BoolVal(True)
        else:
            return ops.And(*list(invs.values()))

    def process_packet(self, old_states, ele_name, packet=None):
        name = ele_name
        if type(ele_name) != str:
            name = self.sources[ele_name]
        result = self.graph.process_packet(old_states, name, packet)

        all_edge_packets = result[0]
        packet_sets = {}
        for e in self.sinks:
            if e not in packet_sets:
                packet_sets[e] = []
            for edge in filter(lambda edge: edge.dst == e, self.graph.edges):
                packet_sets[e] += all_edge_packets[edge]

        for k in packet_sets:
            packet_sets[k] = PacketSet(packet_sets[k], self.packet_format)

        internal_set = {}
        for e, s in all_edge_packets.items():
            if e.src not in internal_set:
                internal_set[e.src] = {}
            internal_set[e.src][e.src_idx] = s

        for k, v in internal_set.items():
            for edge_idx in v:
                packet_list = internal_set[k][edge_idx]
                internal_set[k][edge_idx] = PacketSet(packet_list, self.packet_format)

        packet_sets['__edges'] = internal_set
        return packet_sets, result[1]

    def handle_event(self, old_states, ele_name, event_name, *args):
        name = ele_name
        if type(ele_name) != str:
            name = self.sources[ele_name]
        result = self.graph.handle_event(old_states, name, event_name, *args)

        all_edge_packets = result[0]
        packet_sets = {}
        for e in self.sinks:
            if e not in packet_sets:
                packet_sets[e] = []
            for edge in filter(lambda edge: edge.dst == e, self.graph.edges):
                packet_sets[e] += all_edge_packets[edge]

        for k in packet_sets:
            packet_sets[k] = PacketSet(packet_sets[k], self.packet_format)
        return packet_sets, result[1]

class ConfigVerifyTask(object):
    conf_obj = None
    conf_initialized = False
    @classmethod
    def conf(cls):
        if not cls.conf_initialized:
            cls.conf_obj = cls.build_conf()
            cls.conf_initialized = True
        return cls.conf_obj

    @classmethod
    def build_conf(cls):
        raise NotImplementedError()

    def test_element_invs(self):
        c = self.conf()
        p, s = c.fresh_packet(), c.fresh_states()
        invs = {}
        for name, e in c.graph.elements.items():
            try:
                invs[name] = e.state_inv(s[name])
            except NotImplementedError:
                continue

        for source_name in c.sources:
            out, new_s = c.process_packet(s, source_name, p)
            for name, e in c.graph.elements.items():
                if name in invs:
                    inv_post = e.state_inv(new_s[name])
                    self.verify(ops.Implies(invs[name], inv_post), lambda m: [name, m])


    def verify(self, clause, printer=None):
        s = z3.Solver()
        s.add(z3.Not(clause))
        result = s.check()
        # TODO: print counterexample
        if result != z3.unsat:
            if result != z3.sat:
                print("got result {}".format(result))
            fail_msg = printer(s.model()) if callable(printer) else "Counterexample found"
            self.fail(fail_msg)
