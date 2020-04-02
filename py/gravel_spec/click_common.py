from .utils import *
from .element import *
from .graph import *
from .config import *
#from .ops import *
from .click_element import *
from .click_api import *
from functools import reduce


class Tee(ClickElement):
    num_in_ports = 1
    num_out_ports = 2
    def process_packet(self, old, p, in_port, se=z3):
        return Action(se.BoolVal(True),
                      {0: p, 1: p.copy()},
                      old)


class Classifier(ClickElement):
    num_in_ports = 1
    def __init__(self, confs):
        self.confs = confs

    def num_out(self):
        return len(self.confs)

    def process_packet(self, old, p, in_port, se=z3):
        actions = []
        pre_filter = True
        for o_port, c in enumerate(self.confs):
            if type(c) is list:
                conds = []
                for field, val in c:
                    fields = field.split('.')
                    header = getattr(p, fields[0])
                    f_val = getattr(header, fields[1])
                    conds.append(f_val == val)
                actions += Action(se.And(pre_filter, *conds), {o_port: p}, old)
                pre_filter = se.And(pre_filter, se.Not(se.And(*conds)))
            elif type(c) is tuple:
                field, val = c
                fields = field.split('.')
                header = getattr(p, fields[0])
                f_val = getattr(header, fields[1])
                actions += Action(se.And(pre_filter, f_val == val), {o_port: p}, old)
                pre_filter = se.And(pre_filter, f_val != val)
            elif c == '-':
                actions += Action(pre_filter, {o_port: p}, old)
                pre_filter = False
        return actions


class EtherEncap(ClickElement):
    num_in_ports = 1
    num_out_ports = 1
    def __init__(self, ether_type, dst, src):
        self.ether_type = ether_type
        self.dst = dst
        self.src = src

    def process_packet(self, old, p, in_port, se=z3):
        p = p.copy()
        p.ether.ether_type = self.ether_type
        p.ether.dst = self.dst
        p.ether.src = self.src
        return Action(se.BoolVal(True),
                      {0: p},
                      old)

class EtherSwitch(ClickElement):
    ether_map = ClickMap(6, 4)
    def __init__(self, num_in, num_out):
        self.num_in_ports = num_in
        self.num_out_ports = num_out

    def process_packet(self, s, p, in_port, se=z3):
        actions = []
        
        src = p.ether.src
        dst = p.ether.dst
        has_mapping = s.ether_map.has_key(dst)
        dst_port = s.ether_map[dst][0]

        updated = s.copy()
        updated.ether_map[src] = se.BitVecVal(in_port, 32)
        broadcast = {}
        #print(se.simplify(updated.ether_map.has_key(src)))
        for i in range(self.num_out_ports):
            actions += Action(And(has_mapping, dst_port == i),
                              {i : p}, updated)
            broadcast[i] = p.copy()
        actions += Action(Not(has_mapping), broadcast, updated)
        return actions

    def state_inv(self, s, se=z3):
        src = fresh_bv('src', 8 * 6)
        bound = se.ULT(s.ether_map[src][0], self.num_out_ports)
        return se.ForAll([src], Implies(s.ether_map.has_key(src),
                                        bound))

class ARPQuerier(ClickElement):
    num_in_ports = 2
    num_out_ports = 1
    def __init__(self, my_ether_addr):
        self.addr = my_ether_addr

    def process_packet(self, old, p, in_port, se=z3):
        return Action(in_port == 0,
                      {0: p},
                      old)


class ARPResponder(ClickElement):
    num_in_ports = 1
    num_out_ports = 1
    def __init__(self, my_ether_addr, my_ip_addr):
        self.ip = my_ip_addr
        self.ether = my_ether_addr

    def process_packet(self, old, p, in_port, se=z3):
        return Action(se.BoolVal(True),
                      {},
                      old)


class Discard(ClickElement):
    num_in_ports = 1
    num_out_ports = 0

    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {}, old)


class RewriteSpec(object):
    def __init__(self, op, foutput, doutput, *args):
        self.args = args
        self.op = op
        self.foutput = foutput
        self.doutput = doutput

class IPRewriteEntry(SpecStruct):
    _fields = [('saddr', sizeof(c_int)),
               ('daddr', sizeof(c_int)),
               ('sport', sizeof(c_short)),
               ('dport', sizeof(c_short)), 
               ('output', sizeof(c_int))]
    _struct_name = 'IPRewriteEntry'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class IPRewriter(ClickElement):
    udp_map = ClickMap(IPFlowID, IPRewriteEntry)
    tcp_map = ClickMap(IPFlowID, IPRewriteEntry)
    def __init__(self, confs):
        self.confs = confs
        nout = 0
        for c in self.confs:
            nout = max(c.foutput, c.doutput, nout)
        self.num_in_ports = len(confs)
        self.num_out_ports = nout + 1

    @staticmethod
    def tcp_flow_apply(flow, pkt):
        pkt.ip.src = flow.saddr
        pkt.ip.dst = flow.daddr
        pkt.tcp.src = flow.sport
        pkt.tcp.dst = flow.dport

    @staticmethod
    def udp_flow_apply(flow, pkt):
        pkt.ip.src = flow.saddr
        pkt.ip.dst = flow.daddr
        pkt.udp.src = flow.sport
        pkt.udp.dst = flow.dport

    def process_packet(self, s, p, in_port, se=z3):
        actions = []
        spec = self.confs[in_port]
        is_tcp = (p.ip.proto == 6)
        is_udp = (p.ip.proto == 17)

        flow_id = get_flowid(p)
        m = se.If(is_tcp, s.tcp_map, s.udp_map)
        has_mapping = m.has_key(flow_id)
        translated_tcp = p.copy()
        translated_udp = p.copy()
        rewritten_flow = IPRewriteEntry.from_tuple(m[flow_id.to_tuple()])
        self.tcp_flow_apply(rewritten_flow, translated_tcp)
        self.udp_flow_apply(rewritten_flow, translated_udp)

        for i in range(self.num_out_ports):
            actions += Action(And(has_mapping, rewritten_flow.output == i, is_tcp),
                              {i: translated_tcp}, s)
            actions += Action(And(has_mapping, rewritten_flow.output == i, is_udp),
                              {i: translated_udp}, s)

        if spec.op == 'pattern':
            sport = fresh_bv('sport', 16)
            dport = fresh_bv('dport', 16)
            new_flow = IPRewriteEntry()
            new_flow.saddr = spec.args[0] if spec.args[0] is not None else p.ip.src
            new_flow.daddr = spec.args[2] if spec.args[2] is not None else p.ip.dst
            new_flow.sport = sport if spec.args[1] is not None else se.If(is_tcp, p.tcp.src, p.udp.src)
            new_flow.dport = dport if spec.args[3] is not None else se.If(is_tcp, p.tcp.dst, p.udp.dst)
            new_flow.output = spec.foutput

            new_flow_rev = IPRewriteEntry() 
            new_flow_rev.daddr = spec.args[0] if spec.args[0] is not None else p.ip.src
            new_flow_rev.saddr = spec.args[2] if spec.args[2] is not None else p.ip.dst
            new_flow_rev.dport = sport if spec.args[1] is not None else se.If(is_tcp, p.tcp.src, p.udp.src)
            new_flow_rev.sport = dport if spec.args[3] is not None else se.If(is_tcp, p.tcp.dst, p.udp.dst)
            new_flow_rev.output = spec.doutput

            ns_tcp = s.copy()
            ns_tcp.tcp_map[flow_id.to_tuple()] = new_flow.to_tuple()
            ns_tcp.tcp_map[new_flow.to_tuple()[:-1]] = new_flow_rev.to_tuple()

            ns_udp = s.copy()
            ns_udp.udp_map[flow_id.to_tuple()] = new_flow.to_tuple()
            ns_udp.udp_map[new_flow.to_tuple()[:-1]] = new_flow_rev.to_tuple()

            # actions += Action(And(Not(has_mapping), is_tcp),
            #                   {new_flow.output : translated_tcp}, ns_tcp)
            # actions += Action(And(Not(has_mapping), is_udp),
            #                   {new_flow.output : translated_udp}, ns_udp)
        elif spec.op == 'drop':
            return Action(True, {}, s)
        elif spec.op == 'pass':
            pass


class ProxyRewriter(ClickElement):
    num_in_ports = 1
    num_out_ports = 2
    udp_map = ClickMap(IPFlowID, IPRewriteEntry)
    tcp_map = ClickMap(IPFlowID, IPRewriteEntry)

    @staticmethod
    def rev_entry(key, val, se):
        rev_key = IPFlowID()
        rev_key.saddr = val.daddr
        rev_key.daddr = val.saddr
        rev_key.sport = val.dport
        rev_key.dport = val.sport

        rev_val = IPRewriteEntry()
        rev_val.saddr = key.daddr
        rev_val.daddr = key.saddr
        rev_val.sport = key.dport
        rev_val.dport = key.sport
        rev_val.output = se.BitVecVal(1, 32)
        return rev_key, rev_val

    @staticmethod
    def rewrite_tcp(p, entry):
        p.ip.src = entry.saddr
        p.ip.dst = entry.daddr
        p.tcp.src = entry.sport
        p.tcp.dst = entry.dport

    @staticmethod
    def rewrite_udp(p, entry):
        p.ip.src = entry.saddr
        p.ip.dst = entry.daddr
        p.udp.src = entry.sport
        p.udp.dst = entry.dport
    
    def process_packet(self, s, p, in_port, se=z3):
        actions = []
        is_tcp = (p.ip.proto == 6)
        is_udp = (p.ip.proto == 17)

        flow_id = get_flowid(p)
        m = se.If(is_tcp, s.tcp_map, s.udp_map)
        has_mapping = m.has_key(flow_id)
        translated_tcp = p.copy()
        translated_udp = p.copy()
        rewritten_flow = IPRewriteEntry.from_tuple(m[flow_id.to_tuple()])

        self.rewrite_tcp(translated_tcp, rewritten_flow)
        self.rewrite_udp(translated_udp, rewritten_flow)

        for i in range(self.num_out_ports):
            actions += Action(And(has_mapping, rewritten_flow.output == i, is_tcp),
                              {i: translated_tcp}, s)
            actions += Action(And(has_mapping, rewritten_flow.output == i, is_udp),
                              {i: translated_udp}, s)

        port = fresh_bv('port', 16)
        new_flow = IPRewriteEntry()
        new_flow.saddr = se.BitVecVal(0xc0c0c0c0, 32)
        new_flow.daddr = se.BitVecVal(0xa0a0a0a0, 32)
        new_flow.sport = port
        new_flow.dport = se.BitVecVal(8000, 16)
        new_flow.output = se.BitVecVal(0, 32)
        ns_tcp = s.copy()
        ns_tcp.tcp_map[flow_id.to_tuple()] = new_flow.to_tuple()
        ns_udp = s.copy()
        ns_udp.udp_map[flow_id.to_tuple()] = new_flow.to_tuple()

        rev_k, rev_v = self.rev_entry(flow_id, new_flow, se)
        ns_tcp.tcp_map[rev_k.to_tuple()] = rev_v.to_tuple()
        ns_udp.udp_map[rev_k.to_tuple()] = rev_v.to_tuple()

        could_alloc = And(m.has_key(flow_id.to_tuple()),
                          m.has_key(rev_k.to_tuple()))
        
        np = p.copy()
        self.rewrite_tcp(np, new_flow)
        actions += Action(And(Not(has_mapping), in_port == 0, is_tcp, could_alloc), 
                          {0: np}, ns_tcp)
        np = p.copy()
        self.rewrite_udp(np, new_flow)
        actions += Action(And(Not(has_mapping), in_port == 0, is_udp, could_alloc), 
                          {0: np}, ns_udp)
        
        return actions

    def state_inv(self, s, se=z3):
        key = IPFlowID()
        maps = [s.tcp_map, s.udp_map]
        conds = []
        def flow_rev_eq(f1, f2):
            return And(f1.saddr == f2.daddr,
                       f1.sport == f2.dport,
                       f1.daddr == f2.saddr,
                       f1.dport == f2.sport)
        for m in maps:
            val = IPRewriteEntry.from_tuple(m[key.to_tuple()])
            k2 = IPFlowID()
            k2.saddr = val.daddr
            k2.sport = val.dport
            k2.daddr = val.saddr
            k2.dport = val.sport
            rev_val = IPRewriteEntry.from_tuple(m[k2.to_tuple()])
            conds.append(se.ForAll(list(key.to_tuple()), 
                                se.Implies(m.has_key(key), 
                                    se.And(m.has_key(k2), 
                                        flow_rev_eq(rev_val, key), 
                                        se.Or(val.output == 0, val.output == 1),
                                        val.output == 1 - rev_val.output))))
        return And(*conds)


class MyIPRewriter(ClickElement):
    num_in_ports = 5
    num_out_ports = 3
    udp_map = ClickMap(IPFlowID, IPFlowID)
    tcp_map = ClickMap(IPFlowID, IPFlowID)
    def __init__(self):
        pass

    @staticmethod
    def pkt_tcp_flow_id(pkt):
        flow_id = IPFlowID()
        flow_id.saddr = pkt.ip.src
        flow_id.daddr = pkt.ip.dst
        flow_id.sport = pkt.tcp.src
        flow_id.dport = pkt.tcp.dst
        return flow_id

    @staticmethod
    def pkt_udp_flow_id(pkt):
        flow_id = IPFlowID()
        flow_id.saddr = pkt.ip.src
        flow_id.daddr = pkt.ip.dst
        flow_id.sport = pkt.udp.src
        flow_id.dport = pkt.udp.dst
        return flow_id

    @staticmethod
    def tcp_flow_apply(flow, pkt):
        pkt.ip.src = flow.saddr
        pkt.ip.dst = flow.daddr
        pkt.tcp.src = flow.sport
        pkt.tcp.dst = flow.dport

    @staticmethod
    def udp_flow_apply(flow, pkt):
        pkt.ip.src = flow.saddr
        pkt.ip.dst = flow.daddr
        pkt.udp.src = flow.sport
        pkt.udp.dst = flow.dport

    def process_packet(self, old, p, in_port, se=z3):
        actions = []

        is_tcp = (p.ip.proto == 6)
        is_udp = (p.ip.proto == 17)
        tcp_id = self.pkt_tcp_flow_id(p).to_expr()
        udp_id = self.pkt_udp_flow_id(p).to_expr()
        
        m = se.If(is_tcp, old.tcp_map, old.udp_map)
        flow_id = se.If(is_tcp, tcp_id, udp_id)
        
        have_mapping = m.has_key(flow_id)
        translated_tcp = p.copy()
        translated_udp = p.copy()
        rewritten_flow = IPFlowID.from_expr(m[flow_id][0])
        self.tcp_flow_apply(rewritten_flow, translated_tcp)
        self.udp_flow_apply(rewritten_flow, translated_udp)
        
        actions += Action(And(in_port == 0, is_tcp, have_mapping),
                          {0: translated_tcp},
                          old)
        actions += Action(And(in_port == 1, is_tcp, have_mapping),
                          {1: translated_tcp},
                          old)
        actions += Action(And(in_port == 2, is_tcp, have_mapping),
                          {1: translated_tcp},
                          old)
        
        return actions


class MyIPRewriterMod(ClickElement):
    class NatExternKey(SpecStruct):
        _fields = [('port', sizeof(c_short)),
                   ('protocol', sizeof(c_char))]
        _struct_name = "NatExtKey"

    class NatInternKey(SpecStruct):
        _fields = [('addr', sizeof(c_int)),
                   ('port', sizeof(c_short)),
                   ('protocol', sizeof(c_char))]
        _struct_name = "NatIntKey"

    num_in_ports = 5
    num_out_ports = 3
    public_ip = ClickVal(c_int)
    map_extern = ClickMap(NatExternKey, IPFlowID)
    map_intern = ClickMap(NatInternKey, IPFlowID)
    curr_time = ClickVal(c_ulonglong)
    
    def __init__(self, extern_ip):
        pass
    
    @staticmethod
    def extern_tcp_rewrite(flow, p):
        pkt = p.copy()
        pkt.ip.dst = flow.daddr
        pkt.tcp.dst = flow.dport
        return pkt

    @staticmethod
    def extern_udp_rewrite(flow, p):
        pkt = p.copy()
        pkt.ip.dst = flow.daddr
        pkt.udp.dst = flow.dport
        return pkt

    @staticmethod
    def intern_tcp_rewrite(flow, p):
        pkt = p.copy()
        pkt.ip.src = flow.saddr
        pkt.tcp.src = flow.sport
        return pkt

    @staticmethod
    def intern_udp_rewrite(flow, p):
        pkt = p.copy()
        pkt.ip.src = flow.saddr
        pkt.udp.src = flow.sport
        return pkt

    def impl_state_equiv(self, lib, spec_s, impl_s):
        # equivalence of maps
        se = CobbleSymGen(lib)
        conds = []
        public_ip_buf = CobbleBuffer(lib, ptr=lib.get_obj_handle_by_off(impl_s, 268))
        impl_extern_map = lib.get_obj_handle_by_off(impl_s, 272)
        impl_intern_map = lib.get_obj_handle_by_off(impl_s, 328)
        def extern_key_eq(spec_k, impl_k):
            spec_bv = lib.bv_concat(spec_k[0], spec_k[1])
            impl_fields = []
            impl_fields.append(se.bv_bswap(se.bv_extract_from_top(impl_k[0], 0, 16)))
            impl_fields.append(se.bv_extract_from_top(impl_k[0], 16, 16 + 8))
            impl_v = se.Concat(*impl_fields)
            return lib.bv_eq(spec_bv, impl_v.inner())

        def intern_key_eq(spec_k, impl_k):
            impl_fields = []
            impl_fields.append(se.bv_bswap(se.bv_extract_from_top(impl_k[0], 0, 32)))
            impl_fields.append(se.bv_bswap(se.bv_extract_from_top(impl_k[0], 32, 32 + 16)))
            impl_fields.append(se.bv_extract_from_top(impl_k[0], 32 + 16, 32 + 16 + 8))
            return se.And(*map(lambda x, y: x == y, impl_fields, spec_k)).inner()

        def extern_val_eq(spec_val, impl_val):
            daddr = se.bv_bswap(se.bv_extract_from_top(impl_val[0], 32, 64))
            dport = se.bv_bswap(se.bv_extract_from_top(impl_val[0], 64 + 16, 64 + 32))
            spec_daddr = spec_val[1]
            spec_dport = spec_val[3]
            return se.And(daddr == spec_daddr, dport == spec_dport)
        
        def intern_val_eq(spec_val, impl_val):
            saddr = se.bv_bswap(se.bv_extract_from_top(impl_val[0], 0, 32))
            sport = se.bv_bswap(se.bv_extract_from_top(impl_val[0], 64, 64 + 16))
            spec_saddr = spec_val[0]
            spec_sport = spec_val[2]
            return se.And(saddr == spec_saddr, sport == spec_sport)

        conds.append(spec_s.public_ip == public_ip_buf.load(0, 4))
        conds.append(spec_s.map_extern.map_eq(impl_extern_map, impl_key_sz=[24],
            key_eq_func=extern_key_eq, vals_eq_func=extern_val_eq))
        conds.append(spec_s.map_intern.map_eq(impl_intern_map, impl_key_sz=[56],
            key_eq_func=intern_key_eq, vals_eq_func=intern_val_eq))
        return reduce(lib.bool_and, map(get_inner, conds))

    def process_packet(self, old, p, in_port, se=z3):
        actions = []

        is_tcp = (p.ip.proto == 6)
        is_udp = (p.ip.proto == 17)
        ext_id = self.NatExternKey()
        ext_id.port = se.If(is_tcp, p.tcp.dst, p.udp.dst)
        ext_id.protocol = p.ip.proto
        ext_id = ext_id.to_tuple()

        have_mapping = old.map_extern.has_key(ext_id)
        rewritten_flow = IPFlowID.from_tuple(old.map_extern[ext_id])
        # actions += Action(And(in_port == 1, have_mapping, is_tcp),
        #                   {1: self.extern_tcp_rewrite(rewritten_flow, p)},
        #                   old)
        # actions += Action(And(in_port == 1, have_mapping, is_udp),
        #                   {1: self.extern_udp_rewrite(rewritten_flow, p)},
        #                   old)
        do_hairpin = (old.public_ip == p.ip.dst)
        do_to_intern = se.And(do_hairpin, se.Or(in_port == 1, in_port == 0, in_port == 3))
        actions += Action(se.And(do_to_intern, have_mapping, is_tcp),
                          {1: self.extern_tcp_rewrite(rewritten_flow, p)},
                          old)
        actions += Action(se.And(do_to_intern, have_mapping, is_udp),
                          {1: self.extern_udp_rewrite(rewritten_flow, p)},
                          old)

        int_id = self.NatInternKey(se=se)
        int_id.addr = p.ip.src
        int_id.port = se.If(is_tcp, p.tcp.src, p.udp.src)
        int_id.protocol = p.ip.proto
        int_id = int_id.to_tuple()

        have_mapping = old.map_intern.has_key(int_id)
        rewritten_flow = IPFlowID.from_tuple(old.map_intern[int_id])
        actions += Action(se.And(se.Not(do_hairpin), in_port == 0, have_mapping, is_tcp),
                          {0: self.intern_tcp_rewrite(rewritten_flow, p)},
                          old)
        actions += Action(se.And(se.Not(do_hairpin), in_port == 0, have_mapping, is_udp),
                          {0: self.intern_udp_rewrite(rewritten_flow, p)},
                          old)

        ns = old.copy()
        ext_id = self.NatExternKey(se)
        int_id = self.NatInternKey(se)
        ext_id.port = self.exists_bv('port', 16, se=se)
        ext_id.protocol = p.ip.proto
        int_id.addr = p.ip.src
        int_id.port = se.If(is_tcp, p.tcp.src, p.udp.src)
        int_id.protocol = p.ip.proto

        ext_flow = IPFlowID(se)
        ext_flow.daddr = int_id.addr
        ext_flow.dport = int_id.port
        int_flow = IPFlowID(se)
        int_flow.saddr = old.public_ip
        int_flow.sport = ext_id.port

        ns.map_extern[ext_id.to_tuple()] = ext_flow.to_tuple()
        ns.map_intern[int_id.to_tuple()] = int_flow.to_tuple()

        could_alloc = se.Not(old.map_extern.has_key(ext_id.to_tuple()))
        actions += Action(se.And(se.Not(do_hairpin), se.Not(have_mapping), in_port == 0, could_alloc, is_tcp),
                          {0: self.intern_tcp_rewrite(int_flow, p)},
                          ns)

        actions += Action(se.And(se.Not(do_hairpin), se.Not(have_mapping), in_port == 0, could_alloc, is_udp),
                          {0: self.intern_udp_rewrite(int_flow, p)},
                          ns)
        
        return actions

    def handle_event(self, s, event, *params):
        if event == 'time':
            return Action(True, {}, s)

    def state_inv(self, s, se=z3):
        ext_id = self.NatExternKey()
        int_id = self.NatInternKey()
        int_id.protocol = ext_id.protocol

        ext_flow = IPFlowID.from_tuple(s.map_extern[ext_id.to_tuple()])
        int_flow = IPFlowID.from_tuple(s.map_intern[int_id.to_tuple()])

        ext_val = self.NatInternKey()
        ext_val.addr = ext_flow.daddr
        ext_val.port = ext_flow.dport
        ext_val.protocol = ext_id.protocol

        int_val = self.NatExternKey()
        int_val.port = int_flow.sport
        int_val.protocol = ext_id.protocol
        
        ext_map = s.map_extern
        int_map = s.map_intern
        return ForAll([ext_id.port, ext_id.protocol,
                       int_id.addr, int_id.port], 
                      And(Implies(ext_map.has_key(ext_id), int_map.has_key(ext_val)),
                          Implies(int_map.has_key(int_id), ext_map.has_key(int_val)),
                          Implies(ext_map.has_key(ext_id),
                                  IPFlowID.from_tuple(int_map[ext_val.to_tuple()]).sport == ext_id.port),
                          Implies(int_map.has_key(int_id),
                                  And(IPFlowID.from_tuple(ext_map[int_val.to_tuple()]).dport == int_id.port,
                                      IPFlowID.from_tuple(ext_map[int_val.to_tuple()]).daddr == int_id.addr))))
        


class TCPRewriter(ClickElement):
    num_in_ports = 2
    num_out_ports = 2
    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {}, old)


class GetIPAddress(ClickElement):
    num_in_ports = 1
    num_out_ports = 1
    def __init__(self, offset):
        self.offset = offset

    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {0: p}, old)


class CheckIPHeader(ClickElement):
    num_in_ports = 1
    num_out_ports = 1

    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {0: p}, old)


class IPClassifier(ClickElement):
    num_in_ports = 1
    num_out_ports = 1
    def __init__(self, classes):
        self.classes = classes

    def num_out(self):
        return len(self.classes)

    def process_packet(self, old, p, in_port, se=z3):
        actions = []
        pre = True
        for o_port, c in enumerate(self.classes):
            cond = c(p, se)
            actions += Action(se.And(pre, cond), {o_port: p}, old)
            pre = se.And(pre, se.Not(cond))
        return actions


class Strip(ClickElement):
    num_in_ports = 1
    num_out_ports = 1
    def __init__(self, amount):
        self.amount = amount

    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {0: p}, old)


class FTPPortMapper(ClickElement):
    num_in_ports = 1
    num_out_ports = 1

    def process_packet(self, old, p, in_port, se=z3):
        return Action(True, {}, old)
