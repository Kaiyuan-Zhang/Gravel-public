import numbers
import z3
from . import utils
from . import ops
from .spec_ast import SpecAst
import copy


def format_eq(lhs, rhs):
    if set(lhs.keys()) != set(rhs.keys()):
        return False
    for k in lhs:
        if isinstance(lhs[k], numbers.Number):
            if lhs[k] != rhs[k]:
                return False
        elif not dict_eq(lhs[k], rhs[k]):
            return False
    return True


def dict_eq(lhs, rhs):
    if set(lhs.keys()) != set(rhs.keys()):
        return False
    for k in lhs:
        if lhs[k] != rhs[k]:
            return False
    return True


class Header(object):
    def __init__(self, fields):
        self.field_names = set([])
        for k in fields:
            assert utils.valid_field_name(k)
            assert k not in self.__dict__
            self.field_names.add(k)
            self.__dict__[k] = fields[k]

    def copy(self):
        fields = {}
        for k in self.field_names:
            fields[k] = self.__dict__[k]
        new = Header(fields)
        return new

    def __str__(self):
        s = ""
        for f in self.field_names:
            s = s + "({} : {})\n".format(f, self.__dict__[f])
        if len(s) != 0 and s[-1] == '\n':
            s = s[:-1]
        return s

    def eval_with(self, m):
        s = ""
        for f in self.field_names:
            s = s + "({} : {})\n".format(f, m.evaluate(self.__dict__[f]))
        if len(s) != 0 and s[-1] == '\n':
            s = s[:-1]
        return s


class Packet(object):
    def __init__(self, header_format):
        self.headers = {}
        self.packet_format = header_format
        for hn, h in header_format.items():
            header = {}
            assert utils.valid_field_name(hn)
            if isinstance(h, numbers.Number):
                # This header is simply a blob
                bv = utils.fresh_bv(hn, h)
                self.headers[hn] = bv
                self.__dict__[hn] = bv
                continue
            for fn, f_size in h.items():
                assert utils.valid_field_name(fn), fn
                header[fn] = utils.fresh_bv('{}!{}'.format(hn, fn),
                                            f_size * 8)
            self.headers[hn] = Header(header)
            self.__dict__[hn] = self.headers[hn]

    def __getitem__(self, header_name):
        return self.headers[header_name]

    def copy(self):
        new = Packet({})
        new.packet_format = self.packet_format
        for hn, h in self.headers.items():
            new.headers[hn] = h.copy() if 'copy' in dir(h) else h
            new.__dict__[hn] = new.headers[hn]
        return new

    def __repr__(self):
        s = ""
        for hn in self.headers:
            s = s + "{} : \n({})\n".format(hn, self.__dict__[hn])
        if len(s) != 0 and s[-1] == '\n':
            s = s[:-1]
        return s

    def eval_with(self, m):
        s = ""
        for hn in self.headers:
            if 'eval_with' in dir(self.__dict__[hn]):
                s = s + "{} : \n({})\n".format(hn, self.__dict__[hn].eval_with(m))
            else:
                s = s + "{} : \n({})\n".format(hn, m.evaluate(self.__dict__[hn]))
        if len(s) != 0 and s[-1] == '\n':
            s = s[:-1]
        return s


class PacketSet(object):
    def __init__(self, packet_set, format_=None):
        # first we need to make sure that all the packets in packet_set have same format
        self.packets = packet_set
        if len(packet_set) == 0:
            self.packet_format = format_
            fresh_p = Packet(format_)
            for hn, h in self.packet_format.items():
                fields = {}
                if isinstance(h, numbers.Number):
                    self.__dict__[hn] = fresh_p.__dict__[hn]
                    continue
                for fn in h:
                    fields[fn] = fresh_p.__dict__[hn].__dict__[fn]
                self.__dict__[hn] = Header(fields)
            return
        f = None
        for entry in self.packets:
            p = entry['packet']
            if f is None:
                f = p.packet_format
            else:
                assert format_eq(f, p.packet_format)

        self.packet_format = f

        # now compute each field as a huge ite
        fresh_p = Packet(f)
        for entry in self.packets:
            p = entry['packet']
            for hn, h in self.packet_format.items():
                if isinstance(h, numbers.Number):
                    v = p.__dict__[hn]
                    old_v = fresh_p.__dict__[hn]
                    new_v = ops.If(entry['cond'], v, old_v)
                    fresh_p.__dict__[hn] = new_v
                    continue
                for fn in h:
                    v = p.__dict__[hn].__dict__[fn]
                    old_v = fresh_p.__dict__[hn].__dict__[fn]
                    new_v = ops.If(entry['cond'], v, old_v)
                    fresh_p.__dict__[hn].__dict__[fn] = new_v

        for hn, h in self.packet_format.items():
            fields = {}
            if isinstance(h, numbers.Number):
                self.__dict__[hn] = fresh_p.__dict__[hn]
                continue
            for fn in h:
                fields[fn] = fresh_p.__dict__[hn].__dict__[fn]
            self.__dict__[hn] = Header(fields)

    def get_num_cond(self):
        return len(self.packets)

    def not_empty(self):
        return z3.Not(self.is_empty())

    def is_empty(self):
        conds = []
        for entry in self.packets:
            conds.append(ops.Not(entry['cond']))
        if len(conds) == 0:
            return z3.BoolVal(True)
        else:
            return ops.And(*conds)

    def __repr__(self):
        return repr(self.packets)


ETHER_HEADER = { 'dst' : 6,
                 'src' : 6,
                 'ether_type' : 2 }


IPv4_HEADER = { 'tos' : 1,
                'tot_len' : 2,
                'id' : 2,
                'frag_off' : 2,
                'ttl' : 1,
                'proto' : 1,
                'check' : 2,
                'src' : 4,
                'dst' : 4 }

TCP_HEADER = { 'src' : 2,
               'dst' : 2,
               'seq' : 4,
               'ack_seq' : 4,
               'flags' : 2,
               'window' : 2,
               'check' : 2,
               'urg_ptr' : 2 }

ARP_HEADER = { 'htype' : 2,
               'hproto' : 2,
               'hlen' : 1,
               'plen' : 1,
               'op' : 2,
               'sha' : 6,
               'spa' : 4,
               'tha' : 6,
               'tpa' : 4 }


# some helper functions for packets
def is_tcp(p):
    return ops.And(p.ether.ether_type == 0x0800,
                   p.ip4.proto == 6)


def is_udp(p):
    return ops.And(p.ether.ether_type == 0x0800,
                   p.ip4.proto == 17)


def is_udp_or_tcp(p):
    return ops.And(p.ether.ether_type == 0x0800,
                   ops.Or(p.ip4.proto == 6, p.ip4.proto == 17))


def is_tcp_syn(p):
    return ops.And(is_tcp(p),
                   (p.tcp.flags & 0x02) != 0)


def is_tcp_fin(p):
    return ops.And(is_tcp(p),
                   (p.tcp.flags & 0x01) != 0)

def is_tcp_rst(p):
    return ops.And(is_tcp(p),
                   (p.tcp.flags & 0x04) != 0)


class SymHeader(object):
    def __init__(self, fields):
        self.field_names = set()
        for k in fields:
            assert utils.valid_field_name(k)
            assert k not in self.__dict__
            self.field_names.add(k)
            self.__dict__[k] = fields[k]
        self.write_set = set()

    def __setattr__(self, name, val):
        if name not in ['field_names', 'write_set'] and 'write_set' in dir(self):
            self.write_set.add(name)
        return super().__setattr__(name, val)

    def copy(self):
        fields = {}
        for k in self.field_names:
            fields[k] = self.__dict__[k]
        new = SymHeader(fields)
        return new

    def __repr__(self):
        s = ""
        for f in self.field_names:
            s = s + "({} : {})\n".format(f, self.__dict__[f])
        if len(s) != 0 and s[-1] == '\n':
            s = s[:-1]
        return s


class SymPacket(object):
    def __init__(self, name, header_format):
        self.headers = {}
        self.packet_format = header_format
        self.name = name
        for hn, h in header_format.items():
            header = {}
            assert utils.valid_field_name(hn)
            if isinstance(h, numbers.Number):
                # This header is simply a blob
                bv = SpecAst('get-field', "\"{}\"".format(hn), "\"data\"", name)
                self.headers[hn] = bv
                self.__dict__[hn] = bv
                continue
            for fn, f_size in h.items():
                assert utils.valid_field_name(fn)
                header[fn] = SpecAst('get-field', "\"{}\"".format(hn), "\"{}\"".format(fn), name)
            self.headers[hn] = SymHeader(header)
            self.__dict__[hn] = self.headers[hn]

    def __getitem__(self, header_name):
        return self.headers[header_name]

    def copy(self):
        #new = Packet({})
        new = SymPacket(self.name, {})
        new.packet_format = self.packet_format
        for hn, h in self.headers.items():
            new.headers[hn] = h.copy() if 'copy' in dir(h) else h
            new.__dict__[hn] = new.headers[hn]
        return new

    def get_sexpr(self, packet_name):
        ast = []
        expr = self.name
        num_fields_written = 0
        for hn in self.headers:
            if 'write_set' in dir(self.__dict__[hn]):
                h = self.__dict__[hn]
                if len(h.write_set) > 0:
                    for fn in h.write_set:
                        f = h.__dict__[fn]
                        expr = SpecAst('rewrite', "\"{}\"".format(hn), "\"{}\"".format(fn), f, expr)
                        num_fields_written += 1

        if num_fields_written == 0:
            return SpecAst('packet-eq', self.name, packet_name)
        else:
            return SpecAst('packet-eq', expr, packet_name)

        for hn, h in self.headers.items():
            if isinstance(h, SymHeader):
                for fn in self.packet_format[hn]:
                    f = self.__dict__[hn].__dict__[fn]
                    field_val = SpecAst("get-field", "\"{}\"".format(hn), "\"{}\"".format(fn), packet_name)
                    ast.append(SpecAst("eq", field_val, f))
            else:
                f = self.__dict__[hn]
                field_val = SpecAst("get-field", "\"{}\"".format(hn), "\"data\"", packet_name)
                ast.append(SpecAst("eq", field_val, f))
        return ops.And(*ast)


class HeaderFormat(object):
    def __init__(self, header_name, header_format):
        '''
        header_format :: [(field-name, num-of-bytes)]
        '''
        self.name = header_name
        self.sizes = {}
        self.fields = []
        for entry in header_format:
            self.fields.append(entry[0])
            self.sizes[entry[0]] = entry[1]

    def header_size(self):
        sz = 0
        for k, v in self.sizes.items():
            sz += v
        return sz

    def to_field_list(self):
        result = []
        for f in self.fields:
            result.append((f, self.sizes[f]))
        return result


class HeaderParser(object):
    class FieldMatch(object):
        def __init__(self, match_type, args):
            num_args = { 'eq' : 1,
                         'ternary' : 2,
                         'always' : 0 }
            assert match_type in num_args
            #assert num_args[match_type] == len(args)
            self.match_type = match_type
            self.args = args

        def to_expr(self):
            s = [self.match_type]
            for a in self.args:
                s.append(str(a))
            return SpecAst(*s)

    def __init__(self):
        self.headers = {}
        self.connections = {}
        self.header_pre_req = {}
        self.branch_field = {}
        self.fresh_name_map = {}

    def fresh_name(self, base):
        if base not in self.fresh_name_map:
            self.fresh_name_map[base] = 0
        cnt = self.fresh_name_map[base]
        self.fresh_name_map[base] = cnt + 1
        return "{}!{}".format(base, cnt)

    def add_header(self, name, header_format):
        hf = header_format
        if not isinstance(header_format, HeaderFormat):
            hf = HeaderFormat(self.fresh_name('anon_header'), header_format)
        assert name not in self.headers
        self.headers[name] = hf
        self.branch_field[name] = None
        self.connections[name] = []
        self.header_pre_req[name] = []

    def add_edges(self, edges):
        es = edges.to_conn_list()
        for entry in es:
            self.add_connection(*entry)

    def add_connection(self, src, field, dst_list):
        '''
        dst_list :: [(match_value, target)]
        match_value = ("eq" val)
                    | ("ternary" mask val)
                    | ("always")
        '''
        assert src in self.headers
        if len(dst_list) == 1 and dst_list[0][0][0] == 'always':
            field = self.headers[src].fields[0]
        assert field in self.headers[src].fields, "{} not in {}".format(field, self.headers[src].fields)
        assert self.branch_field[src] is None
        self.branch_field[src] = field
        for dst in dst_list:
            assert dst[1] in self.headers

        for dst in dst_list:
            target = dst[1]
            match_value = self.FieldMatch(dst[0][0], dst[0][1:])
            self.connections[src].append((match_value, target))
            self.header_pre_req[target].append((src, field))

    def as_sexpr(self):
        '''
        format:
        (def-parser <name>
          ((<format-name> (<field-name> <num-of-bytes>) ...)
           ...)
          (<header-name> <format-name> ((<match-clause> <target-header-name>)
                                        ...))
          ...)
        '''
        # for now the name is not used at-all
        def_s = ['def-parser', 'parser']
        s = []
        formats = {}
        for k, v in self.headers.items():
            if v.name not in formats:
                format_s = [v.name]
                for f in v.fields:
                    format_s.append(SpecAst(f, str(v.sizes[f])))
                s.append(SpecAst(*format_s))
            formats[v.name] = 1
        def_s.append(SpecAst(*s))

        s = []
        for k, v in self.headers.items():
            format_s = [k, v.name]
            if self.branch_field[k] is not None:
                format_s.append(self.branch_field[k])
                connections = self.connections[k]
                for match in connections:
                    rule_s = [match[0].to_expr(), match[1]]
                    format_s.append(SpecAst(*rule_s))
            s.append(SpecAst(*format_s))
        def_s.append(SpecAst(*s))
        return SpecAst(*def_s).as_sexpr()

    def spec_format(self):
        packet_format = {}
        for hn, h in self.headers.items():
            header = {}
            if len(h.fields) == 1 and h.fields[0] == 'data':
                packet_format[hn] = h.sizes[h.fields[0]]
                continue
            for fn in h.fields:
                header[fn] = h.sizes[fn]
            packet_format[hn] = header
        return packet_format

class ParserEdge(object):
    match_types = ['eq', 'ternary']
    def __init__(self, name):
        self.curr = name
        self.edges = {}

    def __rshift__(self, next_node):
        # node >> (('eq', 6, 17), 'ports') >> ...
        c = copy.deepcopy(self)
        if self.curr not in c.edges.keys():
            c.edges[self.curr] = []
        c.edges[self.curr].append(next_node)
        assert isinstance(next_node[-1], str)
        c.curr = next_node[-1]
        return c

    def __add__(self, other):
        c = copy.deepcopy(self)
        for n, es in other.edges.items():
            if n not in c.edges:
                c.edges[n] = es
            else:
                c.edges[n] = c.edges[n] + es

        return c

    def to_conn_list(self):
        l = []
        for n, es in self.edges.items():
            fn = None
            rules = []
            for e in es:
                cond = e[0]
                dst = e[1]
                if fn is not None and cond[0] != fn and type(cond) != str:
                    raise Exception("matching multiple fields of one header")
                if fn is None:
                    fn = cond[0]
                if cond == 'always':
                    rules.append(((cond,), dst))
                else:
                    rules.append((cond[1:], dst))
            assert len(rules) > 0
            l.append((n, fn, rules))
        return l


class ImplPktFormat(object):
    def __init__(self, headers):
        # headers : list of (offset, Headerformat) or (offset, (name, blob_size))
        self.header_names = []
        self.header_def = {}
        self.header_offset = {}
        for h_def in headers:
            off = h_def[0]
            h_info = h_def[1]
            name = None
            if isinstance(h_info, HeaderFormat):
                name = h_info.name
                self.header_def[name] = h_info
            else:
                name = h_info[0]
                self.header_def[name] = h_info[1]
            self.header_offset[name] = off
            self.header_names.append(name)

    def to_pkt_format(self):
        result = []
        for hn in self.header_names:
            off = self.header_offset[hn]
            h_def = self.header_def[hn]
            if isinstance(h_def, HeaderFormat):
                h_def = h_def.to_field_list()
            result.append((hn, off, h_def))
        return result


ETHER_HDR = HeaderFormat('ether', [('dst', 6),
                                   ('src', 6),
                                   ('ether_type', 2)])


IPv4_HDR = HeaderFormat('ip4', [('vihl', 1),
                                ('tos', 1),
                                ('length', 2),
                                ("id", 2),
                                ("offset", 2),
                                ("ttl", 1),
                                ("proto", 1),
                                ("chksum", 2),
                                ("src", 4),
                                ("dst", 4)])


TCP_HDR = HeaderFormat('tcp', [("src", 2),
                               ("dst", 2),
                               ("seqno", 4),
                               ("ackno", 4),
                               ("flags", 2),
                               ("wnd", 4),
                               ("chksum", 4),
                               ("urgp", 4)])


UDP_HDR = HeaderFormat('udp', [("src", 2),
                               ("dst", 2),
                               ("len", 2),
                               ("chksum", 2)])


ARP_HDR = HeaderFormat('arp', [('htype', 2),
                               ('ptype', 2),
                               ('hlen', 1),
                               ('plen', 1),
                               ('op', 2),
                               ('sha', 6),
                               ('spa', 4),
                               ('tha', 6),
                               ('tpa', 4)])

IPv4_HDR2 = HeaderFormat('ip', [('vihl', 1),
                                ('tos', 1),
                                ('length', 2),
                                ("id", 2),
                                ("offset", 2),
                                ("ttl", 1),
                                ("proto", 1),
                                ("chksum", 2),
                                ("src", 4),
                                ("dst", 4)])
COMMON_PKT = ImplPktFormat([(0, ETHER_HDR),
    (ETHER_HDR.header_size(), IPv4_HDR2),
    (ETHER_HDR.header_size() + IPv4_HDR2.header_size(), TCP_HDR),
    (ETHER_HDR.header_size() + IPv4_HDR2.header_size(), UDP_HDR)])
