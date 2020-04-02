from .utils import *
from .element import *
from .graph import *
from .config import *
from .ops import *
from .symbolic import *
from .packet import *
from functools import reduce


class ElementVerificationResult(object):
    def __init__(self, verified):
        self.verified = verified

    def __str__(self):
        return "<ElementVerificationResult verified: {}>".format(self.verified)

class ElementVerificationError(Exception):
    pass

class ClickElement(Element):
    def fresh_state(self, is_spec=True, cobble_lib=None):
        fields = {}
        if hasattr(self, '_fields'):
            fields = getattr(self, '_fields')
        else:
            for attr in dir(self):
                field = getattr(self, attr)
                if isinstance(getattr(self, attr), ElementField):
                    fields[attr] = field
            self._fields = fields

        if is_spec:
            return ClickElementState(fields)
        else:
            return CobbleElementState(fields, cobble_lib)

    def clear_exists_vars(self):
        self.exists_var_list = []

    def exists_bv(self, name, bit_width, se=z3):
        if not hasattr(self, 'exists_var_list'):
            self.exists_var_list = []
        bv = fresh_bv(name, bit_width, se=se)
        self.exists_var_list.append(bv)
        return bv

    def impl_state_equiv(self, lib, spec_state, impl_state):
        raise NotImplementedError()

    def verify_pkt_handler(self, lib, ll_file, pkt_format, state_equiv_fn=None, element_name=None, concretization=None):
        verified = True
        state_equiv_func = state_equiv_fn if state_equiv_fn is not None else (lambda l, s, i: self.impl_state_equiv(l, s, i))
        try:
            ele_name = element_name if element_name is not None else self.__class__.__name__
            runner = lib.create_element_runner(ll_file.encode('utf-8'), ele_name.encode('utf-8'))
            # runner = lib.create_element_runner_verbose(ll_file.encode('utf-8'), ele_name.encode('utf-8'))
            init_state = lib.get_init_runner_state(runner)
            lib.set_state_num_out(init_state, self.num_out())
            states = lib.run_pkt_handler_py(runner)

            impl_in_port = CobbleSymVal(lib, c_void_p(lib.get_in_port_val(runner)))

            se = CobbleSymGen(lib)
            pkt = lib.init_pkt_of_runner(runner)
            pkt.create_fields_from_format(pkt_format)

            for in_port in range(self.num_in()):
                s = self.fresh_state(is_spec=False, cobble_lib=lib)
                self.clear_exists_vars()
                actions = self.process_packet(s, pkt, in_port, se=se)
                pre_equiv = state_equiv_func(lib, s, init_state)
                for s_idx, impl_s in enumerate(states):
                    for a_idx, action in enumerate(actions):
                        pre_cond = action['pre_cond']
                        out_pkts = action['packets']
                        new_s = action['new_state']
                        post_equiv = state_equiv_func(lib, new_s, impl_s)
                        if type(pre_cond) == bool:
                            pre_cond = se.BoolVal(pre_cond)
                        pre = lib.bool_and(pre_equiv, pre_cond.inner())
                        pre = lib.bool_and(pre, (impl_in_port == se.BitVecVal(in_port, 32)).inner())
                        pre = lib.bool_and(pre, c_void_p(lib.state_pre_cond(impl_s)))

                        pkt_eq_list = []
                        for o_port, o_pkt in out_pkts.items():
                            impl_o_pkt = lib.result_pkt_of_port(impl_s, o_port)
                            if impl_o_pkt is None:
                                pkt_eq_list.append(se.Not(o_pkt.not_empty()))
                            else:
                                pkt_eq_list.append(o_pkt.buf_eq(impl_o_pkt))
                        post = post_equiv
                        # print("Post:")
                        # lib.print_expr(get_inner(se.And(*pkt_eq_list)))
                        if len(pkt_eq_list) > 0:
                            # print("POST:", [post] + pkt_eq_list)
                            post = se.And(*([post] + pkt_eq_list)).inner()
                        # print(post)
                        target = se.Implies(pre, post)
                        if len(self.exists_var_list) > 0:
                            ev_list = list(map(get_inner, self.exists_var_list))
                            target = se.Exists(ev_list, target)
                            # post = se.Exists(ev_list, post)
                        # print(target)
                        result = lib.verify_or_ce(get_inner(target))
                        # lib.print_expr(target)
                        if result is not None:
                            ce = c_void_p(result)
                            # print("CounterExample:")
                            # lib.print_model(ce)
                            # print("Spec pre_cond:")
                            # lib.print_expr(pre_cond.inner())
                            # print("Impl pre_cond:")
                            # lib.print_expr(lib.state_pre_cond(impl_s))
                            print("PRE:")
                            lib.print_expr(get_inner(pre))

                            print("POST:")
                            lib.print_expr(get_inner(post))

                            print("PKT_EQ:")
                            pkt_eq = se.And(*pkt_eq_list)
                            lib.print_expr(get_inner(pkt_eq))
                            print("Verify: {}".format(lib.verify_or_ce(get_inner(pkt_eq))))

                            print("State_EQ:")
                            lib.print_expr(get_inner(post_equiv))
                            print("Verify: {}".format(lib.verify_or_ce(get_inner(post_equiv))))

                            # off = se.BitVec(fresh_name("pkt_idx"), 64)
                            # s_byte = out_pkts[0].get_bv_by_off(off, 1)
                            # i_byte = impl_o_pkt.get_bv_by_off(off, 1)
                            # eq_cond = se.gen_wrapper(lib.bv_eq(s_byte, i_byte))
                            # m = lib.verify_or_ce(se.Not(eq_cond).inner())
                            # if m is not None:
                            #     print("pkt mismatch:")
                            #     lib.print_eval_with_model(c_void_p(m), off.inner())

                            lib.drop_all_model()
                            raise ElementVerificationError()
        except ElementVerificationError:
            verified = False
        lib.free_element_runner(runner)
        lib.drop_expr_cache()
        return ElementVerificationResult(verified)


class ClickElementState(ElementState):
    def __init__(self, fields, vals=None):
        self.fields = fields
        self.state_type = fields
        self.states = {}
        self.cond_list = []
        if vals is None:
            for k, t in self.fields.items():
                self.states[k] = t.instance(k)
        else:
            self.states = vals.copy()

        for k, v in self.states.items():
            assert not hasattr(self, k)
            self.__dict__[k] = v

    def copy(self):
        new_s = self.states.copy()
        for k in new_s:
            self.states[k] = self.__dict__[k]
            new_s[k] = self.__dict__[k]
            if 'copy' in dir(new_s[k]):
                new_s[k] = new_s[k].copy()
        new = ClickElementState(self.fields, new_s)
        new.cond_list = self.cond_list[:]
        return new


class CobbleElementState(ElementState):
    def __init__(self, fields, cobble_lib, vals=None):
        self.lib = cobble_lib
        self.fields = fields
        self.state_type = fields
        self.states = {}
        self.cond_list = []
        if vals is None:
            for k, t in self.fields.items():
                self.states[k] = t.cobble_instance(k, self.lib)
        else:
            self.states = vals.copy()

        for k, v in self.states.items():
            assert not hasattr(self, k)
            self.__dict__[k] = v

    def copy(self):
        new_s = self.states.copy()
        for k in new_s:
            self.states[k] = self.__dict__[k]
            new_s[k] = self.__dict__[k]
            if 'copy' in dir(new_s[k]):
                new_s[k] = new_s[k].copy()
        new = CobbleElementState(self.fields, self.lib, new_s)
        new.cond_list = self.cond_list[:]
        return new


class ElementField(object):
    def instance(self, name):
        raise NotImplementedError()

    def cobble_instance(self, name, cobble_lib):
        raise NotImplementedError()


class ConditionalPacket(object):
    def __init__(self, cond, pkt):
        self.cond = cond
        self.pkt = pkt


class SymPacketSet(object):
    def __init__(self):
        self.conds = []

    def add_cond(self, cond):
        self.conds.append(cond)

    def at_most_one(self):
        cnt = z3.BitVecVal(0, 64)
        for c in self.conds:
            cond = c.cond
            cnt = cnt + z3.If(cond, 1, 0)
        sol = z3.Solver()
        sol.add(z3.UGT(cnt, 1))
        return sol.check() == z3.unsat

class ConditionalState(object):
    def __init__(self, cond, state):
        self.cond = cond
        self.state = state


class ClickGraph(Graph):
    def __init__(self, elements, edges):
        self.elements = elements
        self.edges = edges

        self.out_edges = {}

        for name, e in self.elements.items():
            self.out_edges[name] = [None] * e.num_out()

        for name in self.elements:
            es = filter(lambda edge: edge.src == name, edges)
            for edge in es:
                assert self.out_edges[name][edge.src_idx] is None, name
                self.out_edges[name][edge.src_idx] = edge

        for name in self.elements:
            for i in range(len(self.out_edges[name])):
                e = self.out_edges[name][i]
                assert e is not None, "out edge %d for %s missing" % (i, name)

        self.sources = []
        self.sinks = []
        for name, e in self.elements.items():
            if e.num_in() == 0:
                self.sources.append(name)
            if e.num_out() == 0:
                self.sinks.append(name)


class ClickConfig(Config):
    def __init__(self, elements, edges, parser):
        packet_format = parser.spec_format()
        self.parser = parser
        self.elements = elements
        self.sources = []
        self.sinks = []

        self.graph = ClickGraph(elements, edges)
        self.packet_format = packet_format
        for e in self.graph.elements:
            self.graph.elements[e].packet_format = packet_format

        for e_name, ele in self.elements.items():
            if ele.num_in() == 0:
                self.sources.append(e_name)
            if ele.num_out() == 0 and type(ele).__name__ != 'Discard':
                self.sinks.append(e_name)


def Action(cond, packets, state):
    c = cond
    if type(c) == bool:
        c = z3.BoolVal(c)
    return [{ 'pre_cond'  : c,
              'packets'   : packets,
              'new_state' : state }]
