import z3
from . import utils
from . import ops
from .packet import *
from .spec_ast import SpecAst


class Element(object):
    private_state_type = None
    helper_funcs = None
    def __init__(self, name=None):
        # each instance of the element will get a unique name upon creation
        self.se = z3
        self.unique_name = None
        if name is not None:
            self.unique_name = name
        else:
            self.unique_name = utils.fresh_name(self.name())
        self.state = {}
        self.packet_format = None

        cls = self.__class__
        if self.helper_funcs is not None and not hasattr(cls, '_ele_helpers'):
            for entry in self.helper_funcs:
                t = entry[1]
                if t == 'deter':
                    key_sorts = []
                    for kt in entry[2]:
                        key_sorts.append(z3.BitVecSort(kt * 8))
                    fs = []
                    cnt = 0
                    num_val = len(entry[3])
                    func_name = cls.__name__ + "!" + entry[0]
                    for vt in entry[3]:
                        v_sort = z3.BitVecSort(vt * 8)
                        f = z3.Function(func_name + "!" + str(cnt),
                                        *key_sorts, v_sort)
                        fs.append(f)
                        cnt += 1
                        
                    def helper_func(*params):
                        result = []
                        if 'as_sexpr' not in dir(params[0]):
                            for i in range(num_val):
                                result.append(fs[i](*params))
                        else:
                            for i in range(num_val):
                                result.append(SpecAst(func_name, i, *params))
                        return tuple(result)
                    setattr(cls, entry[0], helper_func)
            setattr(cls, '_ele_helpers', True)
                

    def fresh_packet(self):
        # p = {}
        # for h in self.packet_format:
        #     p[h] = {}
        #     for f in self.packet_format[h]:
        #         num_bits = self.packet_format[h][f] * 8
        #         var_name = "packet!{}!{}!{}".format(self.unique_name, h, f)
        #         p[h][f] = utils.fresh_bv(var_name, num_bits)
        p = Packet(self.packet_format)
        return p

    def fresh_state(self, factory=utils.SpecFactory):
        state_type = self.element_states()
        return ElementState(state_type, factory=factory)

    def name(self):
        if hasattr(self, 'ele_name'):
            return self.ele_name
        else:
            return type(self).__name__

    def element_states(self):
        if hasattr(self, 'private_state_type'):
            return self.private_state_type
        else:
            raise NotImplementedError()

    def num_in(self):
        if hasattr(self, 'num_in_ports'):
            return self.num_in_ports
        else:
            raise NotImplementedError(str(self.__class__))

    def num_out(self):
        if hasattr(self, 'num_out_ports'):
            return self.num_out_ports
        else:
            raise NotImplementedError(str(self.__class__))

    def mk_packet(self):
        if self.packet_format is None:
            raise Exception("Format not set")
        else:
            return Packet(self.packet_format)

    def process_packet(self, old, packet_in, in_port, se=z3):
        # process_packet :: State -> Packet -> int -> [(pre_cond, post_cond, { int : packet }, new_state)]
        raise NotImplementedError()

    def handle_event(self, old, event, *params):
        # handle_event :: State -> event_name -> [(pre_cond, post_cond, { int : packet }, new_state)]
        raise NotImplementedError()

    def state_inv(self, state):
        raise NotImplementedError()
    

class NullElement(object):
    def name(self):
        return "null"

    def num_in(self):
        return 1

    def num_out(self):
        return 1

    def element_states(self):
        return None

    def process_packet(self, old, p, in_port):
        return []

    def handle_event(self, old, e, *params):
        return []


class ElementState(object):
    def __init__(self, state_type, vals=None, factory=utils.SpecFactory):
        self.state_type = None
        self.cond_list = []
        if state_type is None:
            self.states = {}
            return
        state = {}
        if vals is None:
            for t in state_type:
                name = t[0]
                category = t[1]
                s = factory.new_instance(category, name, *t[2:])
                state[name] = s
        else:
            state = vals.copy()

        self.state_type = state_type
        self.states = state
        for k in self.states:
            assert utils.valid_field_name(k)
            assert k not in self.__dict__
            self.__dict__[k] = self.states[k]

    # def __getitem__(self, field_name):
    #     return self.states[field_name]

    # def __setitem__(self, field_name, val):
    #     self.states[field_name] = val

    def __contains__(self, field_name):
        return field_name in self.states

    def copy(self):
        new_s = self.states.copy()
        for k in new_s:
            self.states[k] = self.__dict__[k]
            new_s[k] = self.__dict__[k]
            if 'copy' in dir(new_s[k]):
                new_s[k] = new_s[k].copy()
        new = ElementState(self.state_type, new_s)
        new.cond_list = self.cond_list[:]
        return new

    def add_cond(self, cond):
        self.cond_list.append(cond)
    
    def where(self, cond_lambda):
        new = self.copy()
        cond = cond_lambda(new)
        new.add_cond(cond)
        return new

    def conds(self):
        return self.cond_list

    @classmethod
    def ite_handler(cls, cond, tc, fc):
        new = cls(tc.state_type, tc.states)
        for k in tc.states:
            new.__dict__[k] = ops.If(cond, tc.states[k], fc.states[k])
            new.states[k] = new.__dict__[k]
        for c in (tc.cond_list + fc.cond_list):
            new.cond_list.append(ops.Implies(cond, c))
        return new

    @classmethod
    def merge_states(cls, cond_states, default_state=None):
        '''
        states is a list of condition and state obj pairs
        e.g. states = [{ 'cond' : cond1, 'state' : state1}, { 'cond' : cond2, 'state' : state 2}, ... ]
        '''
        if len(cond_states) == 0:
            if default_state is None:
                return cls(None)
            else:
                return default_state.copy()
        states = None
        state_type = None
        for entry in cond_states:
            cond = entry['cond']
            s = entry['state'].copy()
            if states is None:
                state_type = s.state_type
                if default_state is not None:
                    states = default_state.states.copy()
                else:
                    states = cls(s.state_type).states
            for k, v in s.states.items():
                states[k] = ops.If(cond, v, states[k])
        new = cls(state_type, states)
        new.cond_list = []
        for entry in cond_states:
            cond = entry['cond']
            s = entry['state']
            for c in s.cond_list:
                new.add_cond(ops.And(cond, c))

        return new


class Source(Element):
    def __init__(self, name='source', num_out_ports=1):
        super().__init__(name)
        self.num_out_ports = num_out_ports

    def name(self):
        return 'source'

    def num_in(self):
        return 0

    def num_out(self):
        return self.num_out_ports

    def element_states(self):
        return None

    def process_packet(self, old, p, in_port):
        return []

    def handle_event(self, old, e, *params):
        if e == 'fresh_packet':
            p = None
            if len(params) == 0:
                p = self.fresh_packet()
            else:
                p = params[0]
            new = old.copy()
            return [{'pre_cond': True, 
                     'packets' : { 0 : p },
                     'new_state' : new }]
        else:
            return []


class Sink(Element):
    def __init__(self, name='sink', num_in_ports=1):
        super().__init__(name)
        self.num_in_ports = num_in_ports

    def name(self):
        return 'sink'

    def num_in(self):
        return self.num_in_ports

    def num_out(self):
        return 0

    def element_states(self):
        return None

    def process_packet(self, old, p, in_port):
        return []

    def handle_event(self, old, e, *params):
        return []
