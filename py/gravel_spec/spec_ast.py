import copy
from .utils import fresh_name


class SpecAst(object):
    '''
    This is simply a wrapper of a list
    '''
    def __init__(self, *args):
        self.args = list(args)[:]
        self.is_atom = False

    @classmethod
    def from_const(cls, const):
        #return SpecAst('const', const)
        ast = SpecAst(const)
        ast.is_atom = True
        return ast

    @classmethod
    def from_var_name(cls, name):
        assert type(name) == str
        ast = SpecAst(name)
        ast.is_atom = True
        return ast

    @classmethod
    def ite_handler(cls, cond, tc, fc):
        return SpecAst('ite', cond, tc, fc)

    def as_sexpr(self):
        if self.is_atom:
            return self.args[0]
        s = "("
        for i in range(len(self.args)):
            s += "{}"
            if i != len(self.args) - 1:
                s += " "
        def to_sexpr(x):
            if isinstance(x, SpecAst) or 'as_sexpr' in dir(x):
                return x.as_sexpr()
            else:
                return str(x)
        s += ")"
        result = s.format(*list(map(to_sexpr, self.args)))
        return result

    @classmethod
    def to_ast(cls, x):
        o = x
        if not isinstance(o, cls):
            o = cls.from_const(x)
        return o

    @classmethod
    def bin_op(cls, op, lhs, rhs):
        return SpecAst(op, cls.to_ast(lhs), cls.to_ast(rhs))

    @classmethod
    def apply(cls, op, *args):
        return SpecAst(op, *list(map(lambda x: cls.to_ast(x), args)))

    def __add__(self, other):
        return self.bin_op('add', self, other)

    def __radd__(self, other):
        return self.bin_op('add', other, self)

    def __sub__(self, other):
        return self.bin_op('sub', self, other)

    def __rsub__(self, other):
        return self.bin_op('sub', other, self)

    def __mul__(self, other):
        return self.bin_op('mul', self, other)

    def __mod__(self, other):
        return self.bin_op('urem', self, other)

    def __div__(self, other):
        return self.bin_op('div', self, other)

    def __and__(self, other):
        return self.bin_op('bit_and', self, other)

    def __or__(self, other):
        return self.bin_op('bit_or', self, other)

    def __eq__(self, other):
        return self.bin_op('eq', self, other)

    def __ne__(self, other):
        return self.bin_op('ne', self, other)

    def __le__(self, other):
        return self.bin_op('le', self, other)

    def __lt__(self, other):
        return self.bin_op('lt', self, other)

    def __gt__(self, other):
        return self.bin_op('gt', self, other)

    def __ge__(self, other):
        return self.bin_op('ge', self, other)

    def __repr__(self):
        return self.as_sexpr()


class AstMapValContainer(object):
    def __init__(self, keys, num_vals, map_obj):
        self.keys = keys
        self.num_vals = num_vals
        self.map_obj = map_obj

    def __getitem__(self, idx):
        map_name = self.map_obj.get_expr()
        return SpecAst('map-get', idx, *list(self.keys), map_name)

    def __setitem__(self, idx, val):
        self.map_obj.set_val(self.keys, idx, val)

    def __iter__(self):
        vals = list(map(lambda i: self[i], range(self.num_vals)))
        return iter(vals)


class AstMap(object):
    def __init__(self, name, key_type, val_type):
        self.name = name
        self.key_type = key_type
        self.val_type = val_type
        self.write_set = []

    def get_expr(self):
        if len(self.write_set) == 0:
            return self.name
        else:
            expr = self.name
            for entry in self.write_set:
                op = entry[0]
                if op == 'set':
                    keys = entry[1]
                    idx = entry[2]
                    val = entry[3]
                    expr = SpecAst('map-put-idx', str(idx), *list(keys), val, expr)
                elif op == 'delete':
                    keys = entry[1]
                    expr = SpecAst('map-delete', *list(keys), expr)
            return expr

    def as_sexpr(self):
        expr = self.get_expr()
        if 'as_sexpr' in dir(expr):
            return expr.as_sexpr()
        else:
            return expr

    def num_keys(self):
        return len(self.key_type)
        
    def num_vals(self):
        return len(self.val_type)

    def has_key(self, *keys):
        k_list = list(keys)
        if len(keys) == 1 and type(keys[0]) == tuple:
            k_list = list(keys[0])
        return SpecAst('map-contains', *k_list, self.get_expr())

    def __getitem__(self, keys):
        key_list = keys
        if type(keys) != type((1,)):
            key_list = [keys]
        assert len(key_list) == len(self.key_type)
        return AstMapValContainer(key_list, len(self.val_type), self)

    def __setitem__(self, k, vals):
        v_list = vals
        if not hasattr(vals, '__iter__'):
            v_list = (vals,)

        keys = k
        if not hasattr(k, '__iter__'):
            keys = (k,)
            
        assert len(v_list) == len(self.val_type)
        for i in range(len(v_list)):
            self.set_val(keys, i, v_list[i])

    def set_val(self, keys, idx, val):
        self.write_set.append(('set', keys, idx, val))

    def delete(self, keys):
        self.write_set.append(('delete', keys))

    @classmethod
    def ite_handler(cls, cond, tc, fc):
        new_map = SpecAst('ite', cond, tc.get_expr(), fc.get_expr())
        new_map_name = new_map.as_sexpr()
        return AstMap(new_map_name, tc.key_type, tc.val_type)

    def copy(self):
        return copy.deepcopy(self)


def fresh_bv(name, size):
    if getattr(fresh_bv, 'map_', None) is None:
        setattr(fresh_bv, 'map_', {})
    import inspect
    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    #print('caller name:', calframe[1][3], 'in', calframe[1][4][0][6: -2])
    var_name = fresh_name(name)
    new_var = SpecAst.from_var_name(var_name)
    assert var_name not in fresh_bv.map_
    fresh_bv.map_[var_name] = size
    return new_var


class ImplFactory(object):
    @classmethod
    def new_instance(cls, category, name, *args):
        n = "(old \"{}\")".format(name)
        if category == 'map':
            s = AstMap(n, args[0], args[1])
        elif category == 'bitvec':
            s = SpecAst.from_const(n) #fresh_bv(n, args[0] * 8)
        else:
            raise Exception('unknown state type')
        return s
