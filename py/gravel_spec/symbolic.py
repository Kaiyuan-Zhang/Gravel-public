import z3
from functools import reduce
from ctypes import *
import numbers


def get_inner(v):
    if isinstance(v, CobbleSymVal):
        return v.inner()
    else:
        return v

def convert_to_void_p(v):
    if not isinstance(v, c_void_p):
        return c_void_p(v)
    else:
        return v

class CobbleSymVal(object):
    def __init__(self, lib, ptr):
        self.lib = lib
        if type(ptr) != c_void_p:
            ptr = c_void_p(ptr)
        self.ptr = ptr

    def inner(self):
        return self.ptr

    def bin_op_generic(self, other, fn):
        if isinstance(other, numbers.Number):
            bit_width = self.lib.get_bv_width(self.ptr)
            other = self.lib.mk_bv_const(other, bit_width)
        return CobbleSymVal(self.lib, fn(self.ptr, get_inner(other)))

    def __add__(self, other):
        return self.bin_op_generic(other, self.lib.bv_add)

    def __sub__(self, other):
        return self.bin_op_generic(other, self.lib.bv_sub)

    def __mul__(self, other):
        return self.bin_op_generic(other, self.lib.bv_mul)

    def __truediv__(self, other):
        return self.bin_op_generic(other, self.lib.bv_div)

    def __mod__(self, other):
        return self.bin_op_generic(other, self.lib.bv_mod)

    def __lt__(self, other):
        return self.bin_op_generic(other, self.lib.bv_lt)

    def __le__(self, other):
        return self.bin_op_generic(other, self.lib.bv_le)

    def __gt__(self, other):
        return self.bin_op_generic(other, self.lib.bv_gt)

    def __ge__(self, other):
        return self.bin_op_generic(other, self.lib.bv_ge)

    def __eq__(self, other):
        return self.bin_op_generic(other, self.lib.bv_eq)

    def __ne__(self, other):
        return self.bin_op_generic(other, self.lib.bv_ne)


class CobbleSymGen(object):
    def __init__(self, lib):
        self.lib = lib

    def gen_wrapper(self, v):
        return CobbleSymVal(self.lib, v)

    def Bool(self, name):
        return self.gen_wrapper(self.lib.mk_bv_var(name.encode('utf-8'), 1))

    def BoolVal(self, b):
        v = 1 if b else 0
        return self.gen_wrapper(self.lib.mk_bv_const(v, 1))

    def BitVecVal(self, v, sz):
        return self.gen_wrapper(self.lib.mk_bv_const(v, sz))

    def BitVec(self, name, sz):
        return self.gen_wrapper(self.lib.mk_bv_var(name.encode('utf-8'), sz))

    def convert_bool_arg(self, arg):
        if isinstance(arg, bool):
            return self.BoolVal(arg).inner()
        elif isinstance(arg, CobbleSymVal):
            return arg.inner()
        else:
            return arg

    def bv_extract(self, v, start, end):
        v = convert_to_void_p(get_inner(v))
        return self.gen_wrapper(self.lib.bv_extract(v, start, end))

    def bv_extract_from_top(self, v, start, end):
        v = convert_to_void_p(get_inner(v))
        sz = end - start
        bw = self.lib.get_bv_width(v)
        assert(0 <= start and start < bw)
        assert(start + sz <= bw)
        actual_end = bw - start
        actual_start = bw - start - sz
        return self.gen_wrapper(self.lib.bv_extract(v, actual_start, actual_end))

    def bv_bswap(self, v):
        v = convert_to_void_p(get_inner(v))
        return self.gen_wrapper(self.lib.bv_bswap(v))

    def Concat(self, *args):
        args = list(map(lambda a : convert_to_void_p(get_inner(a)), args))
        return self.gen_wrapper(reduce(lambda x, y: c_void_p(self.lib.bv_concat(x, y)), args))

    def And(self, *args):
        return self.gen_wrapper(reduce(self.lib.bool_and, map(self.convert_bool_arg, args)))

    def Or(self, *args):
        return self.gen_wrapper(reduce(self.lib.bool_or, map(self.convert_bool_arg, args)))

    def Not(self, v):
        return self.gen_wrapper(self.lib.bool_not(self.convert_bool_arg(v)))

    def Implies(self, a, b):
        return self.gen_wrapper(self.lib.bool_implies(self.convert_bool_arg(a), self.convert_bool_arg(b)))

    def If(self, cond, t, f):
        cond = self.convert_bool_arg(cond)
        t = get_inner(t)
        f = get_inner(f)
        return self.gen_wrapper(self.lib.ite(cond, t, f))

    def ULE(self, lhs, rhs):
        lhs = get_inner(lhs)
        rhs = get_inner(rhs)
        return self.gen_wrapper(self.lib.bv_ule(lhs, rhs))

    def ULT(self, lhs, rhs):
        lhs = get_inner(lhs)
        rhs = get_inner(rhs)
        return self.gen_wrapper(self.lib.bv_ult(lhs, rhs))

    def UGE(self, lhs, rhs):
        lhs = get_inner(lhs)
        rhs = get_inner(rhs)
        return self.gen_wrapper(self.lib.bv_uge(lhs, rhs))

    def UGT(self, lhs, rhs):
        lhs = get_inner(lhs)
        rhs = get_inner(rhs)
        return self.gen_wrapper(self.lib.bv_ugt(lhs, rhs))

    def ForAll(self, var_list, expr):
        return self.gen_wrapper(self.lib.forall(len(var_list), *map(get_inner, var_list), get_inner(expr)))

    def Exists(self, var_list, expr):
        return self.gen_wrapper(self.lib.exists(len(var_list), *map(get_inner, var_list), get_inner(expr)))

