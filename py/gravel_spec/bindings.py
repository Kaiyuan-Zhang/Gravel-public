import copy
import numbers
from ctypes import *
from . import ops
from .utils import fresh_name, fresh_bv
import z3
from functools import reduce
from .symbolic import CobbleSymVal, CobbleSymGen

funcs = [
    ('is_bv',           [c_void_p],                      c_bool),
    ('get_bv_width',    [c_void_p],                      c_int),
    ('is_valid_expr',   [c_void_p],                      c_bool),
    ('drop_expr_cache', [],                              None),
    ('mk_bv_const',     [c_long, c_long],                c_void_p),
    ('mk_bv_var',       [c_char_p, c_long],              c_void_p),

    ('bv_add',          [c_void_p, c_void_p],            c_void_p),
    ('bv_sub',          [c_void_p, c_void_p],            c_void_p),
    ('bv_mul',          [c_void_p, c_void_p],            c_void_p),
    ('bv_div',          [c_void_p, c_void_p],            c_void_p),
    ('bv_mod',          [c_void_p, c_void_p],            c_void_p),
    ('bv_urem',         [c_void_p, c_void_p],            c_void_p),
    ('bv_concat',       [c_void_p, c_void_p],            c_void_p),
    ('bv_extract',      [c_void_p, c_int, c_int],        c_void_p),
    ('bv_extend_to',    [c_void_p, c_int, c_bool],       c_void_p),
    ('bv_bswap',        [c_void_p],                      c_void_p),

    ('bv_eq',           [c_void_p, c_void_p],            c_void_p),
    ('bv_ne',           [c_void_p, c_void_p],            c_void_p),
    ('bv_le',           [c_void_p, c_void_p],            c_void_p),
    ('bv_lt',           [c_void_p, c_void_p],            c_void_p),
    ('bv_ge',           [c_void_p, c_void_p],            c_void_p),
    ('bv_gt',           [c_void_p, c_void_p],            c_void_p),
    ('bv_ule',          [c_void_p, c_void_p],            c_void_p),
    ('bv_ult',          [c_void_p, c_void_p],            c_void_p),
    ('bv_uge',          [c_void_p, c_void_p],            c_void_p),
    ('bv_ugt',          [c_void_p, c_void_p],            c_void_p),

    ('bool_and',        [c_void_p, c_void_p],            c_void_p),
    ('bool_or',         [c_void_p, c_void_p],            c_void_p),
    ('bool_implies',    [c_void_p, c_void_p],            c_void_p),
    ('bool_iff',        [c_void_p, c_void_p],            c_void_p),
    ('bool_not',        [c_void_p],                      c_void_p),

    ('ite',             [c_void_p, c_void_p, c_void_p],  c_void_p),
    ('forall',          'variadic',                      c_void_p),
    ('exists',          'variadic',                      c_void_p),

    ('free_expr',       [c_void_p],                      None),

    ('verify',                        [c_void_p, c_bool],              c_int),
    ('verify_or_ce',                  [c_void_p],                      c_void_p),
    ('print_model',                   [c_void_p],                      None),
    ('print_eval_with_model',         [c_void_p, c_void_p],            None),
    ('free_model',                    [c_void_p],                      None),
    ('drop_all_model',                [],                              None),

    ('print_expr',                    [c_void_p],                      None),
    ('print_expr_ptrs',               [],                              None),

    ('create_element_runner',         [c_char_p, c_char_p],            c_void_p),
    ('create_element_runner_verbose', [c_char_p, c_char_p],            c_void_p),
    ('get_init_runner_state',         [c_void_p],                      c_void_p),
    ('set_state_num_in',              [c_void_p, c_int],               None),
    ('set_state_num_out',             [c_void_p, c_int],               None),
    ('get_in_port_val',               [c_void_p],                      c_void_p),
    ('get_init_pkt_content',          [c_void_p],                      c_void_p),
    ('free_element_runner',           [c_void_p],                      None),
    ('run_pkt_handler',               [c_void_p],                      py_object),

    ('get_result_pkt_of_port',        [c_void_p, c_int],               py_object),
    ('get_obj_handle_by_off',         [c_void_p, c_uint],              c_void_p),
    ('get_abs_obj_type',              [c_void_p],                      py_object),

    ('abs_obj_copy',                  [c_void_p],                      c_void_p),
    ('abs_obj_free',                  [c_void_p],                      None),

    ('abs_vector_new',                [c_char_p, c_int],               c_void_p),
    ('abs_vector_get',                [c_void_p, c_void_p],            c_void_p),
    ('abs_vector_set',                [c_void_p, c_void_p, c_void_p],  None),

    ('abs_buffer_new',                [c_char_p],                      c_void_p),
    ('abs_buffer_get',                [c_void_p, c_void_p, c_ulonglong], c_void_p),
    ('abs_buffer_get_be',             [c_void_p, c_void_p, c_ulonglong], c_void_p),
    ('abs_buffer_set',                [c_void_p, c_void_p, c_void_p],  None),
    ('abs_buffer_set_be',             [c_void_p, c_void_p, c_void_p],  None),

    ('abs_hashmap_new',               'variadic',                      c_void_p),
    ('abs_hashmap_get',               'variadic',                      py_object),
    ('abs_hashmap_contains',          'variadic',                      c_void_p),
    ('abs_hashmap_set',               'variadic',                      None),
    ('abs_hashmap_remove',            'variadic',                      None),

    ('create_ctx',                    [c_char_p],                      c_void_p),
    ('free_ctx',                      [c_void_p],                      None),
    ('create_state',                  [c_void_p],                      c_void_p),
    ('state_pre_cond',                [c_void_p],                      c_void_p),
    ('state_add_pre_cond',            [c_void_p, c_void_p],            None),
    ('state_set_noutput',             [c_void_p, c_uint],              None),
    ('free_state',                    [c_void_p],                      None),

    ('add_buffer',                    [c_void_p, c_char_p, c_int],     None),
    ('get_buffer_base',               [c_void_p, c_char_p],            c_void_p),
    ('make_pointer',                  [c_void_p, c_char_p, c_int],     c_void_p),
    ('del_pointer',                   [c_void_p],                      None),

    ('run_function',                  'variadic',                      POINTER(c_void_p)),
    ('free_state_list',               [c_void_p],                      None),
    ('read_bytes',                    [c_void_p, c_char_p, c_void_p, c_int], c_void_p),
    ('write_bytes',                   'variadic',                      None),

    ('add_object',                    [c_void_p, c_char_p],            None),
    ('add_container',                 [c_void_p, c_void_p, c_char_p, c_ulonglong], None),

    ('add_pkt',                       [c_void_p, c_char_p],            None),
    ('get_pkt_struct_field',          [c_void_p, c_char_p, c_char_p],  c_void_p),
    ('set_pkt_struct_field',          [c_void_p, c_char_p, c_char_p, c_void_p], c_void_p),

    ('make_vector',          [c_char_p, c_uint],              c_void_p),
    ('vector_get',           [c_void_p, c_void_p],            c_void_p),
    ('vector_resize',        [c_void_p, c_void_p],            None),
    ('vector_push_back',     [c_void_p, c_void_p],            None),

    ('make_map',        [c_char_p, c_uint, c_uint],           c_void_p),

    ('container_find',  [c_void_p, c_void_p, c_void_p],       c_void_p),
    ('container_set',   [c_void_p, c_void_p, c_void_p, c_void_p], None),
]


returns_pointer_list = [
    'abs_hashmap_get',
    'run_pkt_handler',
]


def convert_to_void_p(obj):
    if not isinstance(obj, c_void_p):
        return c_void_p(obj)
    return obj

def load_lib(so_file):
    dylib = cdll.LoadLibrary(so_file)

    for f in funcs:
        if type(f[1]) == list:
            getattr(dylib, f[0]).argtypes = f[1]
        getattr(dylib, f[0]).restype = f[2]

    for f in returns_pointer_list:
        def wrapper(*args):
            result = getattr(dylib, f)(*args)
            return list(map(c_void_p, result))
        setattr(dylib, "{}_py".format(f), wrapper)

    def write_bytes_wrapper(s, buf, off, n_writes, *vals):
        dylib.write_bytes(c_void_p(s), buf, c_void_p(off), n_writes, *map(c_void_p, vals))

    setattr(dylib, 'multi_write', write_bytes_wrapper)
    setattr(dylib, 'multi_read', dylib.read_bytes)

    def result_pkt_of_port(s, idx):
        result = dylib.get_result_pkt_of_port(s, idx)
        if result is None:
            return None
        cond_pkts = list(map(lambda t : (c_void_p(t[0]), c_void_p(t[1])), result))
        return ResultPktBuf(dylib, cond_pkts)

    def get_init_pkt_buf(runner):
        buf = dylib.get_init_pkt_content(runner)
        return SinglePktBuf(dylib, buf)

    setattr(dylib, 'result_pkt_of_port', result_pkt_of_port)
    setattr(dylib, 'init_pkt_of_runner', get_init_pkt_buf)

    return dylib


class CobbleHeaderWrapper(object):
    def __init__(self, pkt_buf, offset, header_format):
        field_off = 0
        self.__dict__['_field_to_off_map'] = {}
        self._offset = offset
        self._field_size = {}
        self._pkt_buf = pkt_buf
        for fn, field_size in header_format:
            v = pkt_buf.get_bv_by_off(offset + field_off, field_size)
            self._field_to_off_map[fn] = field_off + offset
            self._field_size[fn] = field_size
            field_off += field_size
        self._total_size = field_off

    def get_pkt_buf(self):
        return self._pkt_buf

    def set_pkt_buf(self, pkt_buf):
        self._pkt_buf = pkt_buf

    def get_field_names(self):
        return self._field_to_off_map.keys()

    def __getattr__(self, name):
        if name in self.__dict__['_field_to_off_map']:
            off = self._field_to_off_map[name]
            sz = self._field_size[name]
            result = self._pkt_buf.get_bv_by_off(off, sz)
            return CobbleSymVal(self._pkt_buf.lib, result)
        else:
            return super().__getattribute__(name)

    def __setattr__(self, name, value):
        if name in self._field_to_off_map:
            val = _get_inner(value)
            off = self._field_to_off_map[name]
            self._pkt_buf.set_bv_by_off(off, val)
        else:
            super().__setattr__(name, value)

    def get_total_bytes(self):
        return self._total_size


class CobblePktBase(object):
    def __init__(self, lib):
        self.__dict__['_direct_field_off'] = {}
        self.lib = lib
        self._direct_field_size = {}
        self._header_objs = {}
        self._pkt_format = None

    def not_empty(self):
        raise NotImplementedError()

    def copy(self):
        result = copy.copy(self)
        result.__dict__['_direct_field_off'] = {}
        result._direct_field_size = {}
        result._header_objs = {}
        result._pkt_format = None
        if self._pkt_format is not None:
            result.create_fields_from_format(self._pkt_format)
        return result

    def get_bv_by_off(self, off, size, bigendian=True):
        raise NotImplementedError()

    def set_bv_by_off(self, off, val, bigendian=True):
        raise NotImplementedError()

    def __getattr__(self, name):
        if '_direct_field_off' not in self.__dict__:
            return super().__getattribute__(name)
        if name in self.__dict__['_direct_field_off']:
            off = self._direct_field_off[name]
            sz = self._direct_field_size[name]
            return self.get_bv_by_off(off, sz)
        else:
            return super().__getattribute__(name)

    def __setattr__(self, name, val):
        if '_direct_field_off' not in self.__dict__:
            return super().__getattribute__(name)
        if name in self._direct_field_off:
            off = self._direct_field_off[name]
            sz = self._direct_field_size[name]
        else:
            super().__setattr__(name, val)

    def create_fields_from_format(self, pkt_format):
        offset = 0  # offset in bytes
        fields = {}
        self._pkt_format = pkt_format
        for hn, off, h in pkt_format.to_pkt_format():
            if isinstance(h, numbers.Number):
                # simply a blob
                v = self.get_bv_by_off(offset, h)
                self._direct_field_off[hn] = offset
                self._direct_field_size[hn] = h
                offset += h
            else:
                # header with fields
                header = CobbleHeaderWrapper(self, off, h)
                setattr(self, hn, header)
                self._header_objs[hn] = header
                offset += header.get_total_bytes()

    def buf_eq(self, buf, start=None, end=None):
        idx = self.lib.mk_bv_var(fresh_name("buf_eq_idx").encode('utf-8'), 64)
        l_val = self.get_bv_by_off(_to_void_p(idx), 1)
        r_val = buf.get_bv_by_off(_to_void_p(idx), 1)
        eq_cond = self.lib.bv_eq(l_val, r_val)
        if start is not None:
            pre = self.lib.bv_ule(self.lib.mk_bv_const(start, 64), idx)
            eq_cond = self.lib.bool_implies(pre, eq_cond)
        if end is not None:
            pre = self.lib.bv_ult(idx, self.lib.mk_bv_const(end, 64))
            eq_cond = self.lib.bool_implies(pre, eq_cond)
        # print("Pkt buf_eq: idx:")
        # self.lib.print_expr(c_void_p(idx))
        # print("Pkt buf_eq: eq_cond:")
        # self.lib.print_expr(c_void_p(eq_cond))
        return self.lib.forall(1, _to_void_p(idx), _to_void_p(eq_cond))


class SinglePktBuf(CobblePktBase):
    def __init__(self, lib, pkt_buf):
        super().__init__(lib)
        self.buf = pkt_buf

    def not_empty(self):
        result = self.lib.mk_bv_const(1, 1)
        return result

    def copy(self):
        result = super().copy()
        buf_copy = copy.deepcopy(self.buf)
        result.buf = _to_void_p(self.lib.abs_obj_copy(_to_void_p(buf_copy)))
        return result

    def get_bv_by_off(self, off, size, bigendian=True):
        off = _get_inner(off)
        if isinstance(off, numbers.Number):
            off = self.lib.mk_bv_const(off, 64)
        if bigendian:
            result = self.lib.abs_buffer_get_be(self.buf, off, size)
        else:
            result = self.lib.abs_buffer_get(self.buf, off, size);
        return result

    def set_bv_by_off(self, off, val, bigendian=True):
        off = _get_inner(off)
        val = _get_inner(val)
        if isinstance(off, numbers.Number):
            off = self.lib.mk_bv_const(off, 64)
        if bigendian:
            self.lib.abs_buffer_set_be(self.buf, off, val)
        else:
            self.lib.abs_buffer_set(self.buf, off, val)


class ResultPktBuf(CobblePktBase):
    def __init__(self, lib, cond_pkts):
        super().__init__(lib)
        self.conds = list(map(lambda t : t[0], cond_pkts))
        self.bufs = list(map(lambda t : t[1], cond_pkts))
        assert len(self.conds) == len(self.bufs)

    def not_empty(self):
        result = self.lib.mk_bv_const(0, 1)
        for c in self.conds:
            result = self.lib.bool_or(c, result)
        return result

    def get_bv_by_off(self, off, size, bigendian=True):
        # create default value (just a fresh bitvector)
        se = CobbleSymGen(self.lib)
        off = _to_void_p(_get_inner(off))
        result = se.BitVec(fresh_name("pkt_field_by_off_default"), size * 8)
        for i in range(len(self.conds) - 1, -1, -1):
            c = self.conds[i]
            buf = self.bufs[i]
            if bigendian:
                v = self.lib.abs_buffer_get_be(buf, off, size)
            else:
                v = self.lib.abs_buffer_get(buf, off, size)
            result = se.If(c, v, result)
            # print("ite valid: {} {} {}".format(*map(lambda e: self.lib.is_valid_expr(e), [c, v, result])))
        return result.inner()


class SpecStruct(object):
    _fields = []
    _struct_name = None
    _n_bytes = None

    def __init__(self, se=z3, lib=None, name=None):
        self.lib = lib
        self.se = se
        self.name = name if name is not None else ""
        self.n_bytes = None
        self.is_spec = False
        if lib is None:
            self.is_spec = True
            for f_name, f_size in self._fields:
                assert not hasattr(self, f_name)
                n = "{}!{}!{}".format(self._struct_name, self.name, f_name)
                field_val = fresh_bv(n, f_size * 8, se=se)
                setattr(self, f_name, field_val)

    @classmethod
    def size_tuple(cls):
        if hasattr(cls, '_size_tuple'):
            return getattr(cls, '_size_tuple')
        l = []
        for _, f_size in cls._fields:
            l.append(f_size)
        setattr(cls, '_size_tuple', tuple(l))
        return tuple(l)

    @classmethod
    def num_bytes(cls):
        if cls._n_bytes is None:
            n = 0
            for _, f_size in cls._fields:
                n = n + f_size
            cls._n_bytes = n
        return cls._n_bytes

    @classmethod
    def fresh(cls, lib, name):
        self = cls(lib)
        mk_bv_func = None
        if self.is_spec:
            mk_bv_func = ops.fresh_bv
        else:
            mk_bv_func = lambda n, s: self.lib.mk_bv_var(fresh_name(n).encode('utf-8'), s * 8)
        for f_name, f_size in self._fields:
            fn = "spec!{}!{}!{}".format(self._struct_name, name, f_name)
            field_val = mk_bv_func(fn, f_size * 8)
            setattr(self, f_name, field_val)
        return self

    @classmethod
    def from_tuple(cls, t):
        # this is for spec only
        self = None
        if isinstance(t, CobbleMap.CobbleMapValContainer):
            self = cls(CobbleSymGen(t.map_obj.lib))
            self.is_spec = False
        else:
            self = cls(se=z3)
            self.is_spec = True
        cnt = 0
        for f_name, _ in self._fields:
            setattr(self, f_name, t[cnt])
            cnt += 1
        return self

    @classmethod
    def from_expr(cls, expr, lib=None):
        self = cls(lib)
        offset = 0
        extract_func = None
        if self.is_spec:
            extract_func = lambda v, s, e: z3.Extract(e - 1, s, v)
        else:
            extract_func = self.lib.bv_extract
        for f_name, f_size in self._fields:
            f_end = offset + f_size * 8
            field_val = extract_func(expr, offset, f_end)
            setattr(self, f_name, field_val)
            offset = f_end

        return self

    def to_tuple(self):
        l = []
        for f_name, _ in self._fields:
            v = getattr(self, f_name)
            l.append(v)
        return tuple(l)

    def to_expr(self):
        result = None
        for f_name, f_size in self._fields:
            assert hasattr(self, f_name)
            field_val = getattr(self, f_name)
            if result is None:
                result = field_val
            else:
                concat_func = None
                if self.is_spec:
                    concat_func = ops.Concat
                else:
                    concat_func = self.lib.bv_concat
                result = concat_func(field_val, result)
        return result

    def __eq__(self, other):
        assert type(self) == type(other)
        assert self.lib == other.lib
        result = None
        for f_name, f_size in self._fields:
            lhs = getattr(self, f_name)
            rhs = getattr(self, f_name)
            eq_cond = self.lib.bv_eq(lhs, rhs)
            if result is None:
                result = eq_cond
            else:
                result = self.lib.bool_and(result, eq_cond)
        assert result is not None
        return result


def _get_inner(obj):
    if 'inner' in dir(obj):
        return obj.inner()
    else:
        return obj


def _to_void_p(obj):
    if type(obj) != c_void_p:
        return c_void_p(obj)
    else:
        return obj


class CobbleAbsType(object):
    def __init__(self, lib):
        self.lib = lib
        self.ptr = None

    def copy(self):
        result = copy.copy(self)
        result.ptr = c_void_p(self.lib.abs_obj_copy(self.inner()))
        return result

    def inner(self):
        return self.ptr

    def free(self):
        self.lib.abs_obj_free(self.inner())


class CobbleBuffer(CobbleAbsType):
    def __init__(self, lib, name=None, ptr=None):
        super().__init__(lib)
        if name is not None:
            self.ptr = c_void_p(self.lib.abs_buffer_new(name.encode('utf-8')))
        elif ptr is not None:
            self.ptr = _to_void_p(ptr)
        else:
            raise Exception("CobbleBuffer: unknown init")

    def load(self, off, sz):
        if isinstance(off, numbers.Number):
            off = self.lib.mk_bv_const(off, 64)
        off = _get_inner(off)
        return c_void_p(self.lib.abs_buffer_get(self.ptr, off, sz))

    def store(self, off, val):
        if isinstance(off, numbers.Number):
            off = self.lib.mk_bv_const(off, 64)
        off = _get_inner(off)
        val = _get_inner(val)
        self.lib.abs_buffer_set(self.ptr, off, val)


class CobbleVector(CobbleAbsType):
    def __init__(self, lib, name, element_sz):
        super().__init__(lib)
        self.ptr = self.lib.abs_vector_new(name.encode('utf-8'), element_sz)
        self.ptr = c_void_p(self.ptr)

    def get(self, idx):
        idx = _get_inner(idx)
        return self.lib.abs_vector_get(self.ptr, idx)

    def set(self, idx, val):
        idx = _get_inner(idx)
        val = _get_inner(val)
        self.lib.abs_vector_set(self.ptr, idx, val)

    def __getitem__(self, idx):
        return self.get(idx)

    def __setitem__(self, idx, val):
        self.set(idx, val)


class CobbleMap(CobbleAbsType):
    class CobbleMapValContainer(object):
        def __init__(self, map_obj, keys, vals):
            self.keys = keys
            self.vals = vals
            self.map_obj = map_obj

        def __getitem__(self, idx):
            assert 0 <= idx and idx < len(self.vals)
            return self.vals[idx]
        
        def __setitem__(self, idx, val):
            assert 0 <= idx and idx < len(self.vals)
            self.vals[idx] = val
            self.map_obj.set_val_idx(keys, idx, val)
        
        def __iter__(self):
            return iter(self.vals)

    def __init__(self, lib, name, key_sizes, val_sizes):
        super().__init__(lib)
        self.name = name
        self.key_sizes = key_sizes
        self.val_sizes = val_sizes
        self.ptr = self.lib.abs_hashmap_new(name.encode('utf-8'),
                len(key_sizes), len(val_sizes),
                *key_sizes, *val_sizes)
        self.ptr = c_void_p(self.ptr)


    def get_val(self, keys):
        assert len(keys) == len(self.key_sizes)
        keys = map(lambda x: _to_void_p(_get_inner(x)), keys)
        result = self.lib.abs_hashmap_get(self.ptr, *keys)
        result = list(map(lambda v: c_void_p(v), result))
        return list(map(lambda v: CobbleSymVal(self.lib, v), result))

    def set_val(self, keys, vals):
        assert len(keys) == len(self.key_sizes)
        assert len(vals) == len(self.val_sizes)
        keys = map(lambda x: _to_void_p(_get_inner(x)), keys)
        vals = map(lambda x: _to_void_p(_get_inner(x)), vals)
        self.lib.abs_hashmap_set(self.ptr, *keys, *vals)

    def set_val_idx(self, keys, idx, val):
        old_vals = self.get_val(keys)
        old_vals[idx] = val
        self.set_val(keys, old_vals)

    def has_key(self, keys):
        if len(keys) != len(self.key_sizes):
            print("key size mis-match: {} {} vs {}".format(self, keys, self.key_sizes))
        assert len(keys) == len(self.key_sizes)
        keys = list(map(_get_inner, keys))
        result = self.lib.abs_hashmap_contains(self.ptr, *map(_to_void_p, keys))
        return c_void_p(result)

    def delete(self, keys):
        assert len(keys) == len(self.key_sizes)
        keys = map(_get_inner, keys)
        self.lib.abs_hashmap_remove(self.ptr, *map(c_void_p, keys))

    def __contains__(self, keys):
        if '__iter__' in dir(keys):
            return self.has_key(*keys)
        else:
            return self.has_key(keys)

    def __getitem__(self, keys):
        key_list = keys
        if '__iter__' not in dir(keys):
            key_list = [keys]
        vals = self.get_val(key_list)
        return self.CobbleMapValContainer(self, key_list, vals)
    
    def __setitem__(self, keys, vals):
        key_list = keys
        if '__iter__' not in dir(keys):
            key_list = [keys]
        val_list = vals
        if '__iter__' not in dir(vals):
            val_list = [vals]
        self.set_val(key_list, val_list)

    def map_eq(self, other, impl_key_sz=None, key_eq_func=None, vals_eq_func=None):
        se = CobbleSymGen(self.lib)
        other_ptr = other
        other_name = 'other'
        if isinstance(other, CobbleAbsType):
            other_ptr = other.inner()
            other_name = other.name
        else:
            other_ptr = convert_to_void_p(other)
        abs_type = self.lib.get_abs_obj_type(other_ptr)
        assert abs_type == 'HashMap'
        keys = []
        for i, num_bytes in enumerate(self.key_sizes):
            k = self.lib.mk_bv_var(fresh_name("map_eq_{}_{}_k_{}".format(self.name, other_name, i)).encode('utf-8'), num_bytes)
            keys.append(k)
        vals_l = self.get_val(keys)
        
        keys = list(map(lambda k: c_void_p(_get_inner(k)), keys))
        impl_ks = keys
        if key_eq_func is None:
            ks = keys
            result = self.lib.abs_hashmap_get(other_ptr, *ks)
            vals_r = list(map(lambda v: c_void_p(v), result))
        else:
            impl_ks = []
            for i, sz in enumerate(impl_key_sz):
                k = self.lib.mk_bv_var(fresh_name("map_eq_{}_{}_impl_k_{}".format(self.name, other_name, i)).encode('utf-8'), sz)
                impl_ks.append(c_void_p(k))
            result = self.lib.abs_hashmap_get(other_ptr, *impl_ks)
            vals_r = list(map(c_void_p, result))


        contains_l = CobbleSymVal(self.lib, self.has_key(keys))
        contains_r = _to_void_p(self.lib.abs_hashmap_contains(other_ptr, *impl_ks))

        contain_eq = (contains_l == contains_r)

        eq_conds = []
        if vals_eq_func is None:
            for i in range(len(vals_l)):
                eq_conds.append(c_void_p(self.lib.bv_eq(vals_l[i], vals_r[i])))
        else:
            expr = _get_inner(vals_eq_func(vals_l, vals_r))
            eq_conds.append(_get_inner(vals_eq_func(vals_l, vals_r)))
        cond = reduce(lambda x, y: c_void_p(self.lib.bool_and(x, y)), eq_conds)
        cond = se.And(contain_eq, se.Implies(contains_l, cond))
        if key_eq_func is not None:
            key_eq = _get_inner(key_eq_func(keys, impl_ks))
            keys = keys + impl_ks
            cond = se.Implies(key_eq, cond)
        return self.lib.forall(len(keys), *keys, cond.inner())
