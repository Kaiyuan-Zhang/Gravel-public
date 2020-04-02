import z3
import numbers

def start_pdb():
    import pdb
    pdb.set_trace()

def eval_with_model(obj, m):
    if 'eval_with' in dir(obj):
        return obj.eval_with(m)
    else:
        return m.evaluate(obj)

def valid_field_name(name):
    if type(name) != str:
        return False
    if len(name) <= 0:
        return False
    if not (name[0].isalpha() or name[0] == '_'):
        return False
    for c in name:
        if not (c.isalpha() or c.isdigit() or c == '_'):
            return False
    return True


def fresh_name(base_name):
    if getattr(fresh_name, 'map_', None) is None:
        setattr(fresh_name, 'map_', {})
    cnt = 0
    if base_name in fresh_name.map_:
        cnt = fresh_name.map_[base_name]
    fresh_name.map_[base_name] = cnt + 1
    return base_name + '!' + str(cnt)


def fresh_bv(name, num_bits, se=z3):
    return se.BitVec(fresh_name(name), num_bits)


class MapValContainer(object):
    def __init__(self, keys, vals, map_obj):
        self.keys = keys
        self.vals = vals
        self.map_obj = map_obj

    def __getitem__(self, idx):
        assert 0 <= idx and idx < len(self.vals)
        return self.vals[idx]

    def __setitem__(self, idx, val):
        assert 0 <= idx and idx < len(self.vals)
        self.map_obj.set_val(self.keys, idx, val)

    def __iter__(self):
        return iter(self.vals)


class ExactMap(object):
    def __init__(self, name, key_type, val_type):
        self.name = name
        self.key_type = key_type
        self.val_type = val_type

        key_sorts = []
        for t in key_type:
            key_sorts.append(z3.BitVecSort(t * 8))
        self.ufs = []
        uf_name_base = fresh_name(self.name)
        cnt = 0
        contains_uf = z3.Function(uf_name_base + '!contains', *key_sorts, z3.BoolSort())
        self.contains = lambda *keys, old_f=contains_uf: old_f(*keys)
        for t in val_type:
            val_sort = z3.BitVecSort(t * 8)
            uf = z3.Function(uf_name_base + '!' + str(cnt), *key_sorts, val_sort)
            lambda_f = lambda *keys, old_f=uf: old_f(*keys)
            self.ufs.append(lambda_f)
            cnt += 1

    def filter(self, predicate):
        c = self.copy()
        old_contains = c.contains
        def new_contains_func(*keys):
            vals = list(c[keys])
            return z3.If(predicate(keys, vals), 
                         z3.BoolVal(False),
                         old_contains(*keys))
        c.contains = new_contains_func
        return c

    def num_keys(self):
        return len(self.key_type)
        
    def num_vals(self):
        return len(self.val_type)

    def __contains__(self, keys):
        if '__iter__' in dir(keys):
            return self.has_key(*keys)
        else:
            return self.has_key(keys)

    def has_key(self, *keys):
        if len(keys) == 1 and (type(keys[0]) == tuple or 'to_tuple' in dir(keys[0])):
            if type(keys[0]) == tuple:
                key_list = list(keys[0])
            else:
                key_list = list(keys[0].to_tuple())
        else:
            key_list = list(keys)
        key_list = list(map(lambda e: e.to_expr() if 'to_expr' in dir(e) else e, key_list))
        return self.contains(*key_list)

    def __getitem__(self, keys):
        key_list = keys
        if type(keys) != type((1,)):
            key_list = [keys]
        assert len(key_list) == len(self.key_type)
        vals = []
        key_list = list(map(lambda e: e.to_expr() if 'to_expr' in dir(e) else e, key_list))
        for f in self.ufs:
            vals.append(f(*key_list))
        return MapValContainer(key_list, vals, self)

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
        uf = self.ufs[idx]
        self.ufs[idx] = uf_update(uf, keys, val)
        self.contains = uf_update(self.contains, keys, z3.BoolVal(True))

    def delete(self, keys):
        self.contains = uf_update(self.contains, keys, z3.BoolVal(False))

    def copy(self):
        new = ExactMap(self.name, self.key_type, self.val_type)
        new.ufs = self.ufs[:]
        new.contains = self.contains
        return new


class TernaryMap(object):
    def __init__(self, name, key_type, val_type):
        self.name = name
        self.key_type = key_type
        self.val_type = val_type

        key_sorts = []
        for t in key_type:
            key_sorts.append(z3.BitVecSort(t * 8))
        self.ufs = []
        uf_name_base = fresh_name(self.name)
        cnt = 0
        contains_uf = z3.Function(uf_name_base + '!contains', *key_sorts, z3.BoolSort())
        self.contains = lambda *keys, old_f=contains_uf: old_f(*keys)
        for t in val_type:
            val_sort = z3.BitVecSort(t * 8)
            uf = z3.Function(uf_name_base + '!' + str(cnt), *key_sorts, val_sort)
            lambda_f = lambda *keys, old_f=uf: old_f(*keys)
            self.ufs.append(lambda_f)
            cnt += 1

    @staticmethod
    def ternary_uf_update(old_uf, key_list, masks, val):
        f = lambda *keys, old_f=old_uf: z3.If(z3.And(*map(lambda i : keys[i] & masks[i] == key_list[i] & masks[i], 
                                                          range(len(keys)))),
                                              val,
                                              old_f(*keys))
        return f

    def filter(self, predicate):
        pass

    def num_keys(self):
        return len(self.key_type)
        
    def num_vals(self):
        return len(self.val_type)

    def has_match(self, *keys):
        if len(keys) == 1 and type(keys[0]) == tuple:
            return self.contains(*keys[0])
        return self.contains(*keys)

    def __getitem__(self, keys):
        key_list = keys
        if type(keys) != type((1,)):
            key_list = [keys]
        assert len(key_list) == len(self.key_type)
        vals = []
        for f in self.ufs:
            vals.append(f(*key_list))
        return MapValContainer(key_list, vals, self)

    def __setitem__(self, k, vals):
        # obj[(k1, k2, k3), (mask1, mask2, mask3)] = (val1, val2)
        v_list = vals
        if not hasattr(vals, '__iter__'):
            v_list = (vals,)

        if not hasattr(k, '__iter__'):
            raise Exception("require masks")

        assert len(k) == 2
        keys = k[0]
        masks = k[1]
            
        assert len(keys) == len(self.key_type)
        assert len(masks) == len(self.key_type)
        assert len(v_list) == len(self.val_type)
        for i in range(len(v_list)):
            self.set_val(keys, masks, i, v_list[i])

    def set_val(self, keys, masks, idx, val):
        uf = self.ufs[idx]
        self.ufs[idx] = self.ternary_uf_update(uf, keys, masks, val)
        self.contains = self.ternary_uf_update(self.contains, keys, masks, z3.BoolVal(True))

    def delete(self, keys, masks):
        self.contains = self.ternary_uf_update(self.contains, keys, masks, z3.BoolVal(False))

    def copy(self):
        new = ExactMap(self.name, self.key_type, self.val_type)
        new.ufs = self.ufs[:]
        new.contains = self.contains
        return new


class OracleFunc(object):
    def __init__(self, name, param_type, return_type):
        self.name = name
        self.param_type = param_type
        self.return_type = return_type
        key_sorts = []
        for t in param_type:
            key_sorts.append(z3.BitVecSort(t * 8))
        val_sort = None
        if val_sort == 'bool':
            val_sort = z3.BoolSort()
        else:
            val_sort = z3.BitVecSort(return_type * 8)
        self.uf = z3.Function(fresh_name(self.name), *key_sorts, val_sort)
        
    def __call__(self, *params):
        return self.uf(*params)


class SpecFactory(object):
    @classmethod
    def new_instance(cls, category, name, *args):
        if category == 'map':
            s = ExactMap(name, args[0], args[1])
        elif category == 'bitvec':
            s = fresh_bv(name, args[0] * 8)
        elif category == 'uf':
            s = OracleFunc(name, args[0], args[1])
        else:
            raise Exception('unknown state type')
        return s


def uf_update(old_uf, key, val):
    f = lambda *keys, old_f=old_uf: z3.If(z3.And(*map(lambda i : key[i] == keys[i], range(len(keys)))), 
                                          val, 
                                          old_f(*keys))
    return f


def fresh_key(ts):
    keys = []
    for t in ts:
        keys.append(fresh_bv('key', t * 8))
    return keys


def is_reverse(f1, f2, se=z3):
    assert isinstance(f1, ExactMap)
    assert isinstance(f2, ExactMap)

    assert f1.key_type == f2.val_type
    assert f1.val_type == f2.key_type

    f1_key = []
    f2_key = []
    for t in f1.key_type:
        f1_key.append(fresh_bv('is_reverse!key', t * 8))

    for t in f2.key_type:
        f2_key.append(fresh_bv('is_reverse!key', t * 8))
    
    f1_key = tuple(f1_key)
    f2_key = tuple(f2_key)
        
    f1_val = tuple(f1[f1_key])
    f2_val = tuple(f2[f2_key])
    
    def Eq(lhs, rhs):
        if '__iter__' in dir(lhs) and '__iter__' in dir(rhs):
            return se.And(*list(map(lambda x, y: x == y, lhs, rhs)))
        else:
            return lhs == rhs

    return se.ForAll(list(f1_key + f2_key), 
                     se.And(se.Implies(f1.has_key(f1_key), f2.has_key(f1_val)),
                            se.Implies(f2.has_key(f2_key), f1.has_key(f2_val)),
                            se.Implies(f1.has_key(f1_key), Eq(f2[f1_val], f1_key)),
                            se.Implies(f2.has_key(f2_key), Eq(f1[f2_val], f2_key))))
