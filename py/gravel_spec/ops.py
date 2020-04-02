from .utils import *
from . import spec_ast as ast
from functools import reduce

def all_bool(args):
    for a in args:
        if type(args) != bool:
            return False
    return True


def exist_ast(args):
    for a in args:
        if isinstance(a, ast.SpecAst) or type(a) == str:
            return True
    return False


def And(*args):
    if all_bool(args):
        return reduce(lambda x, y: x and y, args)
    if len(args) > 0 and exist_ast(args):
        return ast.SpecAst.apply('bool_and', *args)
    return z3.And(*args)


def Or(*args):
    if all_bool(args):
        return reduce(lambda x, y: x and y, args)
    if len(args) > 0 and exist_ast(args):
        return ast.SpecAst.apply('bool_or', *args)
    return z3.Or(*args)


def Not(b):
    if isinstance(b, ast.SpecAst):
        return ast.SpecAst('bool_not', ast.SpecAst.to_ast(b))
    return z3.Not(b)

def Concat(*bv_list):
    return z3.Concat(*bv_list)


def Implies(pre, post):
    if isinstance(pre, ast.SpecAst) or isinstance(post, ast.SpecAst):
        return ast.SpecAst.apply('implies', pre, post)
    return z3.Implies(pre, post)


def Iff(lhs, rhs):
    return And(Implies(lhs, rhs), Implies(rhs, lhs))


def ForAll(variables, clause):
    # TODO: handle packet and state type
    if isinstance(clause, ast.SpecAst):
        pass
    return z3.ForAll(variables, clause)


def Exists(variables, clause):
    return z3.Exists(variables, clause)


def Eq(lhs, rhs):
    if '__iter__' in dir(lhs) and '__iter__' in dir(rhs):
        return And(*list(map(lambda x, y: x == y, lhs, rhs)))
    else:
        return lhs == rhs


def If(cond, t_clause, f_clause):
    if type(t_clause) != type(f_clause):
        if isinstance(t_clause, numbers.Number) and "as_ast" in dir(f_clause):
            t_clause = z3.BitVecVal(t_clause, f_clause.size())
        elif isinstance(f_clause, numbers.Number) and "as_ast" in dir(t_clause):
            f_clause = z3.BitVecVal(f_clause, t_clause.size())
    if isinstance(t_clause, z3.z3.BitVecRef):
        assert isinstance(f_clause, z3.z3.BitVecRef)
    else:
        assert type(t_clause) == type(f_clause), "{} vs {}".format(type(t_clause), type(f_clause))
    if callable(t_clause):
        f = lambda *args, tf=t_clause, ff=f_clause: z3.If(cond, tf(*args), ff(*args))
        return f
    elif isinstance(t_clause, ExactMap):
        assert t_clause.key_type == f_clause.key_type
        assert t_clause.val_type == f_clause.val_type
        if_map = ExactMap(t_clause.name+'!or!'+f_clause.name, t_clause.key_type, t_clause.val_type)
        for i in range(len(t_clause.ufs)):
            if_map.ufs[i] = If(cond, t_clause.ufs[i], f_clause.ufs[i])
        if_map.contains = If(cond, t_clause.contains, f_clause.contains)
        return if_map
    elif not hasattr(t_clause, 'as_ast'):
        # not a z3 object
        return type(t_clause).ite_handler(cond, t_clause, f_clause)
    else:
        return z3.If(cond, t_clause, f_clause)
