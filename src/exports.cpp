#include "exports.hpp"
#include <unordered_map>
#include <functional>
#include <cstdio>
#include <cstdarg>
#include "z3-gen.hpp"
#include <sstream>

using namespace Symbolic;

static std::unordered_map<void *, ExprPtr> exprs = {};

static std::unordered_map<void *, std::shared_ptr<Pointee>> data_structure_cache = {};

static std::unordered_map<void *, std::shared_ptr<z3::model>> models = {};
static std::unordered_map<void *, std::shared_ptr<Z3Context>> ctxs = {};

bool is_valid_expr(void *expr) {
    return exprs.find(expr) != exprs.end();
}

void drop_expr_cache(void) {
    exprs.clear();
}

void *ret_expr(ExprPtr expr) {
    if (expr == nullptr) {
        throw "ret_expr: nullptr inserted";
    }
    if (expr.get() == nullptr) {
        throw "ret_expr: nullptr inserted";
    }
    exprs.insert({expr.get(), expr});
    return expr.get();
}

ExprPtr get_expr(void *ptr) {
    auto expr_iter = exprs.find(ptr);
    if (expr_iter == exprs.end()) {
        return nullptr;
    }
    return expr_iter->second;
}
//
// this version throws exception when failure
ExprPtr get_expr_fail(void *ptr) {
    auto result = get_expr(ptr);
    if (result == nullptr) {
        throw "get_expr_fail: invalid expr";
    }
    return result;
}

bool is_bv(void *expr) {
    auto e = get_expr(expr);
    if (e == nullptr) {
        return false;
    } else {
        return e->type->is_bv_type();
    }
}

int get_bv_width(void *expr) {
    auto e = get_expr(expr);
    if (e == nullptr) {
        return 0;
    } else {
        assert(e->type->is_bv_type());
        return e->type->get_bv_width();
    }
}

void *mk_bv_const(uint64_t val, uint64_t size) {
    auto bv = mk_concrete_bv(size, val);
    return ret_expr(bv);
}

void *mk_bv_var(const char *name, uint64_t size) {
    std::string n(name);
    auto t = std::make_shared<BitVecType>(size);
    auto bv = mk_expr_ptr(SymbolicVar, t, n);
    return ret_expr(bv);
}

void *expr_bin_op(void *lhs, void *rhs, const std::function<ExprPtr(ExprPtr, ExprPtr)> &f) {
    auto l_iter = exprs.find(lhs);
    auto r_iter = exprs.find(rhs);
    if (l_iter == exprs.end() || r_iter == exprs.end()) {
        return NULL;
    }

    auto l = l_iter->second;
    auto r = r_iter->second;
    auto result = f(l, r);
    return ret_expr(result);
}

// template<typename ExprT>
// void *expr_arg_list_op(const std::vector<void *> &args) {
//     std::vector<ExprPtr> expr_args;
//     for (auto &a : args) {
//         if (exprs.find(a) == exprs.end()) {
//             return NULL;
//         } else {
//             expr_args.push_back(exprs[a]);
//         }
//     }
//     auto result = std::make_shared<ExprT>(expr_args);
//     exprs.insert({result.get(), result});
//     return result.get();
// }

#define BIN_OP_IMPL_BODY(expr_t, l, r)  \
    std::vector<ExprPtr> expr_args;     \
    auto l_iter = exprs.find(l);        \
    auto r_iter = exprs.find(r);        \
    if (l_iter == exprs.end() || r_iter == exprs.end()) {\
        throw "bin_op_impl: invalid expr"; \
        return nullptr;                 \
    }                                   \
    auto result = mk_expr_ptr(expr_t, {l_iter->second, r_iter->second});\
    return ret_expr(result);

#define BIN_OP_IMPL(func_name, expr_t)                  \
    void *func_name(void *lhs, void *rhs) {             \
        BIN_OP_IMPL_BODY(expr_t, lhs, rhs);             \
    }

void *bv_add(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(AddExpr, lhs, rhs);
}

void *bv_sub(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(SubExpr, lhs, rhs);
}

void *bv_mul(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(MulExpr, lhs, rhs);
}

void *bv_div(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(DivExpr, lhs, rhs);
}

void *bv_mod(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(ModExpr, lhs, rhs);
}

void *bv_urem(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(UModExpr, lhs, rhs);
}

void *bv_concat(void *lhs, void *rhs) {
    BIN_OP_IMPL_BODY(ConcatExpr, lhs, rhs);
}

void *bv_extract(void *p, int start, int end) {
    auto v_iter = exprs.find(p);
    if (v_iter == exprs.end()) {
        return NULL;
    }

    auto v = v_iter->second;
    auto result = std::make_shared<ExtractExpr>(v, start, end);
    return ret_expr(result);
}

void *bv_extend_to(void *p, int sz, bool is_signed) {
    auto v_iter = exprs.find(p);
    if (v_iter == exprs.end()) {
        return NULL;
    }

    auto v = v_iter->second;
    ExprPtr result = nullptr;
    if (is_signed) {
        result = std::make_shared<SExtExpr>(v, sz);
    } else {
        result = std::make_shared<UExtExpr>(v, sz);
    }
    return ret_expr(result);
}

void *bv_bswap(void *v) {
    // make sure that the bitvec value have correct length
    auto bv = get_expr_fail(v);
    auto result = endian_reverse(bv);
    return ret_expr(result);
}

BIN_OP_IMPL(bv_eq,  EqExpr)
BIN_OP_IMPL(bv_ne,  NeqExpr)
BIN_OP_IMPL(bv_le,  LeExpr)
BIN_OP_IMPL(bv_lt,  LtExpr)
BIN_OP_IMPL(bv_ge,  GeExpr)
BIN_OP_IMPL(bv_gt,  GtExpr)
BIN_OP_IMPL(bv_ule, UleExpr)
BIN_OP_IMPL(bv_ult, UltExpr)
BIN_OP_IMPL(bv_uge, UgeExpr)
BIN_OP_IMPL(bv_ugt, UgtExpr)

BIN_OP_IMPL(bool_and,     LAndExpr);
BIN_OP_IMPL(bool_or,      LOrExpr);
BIN_OP_IMPL(bool_implies, ImpliesExpr);

void *bool_iff(void *lhs, void *rhs) {
    auto l_iter = exprs.find(lhs);
    auto r_iter = exprs.find(rhs);
    if (l_iter == exprs.end() || r_iter == exprs.end()) {
        return NULL;
    }

    auto l = l_iter->second;
    auto r = r_iter->second;
    auto c1 = mk_expr_ptr(ImpliesExpr, {l, r});
    auto c2 = mk_expr_ptr(ImpliesExpr, {r, l});
    auto result = mk_expr_ptr(LAndExpr, {c1, c2});
    return ret_expr(result);
}

void *bool_not(void *v) {
    auto v_iter = exprs.find(v);
    if (v_iter == exprs.end()) {
        return NULL;
    }

    auto val = v_iter->second;
    auto result = mk_expr_ptr(LNotExpr, val);
    return ret_expr(result);
}

void *ite(void *c, void *t, void *f) {
    auto c_i = exprs.find(c);
    auto t_i = exprs.find(t);
    auto f_i = exprs.find(f);

    if (c_i == exprs.end() || t_i == exprs.end() || f_i == exprs.end()) {
        throw "ite: invalid expr";
        return NULL;
    }

    auto cc = c_i->second;
    auto tt = t_i->second;
    auto ff = f_i->second;
    auto result = mk_expr_ptr(IteExpr, cc, tt, ff);
    return ret_expr(result);
}

void *forall(int num_vars, ...) {
    va_list vl;
    va_start(vl, num_vars);
    std::vector<ExprPtr> vars;
    for (int i = 0; i < num_vars; i++) {
        void *var = va_arg(vl, void *);
        try {
        auto var_expr = get_expr_fail(var);
        if (var_expr == nullptr) {
            throw "forall: invalid expr";
        }
        vars.push_back(var_expr);
        } catch (...) {
            std::cerr << "got exception" << std::endl;
            //PyErr_SetString(PyExc_RuntimeError, "Unexpected exception in C++");
            PyErr_SetObject(PyExc_ValueError, Py_None);
        }
    }
    void *cond = va_arg(vl, void *);
    auto cond_expr = get_expr_fail(cond);
    auto result = mk_expr_ptr(ForallExpr, vars, cond_expr);
    va_end(vl);
    return ret_expr(result);
}

void *exists(int num_vars, ...) {
    va_list vl;
    va_start(vl, num_vars);
    std::vector<ExprPtr> vars;
    for (int i = 0; i < num_vars; i++) {
        void *var = va_arg(vl, void *);
        auto var_expr = get_expr_fail(var);
        vars.push_back(var_expr);
    }
    void *cond = va_arg(vl, void *);
    auto cond_expr = get_expr_fail(cond);
    auto result = mk_expr_ptr(ExistsExpr, vars, cond_expr);
    va_end(vl);
    return ret_expr(result);
}

#undef BIN_OP_IMPL

void free_expr(void *expr) {
    exprs.erase(expr);
}

int verify(void *expr, bool new_process) {
    auto e_iter = exprs.find(expr);
    if (e_iter == exprs.end()) {
        return -1;
    }
    auto e = e_iter->second;
    try {
        Z3Context ctx;
        auto result = verify_with_z3(ctx, nullptr, e, new_process);
        if (result) {
            return 0;
        } else {
            return 1;
        }
    } catch (z3::exception &e) {
        std::cerr << "Z3 exception: " << e << std::endl;
    }
    return -1;
}

void *verify_or_ce(void *expr) {
    auto e_iter = exprs.find(expr);
    if (e_iter == exprs.end()) {
        std::cerr << "verify_or_ce: could not find expr" << std::endl;
        throw "verify_or_ce: expr not found";
        return (void *)-1;
    }
    auto e = e_iter->second;
    auto ctx = std::make_shared<Z3Context>();
    auto e_z3 = gen_z3_expr(*ctx, e);
    z3::solver sol(ctx->ctx);
    sol.add(!e_z3.get_bool().simplify());
    auto result = sol.check();
    if (result == z3::unsat) {
        return nullptr;
    } else {
        auto model = sol.get_model();
        auto model_ptr = std::make_shared<z3::model>(model);
        models.insert({model_ptr.get(), model_ptr});
        ctxs.insert({model_ptr.get(), ctx});
        std::cerr << "verify_or_ce: counterexample found " << model_ptr.get() << std::endl;
        return model_ptr.get();
    }
}

void print_model(void *model) {
    auto m_iter = models.find(model);

    if (m_iter == models.end()) {
        printf("could not find model\n");
        return;
    }
    auto m = m_iter->second;
    std::cout << *m << std::endl;
}

void print_eval_with_model(void *model, void *expr) {
    auto m_iter = models.find(model);
    auto e_iter = exprs.find(expr);

    if (m_iter == models.end()) {
        printf("could not find model\n");
        return;
    }

    if (e_iter == exprs.end()) {
        printf("could not find expr\n");
        return;
    }

    auto m = m_iter->second;
    auto e = e_iter->second;
    auto c = ctxs.find(model)->second;
    std::cout << m->eval(gen_z3_expr(*c, e).get_expr()) << std::endl;
}

void free_model(void *model) {
    models.erase(model);
    ctxs.erase(model);
}

void drop_all_model(void) {
    models.clear();
    ctxs.clear();
}

void print_expr(void *e) {
    Z3Context ctx;
    auto e_iter = exprs.find(e);
    printf("printing for pointer %p\n", e);
    if (e_iter == exprs.end()) {
        std::cerr << "expr not found!" << std::endl;
    } else {
        auto expr = e_iter->second;
        std::cout << gen_z3_expr(ctx, expr).get_expr().simplify() << std::endl;
    }
}

void print_expr_ptrs(void) {
    for (auto iter = exprs.begin(); iter != exprs.end(); iter++) {
        printf("expr: %p %p\n", iter->first, iter->first);
    }
}


void *create_ctx(const char *filename) {
    auto ctx = new SymExeCtx();
    ctx->module = llvm::parseIRFile(std::string(filename), ctx->err, ctx->ctx);
    return (void *)ctx;
}

void free_ctx(void *ctx) {
    SymExeCtx *c = (SymExeCtx *)ctx;
    delete c;
}

void *create_element_runner(const char *filename,
                            const char *element_name) {
    try {
        SymExecConf conf;
        conf.log_level = SymExecConf::LOG_NORMAL;
        auto runner = new ElementExecutor(filename, element_name, conf);
        runner->initilize();
        return (void *)runner;
    } catch (std::string e) {
        std::cout << "Error: " << e << std::endl;
        throw e;
    }
}

void *create_element_runner_verbose(const char *filename, const char *element_name) {
    try {
        SymExecConf conf;
        conf.log_level = SymExecConf::LOG_VERBOSE;
        auto runner = new ElementExecutor(filename, element_name, conf);
        runner->initilize();
        return (void *)runner;
    } catch (std::string e) {
        std::cout << "Error: " << e << std::endl;
        throw e;
    }
}

void *get_init_runner_state(void *e_runner) {
    auto runner = (ElementExecutor *)e_runner;
    return (void *)runner->init_state_.get();
}

void *get_in_port_val(void *e_runner) {
    auto runner = (ElementExecutor *)e_runner;
    auto v = runner->input_port_val_;
    return ret_expr(v);
}

void set_state_num_in(void *s, int n) {
}

void set_state_num_out(void *s, int n) {
    ((ExecContext *)s)->state_.num_out = n;
}

void *deep_copy_state(void *s) {
    auto state = (ExecContext *)s;
    return nullptr;
}

void *get_init_pkt_content(void *element_runner) {
    auto *runner = (ElementExecutor *)element_runner;
    return runner->init_pkt_content_.get();
}

void free_element_runner(void *ptr) {
    delete (ElementExecutor *)ptr;
}

PyObject *run_pkt_handler(void *element_runner) {
    auto *runner = (ElementExecutor *)element_runner;
    runner->run();
    PyObject *result = PyList_New(0);
    for (auto &s : runner->result_paths_) {
        auto p = PyLong_FromVoidPtr((void *)s.get());
        PyList_Append(result, p);
    }
    return result;
}

PyObject *get_result_pkt_of_port(void *exec_ctx, int port_idx) {
    auto ctx = (ExecContext *)exec_ctx;
    auto &result_pkts = ctx->out_pkts_[port_idx];
    if (result_pkts.size() == 0) {
        Py_RETURN_NONE;
    }

    auto result = PyList_New(0);
    for (auto &e : result_pkts) {
        auto buf_ptr = ctx->tmp_data[e.pkt->content_buf_name];
        assert(buf_ptr != nullptr);
        exprs[e.cond.get()] = e.cond;
        auto cond_v = PyLong_FromVoidPtr((void *)e.cond.get());
        auto buf_v = PyLong_FromVoidPtr((void *)buf_ptr.get());
        auto t = PyTuple_Pack(2, cond_v, buf_v);
        PyList_Append(result, t);
    }
    return result;
}

void *get_obj_handle_by_off(void *exec_ctx, uint64_t off) {
    auto ctx = (ExecContext *)exec_ctx;
    auto &state = ctx->state_;
    auto &layout = state.struct_meta["this_element"];
    assert(layout.out_refs.find(off) != layout.out_refs.end());
    auto obj_name = layout.out_refs[off].ref_name;
    assert(state.abstract_data.find(obj_name) != state.abstract_data.end());
    return (void *)state.abstract_data[obj_name].get();
}

PyObject *get_abs_obj_type(void *abs_obj) {
    std::stringstream ss;
    Pointee *obj = (Pointee *)abs_obj;
    ss << obj->type();
    return PyUnicode_FromString(ss.str().c_str());
}

void *abs_obj_copy(void *abs_obj) {
    Pointee *buf = (Pointee *)abs_obj;
    auto new_buf = buf->copy_self();
    data_structure_cache.insert({(void *)new_buf.get(), new_buf});
    return (void *)new_buf.get();
}

void abs_obj_free(void *abs_obj) {
    if (data_structure_cache.find(abs_obj) != data_structure_cache.end()) {
        data_structure_cache.erase(abs_obj);
    }
}

void *abs_vector_new(const char *name, int element_size) {
    auto ele_t = std::make_shared<Symbolic::BitVecType>(element_size);
    auto vec = std::make_shared<AbstractVector>(name, ele_t);
    data_structure_cache.insert({vec.get(), vec});
    return (void *)vec.get();
}

void *abs_vector_get(void *abs_vec, void *off) {
    AbstractVector *vec = (AbstractVector *)abs_vec;
    auto off_expr = get_expr(off);
    if (off_expr == nullptr) {
        throw "abs_vector_get: invalid offset";
        return nullptr;
    }
    auto result = vec->get(off_expr);
    return ret_expr(result);
}

void abs_vector_set(void *abs_vec, void *off, void *val) {
    AbstractVector *vec = (AbstractVector *)abs_vec;
    auto off_expr = get_expr_fail(off);
    auto val_expr = get_expr_fail(val);
    vec->set(off_expr, val_expr);
}

void *abs_buffer_new(const char *name) {
    auto buf = std::make_shared<Buffer>(name);
    data_structure_cache.insert({buf.get(), buf});
    return (void *)buf.get();
}

void *abs_buffer_get(void *abs_buf, void *off, uint64_t num_bytes) {
    Buffer *buf = (Buffer *)abs_buf;
    auto off_expr = get_expr(off);
    if (off_expr == nullptr) {
        throw "abs_buffer_get: unknown offset";
        return nullptr;
    }
    auto result = buf->load(off_expr, num_bytes);
    if (result.is_ptr()) {
        throw "abs_buffer_get: result is ptr";
        return nullptr;
    }
    auto v = result.get_val();
    
    /*
    std::cout << "Abs buffer get: " << v.get() << " "
              << v->type.get()
              << " " << v->type->get_bv_width() << std::endl;
    */
 
    return ret_expr(result.get_val());
}

void *abs_buffer_get_be(void *abs_buf, void *off, uint64_t num_bytes) {
    Buffer *buf = (Buffer *)abs_buf;
    auto off_expr = get_expr(off);
    if (off_expr == nullptr) {
        throw "abs_buffer_get_be: unknown offset";
        return nullptr;
    }
    auto result = buf->load_be(off_expr, num_bytes);
    if (result.is_ptr()) {
        throw "abs_buffer_get_be: result is ptr";
        return nullptr;
    }
    auto v = result.get_val();
    
    /*
    std::cout << "Abs buffer get: " << v.get() << " "
              << v->type.get()
              << " " << v->type->get_bv_width() << std::endl;
    */
 
    return ret_expr(result.get_val());
}

void abs_buffer_set(void *abs_buf, void *off, void *val) {
    Buffer *buf = (Buffer *)abs_buf;
    auto off_expr = get_expr(off);
    if (off_expr == nullptr) {
        throw "abs_buffer_set: invalid offset";
    }
    auto val_expr = get_expr(val);
    if (val_expr == nullptr) {
        throw "abs_buffer_set: invalid value ptr";
    }

    buf->store(off_expr, RegValue{val_expr});
}

void abs_buffer_set_be(void *abs_buf, void *off, void *val) {
    Buffer *buf = (Buffer *)abs_buf;
    auto off_expr = get_expr(off);
    if (off_expr == nullptr) {
        throw "abs_buffer_set: invalid offset";
    }
    auto val_expr = get_expr(val);
    if (val_expr == nullptr) {
        throw "abs_buffer_set: invalid value ptr";
    }

    buf->store_be(off_expr, RegValue{val_expr});
}

void *abs_hashmap_new(const char *name, int num_key, int num_val, ...) {
    Symbolic::PtrList<Symbolic::Type> key_types;
    Symbolic::PtrList<Symbolic::Type> val_types;
    va_list vl;
    va_start(vl, num_val);
    for (int i = 0; i < num_key; i++) {
        int k_size = va_arg(vl, int);
        key_types.push_back(std::make_shared<Symbolic::BitVecType>(k_size));
    }
    for (int i = 0; i < num_val; i++) {
        int v_size = va_arg(vl, int);
        val_types.push_back(std::make_shared<Symbolic::BitVecType>(v_size));
    }
    va_end(vl);
    auto abs_map = std::make_shared<AbstractMap>(name, key_types, val_types);
    data_structure_cache.insert({abs_map.get(), abs_map});
    return (void *)abs_map.get();
}

void *abs_hashmap_contains(void *abs_map, ...) {
    AbstractMap *map = (AbstractMap *)abs_map;
    int n_key = map->key_types.size();
    va_list vl;
    va_start(vl, abs_map);
    OpApplyNode::ArgList keys;
    bool have_error = false;
    for (int i = 0; i < n_key; i++) {
        void *arg = va_arg(vl, void *);
        auto arg_expr = get_expr(arg);
        if (arg_expr == nullptr) {
            std::cerr << "hashmap_contains: " << i << "-th key invalid" << std::endl;
            throw "hashmap_contains: key invalid";
            have_error = true;
            break;
        }
        keys.push_back(arg_expr);
    }
    va_end(vl);
    if (have_error) {
        Py_RETURN_NONE;
    }
    auto result = map->contains(keys);
    return ret_expr(result);
}

PyObject *abs_hashmap_get(void *abs_map, ...) {
    AbstractMap *map = (AbstractMap *)abs_map;
    int n_key = map->key_types.size();
    va_list vl;
    va_start(vl, abs_map);
    OpApplyNode::ArgList keys;
    bool have_error = false;
    for (int i = 0; i < n_key; i++) {
        void *arg = va_arg(vl, void *);
        auto arg_expr = get_expr(arg);
        if (arg_expr == nullptr) {
            std::cerr << "abs_hashmap_get: key idx " << i << " not exist" << std::endl;
            std::cerr << arg << std::endl;
            have_error = true;
            break;
        }
        keys.push_back(arg_expr);
    }
    va_end(vl);
    if (have_error) {
        Py_RETURN_NONE;
    }
    auto vals = map->get_vals(keys);
    PyObject *result = PyList_New(0);
    for (auto &v : vals) {
        auto p = PyLong_FromVoidPtr(ret_expr(v));
        PyList_Append(result, p);
    }
    return result;
}

void abs_hashmap_set(void *abs_map, ...) {
    AbstractMap *map = (AbstractMap *)abs_map;
    int n_key = map->key_types.size();
    int n_val = map->val_types.size();
    va_list vl;
    va_start(vl, abs_map);
    OpApplyNode::ArgList keys;
    OpApplyNode::ArgList vals;
    bool have_error = false;
    for (int i = 0; i < n_key; i++) {
        void *arg = va_arg(vl, void *);
        auto arg_expr = get_expr_fail(arg);
        keys.push_back(arg_expr);
    }
    for (int i = 0; i < n_val; i++) {
        void *val = va_arg(vl, void *);
        auto val_expr = get_expr_fail(val);
        vals.push_back(val_expr);
    }
    va_end(vl);
    map->set_vals(keys, vals);
}

void abs_hashmap_remove(void *abs_map, ...) {
    AbstractMap *map = (AbstractMap *)abs_map;
    int n_key = map->key_types.size();
    va_list vl;
    va_start(vl, abs_map);
    OpApplyNode::ArgList keys;
    bool have_error = false;
    for (int i = 0; i < n_key; i++) {
        void *arg = va_arg(vl, void *);
        auto arg_expr = get_expr_fail(arg);
        keys.push_back(arg_expr);
    }
    va_end(vl);
    map->delete_val(keys);
}

void *create_state(void *ptr) {
    return nullptr;
}

void *state_pre_cond(void *state) {
    auto s = (ExecContext *)state;
    auto pre_cond = s->get_pre_cond();
    return ret_expr(pre_cond);
}

void state_add_pre_cond(void *state, void *cond) {
}

void state_set_noutput(void *state, unsigned int n) {
}

void free_state(void *state) {
}

void add_buffer(void *state, const char *name, int num_bytes) {
}

void *get_buffer_base(void *state, const char *name) {
    return nullptr;
}

void *make_pointer(void *state, const char *name, int element_size) {
    return nullptr;
}

void del_pointer(void *ptr) {
}


void *run_function(void *ctx, void *state,
                   const char *funcname, int *num_resulting_states,
                   int num_args, ...) {
    return nullptr;
    /*
    va_list vl;
    va_start(vl, num_args);
    SymExeCtx *c = (SymExeCtx *)ctx;
    LLVMState *s = (LLVMState *)state;

    LLVMEngine e(*(c->module));

    std::vector<LLVMState::RegValue> args;

    for (int i = 0; i < num_args; i++) {
        void *arg = va_arg(vl, void *);
        if (exprs.find(arg) != exprs.end()) {
            // this is an expr
            args.push_back(exprs.find(arg)->second);
        } else {
            // must be a pointer
            LLVMState::Pointer *p_p = (LLVMState::Pointer *)arg;
            args.push_back(*p_p);
        }
    }
    va_end(vl);

    auto states = e.run_function(std::string(funcname), *s, args);
    *num_resulting_states = states.size();

    auto vec = new std::vector<void *>();
    for (int i = 0; i < states.size(); i++) {
        void *s_ptr = (void *)new LLVMState(states[i]);
        vec->push_back(s_ptr);
    }
    return (void *)vec->data();
    */
}

void free_state_list(void *states) {
}


void *read_bytes(void *state, const char *buffer_name, void *off_ptr, int num_bytes) {
    return nullptr;
}

void write_bytes(void *state, const char *buffer_name, void *off_ptr,
                 int num_writes, ...) {
}


void add_object(void *state, const char* name) {
}


void pin_object(void *state, const char *obj_n, const char *parent_n, uint64_t offset) {
}


void add_pkt(void *state, const char *name) {
}

void *get_pkt_struct_field(void *state,
                           const char *pkt_name_ptr,
                           const char *field_name_ptr) {
    return nullptr;
}

void set_pkt_struct_field(void *state, const char *pkt_name_ptr,
                          const char *field_name_ptr, void *val) {
}


void add_container(void *state, void *container, const char *on, uint64_t offset) {
}

void *make_vector(const char *name, unsigned int val_size) {
    return nullptr;
}

void *vector_get(void *vector, void *idx_ptr) {
    return nullptr;
}

void vector_resize(void *vector, void *sz_ptr) {
}

void vector_push_back(void *vector, void *val_ptr) {
}


void *make_map(const char *name, unsigned int key_size, unsigned int val_size) {
    return nullptr;
}

void *container_find(void *container, void *state, void *key) {
    return nullptr;
}

void container_set(void *container, void *state, void *key, void *value) {
}
