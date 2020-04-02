#ifndef _DC_EXPORTS_HPP_
#define _DC_EXPORTS_HPP_

#include "symbolic-expr.hpp"
#include "utils.hpp"
#include "llvm-helpers.hpp"
#include "llvm-incl.hpp"
#include "click-api.hpp"
extern "C" {
#include <Python.h>
}

extern "C" {
    /* Basic Expr */
    bool is_bv(void *expr);
    int get_bv_width(void *expr);
    bool is_valid_expr(void *expr);
    void drop_expr_cache(void);
    void *mk_bv_const(uint64_t val, uint64_t size);
    void *mk_bv_var(const char *name, uint64_t size);

    void *bv_add(void *lhs, void *rhs);
    void *bv_sub(void *lhs, void *rhs);
    void *bv_mul(void *lhs, void *rhs);
    void *bv_div(void *lhs, void *rhs);
    void *bv_mod(void *lhs, void *rhs);
    void *bv_urem(void *lhs, void *rhs);

    void *bv_concat(void *lhs, void *rhs);
    void *bv_extract(void *v, int start, int end);
    void *bv_extend_to(void *v, int sz, bool is_signed);

    // change endianess
    void *bv_bswap(void *v);

    void *bv_eq(void *lhs, void *rhs);
    void *bv_ne(void *lhs, void *rhs);
    void *bv_le(void *lhs, void *rhs);
    void *bv_lt(void *lhs, void *rhs);
    void *bv_ge(void *lhs, void *rhs);
    void *bv_gt(void *lhs, void *rhs);
    void *bv_ule(void *lhs, void *rhs);
    void *bv_ult(void *lhs, void *rhs);
    void *bv_uge(void *lhs, void *rhs);
    void *bv_ugt(void *lhs, void *rhs);

    void *bool_and(void *lhs, void *rhs);
    void *bool_or(void *lhs, void *rhs);
    void *bool_implies(void *lhs, void *rhs);
    void *bool_iff(void *lhs, void *rhs);
    void *bool_not(void *v);
    void *ite(void *cond, void *t, void *f);

    void *forall(int num_vars, ...);
    void *exists(int num_vars, ...);

    void free_expr(void *expr);

    /*
      return value:  0 == verified
                     1 == not verified
                    -1 == expr not valid
     */
    int verify(void *expr, bool new_process);
    void *verify_or_ce(void *expr);
    void print_model(void *model);
    void print_eval_with_model(void *model, void *expr);

    void free_model(void *model);
    void drop_all_model(void);

    void print_expr(void *);

    void print_expr_ptrs(void);

    /* LLVM Engine */

    struct SymExeCtx {
        llvm::LLVMContext ctx;
        llvm::SMDiagnostic err;
        std::unique_ptr<llvm::Module> module;
        NameFactory name_gen;
    };

    void *create_ctx(const char *filename);
    void free_ctx(void *ctx);
    void *create_element_runner(const char *filename, const char *element_name);
    void *create_element_runner_verbose(const char *filename, const char *element_name);
    void *get_init_runner_state(void *runner);
    void *get_in_port_val(void *runner);

    void set_state_num_in(void *s, int n);
    void set_state_num_out(void *s, int n);
    void *deep_copy_state(void *s);

    void *get_init_pkt_content(void *runner);
    void free_element_runner(void *ptr);

    PyObject *run_pkt_handler(void *element_runner);

    PyObject *get_result_pkt_of_port(void *exec_ctx, int port_idx);
    void *get_obj_handle_by_off(void *exec_ctx, uint64_t off);
    PyObject *get_abs_obj_type(void *abs_obj);

    void *abs_obj_copy(void *abs_obj);
    void abs_obj_free(void *abs_obj);

    void *abs_vector_new(const char *name, int element_size);
    void *abs_vector_get(void *abs_vec, void *off);
    void abs_vector_set(void *abs_vec, void *off, void *val);

    void *abs_buffer_new(const char *name);
    void *abs_buffer_get(void *abs_buf, void *off, uint64_t num_bytes);
    void *abs_buffer_get_be(void *abs_buf, void *off, uint64_t num_bytes);
    void abs_buffer_set(void *abs_buf, void *off, void *val);
    void abs_buffer_set_be(void *abs_buf, void *off, void *val);
    void *abs_buffer_eq(void *lhs, void *rhs);

    void *abs_hashmap_new(const char *name, int num_key, int num_val, ...);
    PyObject *abs_hashmap_get(void *abs_map, ...);
    void *abs_hashmap_contains(void *abs_map, ...);
    void abs_hashmap_set(void *abs_map, ...);
    void abs_hashmap_remove(void *abs_map, ...);

    void *create_state(void *ctx);
    void *state_pre_cond(void *state);
    void state_add_pre_cond(void *state, void *cond);
    void state_set_noutput(void *state, unsigned int n);
    void free_state(void *state);

    void add_buffer(void *state, const char *name, int num_bytes);
    void *get_buffer_base(void *state, const char *name);
    void *make_pointer(void *state, const char *name, int element_size);
    void del_pointer(void *ptr);

    void *run_function(void *ctx, void *state,
                       const char *funcname, int *num_resulting_states,
                       int num_args, ...);
    void free_state_list(void *states);

    void *read_bytes(void *state, const char *buffer_name, void *off, int num_bytes);
    void write_bytes(void *state, const char *buffer_name, void *off,
                     int num_writes, ...);

    void add_object(void *state, const char *name);

    void pin_object(void *state, const char *obj_n, const char *parent_n, uint64_t offset);

    void add_pkt(void *state, const char *name);
    void *get_pkt_struct_field(void *state, const char *pkt_name, const char *field_name);
    void set_pkt_struct_field(void *state, const char *pkt_name, const char *field_name, void *val);

    // should not modify through the "container" pointer after calling this function
    void add_container(void *state, void *container,
                       const char *obj_name,
                       uint64_t offset);

    void *make_vector(const char *name, unsigned int val_size);
    void *vector_get(void *vector, void *idx);
    void vector_resize(void *vector, void *size);
    void vector_push_back(void *vector, void *val);

    void *make_map(const char *name, unsigned int key_size, unsigned int val_size);

    void *container_find(void *container, void *state, void *key);
    void container_set(void *container, void *state, void *key, void *value);
}


#endif /* _DC_EXPORTS_HPP_ */
