import gravel_spec
from gravel_spec.bindings import load_lib
import sys
import ctypes


fn = sys.argv[1]
ele_name = sys.argv[2]

lib = load_lib('../build/libcobbleso.so')

runner = lib.create_element_runner(fn.encode('utf-8'), ele_name.encode('utf-8'))

init_pkt = lib.init_pkt_of_runner(runner)
init_state = lib.get_init_runner_state(runner)
lib.set_state_num_out(init_state, 2)

states = lib.run_pkt_handler_py(runner)

print("Done Symbolic Execution: got {} states".format(len(states)))

off = lib.mk_bv_const(23, 64)
for i, s in enumerate(states):
    for j in range(2):
        pkt_set = lib.result_pkt_of_port(s, j)
        if pkt_set is None:
            continue
        result_field = pkt_set.get_bv_by_off(off, 2)
        init_field = init_pkt.get_bv_by_off(off, 2)
        target = lib.bool_implies(pkt_set.not_empty(),
            lib.bv_eq(result_field,
                init_field))
        target = lib.bool_implies(lib.state_pre_cond(s), target)
        # lib.print_expr(lib.state_pre_cond(s))
        # lib.print_expr(result_field)
        # lib.print_expr(init_field)
        print("path {}, port {}: {}".format(i, j, lib.verify(target, False)))
lib.drop_expr_cache()
lib.free_element_runner(runner)
print("Done")
