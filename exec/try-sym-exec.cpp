#include "click-exec.hpp"
#include "llvm-helpers.hpp"
#include "utils.hpp"
#include "click-state.hpp"
#include "click-api.hpp"
#include <optional>

int main(int argc, char *argv[]) {
    llvm::LLVMContext ctx;
    llvm::SMDiagnostic err;
    if (argc != 3) {
        printf("Usage: %s <class-ir-file> <class-name>\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    const std::string element_name = std::string(argv[2]);

    auto module = llvm::parseIRFile(ir_filename, err, ctx);

    if (module == nullptr) {
        std::cerr << "failed to parse IR file" << std::endl;
        return -1;
    }

    llvm::StructType *element_t = nullptr;
    std::string element_class_name = "class." + element_name;
    auto structs = module->getIdentifiedStructTypes();
    for (auto &s : structs) {
        if (s->getName() == element_class_name) {
            element_t = s;
            break;
        }
    }

    if (element_t == nullptr) {
        std::cout << "Error: could not find element class definition" << std::endl;
    } else {
        printf("Element State: %p %s\n", element_t, get_type_name(element_t).c_str());
    }

    auto entries = find_element_entry(module.get(), element_name);

    std::optional<std::string> push_entry;
    std::optional<std::string> pull_entry;
    std::optional<std::string> simple_act_entry;

    for (auto e : entries) {
        if (e.find("push") != std::string::npos) {
            push_entry = e;
        }
        if (e.find("pull") != std::string::npos) {
            pull_entry = e;
        }
        if (e.find("simple_action") != std::string::npos) {
            simple_act_entry = e;
        }
    }
    if (entries.size() <= 0) {
        std::cerr << "could not find element entry" << std::endl;
    }

    std::string entry;
    if (simple_act_entry != std::nullopt) {
        entry = simple_act_entry.value();
    } else if (push_entry != std::nullopt) {
        entry = push_entry.value();
    } else if (pull_entry != std::nullopt) {
        entry = pull_entry.value();
    }
    auto init_fp = module->getFunction(entry);
    auto init = std::make_shared<ExecContext>();
    init->curr_bb_ = &init_fp->getEntryBlock();
    init->inst_iter_ = init->curr_bb_->begin();
    init->module_ = module.get();

    // Create state for the element
    auto name_gen_ptr = std::make_shared<NameFactory>();
    auto element_state = parse_element_state(module.get(), element_t, *name_gen_ptr);

    SymPointer this_ptr;
    this_ptr.pointer_base = "this_element";
    this_ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
    SymPointer pkt_ptr;
    pkt_ptr.pointer_base = "input_pkt";
    pkt_ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
    init->set_reg_val("%0", RegValue{this_ptr});
    if (simple_act_entry != std::nullopt) {
        init->set_reg_val("%1", RegValue{pkt_ptr});
    } else if (push_entry != std::nullopt) {
        auto bv_32 = std::make_shared<Symbolic::BitVecType>(32);
        init->set_reg_val("%1", RegValue{mk_expr_ptr(SymbolicVar, bv_32, "input_port")});
        init->set_reg_val("%2", RegValue{pkt_ptr});
    } else if (pull_entry != std::nullopt) {
        std::cerr << "PULL only element not supported" << std::endl;
        exit(-1);
    }

    init->state_ = element_state;
    init->abs_funcs.push_back(std::make_shared<PktGeneral>());
    init->abs_funcs.push_back(std::make_shared<VectorOps>());
    init->abs_funcs.push_back(std::make_shared<HashMapOps>());
    init->abs_funcs.push_back(std::make_shared<ElementFuncs>());
    init->abs_funcs.push_back(std::make_shared<ByteRotationFunc>());
    init->abs_funcs.push_back(std::make_shared<IPFlowIDConstr>());
    init->abs_funcs.push_back(std::make_shared<LLVMMemcpy>());
    init->abs_funcs.push_back(std::make_shared<LLVMMemset>());
    init->abs_funcs.push_back(std::make_shared<LLVMMemcmp>());
    init->abs_funcs.push_back(std::make_shared<ClickLibFunc>());
    init->abs_funcs.push_back(std::make_shared<IP6Helper>());

    init->abs_funcs.push_back(std::make_shared<CheckIPHdrHelper>());

    init->name_gen = name_gen_ptr;
    init->call_stack_.push(entry);

    auto pkt_struct = std::make_shared<Packet>("input_pkt", init);
    init->tmp_data.insert({"input_pkt", pkt_struct});

    auto pkt_buf = init->tmp_data[pkt_struct->content_buf_name];
    // pkt_buf->store(mk_concrete_bv(64, 14), RegValue{mk_concrete_bv(8, 0x45)});

    auto size_lb = mk_expr_ptr(LtExpr, {mk_concrete_bv(32, 34), pkt_struct->len});
    auto size_ub = mk_expr_ptr(LeExpr, {pkt_struct->len, mk_concrete_bv(32, 1500)});

    init->add_pre_cond(size_lb);
    init->add_pre_cond(size_ub);
    
    ClickSymExecutor executor(module.get());
    auto results = executor.run(init);

    std::cout << "Done Execution. Got " << results.size() << " pathes" << std::endl;

    return 0;
}
