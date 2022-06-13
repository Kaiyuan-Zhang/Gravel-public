#include "click-exec.hpp"
#include "llvm-helpers.hpp"
#include "data-structures.hpp"
#include "z3-gen.hpp"
#include <cassert>
#include <iostream>
#include "click-api.hpp"


ExecError::ExecError() : file_name(""), line_number(-1) {}

ExecError::ExecError(const std::string &s) : msg(s), file_name(""), line_number(-1) {}

ExecError::ExecError(const llvm::Instruction &inst, const std::string &s) : msg(s) {
    if (llvm::DILocation *Loc = inst.getDebugLoc()) { // Here I is an LLVM instruction
        unsigned ln = Loc->getLine();
        auto fn = Loc->getFilename().str();
        auto dir = Loc->getDirectory().str();
        file_name = dir + "/" + fn;
        line_number = ln;
    } else {
        file_name = "";
        line_number = -1;
    }
}

SymExecConf default_conf { .log_level = SymExecConf::LOG_NORMAL };

bool RegValue::is_val() const {
    return std::holds_alternative<::Symbolic::ExprPtr>(content);
}

bool RegValue::is_ptr() const {
    return std::holds_alternative<::SymPointer>(content);
}

::Symbolic::ExprPtr &RegValue::get_val() {
    return std::get<::Symbolic::ExprPtr>(content);
}

SymPointer &RegValue::get_ptr() {
    return std::get<SymPointer>(content);
}

const ::Symbolic::ExprPtr &RegValue::get_val() const {
    return std::get<::Symbolic::ExprPtr>(content);
}

const SymPointer &RegValue::get_ptr() const {
    return std::get<SymPointer>(content);
}

std::shared_ptr<ExecContext> ExecContext::copy_self() const {
    auto result = std::make_shared<ExecContext>(*this);

    // copy tmp_data
    for (auto &kv : tmp_data) {
        result->tmp_data[kv.first] = kv.second->copy_self();
    }

    // copy element state (abstract types)
    for (auto &kv : state_.abstract_data) {
        result->state_.abstract_data[kv.first] = kv.second->copy_self();
    }

    return result;
}

void ExecContext::push_ctx(llvm::Function *fp, const std::string &ret_reg) {
    inst_iter_++;
    FuncCallCtx ctx;
    ctx.reg_map = reg_val_;
    ctx.inst_iter = inst_iter_;
    ctx.ret_reg = ret_reg;
    old_ctx_.push(ctx);
    reg_val_.clear();
    curr_bb_ = &fp->getEntryBlock();
    prev_bb_ = nullptr;
    inst_iter_ = curr_bb_->begin();
    call_stack_.push(fp->getName().str());
}

void ExecContext::pop_ctx(const std::string &ret_reg) {
    FuncCallCtx ctx = old_ctx_.top();
    old_ctx_.pop();
    curr_bb_ = ctx.inst_iter->getParent();
    prev_bb_ = nullptr;
    inst_iter_ = ctx.inst_iter;
    auto ret_val = get_reg_val(ret_reg);
    reg_val_ = ctx.reg_map;
    set_reg_val(ctx.ret_reg, ret_val);
    call_stack_.pop();
}

RegValue ExecContext::get_reg_val(const llvm::Value &value) const {
    auto val_name = get_name(value);
    auto t = value.getType();
    if (t->isPointerTy() && t->getPointerElementType()->isFunctionTy()) {
        throw "TODO: get func_name";
    }

    if (val_name == "undef") {
        auto bv64_t = std::make_shared<Symbolic::BitVecType>(64);
        if (t->isPointerTy()) {
            SymPointer ptr{"undef", nullptr, mk_expr_ptr(SymbolicVar, bv64_t, name_gen->gen("undef"))};
            return RegValue{ptr};
        } else if (t->isIntegerTy()) {
            auto size = t->getIntegerBitWidth();
            return RegValue{mk_expr_ptr(SymbolicVar, bv64_t, name_gen->gen("undef"))};
        }
    }

    if (const llvm::ConstantInt* CI = llvm::dyn_cast<const llvm::ConstantInt>(&value)) {
        // constant integer
        if (CI->getBitWidth() <= 64) {
            return RegValue{mk_expr_ptr(ConcreteBv, CI->getBitWidth(), CI->getSExtValue())};
        } else {
            assert(false && "integer too large");
        }
    }

    return get_reg_val(val_name);
}

RegValue ExecContext::get_reg_val(const std::string &reg_name) const {
    if (reg_val_.find(reg_name) != reg_val_.end()) {
        return reg_val_.find(reg_name)->second;
    }
    if (reg_name == "null") {
        SymPointer ptr;
        ptr.pointer_base = "";
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
        return RegValue{ptr};
    } else if (reg_name == "true") {
        return RegValue{mk_expr_ptr(ConcreteBv, 1, 1)};
    } else if (reg_name == "false") {
        return RegValue{mk_expr_ptr(ConcreteBv, 1, 0)};
    }

    throw ExecError("unknown register");
}
void ExecContext::set_reg_val(const std::string &reg_name, const RegValue &val) {
    reg_val_[reg_name] = val;
}

void ExecContext::jump_to_bb(llvm::BasicBlock *bb) {
    prev_bb_ = curr_bb_;
    curr_bb_ = bb;
    inst_iter_ = curr_bb_->begin();
}

void ExecContext::call_func(llvm::Function *func) {
    prev_bb_ = nullptr;
    ret_addrs_.push(inst_iter_);
    curr_bb_ = &func->getEntryBlock();
    inst_iter_ = curr_bb_->begin();
}

void ExecContext::add_pre_cond(::Symbolic::ExprPtr c) {
    // Symbolic::Z3Context ctx;
    // auto e = gen_z3_expr(ctx, c).get_expr();
    // std::cout << "Adding cond #" << pre_cond_list_.size() << " : "
    //           << gen_z3_expr(ctx, c).get_expr() << std::endl;
    // std::stringstream ss;
    // ss << e;
    // if (ss.str() == "null") {
    //     assert(false);
    // }
    pre_cond_list_.push_back(c->simplify());
    have_new_cond_ = true;
}

Symbolic::ExprPtr ExecContext::get_pre_cond() const {
    Symbolic::ExprPtr result = mk_expr_ptr(ConcreteBv, 1, 1);
    for (auto cond : pre_cond_list_) {
        result = mk_expr_ptr(LAndExpr, {result, cond});
    }
    return result->simplify();
}

std::shared_ptr<Pointee> ExecContext::find_pointee(const std::string &name) const {
    if (tmp_data.find(name) != tmp_data.end()) {
        return tmp_data.find(name)->second;
    }

    if (state_.abstract_data.find(name) != state_.abstract_data.end()) {
        return state_.abstract_data.find(name)->second;
    }
    assert(false && "Could not find Pointee");
}

class SymExecVisitor : public llvm::InstVisitor<SymExecVisitor> {
public:
    const SymExecConf &conf;
    std::shared_ptr<ExecContext> state;
    std::vector<std::shared_ptr<ExecContext>> &nexts, &finished;

    SymExecVisitor(std::shared_ptr<ExecContext> s,
                   std::vector<std::shared_ptr<ExecContext>> &r,
                   std::vector<std::shared_ptr<ExecContext>> &f,
                   const SymExecConf &_conf): state(s),
                                              nexts(r),
                                              finished(f),
                                              conf(_conf){}

    void visitInstruction(const llvm::Instruction &inst) {
        llvm::errs() << "OOPS: ";
        inst.print(llvm::errs());
        llvm::errs() << "\n";
        assert(false && "unknow instruction");
    }

    void visitReturnInst(const llvm::ReturnInst &inst) {
        // "ret" instruction
        if (state->ret_addrs_.empty()) {
            finished.push_back(state);
        } else {
            // return to the previous function
            auto ret_reg = get_name(*inst.getOperand(0));
            state->pop_ctx(ret_reg);
            nexts.push_back(state);
        }
    }

    void visitBranchInst(const llvm::BranchInst &inst) {
        if (inst.isConditional()) {
            if (conf.log_level == SymExecConf::LOG_VERBOSE) {
                std::cout << "Branching..." << std::endl;
            }
            auto cond_reg = get_name(*inst.getCondition());
            assert(state->reg_val_.find(cond_reg) != state->reg_val_.end());
            auto cond_val = state->reg_val_[cond_reg];
            assert(cond_val.is_val());
            auto t_target_bb = inst.getSuccessor(0);
            auto f_target_bb = inst.getSuccessor(1);

            // now create two copies of the ExecContext
            auto t_ctx = state->copy_self();
            t_ctx->jump_to_bb(t_target_bb);
            t_ctx->add_pre_cond(cond_val.get_val());
            nexts.push_back(t_ctx);

            auto f_ctx = state->copy_self();
            f_ctx->jump_to_bb(f_target_bb);
            f_ctx->add_pre_cond(mk_expr_ptr(LNotExpr, cond_val.get_val()));
            nexts.push_back(f_ctx);
        } else {
            auto target_bb = inst.getSuccessor(0);
            state->jump_to_bb(target_bb);
            nexts.push_back(state);
        }
    }

    void visitSwitchInst(const llvm::SwitchInst &inst) {
        auto cond_reg_val = state->reg_val_[get_name(*inst.getCondition())];
        assert(cond_reg_val.is_val());
        auto cond_val = cond_reg_val.get_val();
        auto bw = cond_val->type->get_bv_width();

        Symbolic::ExprPtr default_cond = nullptr;
        for (auto i = inst.case_begin(); i != inst.case_end(); i++) {
            auto c = *i;
            auto val = c.getCaseValue()->getSExtValue();
            auto target_bb = c.getCaseSuccessor();
            auto eq = mk_expr_ptr(EqExpr,
                        {cond_val, mk_expr_ptr(ConcreteBv, bw, val)});
            auto neq = mk_expr_ptr(LNotExpr, eq);

            if (default_cond == nullptr) {
                default_cond = neq;
            } else {
                default_cond = mk_expr_ptr(LAndExpr, {default_cond, neq});
            }
            auto taken_ctx = state->copy_self();
            taken_ctx->jump_to_bb(const_cast<llvm::BasicBlock *>(target_bb));
            taken_ctx->add_pre_cond(eq);
            nexts.push_back(taken_ctx);
        }
        auto default_bb = inst.getDefaultDest();
        auto default_ctx = state->copy_self();
        default_ctx->jump_to_bb(default_bb);
        default_ctx->add_pre_cond(default_cond);
        nexts.push_back(default_ctx);
    }

    void visitICmpInst(const llvm::ICmpInst &inst) {
        auto dst_reg = get_name(inst);
        using P = llvm::CmpInst::Predicate;
        auto predicate = inst.getPredicate();
        auto op_val1 = state->get_reg_val(*inst.getOperand(0));
        auto op_val2 = state->get_reg_val(*inst.getOperand(1));
        Symbolic::ExprPtr op1 = nullptr;
        Symbolic::ExprPtr op2 = nullptr;
        if (op_val1.is_ptr()) {
            // pointer comparasion, only support eq or ne null
            auto ptr1 = op_val1.get_ptr();
            auto ptr2 = op_val2.get_ptr();
            // assert(predicate == P::ICMP_EQ || predicate == P::ICMP_NE);
            bool same_buffer = (ptr1.pointer_base == ptr2.pointer_base);
            Symbolic::ExprPtr ptr_eq = nullptr;

            if (same_buffer) {
                op1 = ptr1.offset;
                op2 = ptr2.offset;
            } else if (predicate == P::ICMP_EQ || predicate == P::ICMP_NE) {
                state->set_reg_val(dst_reg, RegValue{mk_concrete_bv(1, 0)});
                state->inst_iter_++;
                nexts.push_back(state);
                return;
            } else {
                assert(false && "comparing different pointers");
            }
        } else {
            op1 = state->get_reg_val(*inst.getOperand(0)).get_val();
            op2 = state->get_reg_val(*inst.getOperand(1)).get_val();
        }
        Symbolic::ExprPtr val = nullptr;
#define PRED_CASE(LLVM_PRED, EXPR_T)               \
        case LLVM_PRED:                            \
            val = mk_expr_ptr(EXPR_T, {op1, op2}); \
            break
        switch (predicate) {
            PRED_CASE(P::ICMP_EQ, EqExpr);
            PRED_CASE(P::ICMP_NE, NeqExpr);
            PRED_CASE(P::ICMP_SLE, LeExpr);
            PRED_CASE(P::ICMP_SLT, LtExpr);
            PRED_CASE(P::ICMP_SGE, GeExpr);
            PRED_CASE(P::ICMP_SGT, GtExpr);
            PRED_CASE(P::ICMP_ULE, UleExpr);
            PRED_CASE(P::ICMP_ULT, UltExpr);
            PRED_CASE(P::ICMP_UGE, UgeExpr);
            PRED_CASE(P::ICMP_UGT, UgtExpr);
        default:
            assert(false && "unsupported icmp");
        }
        auto n = state->copy_self();
        n->set_reg_val(dst_reg, RegValue{val});
        n->inst_iter_++;
        nexts.push_back(n);
    }

    void visitAllocaInst(const llvm::AllocaInst &inst) {
        auto dst = get_name(inst);
        const llvm::Value *val = inst.getArraySize();
        int64_t size = get_int_val(val);
        assert(size > 0);

        auto type = inst.getAllocatedType();
        auto type_size = get_type_size(state->module_, type);
        assert(type_size > 0);

        auto buf_name = state->name_gen->gen("alloca" + dst);
        auto buf = std::make_shared<Buffer>(buf_name, type_size);
        state->tmp_data.insert({buf_name, std::dynamic_pointer_cast<Pointee>(buf)});

        SymPointer ptr;
        ptr.pointer_base = buf_name;
        ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst, RegValue{ptr});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitLoadInst(const llvm::LoadInst &inst) {
        std::string dst_reg = get_name(inst);
        auto ptr_reg = get_name(*inst.getOperand(0));
        auto ptr = state->get_reg_val(*inst.getOperand(0)).get_ptr();
        auto base = ptr.pointer_base;

        auto ptr_type = inst.getPointerOperand()->getType();
        auto data_type = ptr_type->getPointerElementType();
        uint64_t size = get_type_size(state->module_, data_type);

        // find the buffer
        std::shared_ptr<Pointee> pointee = state->find_pointee(base);
        if (pointee == nullptr) {
            throw ExecError{"could not find buffer to load from"};
        }
        auto val = pointee->load(ptr.offset, size);
        state->set_reg_val(dst_reg, val);
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitStoreInst(const llvm::StoreInst &inst) {
        auto ptr_reg = get_name(*inst.getOperand(1));
        auto ptr = state->get_reg_val(*inst.getOperand(1)).get_ptr();
        auto base = ptr.pointer_base;
        auto val = state->get_reg_val(*inst.getOperand(0));
        // find the buffer
        std::shared_ptr<Pointee> pointee = state->find_pointee(base);
        if (pointee == nullptr) {
            throw ExecError{"could not find buffer to load from"};
        }
        pointee->store(ptr.offset, val);
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
        auto base_ptr = state->get_reg_val(*inst.getOperand(0));
        std::vector<Symbolic::ExprPtr> offsets_sym;
        std::vector<int> offsets_int;
        std::vector<Symbolic::ExprPtr> offsets;
        for (int i = 1; i < inst.getNumOperands(); i++) {
            // need to extend offsets to 64-bit integer
            auto v = inst.getOperand(i);
            Symbolic::ExprPtr off = nullptr;
            if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
                offsets_int.push_back(CI->getSExtValue());
                offsets_sym.push_back(nullptr);
                off = mk_expr_ptr(ConcreteBv, 64, CI->getSExtValue());
            } else {
                offsets_int.push_back(-1);
                off = state->get_reg_val(*inst.getOperand(i)).get_val();
                offsets_sym.push_back(off);
            }
            assert(off != nullptr);
            offsets.push_back(off);
        }
        auto type = inst.getOperand(0)->getType();
        Symbolic::ExprPtr off_val = mk_expr_ptr(ConcreteBv, 64, 0);
        for (int i = 0; i < offsets.size(); i++) {
            if (type->isPointerTy()) {
                auto size = get_type_size(state->module_, type->getPointerElementType());
                auto off = mk_expr_ptr(MulExpr, {offsets[i],
                            mk_expr_ptr(ConcreteBv, 64, size)});
                off_val = mk_expr_ptr(AddExpr, {off_val, off});
                type = type->getPointerElementType();
            } else if (type->isStructTy()) {
                auto dl = std::make_shared<llvm::DataLayout>(state->module_);
                auto sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
                assert(offsets_int[i] >= 0);
                auto off = sl->getElementOffset(offsets_int[i]);
                off_val = mk_expr_ptr(AddExpr, {off_val, mk_expr_ptr(ConcreteBv, 64, off)});
                type = type->getStructElementType(offsets_int[i]);
            } else if (type->isArrayTy()) {
                auto size = get_type_size(state->module_, type->getArrayElementType());
                auto off = mk_expr_ptr(MulExpr, {offsets[i],
                            mk_expr_ptr(ConcreteBv, 64, size)});
                off_val = mk_expr_ptr(AddExpr, {off_val, off});
                type = type->getArrayElementType();
            }
            // now check if the pointer falls
        }
        std::string dst_reg = get_name(inst);
        SymPointer ptr = base_ptr.get_ptr();
        // std::cout << ptr.offset.get() << std::endl;
        ptr.offset = mk_expr_ptr(AddExpr, {ptr.offset, off_val});
        ptr.offset = ptr.offset->simplify();
        if (!ptr.offset->is_symbolic()) {
            // try find the actual object
            auto iter = state->state_.struct_meta.find(ptr.pointer_base);
            if (iter != state->state_.struct_meta.end()) {
                auto off_set_val = std::dynamic_pointer_cast<Symbolic::ConcreteBv>(ptr.offset)->get_val();
                auto &struct_meta = iter->second;
                auto ref_i = struct_meta.out_refs.find(off_set_val);
                if (ref_i != struct_meta.out_refs.end()) {
                    auto &ref = ref_i->second;
                    ptr.pointer_base = ref.ref_name;
                    ptr.offset = mk_concrete_bv(64, 0);
                }
            }
        }

        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitPHINode(const llvm::PHINode &inst) {
        auto dst = get_name(inst);
        bool found = false;
        for (auto i = 0; i < inst.getNumIncomingValues(); i++) {
            auto bb = inst.getIncomingBlock(i);
            if (get_name(*state->prev_bb_) == get_name(*bb)) {
                auto val = state->get_reg_val(*inst.getIncomingValue(i));
                state->set_reg_val(dst, val);
                state->inst_iter_++;
                nexts.push_back(state);
                found = true;
                break;
            }
        }
        if (!found) {
            assert(false && "from unknown basic block");
        }
    }

    void visitTruncInst(const llvm::TruncInst &inst) {
        std::string dst_reg = get_name(inst);
        auto val = state->get_reg_val(*inst.getOperand(0));
        assert(val.is_val());
        auto dst_type = inst.getDestTy();
        int target_size = llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
        state->set_reg_val(dst_reg, RegValue{mk_expr_ptr(ExtractExpr, val.get_val(), 0, target_size)});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitZExtInst(const llvm::ZExtInst &inst) {
        std::string dst_reg = get_name(inst);
        auto val = state->get_reg_val(*inst.getOperand(0));
        auto dst_type = inst.getDestTy();
        assert(dst_type->isIntegerTy());
        int target_size = llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
        auto new_val = mk_expr_ptr(UExtExpr, val.get_val(), target_size);
        state->set_reg_val(dst_reg, RegValue{new_val});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitSExtInst(const llvm::SExtInst &inst) {
        std::string dst_reg = get_name(inst);
        auto val = state->get_reg_val(*inst.getOperand(0));
        auto dst_type = inst.getDestTy();
        assert(dst_type->isIntegerTy());
        int target_size = llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
        auto new_val = mk_expr_ptr(SExtExpr, val.get_val(), target_size);
        state->set_reg_val(dst_reg, RegValue{new_val});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitPtrToIntInst(const llvm::PtrToIntInst &inst) {
        std::string dst_reg = get_name(inst);
        auto ptr = state->get_reg_val(*inst.getOperand(0)).get_ptr();

        Symbolic::ExprPtr base = nullptr;
        if (state->pointer_base.find(ptr.pointer_base) != state->pointer_base.end()) {
            base = state->pointer_base.find(ptr.pointer_base)->second;
        } else {
            auto vn = state->name_gen->gen(ptr.pointer_base + "!base");
            auto bv64 = std::make_shared<Symbolic::BitVecType>(64);
            base = mk_expr_ptr(SymbolicVar, bv64, vn);
            state->pointer_base[ptr.pointer_base] = base;
        }

        auto val = mk_expr_ptr(AddExpr, {base, ptr.offset});

        state->set_reg_val(dst_reg, RegValue{val});
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitIntToPtrInst(const llvm::IntToPtrInst &inst) {
        inst.print(llvm::errs());
        llvm::errs() << "\n";
        assert(false && "not implemented");
    }

    void visitBitCastInst(const llvm::BitCastInst &inst) {
        auto src_type = inst.getSrcTy();
        auto dst_type = inst.getDestTy();
        assert (src_type->isPointerTy() && dst_type->isPointerTy());
        src_type = src_type->getPointerElementType();
        dst_type = dst_type->getPointerElementType();

        std::string dst_reg = get_name(inst);
        auto val = state->get_reg_val(*inst.getOperand(0));
        state->set_reg_val(dst_reg, val);
        state->inst_iter_++;
        nexts.push_back(state);
    }

    void visitBinaryOperator(const llvm::BinaryOperator &inst) {
        std::string dst_reg = get_name(inst);
        auto op1 = state->get_reg_val(*inst.getOperand(0));
        auto op2 = state->get_reg_val(*inst.getOperand(1));
        std::string opstring = inst.getOpcodeName();
        using namespace Symbolic;
        using BinOpF = std::function<ExprPtr(ExprPtr, ExprPtr)>;
        bool is_bv = true;
        if (op1.get_val()->type->get_bv_width() == 1) {
            is_bv = false;
        }
        // std::cout << "logical??: " << is_bv << std::endl;
#define BINOP(E) [](ExprPtr a, ExprPtr b) -> ExprPtr {return mk_expr_ptr(E, {a, b});}
        static std::unordered_map<std::string, BinOpF> binop_map = {
            { "add",  BINOP(AddExpr) },
            { "sub",  BINOP(SubExpr) },
            { "mul",  BINOP(MulExpr) },
            { "sdiv", BINOP(DivExpr) },
            { "srem", BINOP(ModExpr) },
            { "urem", BINOP(UModExpr) },
            { "and",  BINOP(AndExpr) },
            { "or",   BINOP(OrExpr) },
            { "xor",  BINOP(XorExpr) },
            { "shl",  BINOP(LshExpr) },
            { "lshr", BINOP(LRshExpr) },
            { "ashr", BINOP(ARshExpr) },
        };
#undef BINOP
        if (binop_map.find(opstring) != binop_map.end()) {
            auto binop_func = binop_map.find(opstring)->second;
            auto result = binop_func(op1.get_val(), op2.get_val());
            state->set_reg_val(dst_reg, RegValue{result});
            state->inst_iter_++;
            nexts.push_back(state);
            if (opstring == "xor") {
                Z3Context ctx;
                auto a1 = gen_z3_expr(ctx, op1.get_val());
                auto a2 = gen_z3_expr(ctx, op2.get_val());
                // std::cout << "xor oprands: " << a1.get_expr().simplify() << ", " << a2.get_expr().simplify() << std::endl;
                // std::cout << is_bv << std::endl;
                // std::cout << "result ptr: " << result << std::endl;
                // std::cout << gen_z3_expr(ctx, result).get_expr().simplify() << std::endl;
            }
        } else {
            throw ExecError{"Unknown Binop"};
        }
    }

    void visitSelectInst(const llvm::SelectInst &inst) {
        auto dst = get_name(inst);
        auto cond = state->get_reg_val(*inst.getCondition());
        auto t_val = state->get_reg_val(*inst.getTrueValue());
        auto f_val = state->get_reg_val(*inst.getFalseValue());

        state->inst_iter_++;
        auto t_ctx = state->copy_self();
        t_ctx->set_reg_val(dst, t_val);
        t_ctx->add_pre_cond(cond.get_val());
        nexts.push_back(t_ctx);

        auto f_ctx = state->copy_self();
        f_ctx->set_reg_val(dst, f_val);
        f_ctx->add_pre_cond(mk_expr_ptr(LNotExpr, cond.get_val()));
        nexts.push_back(f_ctx);
    }


    void visitUnreachableInst(const llvm::UnreachableInst &inst) {
        throw ExecError{"Unreachable"};
    }

    void visitCallInst(const llvm::CallInst &inst) {
        int num_args = inst.getNumArgOperands();
        std::vector<RegValue> params;
        llvm::Function *fp = inst.getCalledFunction();
        std::string func_name;
        if (fp == NULL) {
            const llvm::Value *v = inst.getCalledOperand()->stripPointerCasts();
            llvm::StringRef fname = v->getName();
            func_name = fname.str();
        } else {
            func_name = fp->getName().str();
        }

        std::string dst_reg = "";
        if (inst.getType()->getTypeID() != llvm::Type::TypeID::VoidTyID) {
            dst_reg = get_name(inst);
        }
        if (func_name[0] == '@') {
            func_name = func_name.substr(1);
        }
        std::string raw_name = func_name;
        std::string demangled = demangle_cpp_name(func_name);
        if (demangled != "") {
            func_name = demangled;
        }
        if (func_name == "printf" || func_name == "click_chatter") {
            state->inst_iter_++;
            nexts.push_back(state);
            return;
        }

        if (func_name == "llvm.dbg.declare") {
            state->inst_iter_++;
            nexts.push_back(state);
            return;
        }
        if (func_name == "llvm.dbg.value") {
            state->inst_iter_++;
            nexts.push_back(state);
            return;
        }

        if (is_prefix(func_name, "llvm.lifetime.")) {
            state->inst_iter_++;
            nexts.push_back(state);
            return;
        }

        if (func_name == "__assert_fail") {
            state->is_crash_path = true;
            finished.push_back(state);
            return;
        }

        for (int i = 0; i < num_args; i++) {
            auto val = state->get_reg_val(*inst.getArgOperand(i));
            params.push_back(val);
        }
        // Check if there are matching "abstract functions"
        auto args = split_template(func_name);

        if (fp == nullptr && inst.isInlineAsm()) {
            if (conf.log_level == SymExecConf::LOG_VERBOSE) {
                std::cout << "null fp: " << inst.isInlineAsm() << std::endl;
            }
            auto val = inst.getCalledOperand();
            auto asm_inst = llvm::dyn_cast<llvm::InlineAsm>(val);
            assert(asm_inst != nullptr);
            if (conf.log_level == SymExecConf::LOG_VERBOSE) {
                std::cout << "Asm Inst: " << asm_inst << " " 
                          << asm_inst->getAsmString() << std::endl;
            }
            func_name = asm_inst->getAsmString();
        }
        for (auto &af : state->abs_funcs) {
            if (af->match(func_name)) {
                auto ns = af->call(func_name, params, state, dst_reg);
                for (auto &n : ns) {
                    nexts.push_back(n);
                }
                return;
            }
        }

        // if control reached here, we have to "inline" the function call
        if (fp == nullptr) {
            std::cerr << "Null inline function: " << func_name << std::endl;
        }
        assert(fp != nullptr);
        if (conf.log_level == SymExecConf::LOG_VERBOSE) {
            std::cout << "Calling function: " << func_name << std::endl;
        }
        state->push_ctx(fp, dst_reg);
        for (int i = 0; i < params.size(); i++) {
            state->set_reg_val("%" + std::to_string(i), params[i]);
        }
        nexts.push_back(state);
    }
};


ClickSymExecutor::ResultT
ClickSymExecutor::run(std::shared_ptr<ExecContext> init) {
    assert(task_queue_.empty());
    task_queue_.push_back(init);
    finished_.clear();
    while (!task_queue_.empty()) {
        auto task = task_queue_.back();
        task_queue_.pop_back();
        auto &inst = *task->inst_iter_;
        if (conf_.log_level == SymExecConf::LOG_VERBOSE) {
        // if (conf_.log_level == SymExecConf::LOG_NORMAL) {
            inst.print(llvm::errs());
            llvm::errs() << "\n";
        }
        auto nexts = this->single_step(task);
        for (auto n : nexts) {
            task_queue_.push_back(n);
        }
    }
    return finished_;
}


ClickSymExecutor::ResultT
ClickSymExecutor::single_step(std::shared_ptr<ExecContext> ctx) {
    llvm::Instruction *inst_ptr = nullptr;
// #define PRINT_EXCEPTION
#ifdef PRINT_EXCEPTION
    try {
#endif

    if (ctx->have_new_cond_) {
        Symbolic::Z3Context solver_ctx;
        auto z3_expr = gen_z3_expr(solver_ctx, ctx->get_pre_cond()).get_bool();
        z3::solver sol(solver_ctx.ctx);
        sol.add(z3_expr);
        if (sol.check() == z3::unsat) {
            return {};
        }
        ctx->have_new_cond_ = false;
    }
    auto &inst = *(ctx->inst_iter_);
    inst_ptr = &inst;
    std::vector<std::shared_ptr<ExecContext>> nexts, finished;
    SymExecVisitor visitor(ctx, nexts, finished, conf_);
    visitor.visit(inst);

    for (auto s : finished) {
        finished_.push_back(s);
    }
    return nexts;

#ifdef PRINT_EXCEPTION
    } catch (z3::exception &e) {
        std::cerr << e << std::endl;
    } catch (ExecError &e) {
        std::cerr << "exception: " << e.msg << std::endl;
        if (llvm::DILocation *Loc = inst_ptr->getDebugLoc()) { // Here I is an LLVM instruction
            unsigned ln = Loc->getLine();
            auto fn = Loc->getFilename().str();
            auto dir = Loc->getDirectory().str();
            bool ImplicitCode = Loc->isImplicitCode();
            auto name = dir + "/" + fn;
            std::cerr << " @ " << name << " : " << ln << std::endl;
        }
        throw e;
    }
#endif
    assert(false && "unreachable");
}


ElementExecutor::ElementExecutor(const std::string &ll_file, const std::string &element_name,
                                 const SymExecConf &conf): conf_(conf) {
    module_ = llvm::parseIRFile(ll_file, err_, ctx_);

    if (module_ == nullptr) {
        throw "failed to parse IR file";
    }

    element_t_ = nullptr;
    std::string element_class_name = "class." + element_name;
    auto structs = module_->getIdentifiedStructTypes();
    for (auto &s : structs) {
        if (s->getName() == element_class_name) {
            element_t_ = s;
            break;
        }
    }

    if (element_t_ == nullptr) {
    } else {
        if (conf_.log_level == SymExecConf::LOG_VERBOSE) {
            printf("Element State: %p %s\n", element_t_, get_type_name(element_t_).c_str());
        }
    }

    auto entries = find_element_entry(module_.get(), element_name);

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
        entry_type_ = EntryType::SIMPLE_ACTION;
    } else if (push_entry != std::nullopt) {
        entry = push_entry.value();
        entry_type_ = EntryType::PUSH;
    } else if (pull_entry != std::nullopt) {
        entry = pull_entry.value();
        entry_type_ = EntryType::PULL;
    }
    entry_func_name_ = entry;
    entry_func_ = module_->getFunction(entry);

    if (element_t_ == nullptr) {
        // try to use the first argument of element entry as element type
        auto func_type = entry_func_->getFunctionType();
        assert(func_type->params().size() > 0);
        element_t_ = static_cast<llvm::StructType *>(func_type->params()[0]->getPointerElementType());
    }
}

std::shared_ptr<ExecContext> ElementExecutor::create_initial_state() {
    auto init = std::make_shared<ExecContext>();
    init->curr_bb_ = &entry_func_->getEntryBlock();
    init->inst_iter_ = init->curr_bb_->begin();
    init->module_ = module_.get();

    // Create state for the element
    auto name_gen_ptr = std::make_shared<NameFactory>();
    auto element_state = parse_element_state(module_.get(), element_t_, *name_gen_ptr);

    SymPointer this_ptr;
    this_ptr.pointer_base = "this_element";
    this_ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
    SymPointer pkt_ptr;
    pkt_ptr.pointer_base = "input_pkt";
    pkt_ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
    init->set_reg_val("%0", RegValue{this_ptr});
    auto bv_32 = std::make_shared<Symbolic::BitVecType>(32);

    Symbolic::ExprPtr input_port_val = nullptr;
    switch (entry_type_) {
        case EntryType::SIMPLE_ACTION:
            init->set_reg_val("%1", RegValue{pkt_ptr});
            input_port_val = mk_concrete_bv(0, 32);
            break;
        case EntryType::PUSH:
            input_port_val = mk_expr_ptr(SymbolicVar, bv_32, "input_port");
            init->set_reg_val("%1", RegValue{input_port_val});
            init->set_reg_val("%2", RegValue{pkt_ptr});
            break;
        case EntryType::PULL:
            throw "PULL only element not supported";
            break;
    }

    this->input_port_val_ = input_port_val;

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
    init->call_stack_.push(entry_func_name_);

    auto pkt_struct = std::make_shared<Packet>("input_pkt", init);
    init->tmp_data.insert({"input_pkt", pkt_struct});

    auto pkt_buf = init->tmp_data[pkt_struct->content_buf_name];
    // pkt_buf->store(mk_concrete_bv(64, 14), RegValue{mk_concrete_bv(8, 0x45)});

    auto size_lb = mk_expr_ptr(LtExpr, {mk_concrete_bv(32, 34), pkt_struct->len});
    auto size_ub = mk_expr_ptr(LeExpr, {pkt_struct->len, mk_concrete_bv(32, 1500)});

    init_pkt_content_ = std::dynamic_pointer_cast<Buffer>(pkt_buf->copy_self());

    init->add_pre_cond(size_lb);
    init->add_pre_cond(size_ub);

    return init;
}

void ElementExecutor::run() {
    ClickSymExecutor executor(module_.get());
    executor.conf_ = conf_;
    result_paths_ = executor.run(init_state_);
}
