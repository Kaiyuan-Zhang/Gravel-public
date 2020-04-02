#pragma once

#include "llvm-incl.hpp"
#include "click-state.hpp"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <variant>
#include "utils.hpp"


struct ExecError {
    std::string msg;

    std::string exception_file;
    int exception_line;

    std::string file_name;
    int line_number;

    ExecError();
    ExecError(const std::string &msg);
    ExecError(const llvm::Instruction &inst, const std::string &msg);
};

struct SymPointer {
    std::string pointer_base;
    llvm::Type *llvm_type = nullptr;

    Symbolic::ExprPtr offset;
};

struct RegValue {
    std::variant<Symbolic::ExprPtr, SymPointer> content;

    bool is_val() const;
    bool is_ptr() const;

    Symbolic::ExprPtr &get_val();
    SymPointer &get_ptr();

    const SymPointer &get_ptr() const;
    const Symbolic::ExprPtr &get_val() const;
};

class Pointee;
class AbstractFunc;
class Packet;

struct FuncCallCtx {
    std::unordered_map<std::string, RegValue> reg_map;
    std::string ret_reg;
    llvm::BasicBlock::iterator inst_iter;
};

struct CondPkt {
    Symbolic::ExprPtr cond;
    std::shared_ptr<Packet> pkt;
};

struct ExecContext {
    std::stack<FuncCallCtx> old_ctx_;
    std::stack<std::string> call_stack_;
    std::unordered_map<std::string, RegValue> reg_val_;
    std::vector<Symbolic::ExprPtr> pre_cond_list_;
    std::shared_ptr<NameFactory> name_gen;
    std::unordered_map<std::string, std::shared_ptr<Pointee>> tmp_data;
    std::vector<std::shared_ptr<AbstractFunc>> abs_funcs;
    std::unordered_map<int, std::vector<CondPkt>> out_pkts_;
    ElementState state_;
    llvm::Module *module_;

    bool have_new_cond_ = false;

    bool is_crash_path = false;

    llvm::BasicBlock *prev_bb_;
    llvm::BasicBlock *curr_bb_;
    llvm::BasicBlock::iterator inst_iter_;

    std::stack<llvm::BasicBlock::iterator> ret_addrs_;
    std::unordered_map<std::string, Symbolic::ExprPtr> pointer_base;

    std::shared_ptr<ExecContext> copy_self() const;

    void push_ctx(llvm::Function *fp, const std::string &ret_reg);
    void pop_ctx(const std::string &ret_reg);
    RegValue get_reg_val(const llvm::Value &value) const;
    RegValue get_reg_val(const std::string &reg_name) const;
    void set_reg_val(const std::string &reg_name, const RegValue &val);
    void jump_to_bb(llvm::BasicBlock *bb);
    void call_func(llvm::Function *func);
    void add_pre_cond(Symbolic::ExprPtr c);
    Symbolic::ExprPtr get_pre_cond() const;
    std::shared_ptr<Pointee> find_pointee(const std::string &name) const;
};


struct SymExecConf {
    enum LogLvl {
        LOG_NORMAL = 0,
        LOG_VERBOSE,
    };
    LogLvl log_level;
};


class ClickSymExecutor {
public:
    using ResultT = std::vector<std::shared_ptr<ExecContext>>;
    ClickSymExecutor(llvm::Module *m): module_(m) {}

    ResultT run(std::shared_ptr<ExecContext> init);

    SymExecConf conf_;
    
protected:
    llvm::Module *module_;
    std::vector<std::shared_ptr<ExecContext>> task_queue_;
    std::vector<std::shared_ptr<ExecContext>> finished_;

    ResultT single_step(std::shared_ptr<ExecContext> ctx);
};

extern SymExecConf default_conf;

class Buffer;

class ElementExecutor {
public:
    ElementExecutor(const std::string &ll_file, const std::string &element_name,
                    const SymExecConf &conf=default_conf);

    std::shared_ptr<ExecContext> create_initial_state();

    void initilize() {
        init_state_ = create_initial_state();
    }

    void run();

    enum class EntryType {
        SIMPLE_ACTION,
        PUSH,
        PULL,
    };

    SymExecConf conf_;
    llvm::LLVMContext ctx_;
    llvm::SMDiagnostic err_;
    std::unique_ptr<llvm::Module> module_;
    std::string entry_func_name_;
    llvm::Function *entry_func_;
    llvm::StructType *element_t_;
    EntryType entry_type_;
    std::shared_ptr<ExecContext> init_state_;
    Symbolic::ExprPtr input_port_val_;
    std::shared_ptr<Buffer> init_pkt_content_;

    ClickSymExecutor::ResultT result_paths_;
};
