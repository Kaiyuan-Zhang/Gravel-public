#include "data-structures.hpp"
#include <algorithm>
#include <memory>
#include "z3-gen.hpp"

using namespace Symbolic; 

std::ostream &operator<<(std::ostream &os, const PointeeType &t) {
    switch (t) {
        case PointeeType::Vector:
            os << "Vector";
            break;
        case PointeeType::HashMap:
            os << "HashMap";
            break;
        case PointeeType::Buffer:
            os << "Buffer";
            break;
        case PointeeType::Packet:
            os << "Packet";
            break;
        case PointeeType::Invalid:
            os << "Invalid";
            break;
    }
    return os;
}

Inaccessible::Inaccessible(const std::string &n) {
    name = n;
}

void Inaccessible::print(std::ostream &os) const {
    os << "(Inaccessible " << name << ")";
}

Buffer::Buffer(const std::string &name) {
    auto bv_64 = std::make_shared<BitVecType>(64);
    auto bv_8 = std::make_shared<BitVecType>(8);
    std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
    auto ft = std::make_shared<UFType>(kt_l, bv_8);
    auto uf = std::make_shared<SymbolicVar>(ft, name);
    Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
        return mk_expr_ptr(FuncApply, uf, args);
    };
    content_f = std::make_shared<Lambda>(ft, func);
    sized = false;
    size = 0;
    this->name = name;
}

Buffer::Buffer(const std::string &name, int sz) {
    auto bv_64 = std::make_shared<BitVecType>(64);
    auto bv_8 = std::make_shared<BitVecType>(8);
    std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
    auto ft = std::make_shared<UFType>(kt_l, bv_8);
    auto uf = std::make_shared<SymbolicVar>(ft, name);
    Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
        return mk_expr_ptr(FuncApply, uf, args);
    };
    content_f = std::make_shared<Lambda>(ft, func);
    sized = true;
    size = sz;
    this->name = name;
}

RegValue Buffer::load_be(ExprPtr off, uint64_t size) const {
    int num_bytes = size;
    std::vector<ExprPtr> bytes;
    ExprPtr ptr = off;
    for (int i = 0; i < num_bytes; i++) {
        auto b = mk_expr_ptr(FuncApply, content_f, {ptr});
        ptr = mk_expr_ptr(AddExpr, {ptr, mk_expr_ptr(ConcreteBv, 64, 1)});
        bytes.push_back(b);
    }
    return RegValue {mk_expr_ptr(ConcatExpr, bytes)};
}

void Buffer::store_be(ExprPtr off, RegValue val) {
    assert(val.is_val());
    auto bv = val.get_val();
    auto num_bytes = bv->type->get_bv_width() / 8;
    assert(bv->type->get_bv_width() % 8 == 0);
    std::vector<ExprPtr> bytes;
    for (int i = num_bytes - 1; i >= 0; i--) {
        auto b = mk_expr_ptr(ExtractExpr, bv, i*8, (i+1) * 8);
        bytes.push_back(b);
    }
    auto old_f = content_f;
    Lambda::FuncT func = [off, old_f, num_bytes, bytes](const OpApplyNode::ArgList &args) -> ExprPtr {
        auto result = old_f->func(args);
        for (int i = 0; i < num_bytes; i++) {
            auto off_i = mk_expr_ptr(AddExpr, {off, mk_expr_ptr(ConcreteBv, 64, i)});
            auto eq = mk_expr_ptr(EqExpr, {args[0], off_i});
            result = mk_expr_ptr(IteExpr, eq, bytes[i], result);
        }
        return result;
    };
    content_f = std::make_shared<Lambda>(content_f->type, func);
}

RegValue Buffer::load(ExprPtr off, uint64_t size) const {
    int num_bytes = size;
    std::vector<ExprPtr> bytes;
    ExprPtr ptr = off;
    for (int i = 0; i < num_bytes; i++) {
        auto b = mk_expr_ptr(FuncApply, content_f, {ptr});
        ptr = mk_expr_ptr(AddExpr, {ptr, mk_expr_ptr(ConcreteBv, 64, 1)});
        bytes.push_back(b);
    }
    std::reverse(bytes.begin(), bytes.end());
    return RegValue {mk_expr_ptr(ConcatExpr, bytes)};
}

void Buffer::store(ExprPtr off, RegValue val) {
    assert(val.is_val());
    auto bv = val.get_val();
    auto num_bytes = bv->type->get_bv_width() / 8;
    assert(bv->type->get_bv_width() % 8 == 0);
    std::vector<ExprPtr> bytes;
    for (int i = 0; i < num_bytes; i++) {
        auto b = mk_expr_ptr(ExtractExpr, bv, i*8, (i+1) * 8);
        bytes.push_back(b);
    }
    auto old_f = content_f;
    Lambda::FuncT func = [off, old_f, num_bytes, bytes](const OpApplyNode::ArgList &args) -> ExprPtr {
        auto result = old_f->func(args);
        for (int i = 0; i < num_bytes; i++) {
            auto off_i = mk_expr_ptr(AddExpr, {off, mk_expr_ptr(ConcreteBv, 64, i)});
            auto eq = mk_expr_ptr(EqExpr, {args[0], off_i});
            result = mk_expr_ptr(IteExpr, eq, bytes[i], result);
        }
        return result;
    };
    content_f = std::make_shared<Lambda>(content_f->type, func);
}

void Buffer::print(std::ostream &os) const {
    os << "(Buffer " << name << ")";
}

Symbolic::ExprPtr Buffer::equals(Buffer &other) const {
    return nullptr;
}

AbstractVector::AbstractVector(const std::string &name, 
        std::shared_ptr<Symbolic::Type> ele_type): AbstractVector(name, ele_type, mk_expr_ptr(SymbolicVar, std::make_shared<BitVecType>(64), name + "!len")) {
}


AbstractVector::AbstractVector(const std::string &name, 
        std::shared_ptr<Symbolic::Type> ele_type, 
        uint64_t n): AbstractVector(name, ele_type, mk_expr_ptr(ConcreteBv, 64, n)) {
}

AbstractVector::AbstractVector(const std::string &name, 
        std::shared_ptr<Symbolic::Type> ele_type, 
        Symbolic::ExprPtr n) {
    auto bv_64 = std::make_shared<BitVecType>(64);
    std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
    auto e_type = std::dynamic_pointer_cast<ValType>(ele_type);
    auto ft = std::make_shared<UFType>(kt_l, e_type);
    auto uf = std::make_shared<SymbolicVar>(ft, name);
    Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
        return mk_expr_ptr(FuncApply, uf, args);
    };
    arr_f = std::make_shared<Lambda>(ft, func);
    n_elements = n;
    this->name = name;
    val_type = ele_type;
}

void AbstractVector::print(std::ostream &os) const {
    os << "(vector " << name << ")";
}

RegValue AbstractVector::handle_req(const std::string &method_name, 
                                    const std::vector<RegValue> &args,
                                    std::shared_ptr<ExecContext> ctx) {
    if (method_name == "get") {
    }
    return RegValue{nullptr};
}

bool AbstractVector::bound_check(Symbolic::ExprPtr idx) const {
    Z3Context ctx;
    auto lb = mk_expr_ptr(UleExpr, {mk_expr_ptr(ConcreteBv, 64, 0), idx});
    auto up = mk_expr_ptr(UltExpr, {idx, n_elements});
    auto bound = mk_expr_ptr(LAndExpr, {lb, up});
    auto expr = gen_z3_expr(ctx, bound).get_expr();
    z3::solver sol(ctx.ctx);
    sol.add(!expr);
    return sol.check() == z3::unsat;
}

Symbolic::ExprPtr AbstractVector::get(Symbolic::ExprPtr idx) const {
    using namespace Symbolic;
    assert(idx->type->is_bv_type() && idx->type->get_bv_width() == 64);
    return mk_expr_ptr(FuncApply, arr_f, {idx});
}

void AbstractVector::set(Symbolic::ExprPtr idx, Symbolic::ExprPtr val) {
    using namespace Symbolic;
    assert(idx->type->is_bv_type() && idx->type->get_bv_width() == 64);
    assert(val->type->equal_to(val_type));
    std::shared_ptr<Lambda> old_arr_f = arr_f;
    Lambda::FuncT func = [old_arr_f, val, idx](const OpApplyNode::ArgList &args) -> ExprPtr {
        auto old_val = mk_expr_ptr(FuncApply, old_arr_f, args);
        auto eq = mk_expr_ptr(EqExpr, {idx, args[0]});
        return mk_expr_ptr(IteExpr, eq, val, old_val);
    };
    arr_f = std::make_shared<Lambda>(arr_f->type, func);
}

void AbstractVector::push_back(Symbolic::ExprPtr val) {
    using namespace Symbolic;
    assert(val->type->equal_to(val_type));
    auto idx = n_elements;
    n_elements = mk_expr_ptr(AddExpr, {n_elements, mk_expr_ptr(ConcreteBv, 64, 1)});
    set(idx, val);
}

AbstractMap::AbstractMap(const std::string &name,
        const Symbolic::PtrList<Symbolic::Type> &key_types,
        const Symbolic::PtrList<Symbolic::Type> &val_types) {
    using namespace Symbolic;
    std::vector<std::shared_ptr<ValType>> key_type_list;
    for (auto t : key_types) {
        assert(t->is_val());
        key_type_list.push_back(std::dynamic_pointer_cast<ValType>(t));
    }
    auto bv_1 = std::dynamic_pointer_cast<ValType>(std::make_shared<BitVecType>(1));
    std::vector<std::shared_ptr<ValType>> val_type_list;
    for (auto t : val_types) {
        assert(t->is_val());
        val_type_list.push_back(std::dynamic_pointer_cast<ValType>(t));
    }

    auto ft = std::make_shared<UFType>(key_type_list, bv_1);
    auto uf = mk_expr_ptr(SymbolicVar, ft, name + "!contains");
    Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
        return mk_expr_ptr(FuncApply, uf, args);
    };
    contains_f = std::make_shared<Lambda>(ft, func);

    for (int i = 0; i < val_type_list.size(); i++) {
        auto ft = std::make_shared<UFType>(key_type_list, val_type_list[i]);
        auto uf = mk_expr_ptr(SymbolicVar, ft, name + "!val!" + std::to_string(i));
        Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
            return mk_expr_ptr(FuncApply, uf, args);
        };
        val_f.push_back(std::make_shared<Lambda>(ft, func));
    }
    this->name = name;
    this->key_types = key_types;
    this->val_types = val_types;
}

RegValue AbstractMap::handle_req(const std::string &method_name, 
                                 const std::vector<RegValue> &args,
                                 std::shared_ptr<ExecContext> ctx) {
    if (method_name == "get") {
    }
    return RegValue{nullptr};
}

Symbolic::ExprPtr AbstractMap::contains(const Symbolic::OpApplyNode::ArgList &args) const {
    return mk_expr_ptr(FuncApply, contains_f, args);
}

std::vector<Symbolic::ExprPtr> AbstractMap::get_vals(const Symbolic::OpApplyNode::ArgList &args) const {
    std::vector<Symbolic::ExprPtr> result;
    for (int i = 0; i < val_f.size(); i++) {
        result.push_back(mk_expr_ptr(FuncApply, val_f[i], args));
    }
    return result;
}

void AbstractMap::set_vals(const std::vector<Symbolic::ExprPtr> &args, 
                           const std::vector<Symbolic::ExprPtr> &vals) {
    using namespace Symbolic;
    std::shared_ptr<Lambda> old_f = contains_f;
    std::vector<ExprPtr> keys = args;
    Lambda::FuncT func = [old_f, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
        auto old_result = mk_expr_ptr(FuncApply, old_f, a);
        ExprPtr eq = nullptr;
        for (int i = 0; i < keys.size(); i++) {
            auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
            if (eq == nullptr) {
                eq = c;
            } else {
                eq = mk_expr_ptr(LAndExpr, {eq, c});
            }
        }
        return mk_expr_ptr(IteExpr, eq, mk_expr_ptr(ConcreteBv, 1, 1), old_result);
    };
    contains_f = std::make_shared<Lambda>(old_f->type, func);

    for (int i = 0; i < vals.size(); i++) {
        ExprPtr v = vals[i];
        old_f = val_f[i];
        func = [old_f, v, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
            auto old_result = mk_expr_ptr(FuncApply, old_f, a);
            ExprPtr eq = nullptr;
            for (int i = 0; i < keys.size(); i++) {
                auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
                if (eq == nullptr) {
                    eq = c;
                } else {
                    eq = mk_expr_ptr(LAndExpr, {eq, c});
                }
            }
            return mk_expr_ptr(IteExpr, eq, v, old_result);
        };
        val_f[i] = std::make_shared<Lambda>(old_f->type, func);
    }
}

void AbstractMap::delete_val(const Symbolic::OpApplyNode::ArgList &args) {
    using namespace Symbolic;
    std::shared_ptr<Lambda> old_f = contains_f;
    std::vector<ExprPtr> keys = args;
    Lambda::FuncT func = [old_f, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
        auto old_result = mk_expr_ptr(FuncApply, old_f, a);
        ExprPtr eq = nullptr;
        for (int i = 0; i < keys.size(); i++) {
            auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
            if (eq == nullptr) {
                eq = c;
            } else {
                eq = mk_expr_ptr(LAndExpr, {eq, c});
            }
        }
        return mk_expr_ptr(IteExpr, eq, mk_expr_ptr(ConcreteBv, 1, 0), old_result);
    };
    contains_f = std::make_shared<Lambda>(old_f->type, func);
}

void AbstractMap::print(std::ostream &os) const {
    os << "(abstract-map " << name << ")";
}

Packet::Packet(const std::string &n, std::shared_ptr<ExecContext> state) {
    name = n;
    content_buf_name = name + "!content";
    auto bv32 = std::make_shared<BitVecType>(32);
    len = mk_expr_ptr(SymbolicVar, bv32, name + "!len");

    auto pkt_content = std::make_shared<Buffer>(content_buf_name, 1600);
    state->tmp_data.insert({content_buf_name, pkt_content});

    anno_buf_name = name + "!anno";
    auto anno_buf = std::make_shared<Buffer>(anno_buf_name, 128);
    state->tmp_data.insert({anno_buf_name, anno_buf});
}

void Packet::print(std::ostream &os) const {
    os << "(Packet " << name << ")";
}

RegValue Packet::handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args, 
            std::shared_ptr<ExecContext> ctx) {
    assert(false && "unknown req");
}

