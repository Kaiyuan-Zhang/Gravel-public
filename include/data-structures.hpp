#pragma once

#include <unordered_map>
#include <unordered_set>
#include "symbolic-expr.hpp"
#include "click-exec.hpp"


struct PointeeAccessError {
    std::string msg;
};

enum class PointeeType {
    Vector,
    HashMap,
    Buffer,
    Packet, 
    Invalid,
};

std::ostream &operator<<(std::ostream &os, const PointeeType &t);

class Pointee {
public:
    virtual bool is_abstract() const { return false; }
    virtual bool is_plain_mem() const { return false; }
    virtual RegValue handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args, 
            std::shared_ptr<ExecContext> ctx) = 0;
    virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const = 0;
    virtual void store(Symbolic::ExprPtr off, RegValue val) = 0;

    virtual std::shared_ptr<Pointee> copy_self() const = 0;

    virtual void print(std::ostream &os) const = 0;
    virtual PointeeType type() const {
        return PointeeType::Invalid;
    }
    
    std::string name;
};

class AbstractFunc {
public:
    virtual bool match(const std::string &fn) const = 0;
    virtual std::vector<std::shared_ptr<ExecContext>> 
        call(const std::string &func_name, 
             const std::vector<RegValue> &params,
             std::shared_ptr<ExecContext> state,
             const std::string &dst_reg) = 0;
};



class Inaccessible : public Pointee {
public:
    Inaccessible(const std::string &name);

    virtual RegValue handle_req(const std::string &method_name,
            const std::vector<RegValue> &args,
            std::shared_ptr<ExecContext> ctx) override {
        throw ExecError {"Inaccessible"};
    }
    virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override {
        throw ExecError {"Inaccessible"};
    }
    virtual void store(Symbolic::ExprPtr off, RegValue val) override {
        throw ExecError {"Inaccessible"};
    }

    virtual std::shared_ptr<Pointee> copy_self() const override {
        auto ptr = std::make_shared<Inaccessible>(*this);
        return std::dynamic_pointer_cast<Pointee>(ptr);
    }

    virtual void print(std::ostream &os) const override;
};

class Buffer : public Pointee {
public:
    Buffer(const std::string &name);
    Buffer(const std::string &name, int size);
    virtual bool is_plain_mem() const override { return true; }

    virtual RegValue handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args, 
            std::shared_ptr<ExecContext> ctx) override {
        throw ExecError {"Buffer could not handle request"};
    }
    virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override;
    virtual void store(Symbolic::ExprPtr off, RegValue val) override;

    RegValue load_be(Symbolic::ExprPtr off, uint64_t size) const;
    void store_be(Symbolic::ExprPtr off, RegValue val);

    virtual std::shared_ptr<Pointee> copy_self() const override {
        auto result = std::make_shared<Buffer>(*this);
        return std::dynamic_pointer_cast<Pointee>(result);
    }
    virtual void print(std::ostream &os) const override;
    Symbolic::ExprPtr equals(Buffer &buf) const;

    virtual PointeeType type() const override {
        return PointeeType::Buffer;
    }

    std::shared_ptr<Symbolic::Lambda> content_f;
    bool sized;
    int size;

    bool have_write_back = false;
    std::function<void(std::shared_ptr<Buffer>, std::shared_ptr<ExecContext>)> write_back_fn;
};


class AbstractType : public Pointee {
public:
    virtual bool is_abstract() const override { return true; }
    virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override {
        throw ExecError{ "Could not perform load / store on abstract data structure" };
    }
    virtual void store(Symbolic::ExprPtr off, RegValue val) override {
        throw ExecError{ "Could not perform load / store on abstract data structure" };
    }
};

class AbstractVector : public AbstractType {
public:
    AbstractVector(const std::string &name, std::shared_ptr<Symbolic::Type> ele_type);
    AbstractVector(const std::string &name, std::shared_ptr<Symbolic::Type> ele_type, 
                   Symbolic::ExprPtr n_elements);
    AbstractVector(const std::string &name, std::shared_ptr<Symbolic::Type> ele_type, 
                   uint64_t n_elements);
    virtual RegValue handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args,
            std::shared_ptr<ExecContext> ctx) override;

    virtual std::shared_ptr<Pointee> copy_self() const override {
        auto result = std::make_shared<AbstractVector>(*this);
        return std::dynamic_pointer_cast<Pointee>(result);
    }
    
    virtual void print(std::ostream &os) const override;

    std::shared_ptr<Symbolic::Expr> get(Symbolic::ExprPtr idx) const;
    void set(Symbolic::ExprPtr idx, Symbolic::ExprPtr val);
    void push_back(Symbolic::ExprPtr val);
    
    bool bound_check(Symbolic::ExprPtr idx) const;
    virtual PointeeType type() const override {
        return PointeeType::Vector;
    }
    std::shared_ptr<Symbolic::Lambda> arr_f;
    std::shared_ptr<Symbolic::Type> val_type;
    Symbolic::ExprPtr n_elements;
};

class AbstractMap : public AbstractType {
public:
    AbstractMap(const std::string &name,
        const Symbolic::PtrList<Symbolic::Type> &key_types,
        const Symbolic::PtrList<Symbolic::Type> &val_types);
    virtual RegValue handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args,
            std::shared_ptr<ExecContext> ctx) override;

    virtual std::shared_ptr<Pointee> copy_self() const override {
        auto result = std::make_shared<AbstractMap>(*this);
        return std::dynamic_pointer_cast<Pointee>(result);
    }

    std::vector<std::shared_ptr<Symbolic::Type>> key_types;
    std::vector<std::shared_ptr<Symbolic::Type>> val_types;
    std::shared_ptr<Symbolic::Lambda> contains_f;
    std::vector<std::shared_ptr<Symbolic::Lambda>> val_f;

    Symbolic::ExprPtr contains(const Symbolic::OpApplyNode::ArgList &args) const;
    std::vector<Symbolic::ExprPtr> get_vals(const Symbolic::OpApplyNode::ArgList &args) const;
    void set_vals(const std::vector<Symbolic::ExprPtr> &args, const std::vector<Symbolic::ExprPtr> &vals);
    void delete_val(const Symbolic::OpApplyNode::ArgList &args);
    
    virtual void print(std::ostream &os) const override;
    virtual PointeeType type() const override {
        return PointeeType::HashMap;
    }
};

class Packet : public AbstractType {
public:
    Packet() {}
    Packet(const std::string &name, std::shared_ptr<ExecContext> state);

    std::shared_ptr<Packet> clone_pkt(const std::string& new_name, std::shared_ptr<ExecContext> state);

    virtual RegValue handle_req(const std::string &method_name, 
            const std::vector<RegValue> &args, 
            std::shared_ptr<ExecContext> ctx);

    virtual std::shared_ptr<Pointee> copy_self() const {
        auto ptr = std::make_shared<Packet>(*this);
        return std::dynamic_pointer_cast<Pointee>(ptr);
    }

    virtual void print(std::ostream &os) const;
    virtual PointeeType type() const {
        return PointeeType::Packet;
    }

    std::string anno_buf_name;
    Symbolic::ExprPtr len;
    std::string content_buf_name;
};
