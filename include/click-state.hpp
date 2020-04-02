#pragma once

#include <map>
#include "symbolic-expr.hpp"
#include "llvm-incl.hpp"
#include "llvm-helpers.hpp"
#include "utils.hpp"

class AbstractDataType;
class Pointee;

struct StructLayout {
    enum class EntryType {
        ABSTRACT_STRUCT,
        POINTER,
        STRUCT,
        MEM_REGION,
    };
    struct RefEntry {
        EntryType type;
        std::string ref_name;
        uint64_t size; // in bytes
    };

    std::map<uint64_t, RefEntry> out_refs;

    // write will destroy an existing entry (both abstract data or pointer)
    void update_ref(uint64_t offset, const RefEntry &e);
    void pre_write(uint64_t offset, uint64_t size);
};

class ElementState {
public:
    int num_in;
    int num_out;
    std::unordered_map<std::string, StructLayout> struct_meta;
    std::unordered_map<std::string, std::shared_ptr<Pointee>> abstract_data;
};

ElementState parse_element_state(llvm::Module *module, llvm::Type *element_t, NameFactory &name_gen);

std::unordered_set<std::string> print_element_state(llvm::Module *module, llvm::Type *element_t);

