#pragma once

#include "llvm-incl.hpp"
#include <string>

std::vector<std::string>
find_element_entry(llvm::Module *module,
                   const std::string &element_name);

std::string get_type_name(llvm::Type *t);
std::string llvm_type_to_str(llvm::Type *t);
uint64_t get_type_size(llvm::Module *module, llvm::Type *type);
std::string get_name(const llvm::Value &value);
int64_t get_int_val(const llvm::Value *value);

std::string demangle_cpp_name(const std::string &cpp_name);

std::vector<std::string> split_template(const std::string &cpp_id);
