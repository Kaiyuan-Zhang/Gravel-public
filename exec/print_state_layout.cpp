#include "llvm-incl.hpp"
#include "llvm-helpers.hpp"
#include <iostream>


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
    
    return 0;
}
