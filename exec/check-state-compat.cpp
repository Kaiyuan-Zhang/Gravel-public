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

    std::cout << "Processing: " << element_name << std::endl;

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

    std::cout << "ENTRY: ";

    for (auto e : entries) {
        if (e.find("push") != std::string::npos) {
            std::cout << "PUSH ";
        }
        if (e.find("pull") != std::string::npos) {
            std::cout << "PULL ";
        }
        if (e.find("simple_action") != std::string::npos) {
            std::cout << "PUSH PULL";
        }
    }
    if (entries.size() <= 0) {
        std::cerr << "could not find element entry" << std::endl;
    } else {
        std::cout << std::endl;
    }
    auto strategies = print_element_state(module.get(), element_t);

    std::cout << "DONE: ";
    for (auto s : strategies) {
        std::cout << s << " ";
    }
    std::cout << std::endl;

    // Create state for the element
    return 0;
}
