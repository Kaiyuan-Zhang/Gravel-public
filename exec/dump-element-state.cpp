#include "click-exec.hpp"
#include "llvm-helpers.hpp"
#include "utils.hpp"
#include "click-state.hpp"

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
    for (auto e : entries) {
        std::cout << "got entry: " << e << std::endl;
    }
    if (entries.size() <= 0) {
        std::cerr << "could not find element entry" << std::endl;
    }

    auto init_fd = module->getFunction(entries[0]);
    auto init = std::make_shared<ExecContext>();
    init->curr_bb_ = &init_fd->getEntryBlock();
    init->inst_iter_ = init->curr_bb_->begin();
    init->module_ = module.get();
    
    // Create state for the element
    NameFactory name_gen;
    auto s = parse_element_state(module.get(), element_t, name_gen);

    std::cout << "Done" << std::endl;
    return 0;
}
