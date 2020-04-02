#include "click-exec.hpp"
#include "data-structures.hpp"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <class-ir-file> <class-name>\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    const std::string element_name = std::string(argv[2]);

    ElementExecutor exec(ir_filename, element_name);
    std::cout << "IR loaded" << std::endl;
    exec.initilize();
    std::cout << "Runner initialized" << std::endl;

    for (auto &kv : exec.init_state_->state_.abstract_data) {
        std::shared_ptr<Pointee> ptr = kv.second;
        std::cout << "abs data name: " << kv.first << " " << ptr->type() << std::endl;
    }
    auto &ele_state = exec.init_state_->state_;
    if (ele_state.struct_meta.find("this_element") != ele_state.struct_meta.end()) {
        auto &layout = ele_state.struct_meta["this_element"];
        for (auto &kv : layout.out_refs) {
            std::cout << "out_ref: " << kv.first << " " << (int)kv.second.type
                      << " " << kv.second.ref_name << " " << kv.second.size << std::endl;
            if (ele_state.abstract_data.find(kv.second.ref_name) != ele_state.abstract_data.end()) {
                auto ptr = ele_state.abstract_data[kv.second.ref_name];
                auto t = ptr->type();
                if (t == PointeeType::HashMap) {
                    auto m = std::dynamic_pointer_cast<AbstractMap>(ptr);
                    auto &kts = m->key_types;
                    auto &vts = m->val_types;
                    std::cout << "(";
                    for (auto kt : kts) {
                        auto bw = kt->get_bv_width();
                        std::cout << bw << " ";
                    }
                    std::cout << ") --> (";
                    for (auto vt : vts) {
                        auto bw = vt->get_bv_width();
                        std::cout << bw << " ";
                    }
                    std::cout << ")" << std::endl;
                }
            }
        }
    }
    return 0;
}

