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
        }
    }
    ele_state.num_out = 2;
    exec.run();
    std::cout << "Got " << exec.result_paths_.size() << " paths" << std::endl;
    for (int i = 0; i < exec.result_paths_.size(); i++) {
        auto &res = exec.result_paths_[i];
        std::cout << "Path " << i << ": " << res->out_pkts_[0].size() << " pkts on port 0" << std::endl;
    }

    return 0;
}

