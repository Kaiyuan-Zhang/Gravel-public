#include "click-state.hpp"
#include "data-structures.hpp"
#include <cassert>
#include "utils.hpp"

void StructLayout::update_ref(uint64_t offset, const RefEntry &e) {
    auto iter = out_refs.find(offset);
    if (iter == out_refs.end()) {
        return;
    }

    RefEntry &entry = iter->second;
    assert(e.type == EntryType::POINTER);
    assert(entry.type == e.type);
    entry = e;
}

void StructLayout::pre_write(uint64_t offset, uint64_t size) {
    std::vector<uint64_t> to_remove;
    for (auto &kv : out_refs) {
        auto off = kv.first;
        auto &e = kv.second;
        auto sz = e.size;
        // if there are overlap, add it to "to_remove"
        if (!((offset + size < off) || (offset > off + sz))) {
            // there are overlap
            to_remove.push_back(off);
        }
    }

    for (auto off : to_remove) {
        out_refs.erase(off);
    }
}

struct Entry {
    int offset;
    int size;
    bool is_pointer;
    std::shared_ptr<Pointee> obj;
};


static std::shared_ptr<Pointee> 
try_get_abstract_type(llvm::Module *m, llvm::Type *t, NameFactory &name_gen) {
    std::string class_name = get_type_name(t);
    if (class_name == "%class.Element.base") {
        return std::make_shared<Inaccessible>(name_gen("element_base"));
    } else if (class_name == "%class.HashContainer") {
        return std::make_shared<Inaccessible>(name_gen("hash_container"));
    } else if (is_prefix(class_name, "%class.Vector")) {
        auto vec_ptr = t->getStructElementType(0)->getStructElementType(0);
        auto vec_ele = vec_ptr->getPointerElementType();
        auto ele_size = get_type_size(m, vec_ele);
        auto ele_t = std::make_shared<Symbolic::BitVecType>(ele_size * 8);
        return std::make_shared<AbstractVector>(name_gen("vector"), ele_t, 0xffffffff);
    } else if (is_prefix(class_name, "%class.SizedHashAllocator")) {
        return std::make_shared<Inaccessible>(name_gen("sized_hash_alloc"));
    } else if (class_name == "%class.Timer") {
        return std::make_shared<Inaccessible>(name_gen("timer"));
    } else if (is_prefix(class_name, "%class.HashMap")) {
        using namespace Symbolic;
        auto bucket_p = t->getStructElementType(0)->getPointerElementType();
        auto bucket_t = bucket_p->getPointerElementType();
        auto pair_t = bucket_t->getStructElementType(0);
        auto kt = pair_t->getStructElementType(0);
        auto vt = pair_t->getStructElementType(1);

        auto k_bv_t = std::make_shared<BitVecType>(get_type_size(m, kt) * 8);
        auto v_bv_t = std::make_shared<BitVecType>(get_type_size(m, vt) * 8);
        // std::cout << "HashMap: " << k_bv_t->bitwidth / 8 << " -> " 
        //           << v_bv_t->bitwidth / 8 << std::endl;
        auto kt_ptr = std::dynamic_pointer_cast<Type>(k_bv_t);
        auto vt_ptr = std::dynamic_pointer_cast<Type>(v_bv_t);
        std::vector<std::shared_ptr<Type>> kt_vec = {kt_ptr};
        std::vector<std::shared_ptr<Type>> vt_vec = {vt_ptr};
        return std::make_shared<AbstractMap>(name_gen("hash_map"), kt_vec, vt_vec);
    }

    return nullptr;
}

static std::vector<Entry> get_struct_entries(ElementState &s, llvm::Module *module, 
                                             llvm::Type *t, NameFactory &name_gen) {
    std::vector<Entry> result;
    auto dl = std::make_shared<llvm::DataLayout>(module);
    if (t->isPointerTy()) {
        auto et = t->getPointerElementType();
        auto abs_type = try_get_abstract_type(module, et, name_gen);
        if (abs_type != nullptr) {
            Entry e;
            e.offset = 0;
            e.size = dl->getTypeStoreSize(t);
            e.is_pointer = false;
            e.obj = abs_type;
            result.push_back(e);
        } else {
            auto buf_size = dl->getTypeStoreSize(et);
            std::string type_name = get_type_name(et);
            auto buf = std::make_shared<Buffer>(name_gen(type_name + "!ptr"), buf_size);
            Entry e;
            e.offset = 0;
            e.size = buf_size;
            e.is_pointer = true;
            e.obj = std::dynamic_pointer_cast<Pointee>(buf);
            result.push_back(e);
        }
    } else if (t->isStructTy()) {
        auto abs_type = try_get_abstract_type(module, t, name_gen);
        if (abs_type != nullptr) {
            Entry e;
            e.offset = 0;
            e.size = dl->getTypeStoreSize(t);
            e.is_pointer = false;
            e.obj = abs_type;
            result.push_back(e);
        } else {
            llvm::StructType *st = llvm::dyn_cast<llvm::StructType>(t);
            auto sl = dl->getStructLayout(st);
            // std::cout << "Unrolling struct: " << get_type_name(st) << std::endl;
            for (unsigned i = 0; i < st->getNumElements(); i++) {
                auto field_t = st->getElementType(i);
                // std::cout << "Accessing field : " << i << " " << llvm_type_to_str(field_t) << std::endl;
                auto off = sl->getElementOffset(i);
                auto entries = get_struct_entries(s, module, field_t, name_gen);
                for (auto &e : entries) {
                    e.offset += off;
                    result.push_back(e);
                }
            }
        }
    } else if (t->isArrayTy()) {
        auto num_element = t->getArrayNumElements();
        auto et = t->getArrayElementType();
        auto entries = get_struct_entries(s, module, et, name_gen);
        int off = 0;
        for (int i = 0; i < num_element; i++) {
            for (auto &e : entries) {
                Entry e_copy = e;
                e_copy.offset += off;
                result.push_back(e_copy);
            }
            off += dl->getTypeStoreSize(et);
        }
    } else if (t->isIntegerTy()) {
        auto size = dl->getTypeStoreSize(t);
        // this should be a buffer
        auto buf = std::make_shared<Buffer>(name_gen("state_buf"), size);
        Entry e;
        e.offset = 0;
        e.size = size;
        e.is_pointer = false;
        e.obj = std::dynamic_pointer_cast<Pointee>(buf);
        result.push_back(e);
    }
    return result;
}

ElementState parse_element_state(llvm::Module *module, llvm::Type *element_t, NameFactory &name_gen) {
    ElementState state;
    assert(element_t->isStructTy());
    auto entries = get_struct_entries(state, module, element_t, name_gen);
    StructLayout element_layout;
    for (auto &e : entries) {
        // std::cout << e.offset << ": "
        //           << "(" << e.size << " bytes) "
        //           << e.is_pointer << " ";
        // e.obj->print(std::cout);
        // std::cout << " " << e.obj.get() << std::endl;
        StructLayout::RefEntry r;
        r.type = StructLayout::EntryType::ABSTRACT_STRUCT;
        r.ref_name = e.obj->name;
        r.size = e.size;
        assert(element_layout.out_refs.find(e.offset) == element_layout.out_refs.end());
        element_layout.out_refs.insert({e.offset, r});
        state.abstract_data.insert({e.obj->name, e.obj});
    }

    state.struct_meta.insert({"this_element", element_layout});
    return state;
}


bool have_abstract_type(llvm::Module *module, llvm::Type *t) {
    std::string class_name = get_type_name(t);
    if (class_name == "%class.Element.base") {
        return true;
    } else if (class_name == "%class.HashContainer") {
        return true;
    } else if (is_prefix(class_name, "%class.Vector")) {
        auto vec_ptr = t->getStructElementType(0)->getStructElementType(0);
        auto vec_ele = vec_ptr->getPointerElementType();
        return !vec_ele->isPointerTy();
    } else if (is_prefix(class_name, "%class.SizedHashAllocator")) {
        return true;
    } else if (class_name == "%class.Timer") {
        return true;
    } else if (is_prefix(class_name, "%class.HashMap")) {
        using namespace Symbolic;
        auto bucket_p = t->getStructElementType(0)->getPointerElementType();
        auto bucket_t = bucket_p->getPointerElementType();
        auto pair_t = bucket_t->getStructElementType(0);
        auto kt = pair_t->getStructElementType(0);
        auto vt = pair_t->getStructElementType(1);
        
        return (!kt->isPointerTy()) && (!(vt->isPointerTy()));
    }
    return false;
}

void print_struct_entries(llvm::Module *module, llvm::Type *t, int indent_lvl, int off,
                          std::unordered_set<std::string> &strategies) {
    std::vector<Entry> result;
    auto dl = std::make_shared<llvm::DataLayout>(module);
    if (t->isPointerTy()) {
        auto et = t->getPointerElementType();
        auto class_name = get_type_name(et);
        auto has_abs_type = have_abstract_type(module, et);
        if (off == 0 && is_prefix(class_name, "%class.Element.base")) {
            return;
        }
        if (has_abs_type) {
            strategies.insert("AbstractDataType");
        } else {
            strategies.insert("Fix-sized Array");
        }
    } else if (t->isStructTy()) {
        auto class_name = get_type_name(t);
        if (off == 0 && is_prefix(class_name, "%class.Element.base")) {
            return;
        }
        auto has_abs_type = have_abstract_type(module, t);
        if (has_abs_type) {
            strategies.insert("AbstractDataType");
        } else {
            llvm::StructType *st = llvm::dyn_cast<llvm::StructType>(t);
            auto sl = dl->getStructLayout(st);
            std::cout << "Unrolling struct: " << get_type_name(st) << std::endl;
            for (unsigned i = 0; i < st->getNumElements(); i++) {
                auto field_t = st->getElementType(i);
                std::cout << "Accessing field : " << i << " " << llvm_type_to_str(field_t) << std::endl;
                auto field_off = sl->getElementOffset(i);
                print_struct_entries(module, field_t, indent_lvl + 1, off + field_off, strategies);
            }
        }
    } else if (t->isArrayTy()) {
        auto num_element = t->getArrayNumElements();
        auto et = t->getArrayElementType();
        print_struct_entries(module, et, indent_lvl + 1, off, strategies);
    } else if (t->isIntegerTy()) {
    } else {
        assert(false && "unknown type");
    }
}

std::unordered_set<std::string>
print_element_state(llvm::Module *module, llvm::Type *element_t) {
    assert(element_t->isStructTy());
    std::unordered_set<std::string> strategies;
    print_struct_entries(module, element_t, 0, 0, strategies);
    return strategies;
}
