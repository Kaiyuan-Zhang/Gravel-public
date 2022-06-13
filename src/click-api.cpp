#include "click-api.hpp"
#include "utils.hpp"
#include "llvm-helpers.hpp"
#include "z3-gen.hpp"
#include <type_traits>


template<typename PtrT>
std::shared_ptr<PtrT> get_tmp_obj(const std::string &name,
            std::shared_ptr<ExecContext> state) {
    static_assert(std::is_base_of<Pointee, PtrT>::value,
            "Not derived from Pointee");
    auto &tmp_data = state->tmp_data;
    auto iter = tmp_data.find(name);

    if (iter == tmp_data.end()) {
        return nullptr;
    }

    auto ptr = iter->second;
    return std::dynamic_pointer_cast<PtrT>(ptr);
}

template<typename PtrT>
std::shared_ptr<PtrT> get_state_obj(const std::string &name,
            std::shared_ptr<ExecContext> state) {
    static_assert(std::is_base_of<Pointee, PtrT>::value,
            "Not derived from Pointee");
    auto &abs_obj = state->state_.abstract_data;
    auto iter = abs_obj.find(name);

    if (iter == abs_obj.end()) {
        return nullptr;
    }

    auto ptr = iter->second;
    return std::dynamic_pointer_cast<PtrT>(ptr);
}

template<typename PtrT>
std::shared_ptr<PtrT> get_obj(const std::string &name,
            std::shared_ptr<ExecContext> state) {
    static_assert(std::is_base_of<Pointee, PtrT>::value,
            "Not derived from Pointee");
    auto ptr = get_tmp_obj<PtrT>(name, state);
    if (ptr == nullptr) {
        ptr = get_state_obj<PtrT>(name, state);
    }
    return ptr;
}

template<typename PtrT>
std::shared_ptr<PtrT> get_obj(const SymPointer &ptr,
            std::shared_ptr<ExecContext> state) {
    Symbolic::Z3Context ctx;
    auto const_zero = mk_concrete_bv(64, 0);
    assert(verify_with_z3(ctx, state->get_pre_cond(),
                mk_expr_ptr(EqExpr, {ptr.offset, const_zero})));
    return get_obj<PtrT>(ptr.pointer_base, state);
}

bool PktUniqueify::match(const std::string &fn) const {
    return fn == "Packet::uniqueify()";
}

std::vector<std::shared_ptr<ExecContext>>
PktUniqueify::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    state->set_reg_val(dst_reg, params[0]);
    state->inst_iter_++;
    return {state};
}


bool PktIPHeader::match(const std::string &fn) const {
    return is_prefix(fn, "Packet::ip_header")
        || is_prefix(fn, "WritablePacket::ip_header");
}

std::vector<std::shared_ptr<ExecContext>>
PktIPHeader::call(const std::string &fn,
    const std::vector<RegValue> &params,
    std::shared_ptr<ExecContext> state,
    const std::string &dst_reg) {
    std::cerr << "ip_header called\n";
    SymPointer ptr;
    ptr.pointer_base = "packet_content";
    ptr.offset = mk_expr_ptr(ConcreteBv, 64, 14);
    state->set_reg_val(dst_reg, RegValue{ptr});
    state->inst_iter_++;
    return {state};
}

bool PktGeneral::match(const std::string &fn) const {
    return is_prefix(fn, "Packet::")
        || is_prefix(fn, "WritablePacket::");
}

std::vector<std::shared_ptr<ExecContext>>
PktGeneral::call(const std::string &fn,
                 const std::vector<RegValue> &params,
                 std::shared_ptr<ExecContext> state,
                 const std::string &dst_reg) {
    auto colon_pos = fn.find("::");
    if (colon_pos == std::string::npos) {
        assert(false && "error: parse funcion name");
    }

    // TODO: check if offset is zero
    std::shared_ptr<Packet> pkt_obj = nullptr;
    auto method_name = fn.substr(colon_pos + 2);
    if (!is_prefix(method_name, "make(")) {
        auto pkt_ptr = params[0].get_ptr();
        pkt_obj = get_obj<Packet>(pkt_ptr, state);
    }
    if (is_prefix(method_name, "ether_header")) {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "ip_header")) {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 14);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "ip6_header")) {
        // std::cerr << "ip6_header called\n";
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 14);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "network_header()")) {
        // std::cerr << "network_header called\n";
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 14);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "transport_header()")) {
        // std::cerr << "transport_header called\n";
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 34);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "has_network_header() const") {
        auto bv1 = std::make_shared<Symbolic::BitVecType>(1);
        auto vn = state->name_gen->gen("has_n_hdr");
        auto bool_var = mk_expr_ptr(SymbolicVar, bv1, vn);
        state->set_reg_val(dst_reg, RegValue{bool_var});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "set_ip_header(click_ip const*, unsigned int)") {
        // TODO: implement this
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "timestamp_anno()")) {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->anno_buf_name;
        ptr.offset = mk_concrete_bv(64, 76);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "packet_type_anno() const") {
        // TODO: implement this
        auto bv32 = std::make_shared<Symbolic::BitVecType>(32);
        auto vn = state->name_gen->gen("pkt_type_anno");
        auto val = mk_expr_ptr(SymbolicVar, bv32, vn);
        state->set_reg_val(dst_reg, RegValue{val});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "set_packet_type_anno(Packet::PacketType)") {
        // TODO: implement this
        state->inst_iter_++;
        return {state};
    } else if (method_name == "shift_data(int, bool)") {
        // TODO: implement this
        state->set_reg_val(dst_reg, params[0]);
        state->inst_iter_++;
        return {state};
    } else if (method_name == "xanno()" || method_name == "xanno() const") {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->anno_buf_name;
        ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "set_dst_ip_anno(IPAddress)") {
        // TODO: implement this
        state->inst_iter_++;
        return {state};
    } else if (method_name == "set_anno_u32(int, unsigned int)") {
        // TODO: implement this
        state->inst_iter_++;
        return {state};
    } else if (method_name == "uniqueify()") {
        state->set_reg_val(dst_reg, params[0]);
        state->inst_iter_++;
        return {state};
    } else if (method_name == "network_length() const") {
        auto pkt_len = pkt_obj->len;
        auto ip_off = mk_expr_ptr(ConcreteBv, 32, 14);
        auto result = mk_expr_ptr(SubExpr, {pkt_len, ip_off});
        state->set_reg_val(dst_reg, RegValue{result});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "transport_length() const") {
        auto pkt_len = pkt_obj->len;
        auto tcp_off = mk_expr_ptr(ConcreteBv, 32, 34);
        auto result = mk_expr_ptr(SubExpr, {pkt_len, tcp_off});
        state->set_reg_val(dst_reg, RegValue{result});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "kill()") {
        state->inst_iter_++;
        return {state};
    } else if (method_name == "data() const") {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "end_data() const") {
        SymPointer ptr;
        ptr.pointer_base = pkt_obj->content_buf_name;
        ptr.offset = mk_expr_ptr(UExtExpr, pkt_obj->len, 64);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "length() const") {
        auto pkt_len = pkt_obj->len;
        state->set_reg_val(dst_reg, RegValue{pkt_len});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "take(unsigned int)") {
        // TODO: implemente this
        state->inst_iter_++;
        return {state};
    } else if (method_name == "pull(unsigned int)") {
        // TODO: implemente this
        state->inst_iter_++;
        return {state};
    } else if (method_name == "make(unsigned int, void const*, unsigned int, unsigned int)") {
        auto np_name = state->name_gen->gen("new_pkt");
        auto new_pkt = std::make_shared<Packet>(np_name, state);
        state->tmp_data.insert({np_name, new_pkt});

        SymPointer pkt_ptr;
        pkt_ptr.pointer_base = np_name;
        pkt_ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst_reg, RegValue{pkt_ptr});
        state->inst_iter_++;
        return {state};
    } else if (method_name == "clone()") {
        auto np_name = state->name_gen->gen("new_pkt");
        auto new_pkt = pkt_obj->clone_pkt(np_name, state);
        state->tmp_data.insert({np_name, new_pkt});

        SymPointer pkt_ptr;
        pkt_ptr.pointer_base = np_name;
        pkt_ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst_reg, RegValue{pkt_ptr});
        state->inst_iter_++;
        return {state};
    }

    assert(false && "unknown packet op");
}

bool ElementFuncs::match(const std::string &fn) const {
    return is_prefix(fn, "Element::");
}

std::vector<std::shared_ptr<ExecContext>>
ElementFuncs::call(const std::string &fn,
                   const std::vector<RegValue> &params,
                   std::shared_ptr<ExecContext> state,
                   const std::string &dst_reg) {
    auto colon_pos = fn.find("::");
    auto method_name = fn.substr(colon_pos + 2);
    auto element_struct_name = params[0].get_ptr().pointer_base;
    // auto element_obj_ptr = state->state_.abstract_data.find(element_struct_name)->second;
    // auto element_olb = std::dynamic_pointer_cast
    bool is_push = false;
    std::shared_ptr<Packet> pkt_obj = nullptr;
    Symbolic::ExprPtr out_port_idx = nullptr;

    if (method_name == "checked_output_push(int, Packet*) const") {
        // TODO: implement this
        out_port_idx = params[1].get_val()->simplify();
        pkt_obj = get_obj<Packet>(params[2].get_ptr(), state);
        state->inst_iter_++;
        is_push = true;
    } else if (method_name == "output(int) const") {
        // TODO: implement this
        SymPointer ptr;
        ptr.pointer_base = state->name_gen->gen(element_struct_name + "outport");
        ptr.offset = params[1].get_val()->simplify();
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
    } else if (method_name == "Port::push(Packet*) const") {
        // TODO: implement this
        out_port_idx = params[0].get_ptr().offset->simplify();
        pkt_obj = get_obj<Packet>(params[1].get_ptr(), state);
        state->inst_iter_++;
        is_push = true;
    } else if (method_name == "name() const") {
        state->inst_iter_++;
        return {state};
    } else if (method_name == "noutputs() const") {
        state->inst_iter_++;
        state->set_reg_val(dst_reg, RegValue{mk_concrete_bv(32, state->state_.num_out)});
        return {state};
    }

    if (is_push) {
        if (out_port_idx->is_symbolic()) {
            for (int i = 0; i < state->state_.num_out; i++) {
                CondPkt e;
                e.cond = mk_expr_ptr(EqExpr, {out_port_idx, mk_concrete_bv(32, i)});
                e.pkt = pkt_obj;
                state->out_pkts_[i].push_back(e);
            }
        } else {
            // port idx is concrete
            auto concrete_idx = Symbolic::get_concrete_val(out_port_idx);
            CondPkt e;
            e.cond = mk_concrete_bv(1, 1);
            e.pkt = pkt_obj;
            state->out_pkts_[concrete_idx].push_back(e);
        }
        return {state};
    }
    assert(false && "unknown element method");
}


bool VectorOps::match(const std::string &fn) const {
    auto template_args = split_template(fn);
    return (is_prefix(template_args[0], "Vector::"));
}

std::vector<std::shared_ptr<ExecContext>>
VectorOps::call(const std::string &fn,
                const std::vector<RegValue> &params,
                std::shared_ptr<ExecContext> state,
                const std::string &dst_reg) {
    auto vec_ptr = params[0].get_ptr();
    Symbolic::Z3Context ctx;
    auto expr = Symbolic::gen_z3_expr(ctx, vec_ptr.offset).get_expr();

    // std::cout << "Vector op: " << fn << std::endl;
    auto off = vec_ptr.offset->simplify();
    auto &inst = *state->inst_iter_;
    std::shared_ptr<AbstractVector> vec = nullptr;
    if (!off->is_symbolic()) {
        std::string vec_name = "";
        auto offset_val = std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val();
        auto base = vec_ptr.pointer_base;
        if (offset_val != 0) {
            auto &struct_layout = state->state_.struct_meta.find(base)->second;
            auto &ref_entry = struct_layout.out_refs.find(offset_val)->second;
            base = ref_entry.ref_name;
        }
        auto vec_obj = state->state_.abstract_data.find(base)->second;
        vec = std::dynamic_pointer_cast<AbstractVector>(vec_obj);
        // std::cout << "vec: " << vec->name << " " << vec.get() << std::endl;
    } else {
        assert(false && "could not find where is the vector");
    }

    auto after_colon = fn.find("::");
    auto op_name = fn.substr(after_colon + 2);
    if (op_name == "operator[](int)") {
        // std::cout << "Vector indexing op" << std::endl;
        auto idx = params[1].get_val();
        if (idx->type->get_bv_width() < 64) {
            idx = mk_expr_ptr(SExtExpr, idx, 64);
        }
        auto result = vec->get(idx);
        auto buf_name = state->name_gen->gen("vec_idx_result");
        assert(vec->val_type->get_bv_width() % 8 == 0);
        int val_size = vec->val_type->get_bv_width() / 8;
        auto buf = std::make_shared<Buffer>(buf_name, val_size);
        auto vec_name = vec->name;
        buf->have_write_back = true;
        buf->store(mk_expr_ptr(ConcreteBv, 64, 0), RegValue{result});
        buf->write_back_fn = [vec_name, idx, val_size](std::shared_ptr<Buffer> self, std::shared_ptr<ExecContext> s) {
            assert(self->sized);
            auto v_obj = s->state_.abstract_data[vec_name];
            auto v = std::dynamic_pointer_cast<AbstractVector>(v_obj);
            v->set(idx, self->load(mk_expr_ptr(ConcreteBv, 64, 0), val_size).get_val());
        };
        SymPointer ptr;
        ptr.pointer_base = buf_name;
        ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->tmp_data.insert({buf_name, buf});
        state->inst_iter_++;
        return {state};
    } else if (op_name == "begin()" || op_name == "begin() const") {
        SymPointer ptr;
        ptr.pointer_base = vec->name + "!begin";
        ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    } else if (op_name == "end()" || op_name == "end() const") {
        SymPointer ptr;
        ptr.pointer_base = vec->name + "!end";
        ptr.offset = mk_concrete_bv(64, 0);
        state->set_reg_val(dst_reg, RegValue{ptr});
        state->inst_iter_++;
        return {state};
    }
    assert(false);
    //state->state_.abstract_data
    //return {};
    return {};
}

bool HashMapOps::match(const std::string &fn) const {
    auto template_args = split_template(fn);
    return (is_prefix(template_args[0], "HashMap::"));
}

std::vector<std::shared_ptr<ExecContext>>
HashMapOps::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    using namespace Symbolic;

    auto template_args = split_template(fn);
    auto colon_pos = template_args[0].find("::");
    auto method_name = template_args[0].substr(colon_pos + 2);

    Z3Context ctx;
    auto const_zero = mk_concrete_bv(64, 0);
    auto map_ptr = params[0].get_ptr();
    if (!verify_with_z3(ctx, state->get_pre_cond(),
                mk_expr_ptr(EqExpr, {map_ptr.offset, const_zero}))) {
        auto off = map_ptr.offset->simplify();
        if (off->is_symbolic()) {
            assert(false && "Symbolic non-zero offset");
        }
        auto off_val = std::dynamic_pointer_cast<ConcreteBv>(off)->get_val();
        // std::cout << "HashMap offset: " << off_val << std::endl;
        auto &struct_layout = state->state_.struct_meta[map_ptr.pointer_base];
        auto &ref_entry = struct_layout.out_refs.find(off_val)->second;
        map_ptr.pointer_base = ref_entry.ref_name;
        map_ptr.offset = const_zero;
    }
    auto map_obj = get_obj<AbstractMap>(map_ptr, state);
    assert(map_obj != nullptr);

    if (is_prefix(method_name, "findp(")) {
        std::vector<ExprPtr> keys;
        auto key_buf_ptr = get_obj<Buffer>(params[1].get_ptr(), state);
        auto off = const_zero;
        for (int i = 0; i < map_obj->key_types.size(); i++) {
            auto key_size_bits = map_obj->key_types[i]->get_bv_width();
            assert(key_size_bits % 8 == 0);
            auto key_size_bytes = key_size_bits / 8;

            auto k = key_buf_ptr->load_be(off, key_size_bytes).get_val();
            keys.push_back(k);
            off = mk_expr_ptr(AddExpr, {off, mk_concrete_bv(64, key_size_bytes)});
        }

        auto has_key = map_obj->contains(keys)->simplify();
        auto vals = map_obj->get_vals(keys);

        // now creates a new buffer (with write back) for the value
        auto buf_name = state->name_gen->gen(map_obj->name + "findp_result");
        int total_size = 0;
        for (int i = 0; i < vals.size(); i++) {
            auto num_bits = vals[i]->type->get_bv_width();
            assert(num_bits % 8 == 0);
            auto num_bytes = num_bits / 8;
            total_size += num_bytes;
        }
        auto buf = std::make_shared<Buffer>(buf_name, total_size);

        off = mk_concrete_bv(64, 0);
        for (int i = 0; i < vals.size(); i++) {
            auto num_bits = vals[i]->type->get_bv_width();
            auto num_bytes = num_bits / 8;
            buf->store_be(off, RegValue{vals[i]});
            off = mk_expr_ptr(AddExpr, {off, mk_concrete_bv(64, num_bytes)});
        }

        std::string map_name = map_obj->name;
        buf->have_write_back = true;
        buf->write_back_fn = [map_name, keys](std::shared_ptr<Buffer> self, std::shared_ptr<ExecContext> s) {
            assert(self->sized);
            auto m_obj = get_obj<AbstractMap>(map_name, s);
            std::vector<ExprPtr> new_vals;
            ExprPtr off = mk_concrete_bv(64, 0);
            for (int i = 0; i < m_obj->val_types.size(); i++) {
                auto v = self->load_be(off, m_obj->val_types[i]->get_bv_width());
                new_vals.push_back(v.get_val());
            }
            m_obj->set_vals(keys, new_vals);
        };

        SymPointer ptr;
        ptr.pointer_base = buf_name;
        ptr.offset = mk_concrete_bv(64, 0);
        auto t_state = state->copy_self();
        t_state->set_reg_val(dst_reg, RegValue{ptr});
        t_state->tmp_data.insert({buf_name, buf});
        t_state->add_pre_cond(has_key);
        t_state->inst_iter_++;

        SymPointer null_ptr;
        null_ptr.pointer_base = "";
        null_ptr.offset = mk_concrete_bv(64, 0);
        auto f_state = state->copy_self();
        f_state->set_reg_val(dst_reg, RegValue{null_ptr});
        f_state->add_pre_cond(mk_expr_ptr(LNotExpr, has_key));
        f_state->inst_iter_++;

        return {t_state, f_state};
    } else if (is_prefix(method_name, "insert(")) {
        auto key_buf_ptr = get_obj<Buffer>(params[1].get_ptr(), state);
        auto val_buf_ptr = get_obj<Buffer>(params[2].get_ptr(), state);

        std::vector<ExprPtr> keys;
        std::vector<ExprPtr> vals;
        auto off = const_zero;

        for (int i = 0; i < map_obj->key_types.size(); i++) {
            auto key_size_bits = map_obj->key_types[i]->get_bv_width();
            assert(key_size_bits % 8 == 0);
            auto key_size_bytes = key_size_bits / 8;

            auto k = key_buf_ptr->load_be(off, key_size_bytes).get_val();
            keys.push_back(k);
            off = mk_expr_ptr(AddExpr, {off, mk_concrete_bv(64, key_size_bytes)});
        }

        off = const_zero;
        for (int i = 0; i < map_obj->val_types.size(); i++) {
            auto val_size_bits = map_obj->val_types[i]->get_bv_width();
            assert(val_size_bits % 8 == 0);
            auto val_size_bytes = val_size_bits / 8;

            auto v = val_buf_ptr->load_be(off, val_size_bytes).get_val();
            vals.push_back(v);
            off = mk_expr_ptr(AddExpr, {off, mk_concrete_bv(64, val_size_bytes)});
        }

        map_obj->set_vals(keys, vals);
        state->inst_iter_++;
        return {state};
    } else if (is_prefix(method_name, "erase(")) {
        auto key_buf_ptr = get_obj<Buffer>(params[1].get_ptr(), state);

        std::vector<ExprPtr> keys;
        std::vector<ExprPtr> vals;
        auto off = const_zero;

        for (int i = 0; i < map_obj->key_types.size(); i++) {
            auto key_size_bits = map_obj->key_types[i]->get_bv_width();
            assert(key_size_bits % 8 == 0);
            auto key_size_bytes = key_size_bits / 8;

            auto k = key_buf_ptr->load_be(off, key_size_bytes).get_val();
            keys.push_back(k);
            off = mk_expr_ptr(AddExpr, {off, mk_concrete_bv(64, key_size_bytes)});
        }

        map_obj->delete_val(keys);
        state->set_reg_val(dst_reg, RegValue{mk_concrete_bv(1, 1)});
        state->inst_iter_++;
        return {state};
    }

    assert(false && "unknown HashMap operation");
}

bool ByteRotationFunc::match(const std::string &fn) const {
    return (is_prefix(fn, "rorw $$8, ${0:w}")
        || is_prefix(fn, "llvm.bswap.")
        || is_prefix(fn, "bswap $0"));
}

std::vector<std::shared_ptr<ExecContext>>
ByteRotationFunc::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    using namespace Symbolic;

    auto source = params[0].get_val();
    auto num_bits = source->type->get_bv_width();
    assert(num_bits % 8 == 0);

    auto num_bytes = num_bits / 8;
    std::vector<ExprPtr> bytes;
    for (int i = 0; i < num_bytes; i++) {
        bytes.push_back(mk_expr_ptr(ExtractExpr, source, i * 8, (i + 1) * 8));
    }

    ExprPtr dst_val = nullptr;
    for (int i = 0; i < num_bytes; i++) {
        if (dst_val == nullptr) {
            dst_val = bytes[i];
        } else {
            dst_val = mk_expr_ptr(ConcatExpr, {dst_val, bytes[i]});
        }
    }
    state->set_reg_val(dst_reg, RegValue{dst_val});
    state->inst_iter_++;
    return {state};
}

bool IPFlowIDConstr::match(const std::string &fn) const {
    return (fn == "IPFlowID::IPFlowID(Packet const*, bool)");
}

std::vector<std::shared_ptr<ExecContext>>
IPFlowIDConstr::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    auto flow_id_ptr = params[0].get_ptr();
    auto pkt_ptr = params[1].get_ptr();

    // check if offset is zero
    Symbolic::Z3Context ctx;
    auto const_zero = mk_concrete_bv(64, 0);
    assert(verify_with_z3(ctx, state->get_pre_cond(),
                mk_expr_ptr(EqExpr, {flow_id_ptr.offset, const_zero})));
    assert(verify_with_z3(ctx, state->get_pre_cond(),
                mk_expr_ptr(EqExpr, {pkt_ptr.offset, const_zero})));
    auto flowid_obj = get_obj<Buffer>(flow_id_ptr.pointer_base, state);
    auto pkt_obj = get_obj<Packet>(pkt_ptr.pointer_base, state);
    auto pkt_content = get_obj<Buffer>(pkt_obj->content_buf_name, state);

    /* IPFlowID layout:
     *  0 | uint32_t saddr
     *  4 | uint32_t daddr
     *  8 | uint16_t sport
     * 10 | uint16_t dport
     */

    // note that we also need endian reverse here

    auto saddr = pkt_content->load_be(mk_concrete_bv(64, 14 + 12), 4);
    auto daddr = pkt_content->load_be(mk_concrete_bv(64, 14 + 16), 4);
    auto sport = pkt_content->load_be(mk_concrete_bv(64, 14 + 20), 2);
    auto dport = pkt_content->load_be(mk_concrete_bv(64, 14 + 22), 2);

    flowid_obj->store(mk_concrete_bv(64,  0), saddr);
    flowid_obj->store(mk_concrete_bv(64,  4), daddr);
    flowid_obj->store(mk_concrete_bv(64,  8), sport);
    flowid_obj->store(mk_concrete_bv(64, 10), dport);

    state->inst_iter_++;
    return {state};
}

bool LLVMMemcpy::match(const std::string &fn) const {
    return is_prefix(fn, "llvm.memcpy")
        || is_prefix(fn, "llvm.memmove");
}

std::vector<std::shared_ptr<ExecContext>>
LLVMMemcpy::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    using namespace Symbolic;

    auto dst_ptr = params[0].get_ptr();
    auto src_ptr = params[1].get_ptr();
    auto len = params[2].get_val();
    if (len->type->get_bv_width() < 64) {
        len = mk_expr_ptr(UExtExpr, len, 64);
    }

    len = len->simplify();
    if (len->is_symbolic()) {
        // TODO: need to add a "forall" condition
        std::cerr << "TODO: Symbolic memcpy len" << std::endl;
        state->inst_iter_++;
        return {state};
    } else {
        // simply copy the data byte-by-byte
        auto num_bytes = std::dynamic_pointer_cast<ConcreteBv>(len)->get_val();
        auto dst_buf = get_obj<Buffer>(dst_ptr.pointer_base, state);
        auto src_buf = get_obj<Buffer>(src_ptr.pointer_base, state);
        auto dst_off = dst_ptr.offset;
        auto src_off = src_ptr.offset;
        auto const_1 = mk_concrete_bv(64, 1);
        std::vector<ExprPtr> bytes;
        for (uint64_t i = 0; i < num_bytes; i++) {
            auto byte = src_buf->load(src_off, 1);
            bytes.push_back(byte.get_val());
            src_off = mk_expr_ptr(AddExpr, {src_off, const_1});
        }
        for (uint64_t i = 0; i < num_bytes; i++) {
            dst_buf->store(dst_off, RegValue{bytes[i]});
            dst_off = mk_expr_ptr(AddExpr, {dst_off, const_1});
        }

        state->inst_iter_++;
        return {state};
    }
    assert(false && "unknown op");
}

bool LLVMMemset::match(const std::string &fn) const {
    return is_prefix(fn, "llvm.memset");
}

std::vector<std::shared_ptr<ExecContext>>
LLVMMemset::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    using namespace Symbolic;

    auto dst_ptr = params[0].get_ptr();
    auto val = params[1].get_val();
    assert(val->type->get_bv_width() == 8);
    auto len = params[2].get_val();
    if (len->type->get_bv_width() < 64) {
        len = mk_expr_ptr(UExtExpr, len, 64);
    }

    len = len->simplify();
    if (len->is_symbolic()) {
        // TODO: need to add a "forall" condition
        std::cerr << "TODO: Symbolic memset len" << std::endl;
        state->inst_iter_++;
        return {state};
    } else {
        // simply copy the data byte-by-byte
        auto num_bytes = std::dynamic_pointer_cast<ConcreteBv>(len)->get_val();
        auto dst_buf = get_obj<Buffer>(dst_ptr.pointer_base, state);
        auto dst_off = dst_ptr.offset;
        auto const_1 = mk_concrete_bv(64, 1);
        std::vector<ExprPtr> bytes;
        for (uint64_t i = 0; i < num_bytes; i++) {
            dst_buf->store(dst_off, RegValue{val});
            dst_off = mk_expr_ptr(AddExpr, {dst_off, const_1});
        }

        state->inst_iter_++;
        return {state};
    }
    assert(false && "unknown op");
}

bool LLVMMemcmp::match(const std::string &fn) const {
    return is_prefix(fn, "memcmp");
}

std::vector<std::shared_ptr<ExecContext>>
LLVMMemcmp::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    using namespace Symbolic;

    auto dst_ptr = params[0].get_ptr();
    auto src_ptr = params[1].get_ptr();
    auto len = params[2].get_val();
    if (len->type->get_bv_width() < 64) {
        len = mk_expr_ptr(UExtExpr, len, 64);
    }

    len = len->simplify();
    if (len->is_symbolic()) {
        // TODO: need to add a "forall" condition
        std::cerr << "TODO: Symbolic memcpy len" << std::endl;
        state->inst_iter_++;
        return {state};
    } else {
        // TODO: implement this
        auto bv32 = std::make_shared<BitVecType>(32);
        auto vn = state->name_gen->gen("memcmp!result");
        auto result = mk_expr_ptr(SymbolicVar, bv32, vn);
        state->set_reg_val(dst_reg, RegValue{result});
        state->inst_iter_++;
        return {state};
    }
    assert(false && "unknown op");
}

bool ClickLibFunc::match(const std::string &fn) const {
    static std::unordered_set<std::string> fn_set = {
        "click_jiffies()",
        "Timestamp::assign_now()",
        "clock_gettime",
        "click_chatter",
        "find",
        "IPAddress* find<IPAddress>(IPAddress*, IPAddress*, IPAddress const&)",
        "IPAddress const* find<IPAddress>(IPAddress const*, IPAddress const*, IPAddress const&)",
        "click_in_cksum",
        "click_in_cksum_pseudohdr_hard",
        "click_in_cksum_pseudohdr_raw",
        "in6_fast_cksum",
    };
    return fn_set.find(fn) != fn_set.end();
}

std::vector<std::shared_ptr<ExecContext>>
ClickLibFunc::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    if (fn == "click_in_cksum" || fn == "in6_fast_cksum"
        || fn == "click_in_cksum_pseudohdr_hard" || fn == "click_in_cksum_pseudohdr_raw") {
        // TODO: implement this
        auto sym_var = state->name_gen->gen("cksum");
        auto bv_16 = std::make_shared<Symbolic::BitVecType>(16);
        state->set_reg_val(dst_reg, RegValue{mk_expr_ptr(SymbolicVar, bv_16, sym_var)});
    } else if (fn.find("find") != std::string::npos) {
        // TODO: implement this
        auto sym_var = state->name_gen->gen("find!result");
        auto ptr = params[1].get_ptr();
        auto bv_64 = std::make_shared<Symbolic::BitVecType>(64);
        ptr.offset = mk_expr_ptr(SymbolicVar, bv_64, sym_var);
        state->set_reg_val(dst_reg, RegValue{ptr});
    } else if (fn == "click_jiffies()" || fn == "clock_gettime") {
        auto vn = state->name_gen->gen("jiffie");
        auto bv_32 = std::make_shared<Symbolic::BitVecType>(32);
        auto val = mk_expr_ptr(SymbolicVar, bv_32, vn);
        state->set_reg_val(dst_reg, RegValue{val});
    }
    state->inst_iter_++;
    return {state};
    assert(false);
}

bool CheckIPHdrHelper::match(const std::string &fn) const {
    static std::unordered_set<std::string> fn_set = {
        "CheckIPHeader::drop(CheckIPHeader::Reason, Packet*)",
    };
    return fn_set.find(fn) != fn_set.end();
}

std::vector<std::shared_ptr<ExecContext>>
CheckIPHdrHelper::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    // TODO: add something
    state->inst_iter_++;
    return {state};
}

bool IP6Helper::match(const std::string &fn) const {
    return fn == "IP6Address::ip4_address() const";
}

std::vector<std::shared_ptr<ExecContext>>
IP6Helper::call(const std::string &fn,
        const std::vector<RegValue> &params,
        std::shared_ptr<ExecContext> state,
        const std::string &dst_reg) {
    // TODO: add something
    if (fn == "IP6Address::ip4_address() const") {
        auto bv_32 = std::make_shared<Symbolic::BitVecType>(32);
        auto val = mk_expr_ptr(SymbolicVar, bv_32, state->name_gen->gen("ip6_to_4"));
        state->set_reg_val(dst_reg, RegValue{val});
        state->inst_iter_++;
        return {state};
    }
    assert(false);
}
