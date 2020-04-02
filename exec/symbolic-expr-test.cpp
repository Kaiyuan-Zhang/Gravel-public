#include "symbolic-expr.hpp"
#include "z3-gen.hpp"
#include "data-structures.hpp"


int main(int argc, char *argv[]) {
    using namespace Symbolic;
    auto bv32_t = std::make_shared<BitVecType>(32);
    auto a = mk_expr_ptr(SymbolicVar, bv32_t, "a");
    auto b = mk_expr_ptr(SymbolicVar, bv32_t, "b");
    auto c = mk_expr_ptr(SymbolicVar, bv32_t, "c");
    auto lhs = mk_expr_ptr(AddExpr, {mk_expr_ptr(MulExpr, {a, c}),
                                     mk_expr_ptr(MulExpr, {b, c})});
    auto rhs = mk_expr_ptr(MulExpr, {c, mk_expr_ptr(AddExpr, {a, b})});
    auto eq = mk_expr_ptr(EqExpr, {lhs, rhs});
    {
        Z3Context ctx;
        auto expr = gen_z3_expr(ctx, eq);
        z3::solver sol(ctx.ctx);
        sol.add(!expr.get_expr());
        std::cout << sol.check() << std::endl;
    }

    auto buffer = std::make_shared<Buffer>("test_buf");
    a = mk_expr_ptr(SymbolicVar, std::make_shared<BitVecType>(64), "a");
    buffer->store(a, RegValue{b});
    auto result = buffer->load(a, 4);
    eq = mk_expr_ptr(EqExpr, {result.get_val(), b});
    {
        Z3Context ctx;
        auto expr = gen_z3_expr(ctx, eq);
        z3::solver sol(ctx.ctx);
        sol.add(!expr.get_expr());
        std::cout << sol.check() << std::endl;
    } /*catch (z3::exception &e) {
        std::cerr << e << std::endl;
    }*/

    std::vector<std::shared_ptr<Symbolic::Type>> kt = {bv32_t, bv32_t};
    std::vector<std::shared_ptr<Symbolic::Type>> vt = {bv32_t};
    auto map = std::make_shared<AbstractMap>("map", kt, vt);
    a = mk_expr_ptr(SymbolicVar, bv32_t, "a");
    map->set_vals({a, b}, {c});
    auto contains = map->contains({a, b});
    auto vals = map->get_vals({a, b});
    {
        Z3Context ctx;
        auto has_key = mk_expr_ptr(EqExpr, {contains, mk_expr_ptr(ConcreteBv, 1, 1)});
        auto val_match = mk_expr_ptr(EqExpr, {c, vals[0]});
        auto goal = mk_expr_ptr(LAndExpr, {has_key, val_match});
        auto expr = gen_z3_expr(ctx, goal).get_expr();
        z3::solver sol(ctx.ctx);
        sol.add(!expr);
        std::cout << sol.check() << std::endl;
    }
    
    return 0;
}
