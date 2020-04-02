#pragma once
#include "data-structures.hpp"


#define DECL_ABS_FUNC_CLS(cls_name)                           \
class cls_name : public AbstractFunc {                        \
public:                                                       \
    virtual bool match(const std::string &fn) const override; \
    virtual std::vector<std::shared_ptr<ExecContext>>         \
    call(const std::string &func_name,                        \
         const std::vector<RegValue> &params,                 \
         std::shared_ptr<ExecContext> state,                  \
         const std::string &dst_reg) override;                \
}

DECL_ABS_FUNC_CLS(PktUniqueify);
DECL_ABS_FUNC_CLS(PktIPHeader);
DECL_ABS_FUNC_CLS(PktGeneral);

DECL_ABS_FUNC_CLS(ElementFuncs);

DECL_ABS_FUNC_CLS(VectorOps);
DECL_ABS_FUNC_CLS(HashMapOps);

DECL_ABS_FUNC_CLS(ByteRotationFunc);

DECL_ABS_FUNC_CLS(IPFlowIDConstr);

DECL_ABS_FUNC_CLS(LLVMMemcpy);
DECL_ABS_FUNC_CLS(LLVMMemset);

DECL_ABS_FUNC_CLS(LLVMMemcmp);

DECL_ABS_FUNC_CLS(ClickLibFunc);

DECL_ABS_FUNC_CLS(IP6Helper);

DECL_ABS_FUNC_CLS(CheckIPHdrHelper);
