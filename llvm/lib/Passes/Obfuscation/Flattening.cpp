#include "Utils.h"
#include "CryptoUtils.h"
#include "Flattening.h"
#include "SplitBasicBlock.h"
#include <random>
#include <algorithm>

using namespace llvm;
using std::vector;

#define DEBUG_TYPE "flattening"
STATISTIC(Flattened, "Functions flattened");

PreservedAnalyses FlatteningPass::run(Function& F, FunctionAnalysisManager& AM) {
    Function *tmp = &F;
    if (toObfuscate(flag, tmp, "fla")) {
        INIT_CONTEXT(F);
        if (flatten(*tmp)) {
            ++Flattened;
        }
        return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
}

bool FlatteningPass::flatten(Function &F) {
    if (F.size() <= 1) {
        return false;
    }

    if (F.getName().str().find("$basic_ostream") != std::string::npos) {
        return false;
    }

    vector<BasicBlock*> origBB;

    for (BasicBlock &BB : F) {
        if (isa<InvokeInst>(BB.getTerminator()) || BB.isEHPad()) {
            return false;
        }
        origBB.push_back(&BB);
    }

    // 从 vector 中去除第一个基本块（入口块）
    origBB.erase(origBB.begin());
    BasicBlock &entryBB = F.getEntryBlock();

    // 如果第一个基本块的末尾是条件跳转，单独分离
    if (BranchInst *br = dyn_cast<BranchInst>(entryBB.getTerminator())) {
        if (br->isConditional()) {
            BasicBlock *newBB = entryBB.splitBasicBlock(br, "newBB");
            origBB.insert(origBB.begin(), newBB);
        }
    }

    if (origBB.empty()) {
        return false;
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(origBB.begin(), origBB.end(), rng);

    // 创建分发块和返回块
    BasicBlock *dispatchBB = BasicBlock::Create(*CONTEXT, "dispatchBB", &F, &entryBB);
    BasicBlock *returnBB = BasicBlock::Create(*CONTEXT, "returnBB", &F, &entryBB);
    BranchInst::Create(dispatchBB, returnBB);
    entryBB.moveBefore(dispatchBB);

    entryBB.getTerminator()->eraseFromParent();
    BranchInst *brDispatchBB = BranchInst::Create(dispatchBB, &entryBB);

    // 创建 switch 变量和 XOR key 变量
    AllocaInst *swVarPtr = new AllocaInst(TYPE_I32, 0, "swVar.ptr", brDispatchBB);
    AllocaInst *swXorPtr = new AllocaInst(TYPE_I32, 0, "swXor.ptr", brDispatchBB);

    // 为每个基本块分配 case 值，建立双向映射
    std::map<BasicBlock*, uint32_t> bbCaseMap;
    for (BasicBlock *BB : origBB) {
        bbCaseMap[BB] = cryptoutils->get_uint32_t();
    }

    // 初始化入口的 switch 变量（加密后的值）和 XOR key
    uint32_t firstCase = bbCaseMap[origBB[0]];
    uint32_t entryXorKey = cryptoutils->get_uint32_t();
    uint32_t entryEncVal = firstCase ^ entryXorKey;

    new StoreInst(CONST_I32(entryEncVal), swVarPtr, brDispatchBB);
    new StoreInst(CONST_I32(entryXorKey), swXorPtr, brDispatchBB);

    // 在分发块：load 两个变量，XOR 解密得到真正的 case 值
    LoadInst *swVar = new LoadInst(TYPE_I32, swVarPtr, "swVar", false, dispatchBB);
    LoadInst *swXor = new LoadInst(TYPE_I32, swXorPtr, "swXor", false, dispatchBB);
    BinaryOperator *swDecrypted = BinaryOperator::Create(
        Instruction::Xor, swVar, swXor, "swDecrypted", dispatchBB);

    // 创建 switch
    BasicBlock *swDefault = BasicBlock::Create(*CONTEXT, "swDefault", &F, returnBB);
    BranchInst::Create(returnBB, swDefault);
    SwitchInst *swInst = SwitchInst::Create(swDecrypted, swDefault, origBB.size(), dispatchBB);

    // 添加 case
    for (BasicBlock *BB : origBB) {
        BB->moveBefore(returnBB);
        swInst->addCase(CONST_I32(bbCaseMap[BB]), BB);
    }

    // 处理每个基本块的跳转
    for (BasicBlock *BB : origBB) {
        // 返回块，无后继
        if (BB->getTerminator()->getNumSuccessors() == 0) {
            continue;
        }
        // 非条件跳转
        else if (BB->getTerminator()->getNumSuccessors() == 1) {
            BasicBlock *sucBB = BB->getTerminator()->getSuccessor(0);
            BB->getTerminator()->eraseFromParent();

            // 查找后继块的 case 值
            uint32_t sucCaseVal;
            auto it = bbCaseMap.find(sucBB);
            if (it != bbCaseMap.end()) {
                sucCaseVal = it->second;
            } else {
                // 后继不在 origBB 中，说明是跳到入口块或其他特殊情况
                // 这种情况不应该发生在正常的平坦化流程中
                // 但为了安全，我们跳过这个块的处理
                BranchInst::Create(sucBB, BB);
                continue;
            }

            // 生成新的 XOR key，加密 case 值
            uint32_t xorKey = cryptoutils->get_uint32_t();
            uint32_t encVal = sucCaseVal ^ xorKey;

            new StoreInst(CONST_I32(encVal), swVarPtr, BB);
            new StoreInst(CONST_I32(xorKey), swXorPtr, BB);
            BranchInst::Create(returnBB, BB);
        }
        // 条件跳转
        else if (BB->getTerminator()->getNumSuccessors() == 2) {
            BranchInst *br = dyn_cast<BranchInst>(BB->getTerminator());
            if (!br || !br->isConditional()) {
                continue;
            }

            BasicBlock *sucTrue = br->getSuccessor(0);
            BasicBlock *sucFalse = br->getSuccessor(1);

            // 查找两个后继块的 case 值
            auto itTrue = bbCaseMap.find(sucTrue);
            auto itFalse = bbCaseMap.find(sucFalse);

            // 如果任一后继不在 map 中，保持原跳转
            if (itTrue == bbCaseMap.end() || itFalse == bbCaseMap.end()) {
                continue;
            }

            uint32_t caseTrue = itTrue->second;
            uint32_t caseFalse = itFalse->second;

            // 条件跳转：两个分支用同一个 XOR key
            uint32_t xorKey = cryptoutils->get_uint32_t();
            uint32_t encTrue = caseTrue ^ xorKey;
            uint32_t encFalse = caseFalse ^ xorKey;

            Value *cond = br->getCondition();
            BB->getTerminator()->eraseFromParent();

            SelectInst *sel = SelectInst::Create(
                cond, CONST_I32(encTrue), CONST_I32(encFalse), "selEnc", BB);

            new StoreInst(sel, swVarPtr, BB);
            new StoreInst(CONST_I32(xorKey), swXorPtr, BB);
            BranchInst::Create(returnBB, BB);
        }
    }

    fixStack(F);
    return true;
}

FlatteningPass *llvm::createFlattening(bool flag) {
    return new FlatteningPass(flag);
}
