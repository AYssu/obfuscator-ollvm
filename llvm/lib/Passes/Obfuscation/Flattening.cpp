//===- Flattening.cpp - Flattening Obfuscation pass------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the flattening pass
//
//===----------------------------------------------------------------------===//

#include "Utils.h"
#include "CryptoUtils.h"
#include "Flattening.h"
#include "llvm/ADT/Statistic.h"
#include <vector>

using namespace std;
using namespace llvm;

#define DEBUG_TYPE "flattening"
STATISTIC(Flattened, "Functions flattened");

PreservedAnalyses FlatteningPass::run(Function &F, FunctionAnalysisManager &AM) {
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
    vector<BasicBlock *> origBB;
    BasicBlock *loopEntry;
    BasicBlock *loopEnd;
    LoadInst *load;
    SwitchInst *switchI;
    AllocaInst *switchVar;

    // SCRAMBLER
    char scrambling_key[16];
    cryptoutils->get_bytes(scrambling_key, 16);
    // END OF SCRAMBLER

    // 注意：原版使用 LowerSwitch 将 switch 转为 if-else
    // 在新 Pass Manager 中，我们跳过这一步，因为：
    // 1. Flattening 会创建新的 switch 来控制流程
    // 2. 原有的 switch 会被当作普通的多后继块处理

    // Save all original BB
    for (Function::iterator i = F.begin(); i != F.end(); ++i) {
        BasicBlock *tmp = &*i;
        origBB.push_back(tmp);

        BasicBlock *bb = &*i;
        if (isa<InvokeInst>(bb->getTerminator())) {
            return false;
        }
    }

    // Nothing to flatten
    if (origBB.size() <= 1) {
        return false;
    }

    // Remove first BB
    origBB.erase(origBB.begin());

    // Get a pointer on the first BB
    Function::iterator tmp = F.begin();
    BasicBlock *insert = &*tmp;

    // If main begin with an if
    BranchInst *br = NULL;
    if (isa<BranchInst>(insert->getTerminator())) {
        br = cast<BranchInst>(insert->getTerminator());
    }

    if ((br != NULL && br->isConditional()) ||
        insert->getTerminator()->getNumSuccessors() > 1) {
        BasicBlock::iterator i = insert->end();
        --i;

        if (insert->size() > 1) {
            --i;
        }

        BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
        origBB.insert(origBB.begin(), tmpBB);
    }

    // Remove jump
    insert->getTerminator()->eraseFromParent();

    // Create switch variable and set as it
    switchVar = new AllocaInst(Type::getInt32Ty(*CONTEXT), 0, "switchVar", insert);
    new StoreInst(
        ConstantInt::get(Type::getInt32Ty(*CONTEXT),
                         cryptoutils->scramble32(0, scrambling_key)),
        switchVar, insert);

    // Create main loop
    loopEntry = BasicBlock::Create(*CONTEXT, "loopEntry", &F, insert);
    loopEnd = BasicBlock::Create(*CONTEXT, "loopEnd", &F, insert);

    load = new LoadInst(Type::getInt32Ty(*CONTEXT), switchVar, "switchVar", loopEntry);

    // Move first BB on top
    insert->moveBefore(loopEntry);
    BranchInst::Create(loopEntry, insert);

    // loopEnd jump to loopEntry
    BranchInst::Create(loopEntry, loopEnd);

    BasicBlock *swDefault =
        BasicBlock::Create(*CONTEXT, "switchDefault", &F, loopEnd);
    BranchInst::Create(loopEnd, swDefault);

    // Create switch instruction itself and set condition
    switchI = SwitchInst::Create(&*F.begin(), swDefault, 0, loopEntry);
    switchI->setCondition(load);

    // Remove branch jump from 1st BB and make a jump to the while
    F.begin()->getTerminator()->eraseFromParent();
    BranchInst::Create(loopEntry, &*F.begin());

    // Put all BB in the switch
    for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end(); ++b) {
        BasicBlock *i = *b;
        ConstantInt *numCase = NULL;

        // Move the BB inside the switch (only visual, no code logic)
        i->moveBefore(loopEnd);

        // Add case to switch
        numCase = cast<ConstantInt>(ConstantInt::get(
            switchI->getCondition()->getType(),
            cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
        switchI->addCase(numCase, i);
    }

    // Recalculate switchVar
    for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end(); ++b) {
        BasicBlock *i = *b;
        ConstantInt *numCase = NULL;

        // Ret BB
        if (i->getTerminator()->getNumSuccessors() == 0) {
            continue;
        }

        // If it's a non-conditional jump
        if (i->getTerminator()->getNumSuccessors() == 1) {
            // Get successor and delete terminator
            BasicBlock *succ = i->getTerminator()->getSuccessor(0);
            i->getTerminator()->eraseFromParent();

            // Get next case
            numCase = switchI->findCaseDest(succ);

            // If next case == default case (switchDefault)
            if (numCase == NULL) {
                numCase = cast<ConstantInt>(ConstantInt::get(
                    switchI->getCondition()->getType(),
                    cryptoutils->scramble32(switchI->getNumCases() - 1, scrambling_key)));
            }

            // Update switchVar and jump to the end of loop
            new StoreInst(numCase, load->getPointerOperand(), i);
            BranchInst::Create(loopEnd, i);
            continue;
        }

        // If it's a conditional jump
        if (i->getTerminator()->getNumSuccessors() == 2) {
            // Get next cases
            ConstantInt *numCaseTrue =
                switchI->findCaseDest(i->getTerminator()->getSuccessor(0));
            ConstantInt *numCaseFalse =
                switchI->findCaseDest(i->getTerminator()->getSuccessor(1));

            // Check if next case == default case (switchDefault)
            if (numCaseTrue == NULL) {
                numCaseTrue = cast<ConstantInt>(ConstantInt::get(
                    switchI->getCondition()->getType(),
                    cryptoutils->scramble32(switchI->getNumCases() - 1, scrambling_key)));
            }

            if (numCaseFalse == NULL) {
                numCaseFalse = cast<ConstantInt>(ConstantInt::get(
                    switchI->getCondition()->getType(),
                    cryptoutils->scramble32(switchI->getNumCases() - 1, scrambling_key)));
            }

            // Create a SelectInst
            BranchInst *br = cast<BranchInst>(i->getTerminator());
            SelectInst *sel =
                SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "",
                                   i->getTerminator());

            // Erase terminator
            i->getTerminator()->eraseFromParent();

            // Update switchVar and jump to the end of loop
            new StoreInst(sel, load->getPointerOperand(), i);
            BranchInst::Create(loopEnd, i);
            continue;
        }
    }

    fixStack(F);

    return true;
}

FlatteningPass *llvm::createFlattening(bool flag) {
    return new FlatteningPass(flag);
}
