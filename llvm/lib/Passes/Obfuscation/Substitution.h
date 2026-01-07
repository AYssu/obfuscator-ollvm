//===- SubstitutionIncludes.h - Substitution Obfuscation pass-------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains includes and defines for the substitution pass
//
//===----------------------------------------------------------------------===//

#ifndef _SUBSTITUTIONS_H_
#define _SUBSTITUTIONS_H_


// LLVM include
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/PassManager.h" //new Pass
#include "llvm/Transforms/IPO.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "CryptoUtils.h"

// Namespace
using namespace llvm;

#define NUMBER_ADD_SUBST 7
#define NUMBER_SUB_SUBST 6
#define NUMBER_AND_SUBST 4
#define NUMBER_OR_SUBST 4
#define NUMBER_XOR_SUBST 4

namespace llvm {
    class SubstitutionPass : public PassInfoMixin<SubstitutionPass> {
        public:
          bool flag;
          void (SubstitutionPass::*funcAdd[NUMBER_ADD_SUBST])(BinaryOperator *bo);
          void (SubstitutionPass::*funcSub[NUMBER_SUB_SUBST])(BinaryOperator *bo);
          void (SubstitutionPass::*funcAnd[NUMBER_AND_SUBST])(BinaryOperator *bo);
          void (SubstitutionPass::*funcOr[NUMBER_OR_SUBST])(BinaryOperator *bo);
          void (SubstitutionPass::*funcXor[NUMBER_XOR_SUBST])(BinaryOperator *bo);

          SubstitutionPass(bool flag) {
            this->flag = flag;
            funcAdd[0] = &SubstitutionPass::addNeg;
            funcAdd[1] = &SubstitutionPass::addDoubleNeg;
            funcAdd[2] = &SubstitutionPass::addRand;
            funcAdd[3] = &SubstitutionPass::addRand2;
            funcAdd[4] = &SubstitutionPass::addMBA1;  // MBA: (x^y) + 2*(x&y)
            funcAdd[5] = &SubstitutionPass::addMBA2;  // MBA: (x|y) + (x&y)
            funcAdd[6] = &SubstitutionPass::addMBA3;  // MBA: 2*(x|y) - (x^y)

            funcSub[0] = &SubstitutionPass::subNeg;
            funcSub[1] = &SubstitutionPass::subRand;
            funcSub[2] = &SubstitutionPass::subRand2;
            funcSub[3] = &SubstitutionPass::subMBA1;  // MBA: (x^y) - 2*(~x&y)
            funcSub[4] = &SubstitutionPass::subMBA2;  // MBA: (x&~y) - (~x&y)
            funcSub[5] = &SubstitutionPass::subMBA3;  // MBA: 2*(x&~y) - (x^y)

            funcAnd[0] = &SubstitutionPass::andSubstitution;
            funcAnd[1] = &SubstitutionPass::andSubstitutionRand;
            funcAnd[2] = &SubstitutionPass::andMBA1;  // MBA: (x|y) - (x^y)
            funcAnd[3] = &SubstitutionPass::andMBA2;  // MBA: ~(~x|~y)

            funcOr[0] = &SubstitutionPass::orSubstitution;
            funcOr[1] = &SubstitutionPass::orSubstitutionRand;
            funcOr[2] = &SubstitutionPass::orMBA1;    // MBA: (x&y) + (x^y)
            funcOr[3] = &SubstitutionPass::orMBA2;    // MBA: ~(~x&~y)

            funcXor[0] = &SubstitutionPass::xorSubstitution;
            funcXor[1] = &SubstitutionPass::xorSubstitutionRand;
            funcXor[2] = &SubstitutionPass::xorMBA1;  // MBA: (x|y) - (x&y)
            funcXor[3] = &SubstitutionPass::xorMBA2;  // MBA: (x|y) & (~x|~y)
          }

          PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
          bool substitute(Function *f);

          void addNeg(BinaryOperator *bo);
          void addDoubleNeg(BinaryOperator *bo);
          void addRand(BinaryOperator *bo);
          void addRand2(BinaryOperator *bo);

          void subNeg(BinaryOperator *bo);
          void subRand(BinaryOperator *bo);
          void subRand2(BinaryOperator *bo);

          void andSubstitution(BinaryOperator *bo);
          void andSubstitutionRand(BinaryOperator *bo);

          void orSubstitution(BinaryOperator *bo);
          void orSubstitutionRand(BinaryOperator *bo);

          void xorSubstitution(BinaryOperator *bo);
          void xorSubstitutionRand(BinaryOperator *bo);

          // MBA 变体
          void addMBA1(BinaryOperator *bo);  // (x^y) + 2*(x&y)
          void addMBA2(BinaryOperator *bo);  // (x|y) + (x&y)
          void addMBA3(BinaryOperator *bo);  // 2*(x|y) - (x^y)
          void subMBA1(BinaryOperator *bo);  // (x^y) - 2*(~x&y)
          void subMBA2(BinaryOperator *bo);  // (x&~y) - (~x&y)
          void subMBA3(BinaryOperator *bo);  // 2*(x&~y) - (x^y)
          void andMBA1(BinaryOperator *bo);  // (x|y) - (x^y)
          void andMBA2(BinaryOperator *bo);  // ~(~x|~y)
          void orMBA1(BinaryOperator *bo);   // (x&y) + (x^y)
          void orMBA2(BinaryOperator *bo);   // ~(~x&~y)
          void xorMBA1(BinaryOperator *bo);  // (x|y) - (x&y)
          void xorMBA2(BinaryOperator *bo);  // (x|y) & (~x|~y)

          static bool isRequired() { return true; } // ֱ�ӷ���true����
    };
    SubstitutionPass *createSubstitutionPass(bool flag); // ����������ָ�
} // namespace llvm

#endif

