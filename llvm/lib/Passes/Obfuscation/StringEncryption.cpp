#include "StringEncryption.h"

#define DEBUG_TYPE "strenc"

using namespace llvm;

PreservedAnalyses StringEncryptionPass::run(Module &M, ModuleAnalysisManager &AM) {
  if (this->flag) {
    outs() << "[Soule] force.run.StringEncryptionPass\n";
    if (do_StrEnc(M, AM))
      return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

bool StringEncryptionPass::do_StrEnc(Module &M, ModuleAnalysisManager &AM) {
  std::set<GlobalVariable *> ConstantStringUsers;
  LLVMContext &Ctx = M.getContext();
  ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);

  // 收集所有 C 字符串
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer() ||
        GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
      continue;
    }
    Constant *Init = GV.getInitializer();
    if (Init == nullptr)
      continue;
    if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
      if (CDS->isCString()) {
        CSPEntry *Entry = new CSPEntry();
        StringRef Data = CDS->getRawDataValues();
        Entry->Data.reserve(Data.size());
        for (unsigned i = 0; i < Data.size(); ++i) {
          Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
        }
        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
        Entry->DecGV = nullptr;
        Entry->DecStatus = nullptr;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&GV] = Entry;
        collectConstantStringUser(&GV, ConstantStringUsers);
      }
    }
  }

  if (ConstantStringPool.empty()) {
    return false;
  }

  // 加密字符串
  for (CSPEntry *Entry : ConstantStringPool) {
    getRandomBytes(Entry->EncKey, 16, 32);
    for (unsigned i = 0; i < Entry->Data.size(); ++i) {
      Entry->Data[i] ^= Entry->EncKey[i % Entry->EncKey.size()];
    }
  }

  // 构建加密字符串表
  std::vector<uint8_t> Data;
  std::vector<uint8_t> JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry : ConstantStringPool) {
    JunkBytes.clear();
    getRandomBytes(JunkBytes, 16, 32);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
    Entry->Offset = static_cast<unsigned>(Data.size());
    Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
    Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
  }

  Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
  EncryptedStringTable = new GlobalVariable(
      M, CDA->getType(), true, GlobalValue::PrivateLinkage,
      CDA, "EncryptedStringTable");

  // 为每个字符串创建解密函数
  for (CSPEntry *Entry : ConstantStringPool) {
    Entry->DecFunc = buildDecryptFunction(&M, Entry);
  }

  // 处理常量字符串用户（结构体等）
  for (GlobalVariable *GV : ConstantStringUsers) {
    if (isValidToEncrypt(GV)) {
      Type *EltType = GV->getValueType();
      ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(EltType);
      GlobalVariable *DecGV = new GlobalVariable(
          M, EltType, false, GlobalValue::PrivateLinkage,
          ZeroInit, "dec_" + GV->getName());
      DecGV->setAlignment(MaybeAlign(GV->getAlignment()));
      GlobalVariable *DecStatus = new GlobalVariable(
          M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage, Zero,
          "dec_status_" + GV->getName());
      CSUser *User = new CSUser(EltType, GV, DecGV);
      User->DecStatus = DecStatus;
      User->InitFunc = buildInitFunction(&M, User);
      CSUserMap[GV] = User;
    }
  }

  // 在每个使用点进行栈上解密
  bool Changed = false;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&F);
  }

  for (auto &I : CSUserMap) {
    CSUser *User = I.second;
    Changed |= processConstantStringUse(User->InitFunc);
  }

  deleteUnusedGlobalVariable();
  return Changed;
}

// 构建解密函数：解密到传入的缓冲区，然后清零
// void decrypt_xxx(uint8_t *out_buf, const uint8_t *enc_data, uint32_t key_size, uint32_t data_size)
Function *StringEncryptionPass::buildDecryptFunction(Module *M, const CSPEntry *Entry) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
  
  // 函数签名: void(i8*, i8*)
  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx), {IRB.getPtrTy(), IRB.getPtrTy()}, false);
  Function *DecFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      "decrypt_str_" + Twine::utohexstr(Entry->ID), M);

  auto ArgIt = DecFunc->arg_begin();
  Argument *OutBuf = ArgIt++;
  Argument *EncData = ArgIt;
  OutBuf->setName("out");
  EncData->setName("data");

  BasicBlock *Entry_BB = BasicBlock::Create(Ctx, "entry", DecFunc);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", DecFunc);

  uint32_t KeySize = Entry->EncKey.size();
  uint32_t DataSize = Entry->Data.size();

  // Entry: 跳转到循环
  IRB.SetInsertPoint(Entry_BB);
  IRB.CreateBr(Loop);

  // Loop: 解密循环
  IRB.SetInsertPoint(Loop);
  PHINode *I = IRB.CreatePHI(IRB.getInt32Ty(), 2, "i");
  I->addIncoming(IRB.getInt32(0), Entry_BB);

  // key 在 data 开头
  Value *KeyIdx = IRB.CreateURem(I, IRB.getInt32(KeySize));
  Value *KeyPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncData, KeyIdx);
  Value *KeyByte = IRB.CreateLoad(IRB.getInt8Ty(), KeyPtr);

  // 加密数据在 key 之后
  Value *EncIdx = IRB.CreateAdd(I, IRB.getInt32(KeySize));
  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncData, EncIdx);
  Value *EncByte = IRB.CreateLoad(IRB.getInt8Ty(), EncPtr);

  // XOR 解密
  Value *DecByte = IRB.CreateXor(EncByte, KeyByte);
  Value *OutPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), OutBuf, I);
  IRB.CreateStore(DecByte, OutPtr);

  // 循环计数
  Value *NextI = IRB.CreateAdd(I, IRB.getInt32(1));
  I->addIncoming(NextI, Loop);
  Value *Cond = IRB.CreateICmpULT(NextI, IRB.getInt32(DataSize));
  IRB.CreateCondBr(Cond, Loop, Exit);

  // Exit
  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();

  return DecFunc;
}

bool StringEncryptionPass::processConstantStringUse(Function *F) {
  if (!toObfuscate(flag, F, "cse")) {
    return false;
  }
  if (Options && Options->skipFunction(F->getName())) {
    return false;
  }

  LowerConstantExpr(*F);
  LLVMContext &Ctx = F->getContext();
  bool Changed = false;

  // 收集所有需要处理的指令（普通指令）
  std::vector<std::pair<Instruction*, GlobalVariable*>> ToProcess;
  // 收集 PHI 节点需要处理的情况: <PHINode, incoming index, GV>
  std::vector<std::tuple<PHINode*, unsigned, GlobalVariable*>> PhiToProcess;

  for (BasicBlock &BB : *F) {
    if (BB.isEHPad()) continue;
    
    for (Instruction &Inst : BB) {
      if (Inst.isEHPad()) continue;

      // 处理 PHI 节点
      if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
        for (unsigned i = 0; i < PHI->getNumIncomingValues(); ++i) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
            if (CSPEntryMap.find(GV) != CSPEntryMap.end()) {
              PhiToProcess.push_back({PHI, i, GV});
            }
          }
        }
        continue;
      }

      // 处理普通指令
      for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Inst.getOperand(i))) {
          if (CSPEntryMap.find(GV) != CSPEntryMap.end()) {
            ToProcess.push_back({&Inst, GV});
          }
        }
      }
    }
  }

  // 处理 PHI 节点：在对应的前驱块末尾解密
  for (auto &P : PhiToProcess) {
    PHINode *PHI = std::get<0>(P);
    unsigned IncomingIdx = std::get<1>(P);
    GlobalVariable *GV = std::get<2>(P);
    CSPEntry *Entry = CSPEntryMap[GV];

    if (!Entry->DecFunc) continue;

    // 在前驱块的 terminator 之前插入解密代码
    BasicBlock *IncomingBB = PHI->getIncomingBlock(IncomingIdx);
    Instruction *InsertPoint = IncomingBB->getTerminator();
    IRBuilder<> IRB(InsertPoint);
    uint32_t StrSize = Entry->Data.size();

    // 1. 栈上分配
    AllocaInst *StackBuf = IRB.CreateAlloca(
        IRB.getInt8Ty(), IRB.getInt32(StrSize), "str_buf_phi");
    StackBuf->setAlignment(Align(1));

    // 2. 获取加密数据指针
    Value *EncDataPtr = IRB.CreateInBoundsGEP(
        EncryptedStringTable->getValueType(),
        EncryptedStringTable,
        {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});

    // 3. 调用解密函数
    IRB.CreateCall(Entry->DecFunc, {StackBuf, EncDataPtr});

    // 4. 替换 PHI 的 incoming value
    PHI->setIncomingValue(IncomingIdx, StackBuf);
    MaybeDeadGlobalVars.insert(GV);
    Changed = true;
  }

  // 处理普通指令的使用点
  for (auto &P : ToProcess) {
    Instruction *Inst = P.first;
    GlobalVariable *GV = P.second;
    CSPEntry *Entry = CSPEntryMap[GV];

    if (!Entry->DecFunc) continue;

    IRBuilder<> IRB(Inst);
    uint32_t StrSize = Entry->Data.size();

    // 1. 栈上分配
    AllocaInst *StackBuf = IRB.CreateAlloca(
        IRB.getInt8Ty(), IRB.getInt32(StrSize), "str_buf");
    StackBuf->setAlignment(Align(1));

    // 2. 获取加密数据指针
    Value *EncDataPtr = IRB.CreateInBoundsGEP(
        EncryptedStringTable->getValueType(),
        EncryptedStringTable,
        {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});

    // 3. 调用解密函数
    IRB.CreateCall(Entry->DecFunc, {StackBuf, EncDataPtr});

    // 4. 替换引用
    Inst->replaceUsesOfWith(GV, StackBuf);
    MaybeDeadGlobalVars.insert(GV);
    Changed = true;

    // 5. 在使用指令之后插入清零
    // 如果使用指令是 call，在 call 返回后清零
    Instruction *InsertPoint = Inst->getNextNode();
    if (InsertPoint && !InsertPoint->isTerminator()) {
      IRBuilder<> IRBAfter(InsertPoint);
      // volatile memset 防止被优化掉
      IRBAfter.CreateMemSet(StackBuf, IRBAfter.getInt8(0), StrSize, Align(1), true);
    }
  }

  return Changed;
}

void StringEncryptionPass::getRandomBytes(std::vector<uint8_t> &Bytes,
                                          uint32_t MinSize, uint32_t MaxSize) {
  uint32_t N = RandomEngine.get_uint32_t();
  uint32_t Len;
  assert(MaxSize >= MinSize);
  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize + (N % (MaxSize - MinSize));
  }
  char *Buffer = new char[Len];
  RandomEngine.get_bytes(Buffer, Len);
  for (uint32_t i = 0; i < Len; ++i) {
    Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
  }
  delete[] Buffer;
}

Function *StringEncryptionPass::buildInitFunction(Module *M, const CSUser *User) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
  FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx),
                                           {User->DecGV->getType()}, false);
  Function *InitFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      "__global_variable_initializer_" + User->GV->getName(), M);

  auto ArgIt = InitFunc->arg_begin();
  Argument *thiz = ArgIt;
  thiz->setName("this");
  thiz->addAttr(Attribute::NoCapture);

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
  BasicBlock *InitBlock = BasicBlock::Create(Ctx, "InitBlock", InitFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

  IRB.SetInsertPoint(Enter);
  Value *DecStatus = IRB.CreateLoad(User->DecStatus->getValueType(), User->DecStatus);
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
  IRB.CreateCondBr(IsDecrypted, Exit, InitBlock);

  IRB.SetInsertPoint(InitBlock);
  Constant *Init = User->GV->getInitializer();
  lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);
  IRB.CreateStore(IRB.getInt32(1), User->DecStatus);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();
  return InitFunc;
}

void StringEncryptionPass::lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB,
                                               Value *Ptr, Type *Ty) {
  if (isa<ConstantAggregateZero>(CV)) {
    IRB.CreateStore(CV, Ptr);
    return;
  }
  if (ConstantArray *CA = dyn_cast<ConstantArray>(CV)) {
    lowerGlobalConstantArray(CA, IRB, Ptr, Ty);
  } else if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CV)) {
    lowerGlobalConstantStruct(CS, IRB, Ptr, Ty);
  } else {
    IRB.CreateStore(CV, Ptr);
  }
}

void StringEncryptionPass::lowerGlobalConstantArray(ConstantArray *CA,
                                                    IRBuilder<> &IRB, Value *Ptr,
                                                    Type *Ty) {
  for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
    Constant *CV = CA->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

void StringEncryptionPass::lowerGlobalConstantStruct(ConstantStruct *CS,
                                                     IRBuilder<> &IRB, Value *Ptr,
                                                     Type *Ty) {
  for (unsigned i = 0, e = CS->getNumOperands(); i != e; ++i) {
    Constant *CV = CS->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

void StringEncryptionPass::collectConstantStringUser(
    GlobalVariable *CString, std::set<GlobalVariable *> &Users) {
  SmallPtrSet<Value *, 16> Visited;
  SmallVector<Value *, 16> ToVisit;
  ToVisit.push_back(CString);
  while (!ToVisit.empty()) {
    Value *V = ToVisit.pop_back_val();
    if (Visited.count(V) > 0) continue;
    Visited.insert(V);
    for (Value *User : V->users()) {
      if (auto *GV = dyn_cast<GlobalVariable>(User)) {
        Users.insert(GV);
      } else {
        ToVisit.push_back(User);
      }
    }
  }
}

bool StringEncryptionPass::isValidToEncrypt(GlobalVariable *GV) {
  if (GV->isConstant() && GV->hasInitializer()) {
    return GV->getInitializer() != nullptr;
  }
  return false;
}

void StringEncryptionPass::deleteUnusedGlobalVariable() {
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto Iter = MaybeDeadGlobalVars.begin(); Iter != MaybeDeadGlobalVars.end();) {
      GlobalVariable *GV = *Iter;
      if (!GV->hasLocalLinkage()) { ++Iter; continue; }
      GV->removeDeadConstantUsers();
      if (GV->use_empty()) {
        if (GV->hasInitializer()) {
          Constant *Init = GV->getInitializer();
          GV->setInitializer(nullptr);
          if (isSafeToDestroyConstant(Init)) Init->destroyConstant();
        }
        Iter = MaybeDeadGlobalVars.erase(Iter);
        GV->eraseFromParent();
        Changed = true;
      } else {
        ++Iter;
      }
    }
  }
}

StringEncryptionPass *llvm::createStringEncryption(bool flag) {
  return new StringEncryptionPass(flag);
}
