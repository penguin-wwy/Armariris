#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/CryptoUtils.h"

#define DEBUG_TYPE "flattening"

using namespace llvm;

// Stats
STATISTIC(Flattened, "Functions flattened");

static cl::opt<string> FunctionName(
        "funcFLA", cl::init(""),
        cl::desc(
                "Flatten only certain functions: -mllvm -funcFLA=\"func1,func2\""));

static cl::opt<int> Percentage(
        "perFLA", cl::init(100),
        cl::desc("Flatten only a certain percentage of functions"));

namespace {
    struct Flattening : public FunctionPass {
        static char ID;  // Pass identification, replacement for typeid
        bool flag;

        Flattening() : FunctionPass(ID) {}

        Flattening(bool flag) : FunctionPass(ID) {
            this->flag = flag;
            // Check if the number of applications is correct
            if (!((Percentage > 0) && (Percentage <= 100))) {
                LLVMContext ctx;
                ctx.emitError(Twine("Flattening application function percentage -perFLA=x must be 0 < x <= 100"));
            }
        }

        bool runOnFunction(Function &F);

        bool flatten(Function *f);

        bool addBougusControlFlow(Function &func);
    };
}

char Flattening::ID = 0;
static RegisterPass<Flattening> X("flattening", "Call graph flattening");

Pass *llvm::createFlattening(bool flag) { return new Flattening(flag); }

void changeToAltered(BasicBlock *alteredBlock) {
    for ( BasicBlock::iterator I = alteredBlock->begin(); I != alteredBlock->end(); I++ ) {
        std::set<Instruction *> willDelete;
        Instruction::BinaryOps firstArray[13] = {Instruction::Xor, Instruction::Or, Instruction::And,
                                               Instruction::Add, Instruction::Sub, Instruction::Mul, Instruction::UDiv,
                                               Instruction::SDiv, Instruction::URem, Instruction::SRem, Instruction::Shl,
                                               Instruction::LShr, Instruction::AShr};
        Instruction::BinaryOps secondArray[5] = {Instruction::FAdd, Instruction::FSub, Instruction::FMul,
                                                Instruction::FDiv, Instruction::FRem};
        if ( I->isBinaryOp() ) {
            unsigned opcode = I->getOpcode();
            BinaryOperator *op = NULL;

            if ( opcode == Instruction::Add || opcode == Instruction::Sub ||
                 opcode == Instruction::Mul || opcode == Instruction::UDiv ||
                 opcode == Instruction::SDiv || opcode == Instruction::URem ||
                 opcode == Instruction::SRem || opcode == Instruction::Shl ||
                 opcode == Instruction::LShr || opcode == Instruction::AShr ||
                 opcode == Instruction::And || opcode == Instruction::Or ||
                 opcode == Instruction::Xor ) {
                for ( int random = (int)llvm::cryptoutils->get_range(2); random < 3; random++ ) {
                    unsigned randOp = llvm::cryptoutils->get_range(13);
                    switch ( llvm::cryptoutils->get_range(4) ) {
                        case 0:
                            BinaryOperator::Create(firstArray[randOp], I->getOperand(0),
                                                   I->getOperand(1), I->getName(), &*I);
                            if ( willDelete.find(&*I) == willDelete.end() ) {
                                willDelete.insert(&*I);
                            }
                            break;
                        case 1:
                            BinaryOperator::Create(firstArray[randOp], I->getOperand(0),
                                                   I->getOperand(1), I->getName(), &*I);
                            break;
                        case 2:
                            op = BinaryOperator::Create(firstArray[randOp], I->getOperand(0), I->getOperand(1), "", &*I);
                            BinaryOperator::Create(firstArray[randOp], op, I->getOperand(1), "", &*I);
                            break;
                        case 3:
                            if ( op != nullptr )
                                BinaryOperator::Create(firstArray[randOp], op, I->getOperand(1), "", &*I);
                            else
                                BinaryOperator::Create(firstArray[randOp], I->getOperand(0), I->getOperand(1), "", &*I);
                            break;
                        default:
                            break;
                    }
                }
            }
            if ( opcode == Instruction::FAdd || opcode == Instruction::FSub ||
                 opcode == Instruction::FMul || opcode == Instruction::FDiv ||
                 opcode == Instruction::FRem ) {
                for (int random = (int) llvm::cryptoutils->get_range(2); random < 3; ++random) {
                    unsigned randOp = llvm::cryptoutils->get_range(5);
                    switch (llvm::cryptoutils->get_range(3)) { // can be improved
                        case 0: //do nothing
                            BinaryOperator::Create(secondArray[randOp], I->getOperand(0), I->getOperand(1),
                                               I->getName(), &*I);
                            if ( willDelete.find(&*I) == willDelete.end() ) {
                                willDelete.insert(&*I);
                            }
                            break;
                        case 1:
                            BinaryOperator::Create(secondArray[randOp], I->getOperand(0),
                                                   I->getOperand(1), I->getName(), &*I);
                            break;
                        case 2:
                            op = BinaryOperator::Create(secondArray[randOp], I->getOperand(0),
                                                        I->getOperand(1), "", &*I);
                            BinaryOperator::Create(secondArray[randOp], op,
                                                         I->getOperand(1), "", &*I);
                            break;
                    }
                }
            }
            ICmpInst::Predicate ICmpPreArray[] = {ICmpInst::ICMP_EQ, ICmpInst::ICMP_NE, ICmpInst::ICMP_UGT,
                                                  ICmpInst::ICMP_UGE, ICmpInst::ICMP_ULE, ICmpInst::ICMP_ULT,
                                                  ICmpInst::ICMP_SGE, ICmpInst::ICMP_SGT, ICmpInst::ICMP_SLE,
                                                  ICmpInst::ICMP_SLT};
            if ( opcode == Instruction::ICmp ) {
                ICmpInst *currentI = (ICmpInst *) (&I);
                switch (llvm::cryptoutils->get_range(3)) { // must be improved
                    case 0: //do nothing
                        break;
                    case 1:
                        currentI->swapOperands();
                        break;
                    case 2: // randomly change the predicate
                        currentI->setPredicate(ICmpPreArray[llvm::cryptoutils->get_range(10)]);
                        break;
                }
            }
            FCmpInst::Predicate FCmpPreArray[] = {FCmpInst::FCMP_OEQ, FCmpInst::FCMP_ONE, FCmpInst::FCMP_UGE,
                                                  FCmpInst::FCMP_UGT, FCmpInst::FCMP_ULE, FCmpInst::FCMP_ULT,
                                                  FCmpInst::FCMP_OGE, FCmpInst::FCMP_OGT, FCmpInst::FCMP_OLT,
                                                  FCmpInst::FCMP_OLE};
            if ( opcode == Instruction::FCmp ) {
                FCmpInst *currentI = (FCmpInst *) (&I);
                switch (llvm::cryptoutils->get_range(3)) { // must be improved
                    case 0: //do nothing
                        break;
                    case 1:
                        currentI->swapOperands();
                        break;
                    case 2: // randomly change the predicate
                        currentI->setPredicate(FCmpPreArray[llvm::cryptoutils->get_range(10)]);
                        break;
                }
            }
        }
    }
}

void addBogusFlow(BasicBlock *basicBlock, Function &func, AllocaInst *randNum) {
    BasicBlock::iterator middle = basicBlock->end();
    int pos = basicBlock->size() / 2;
    while (pos--) {
        middle--;
    }
    BasicBlock *realBlock = basicBlock->splitBasicBlock(middle, "RealBlock");
    ValueToValueMapTy VMap;
    BasicBlock::iterator ji = realBlock->begin();
    BasicBlock *alteredBlock = llvm::CloneBasicBlock(realBlock, VMap, "AlteredBlock", &func);
    for ( BasicBlock::iterator I = alteredBlock->begin(); I != alteredBlock->end(); I++ ) {

        for ( User::op_iterator OpI = I->op_begin(); OpI != I->op_end(); OpI++ ) {
            Value *v = MapValue(*OpI, VMap, RF_None, 0);
            if ( v != 0 ) {
                *OpI = v;
            }
        }

        if ( PHINode *PN = dyn_cast<PHINode>(I) ) {
            for ( unsigned j = 0, e = PN->getNumIncomingValues(); j != e; j++ ) {
                Value *v = MapValue(PN->getIncomingBlock(j), VMap, RF_None, 0);
                if ( v != 0 ) {
                    PN->setIncomingBlock(j, cast<BasicBlock>(v));
                }
            }
        }
        SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
        I->getAllMetadata(MDs);
        I->setDebugLoc(ji->getDebugLoc());
        ji++;
    }
    changeToAltered(alteredBlock);

    TerminatorInst *end = basicBlock->getTerminator();
    LoadInst *loadInst = new LoadInst(randNum, "", end);
    BinaryOperator *sub = BinaryOperator::Create(Instruction::Sub, (Value *)loadInst,
                                ConstantInt::get(Type::getInt32Ty(func.getContext()), 1, false),
                                "", end);
    BinaryOperator *mul = BinaryOperator::Create(Instruction::Mul, (Value *)loadInst, sub, "", end);
    BinaryOperator *rem = BinaryOperator::Create(Instruction::URem, mul,
                                ConstantInt::get(Type::getInt32Ty(func.getContext()), 2,
                                                 false), "", end);
    ICmpInst *condition = new ICmpInst(end, ICmpInst::ICMP_EQ, rem,
                             ConstantInt::get(Type::getInt32Ty(func.getContext()), 0,
                                              false));
    BranchInst::Create(realBlock, alteredBlock, (Value *)condition, basicBlock);
    end->eraseFromParent();
    alteredBlock->getTerminator()->setSuccessor(0, realBlock->getTerminator()->getSuccessor(0));
}

bool Flattening::addBougusControlFlow(Function &func) {
    unsigned average = 0;
    int sumLength = 0;
    std::list<BasicBlock *> basicBlocks;
    for ( Function::iterator I = func.begin(); I != func.end(); I++ ) {
        if ( I == func.begin() ) {
            continue;
        }
        sumLength += I->size();
        basicBlocks.push_back(&*I);
    }
    average = sumLength / func.size();
    BasicBlock::iterator begin = func.begin()->begin();
    AllocaInst *randNum = new AllocaInst(Type::getInt32Ty(func.getContext()), 0, "", &*begin);
    while (strcmp(begin->getOpcodeName(), "store")) {
        begin++;
    }
    new StoreInst(ConstantInt::get(Type::getInt32Ty(func.getContext()), llvm::cryptoutils->get_range(100) + 1),
                  randNum, &*begin);
    for ( std::list<BasicBlock *>::iterator I = basicBlocks.begin(); I != basicBlocks.end(); I++ ) {
        if ( (*I)->size() > average ) {
            addBogusFlow(*I, func, randNum);
        }
    }
    return true;
}

bool Flattening::runOnFunction(Function &F) {
    Function *tmp = &F;
    // Do we obfuscate
    if (toObfuscate(flag, tmp, "fla") && ((int) llvm::cryptoutils->get_range(100) <= Percentage)) {
        errs() << "fla " + F.getName() +"\n";
        addBougusControlFlow(F);
        if (flatten(tmp)) {
            ++Flattened;
        }
    }

    return false;
}

bool Flattening::flatten(Function *f) {
    std::vector<BasicBlock *> origBB;
    BasicBlock *loopEntry;
    BasicBlock *loopEnd;
    LoadInst *load;
    SwitchInst *switchI;
    AllocaInst *switchVar;

    // SCRAMBLER
    char scrambling_key[16];
    llvm::cryptoutils->get_bytes(scrambling_key, 16);
    // END OF SCRAMBLER

    // Lower switch
    FunctionPass *lower = createLowerSwitchPass();
    lower->runOnFunction(*f);

    // Save all original BB
    for (Function::iterator i = f->begin(); i != f->end(); ++i) {
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
    Function::iterator tmp = f->begin();  //++tmp;
    BasicBlock *insert = &*tmp;

    // If main begin with an if
    BranchInst *br = NULL;
    if (isa<BranchInst>(insert->getTerminator())) {
        br = cast<BranchInst>(insert->getTerminator());
    }

    if ((br != NULL && br->isConditional()) ||
        insert->getTerminator()->getNumSuccessors() > 1) {
        BasicBlock::iterator i = insert->back().getIterator();

        if (insert->size() > 1) {
            i--;
        }

        BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
        origBB.insert(origBB.begin(), tmpBB);
    }

    // Remove jump
    insert->getTerminator()->eraseFromParent();

    // Create switch variable and set as it
    switchVar =
            new AllocaInst(Type::getInt32Ty(f->getContext()), 0, "switchVar", insert);
    new StoreInst(
            ConstantInt::get(Type::getInt32Ty(f->getContext()),
                             llvm::cryptoutils->scramble32(0, scrambling_key)),
            switchVar, insert);

    // Create main loop
    loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);
    loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

    load = new LoadInst(switchVar, "switchVar", loopEntry);

    // Move first BB on top
    insert->moveBefore(loopEntry);
    BranchInst::Create(loopEntry, insert);

    // loopEnd jump to loopEntry
    BranchInst::Create(loopEntry, loopEnd);

    BasicBlock *swDefault =
            BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
    BranchInst::Create(loopEnd, swDefault);

    // Create switch instruction itself and set condition
    switchI = SwitchInst::Create(&*(f->begin()), swDefault, 0, loopEntry);
    switchI->setCondition(load);

    // Remove branch jump from 1st BB and make a jump to the while
    f->begin()->getTerminator()->eraseFromParent();

    BranchInst::Create(loopEntry, &*(f->begin()));

    // Put all BB in the switch
    for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
         ++b) {
        BasicBlock *i = *b;
        ConstantInt *numCase = NULL;

        // Move the BB inside the switch (only visual, no code logic)
        i->moveBefore(loopEnd);

        // Add case to switch
        numCase = cast<ConstantInt>(ConstantInt::get(
                switchI->getCondition()->getType(),
                llvm::cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
        switchI->addCase(numCase, i);
    }

    // Recalculate switchVar
    for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
         ++b) {
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
                numCase = cast<ConstantInt>(
                        ConstantInt::get(switchI->getCondition()->getType(),
                                         llvm::cryptoutils->scramble32(
                                                 switchI->getNumCases() - 1, scrambling_key)));
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
                numCaseTrue = cast<ConstantInt>(
                        ConstantInt::get(switchI->getCondition()->getType(),
                                         llvm::cryptoutils->scramble32(
                                                 switchI->getNumCases() - 1, scrambling_key)));
            }

            if (numCaseFalse == NULL) {
                numCaseFalse = cast<ConstantInt>(
                        ConstantInt::get(switchI->getCondition()->getType(),
                                         llvm::cryptoutils->scramble32(
                                                 switchI->getNumCases() - 1, scrambling_key)));
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

    fixStack(f);

    return true;
}
