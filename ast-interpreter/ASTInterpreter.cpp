//==--- tools/clang-check/ClangInterpreter.cpp - Clang Interpreter tool --------------===//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/EvaluatedExprVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include <iostream>

using namespace clang;
using namespace std;

#include "Environment.h"

unsigned int step = 0;

// EvaluatedExprVisitor - This class visits 'Expr *'s.
class InterpreterVisitor : 
   public EvaluatedExprVisitor<InterpreterVisitor> {
public:
   explicit InterpreterVisitor(const ASTContext &context, Environment * env)
   : EvaluatedExprVisitor(context), mEnv(env) {}
   virtual ~InterpreterVisitor() {}

   virtual void VisitBinaryOperator (BinaryOperator * bop) {
      if (mEnv->checkretstatus())
         return;
	   VisitStmt(bop);
	   mEnv->binop(bop);
   }
   virtual void VisitDeclRefExpr(DeclRefExpr * expr) {
      if (mEnv->checkretstatus())
         return;
	   VisitStmt(expr);
	   mEnv->declref(expr);
   }

   virtual void VisitCastExpr(CastExpr * expr) {
      if (mEnv->checkretstatus())
         return;
	   VisitStmt(expr);
	   mEnv->cast(expr);
   } 

   virtual void VisitArraySubscriptExpr(ArraySubscriptExpr * expr) {
      if (mEnv->checkretstatus())
         return;
      mEnv->array(expr);
   }

   // call a function
   virtual void VisitCallExpr(CallExpr * call) {
      if (mEnv->checkretstatus())
         return;
	   VisitStmt(call);
	   mEnv->call(call);
      FunctionDecl * fdecl = call->getDirectCallee();
      if (!(fdecl->getName().equals("GET")) && !(fdecl->getName().equals("PRINT"))
       && !(fdecl->getName().equals("MALLOC")) && !(fdecl->getName().equals("FREE"))
       && !(fdecl->getName().equals("main")))
      {
         VisitStmt(fdecl->getBody());
         mEnv->freturn(call);
      }
   }

   virtual void VisitIfStmt(IfStmt *ifstmt) {
      if (mEnv->checkretstatus())
         return;
      if (mEnv->condition(ifstmt))
         Visit(mEnv->getPC());
   }

   virtual void VisitWhileStmt(WhileStmt *whilestmt) {
      if (mEnv->checkretstatus())
         return;
      while(mEnv->whilestmt(whilestmt)) {
         Visit(mEnv->getPC());
      }
   }

   virtual void VisitForStmt(ForStmt *forstmt) {
      if (mEnv->checkretstatus())
         return;
      if (mEnv->checkforinit(forstmt))
         Visit(forstmt->getInit());
      while (mEnv->checkforcond(forstmt)) {
         Visit(forstmt->getBody());
         Visit(forstmt->getInc());
      }
   }

   virtual void VisitDeclStmt(DeclStmt * declstmt) {
      if (mEnv->checkretstatus())
         return;
	   mEnv->decl(declstmt);
   }

   virtual void VisitReturnStmt(ReturnStmt * retstmt) {
      if (mEnv->checkretstatus())
         return;
      VisitStmt(retstmt->getRetValue());
      mEnv->setretvalue(retstmt);
   }

private:
   Environment * mEnv;
};

class InterpreterConsumer : public ASTConsumer {
public:
   explicit InterpreterConsumer(const ASTContext& context) : mEnv(),
   	   mVisitor(context, &mEnv) {
   }
   virtual ~InterpreterConsumer() {}

   virtual void HandleTranslationUnit(clang::ASTContext &Context) {
      // get AST's TranslationUnitDecl
	   TranslationUnitDecl * decl = Context.getTranslationUnitDecl();
	   mEnv.init(decl);

	   FunctionDecl * entry = mEnv.getEntry();
      // entry->getBody() returns the top-level Stmt* of that body.
      // The basis case walks all of the children of the statement or expression, assuming they are all potentially evaluated.
	   mVisitor.VisitStmt(entry->getBody());
  }
private:
   Environment mEnv;
   InterpreterVisitor mVisitor;
};

class InterpreterClassAction : public ASTFrontendAction {
public:
  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
    return std::unique_ptr<clang::ASTConsumer>(
        // customize InterpreterConsumer
        new InterpreterConsumer(Compiler.getASTContext()));
  }
};

int main (int argc, char ** argv) {
   if (argc > 1) {
      // define a action InterpreterClassAction
      clang::tooling::runToolOnCode(std::unique_ptr<clang::FrontendAction>(new InterpreterClassAction), argv[1]);
   }
}