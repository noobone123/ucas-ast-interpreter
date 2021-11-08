//==--- tools/clang-check/ClangInterpreter.cpp - Clang Interpreter tool --------------===//
//===----------------------------------------------------------------------===//
#include <stdio.h>
#include <iostream>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"

using namespace clang;
using namespace std;

class StackFrame {
	/// StackFrame maps Variable Declaration to Value
	/// Which are either integer or addresses (also represented using an Integer value)

	std::map<Decl*, long> mVars;
	std::map<Stmt*, long> mExprs;
	/// The current stmt
	Stmt * mPC;

	// int return 
	int ret_value = 0;
	// return_status: if return , do not visit following Stmts;
	bool return_status = false;

public:
	StackFrame() : mVars(), mExprs(), mPC() {
	}

	void bindDecl(Decl* decl, long val) {
		mVars[decl] = val;
	}    
	long getDeclVal(Decl * decl) {
		assert (mVars.find(decl) != mVars.end());
		return mVars.find(decl)->second;
	}
	void bindStmt(Stmt * stmt, long val) {
		mExprs[stmt] = val;
	}
	long getStmtVal(Stmt * stmt) {
		assert (mExprs.find(stmt) != mExprs.end());
		return mExprs[stmt];
	}
	void setPC(Stmt * stmt) {
		mPC = stmt;
	}
	void setReturnValue(int value) {
		ret_value = value;
		return_status = true;
	}
	int getReturnValue() {
		return ret_value;
	}
	int getReturnStatus() {
		return return_status;
	}
	Stmt * getPC() {
		return mPC;
	}

	void debugDumpVar() {
		for (auto it = mVars.cbegin(); it != mVars.cend(); it++) {
			it->first->dumpColor();
			cout << "The Value is: " << it->second << endl;
		}
	}

	void debugDumpExpr() {
		for (auto it = mExprs.cbegin(); it != mExprs.cend(); it++) {
			it->first->dumpColor();
			cout << "The Value is: " << it->second << endl;
		}
	}

};

/// Heap maps address to a value
// class Heap {
// public:
// 	typedef struct {
// 		void * ptr;
// 		unsigned int size;
// 	} chunk_info;

// 	std::map<Stmt*, chunk_info*> allocated_pointers;
// 	std::map<Stmt*, chunk_info*> freed_pointers;
	
// 	void bind_allocated_pointers(Stmt *stmt, chunk_info* chunk_info_ptr) {
// 		allocated_pointers[stmt] = chunk_info_ptr;
// 	}

// 	void bind_freed_pointers(Stmt *stmt, chunk_info* chunk_info_ptr) {
// 		freed_pointers[stmt] = chunk_info_ptr;
// 	}

// 	chunk_info* get_allocated_pointers(Stmt* stmt) {
// 		assert (allocated_pointers.find(stmt) != allocated_pointers.end());
// 		return allocated_pointers[stmt];
// 	}

// 	chunk_info* get_freed_pointers(Stmt* stmt) {
// 		assert (freed_pointers.find(stmt) != freed_pointers.end());
// 		return freed_pointers[stmt];
// 	}
// };

class Environment {
	std::vector<StackFrame> mStack;

	// Declartions to the built-in functions
	FunctionDecl * mFree;				
	FunctionDecl * mMalloc;
	FunctionDecl * mInput;
	FunctionDecl * mOutput;

	FunctionDecl * mEntry;
public:
	/// Get the declartions to the built-in functions
	Environment() : mStack(), mFree(NULL), mMalloc(NULL), mInput(NULL), mOutput(NULL), mEntry(NULL) {
	}


	/// Initialize the Environment
	void init(TranslationUnitDecl * unit) {
		// decl_iterator -> clang/AST/DeclBase.h.
		// decls_begin() and decls_end() are in clang/AST/DeclBase.h, which returns decl_iterator
		mStack.push_back(StackFrame());
		for (TranslationUnitDecl::decl_iterator i =unit->decls_begin(), e = unit->decls_end(); i != e; ++ i) {
			// The dyn_cast<> operator is a “checking cast” operation. 
			// It checks to see if the operand is of the specified type 
			// and if so, returns a pointer to it (this operator does not work with references). 
			// If the operand is not of the correct type, a null pointer is returned
			if (FunctionDecl * fdecl = dyn_cast<FunctionDecl>(*i) ) {
				if (fdecl->getName().equals("FREE")) mFree = fdecl;
				else if (fdecl->getName().equals("MALLOC")) mMalloc = fdecl;
				else if (fdecl->getName().equals("GET")) mInput = fdecl;
				else if (fdecl->getName().equals("PRINT")) mOutput = fdecl;
				// function entry is main function
				else if (fdecl->getName().equals("main")) mEntry = fdecl;
			}
			// global variables
			else if (VarDecl * vdecl = dyn_cast<VarDecl>(*i)) {
				if (vdecl->getType().getTypePtr()->isIntegerType() || vdecl->getType().getTypePtr()->isCharType()) {
					if (vdecl->hasInit())
						mStack.back().bindDecl(vdecl, expr2value(vdecl->getInit()));
					else	
						mStack.back().bindDecl(vdecl, 0);
				}
			}
		}
	}

	FunctionDecl * getEntry() {
		return mEntry;
	}

   /// !TODO Support comparison operation
	void binop(BinaryOperator *bop) {
		Expr * left = bop->getLHS()->IgnoreImpCasts();
		Expr * right = bop->getRHS()->IgnoreImpCasts();

		// if binaryOP is assignment op (=)
		if (bop->isAssignmentOp()) {
			// if the leftexpr is declrefexpr
			if (DeclRefExpr *declexpr = dyn_cast<DeclRefExpr>(left))
			{	
				long val = expr2value(right);
				mStack.back().bindStmt(left, val);
				Decl *decl = declexpr->getFoundDecl();
				mStack.back().bindDecl(decl, val);
			}

			// if left is array ...
			else if (auto array = dyn_cast<ArraySubscriptExpr>(left))
			{
				DeclRefExpr * arrayleft = dyn_cast<DeclRefExpr>(array->getLHS()->IgnoreImpCasts());
				VarDecl* initdecl = dyn_cast<VarDecl>(arrayleft->getFoundDecl());
				long index = expr2value(array->getRHS());
				long assigned_value = expr2value(right);
				
				// if left array is integer type
				auto init_array = dyn_cast<ConstantArrayType>(initdecl->getType().getTypePtr());
				if (init_array->getElementType().getTypePtr()->isIntegerType()) {
					auto array_pointer = mStack.back().getDeclVal(initdecl);
					long *p = (long*)array_pointer;
					p[index] = assigned_value;
				}

				// if left array is pointer type
				else if (init_array->getElementType().getTypePtr()->isPointerType()) {
					long **p = (long **)mStack.back().getDeclVal(initdecl);
					*(p + index) = (long *)assigned_value;
				}
			}

			// if left is a pointer
			else if (auto ptr = dyn_cast<UnaryOperator>(left)) 
			{
				long val = expr2value(right);
				long *addr = (long*)(expr2value(ptr->getSubExpr()));
				*addr = (long)val;
			}
		}

		// other binary op such as +/-/>/</...
		else {
			auto op = bop->getOpcode();
			long result;
			switch (op) {
				case BO_Add:
					if (left->getType().getTypePtr()->isIntegerType() && right->getType().getTypePtr()->isIntegerType())
						result = expr2value(left) + expr2value(right);
					else if (left->getType().getTypePtr()->isPointerType())
						result = (long)expr2value(left) + sizeof(long) * expr2value(right); 
					break;
				case BO_Sub:
					result = expr2value(left) - expr2value(right);
					break;
				case BO_Mul:
					result = expr2value(left) * expr2value(right);
					break;
				case BO_LT:
					result = expr2value(left) < expr2value(right);
					break;
				case BO_GT:
					result = expr2value(left) > expr2value(right);
					break;
				case BO_EQ:
					result = expr2value(left) == expr2value(right);
					break;
				default:
					llvm::errs() << "Can not find such binaryOP\n";
					exit(1);
					break;
			}
			mStack.back().bindStmt(bop, result);
		}
	}

	// declaration handler
	void decl(DeclStmt * declstmt) {
		for (DeclStmt::decl_iterator it = declstmt->decl_begin(), ie = declstmt->decl_end();
				it != ie; ++ it) {
			Decl * decl = *it;
			// we only concern about vardecl now
			if (VarDecl * vardecl = dyn_cast<VarDecl>(decl)) {

				if (vardecl->getType().getTypePtr()->isIntegerType() || vardecl->getType().getTypePtr()->isPointerType()
					|| vardecl->getType().getTypePtr()->isCharType())
				// if vardecl is a integer/char/pointer, then ...
				{	
					if (vardecl->hasInit()) {
						mStack.back().bindDecl(vardecl, expr2value(vardecl->getInit()));
					} else {
						mStack.back().bindDecl(vardecl, 0);
					}
				}

				else if (vardecl->getType().getTypePtr()->isArrayType()) {
					auto arraytype = dyn_cast<ConstantArrayType>(vardecl->getType().getTypePtr());
					auto arraylen = arraytype->getSize().getSExtValue();
					// use new to alloc memory of array in heap
					long* array = new long[arraylen];
					for (int i = 0; i < arraylen; i++)
						array[i] = 0;
					mStack.back().bindDecl(vardecl, (long)array);
					
				}
			}
		}
	}

	void unaryOP(UnaryOperator *unaryop) {
		auto op = unaryop->getOpcode();
		auto sub_expr = unaryop->getSubExpr();
		auto sub_expr_value = expr2value(sub_expr);

		switch (op) {
			// UO_deref
			case UnaryOperatorKind::UO_Deref:
				mStack.back().bindStmt(unaryop, *(long*)sub_expr_value);
				break;

			// UO_Plus
			case UnaryOperatorKind::UO_Plus:
				break;

			// UO_Minus
			case UnaryOperatorKind::UO_Minus:
				mStack.back().bindStmt(unaryop, -1 * sub_expr_value);
				break;  

			default:
				llvm::errs() << "Can not match such unary Operator.\n";
				exit(1);
		}
		
	}

	// get value from expr
	long expr2value(Expr *expr) {
		expr = expr->IgnoreImpCasts();
		// if expr is Integer, then get value from API
		if (auto intLiteral = dyn_cast<IntegerLiteral>(expr)) {
			llvm::APInt res = intLiteral->getValue();
			return res.getSExtValue();
		
		// if expr is a declrefexpr, get value from mStack
		} else if (auto decl = dyn_cast<DeclRefExpr>(expr)) {
			declref(decl);
			long res = mStack.back().getStmtVal(decl);
			return res;
		
		// if expr is a binaryOP (condition) 
		} else if (auto binaryExpr = dyn_cast<BinaryOperator>(expr)) {
			binop(binaryExpr);
			long res = mStack.back().getStmtVal(binaryExpr);
			return res;
		
		// if expr is a callexpr (in recursion)
		} else if (auto callExpr = dyn_cast<CallExpr>(expr)) {
			return mStack.back().getStmtVal(callExpr);
		
		// if expr is unaryOP
		} else if (auto unaryop = dyn_cast<UnaryOperator>(expr)) {
			unaryOP(unaryop);
			return mStack.back().getStmtVal(unaryop);

		// if expr is an array
		} else if (auto array = dyn_cast<ArraySubscriptExpr>(expr)) {
			DeclRefExpr *arraydefref = dyn_cast<DeclRefExpr>(array->getLHS()->IgnoreImpCasts());
			VarDecl *initdecl = dyn_cast<VarDecl>(arraydefref->getFoundDecl());
			int index = expr2value(array->getRHS()->IgnoreImpCasts());
			
			auto initarray = dyn_cast<ConstantArrayType>(initdecl->getType().getTypePtr());

			// array[n]
			if (initarray->getElementType().getTypePtr()->isIntegerType()) {
				long *pointer = (long*) (mStack.back().getDeclVal(initdecl));
				return pointer[index];
			}

			// int *array[n]
			else if (initarray->getElementType().getTypePtr()->isPointerType()) {
				long ** pointer = (long**) (mStack.back().getDeclVal(initdecl));
				return (long)(*(pointer + index));
			}

		// if expr is UnaryExprOrTypeTraitExpr (sizeof(xxxx))
		} else if (auto typeexpr = dyn_cast<UnaryExprOrTypeTraitExpr>(expr)) {
			if (typeexpr->getArgumentType()->isIntegerType())
				return sizeof(long);
			else if (typeexpr->getArgumentType()->isPointerType())
				return sizeof(long *);
		
		// if expr is CStyleCastExpr 
		} else if (auto cstylecastexpr = dyn_cast<CStyleCastExpr>(expr)) {
			return expr2value(cstylecastexpr->getSubExpr());	
		
		// if expr is ParenExpr
		} else if (auto parenexpr = dyn_cast<ParenExpr>(expr)) {
			return expr2value(parenexpr->getSubExpr());
		}

		expr->dumpColor();
		llvm::errs() << "Can not match this kind of expr.";
		return 0;
	}

	// declrefexpr is the reference of decl, for example: a = 12, a is declrefexpr
	void declref(DeclRefExpr * declref) {
		// set PC point to declrefexpr
		mStack.back().setPC(declref);
		if (declref->getType()->isIntegerType() || declref->getType()->isPointerType() || declref->getType()->isCharType()) {
			// bindStmt of declrefexpr
			Decl* decl = declref->getFoundDecl();
			long val = mStack.back().getDeclVal(decl);
			mStack.back().bindStmt(declref, val);
		}
	}

	void cast(CastExpr * castexpr) {
		mStack.back().setPC(castexpr);
	}

	void array(ArraySubscriptExpr * expr) {
		DeclRefExpr *arrayrefdecl = dyn_cast<DeclRefExpr>(expr->getLHS()->IgnoreImpCasts());
		VarDecl *initdecl = dyn_cast<VarDecl>(arrayrefdecl->getFoundDecl());
		int index = expr2value(expr->getRHS()->IgnoreImpCasts());
			
		auto initarray = dyn_cast<ConstantArrayType>(initdecl->getType().getTypePtr());
		if (initarray->getElementType().getTypePtr()->isIntegerType()) {
			int *pointer = (int*) (mStack.back().getDeclVal(initdecl));
			int array_value = pointer[index];
			mStack.back().bindStmt(expr, array_value);

			// cout << "Array elements: " << pointer[0] << " "
			//	 << pointer[1] << " " << pointer[2] << endl;
		} 
	}

	/// !TODO Support Function Call
	void call(CallExpr * callexpr) {
		mStack.back().setPC(callexpr);
		long val = 0;
		FunctionDecl * callee = callexpr->getDirectCallee();

		if (callee == mInput) {
			// if callee is mInput
			scanf("%ld", &val);
			mStack.back().bindStmt(callexpr, val);

		} else if (callee == mOutput) {
			// if callee is mOutput
			Expr * expr = callexpr->getArg(0);
			Expr *exp = expr->IgnoreImpCasts();

			val = expr2value(exp);

			llvm::errs() << val;

		} else if (callee == mMalloc) {
			Expr *argexpr = callexpr->getArg(0);
			int malloc_size = expr2value(argexpr);

			long *p = (long*)std::malloc(malloc_size);
			// cout << "malloc addr: " << p << endl;
			mStack.back().bindStmt(callexpr, (long)p);

		} else if (callee == mFree) {
			Expr *argexpr = callexpr->getArg(0);
			// cout << "in Free: " << (long*)expr2value(argexpr) << endl;
			std::free((long*)expr2value(argexpr));

		} else if ((callee != mInput) && (callee != mOutput) && (callee != mMalloc) && (callee != mFree)) {
			// get arguments
			vector<long> arg_vector;
			unsigned arg_num = callexpr->getNumArgs();
			Expr** args = callexpr->getArgs();
			for (unsigned i = 0; i < arg_num; ++i) {
				arg_vector.push_back(expr2value(args[i]));
			}

			// if callee is user-defined function
			// push back a new stackframe into mStack
			mStack.push_back(StackFrame());

			// initialize callee's paramters
			// bind ParmVarDecl and arguments
			unsigned param_num = callee->getNumParams();
			for (unsigned i = 0; i < param_num; ++i) {
				ParmVarDecl * parm = callee->getParamDecl(i);
				mStack.back().bindDecl(parm, arg_vector[i]);
			}
		}
	}

	Stmt* getPC() {
		return mStack.back().getPC();
	} 

	bool condition(IfStmt *ifstmt) {
		Expr * condition = ifstmt->getCond();
		// cout << expr2value(condition) << endl;
		if (expr2value(condition)) {
			mStack.back().setPC(ifstmt->getThen());
			return true;
		} else {
			if (ifstmt->getElse()) {
				mStack.back().setPC(ifstmt->getElse());
				return true;
			}
		}
		return false;
	}

	bool whilestmt(WhileStmt *whilestmt) {
		Expr *while_cond = whilestmt->getCond();
		if (expr2value(while_cond)) {
			mStack.back().setPC(whilestmt->getBody());
			return true;
		} else {
			return false;
		}
	}

	bool checkforinit(ForStmt *forstmt) {
		Stmt * forinit = forstmt->getInit();
		if (forinit) {
			mStack.back().setPC(forstmt->getBody());
			return true;
		} else {
			return false;
		}
	}

	bool checkforcond(ForStmt *forstmt) {
		Expr *forcond = forstmt->getCond();
		return expr2value(forcond);
	}

	void freturn(CallExpr *call) {
		int value = mStack.back().getReturnValue();
		mStack.pop_back();
		mStack.back().bindStmt(call, value);
	}

	void setretvalue(ReturnStmt * retstmt) {
		int value = expr2value(retstmt->getRetValue());
		mStack.back().setReturnValue(value);
	}

	bool checkretstatus() {
		return mStack.back().getReturnStatus();
	}

	void debugDumpVector_int(vector<int> &vect) {
		for (int i = 0; i < vect.size(); i++) {
			cout << vect[i] << " ";
		}
		cout << '\n';
	}
};
