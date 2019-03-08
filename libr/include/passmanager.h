/* radare2 - LGPL - Copyright 2019 - oddcoder*/

#ifndef R2_PASSMANAGER_H
#define R2_PASSMANAGER_H

#include <r_util.h>
#include <r_anal.h>

typedef enum {
        ModulePass, //output of rbin
        FunctionPass, // function 
        BBPass, //basic block
	//TODO path for path analysis
} PassType;

typedef struct pm PassManager;
typedef struct pass Pass;
/*
 * Always add elements to this structure at the bottom not at the begining,
 * so it is always backward compatiable
 */

typedef struct pass{
        char *name; //must be unique for every pass;
        PassType t;
        void (*registerDependencies)(PassManager *);
	void *(*run)(PassManager *, Pass *p, void *object); // mandatory
	void (*invalidate)(PassManager *, Pass *p, void *object); //mandatory
	void (*free_pass)(Pass *p);
	void (*free_result)(void *);

	void *customDataStructure;
	//TODO  passes can come with their own set of commands
} Pass;


/*
 * Don't define this unless:-
 * A) You are testing **only** the internals of the passmanager.
 * B) You are extending the functionality of the passmanager.
 */
#ifdef PASSMANAGER_IMPLEMENTATION_FOR_INTERNAL_USE_ONLY


typedef struct pm{
	bool log;
	PassType t;
	HtPP *passes; //(k,v) = (char *Pass->name, Void *PassRunner) 
	RAnal *parent;
}PassManager;

typedef struct {
        Pass *p;
        HtPP *passResults; // (k,v) = (void *object, void *result)
	PassManager *parent;
} PassRunner;


#endif

R_API PassManager *newPassManager(bool log, PassType t);//
R_API void PM_setRAnal(PassManager *pm, RAnal *anal);//
R_API RAnal *PM_getRAnal(PassManager *pm);//
R_API void PM_destroyPassManager(PassManager *pm);
R_API bool PM_registerPass(PassManager *pm, Pass *p);
R_API void *PM_getResult(PassManager *pm, char *passName, void *object);
R_API void *PM_getCachedResult(PassManager *pm, char *passName, void *object);
/*
 * these 2 feel no good, the first 1 I can't file usecase for it
 * the second one is evil! it would assume that we know which pass we want to
 * invalidate. This doesn't sound like the right pattern, Each Pass should
 * identify how it would want to be invalidated, and all we have to do is just
 * notify them that something had changed in the objected.
 * when we invalidate an object if it is a module, we would need to invalidate
 * all the children functions as well as the children basic blocks.
 * same goes for function
 */
//void PM_invalidateEveryThing(PassManager *PM);
//void PM_invalidatePass(PassManager *PM, char *passName);
R_API void PM_invalidate(PassManager *PM, void *object);

#endif
