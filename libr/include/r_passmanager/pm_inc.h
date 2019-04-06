/* radare2 - LGPL - Copyright 2019 - oddcoder*/

#undef Pass_
#undef Pm_
#undef Pr_
#undef PM_
#undef PASS_
#undef PR_

#if !defined(TYPE_NAME) || !defined(TYPE) || !defined(PMFN_)
#error TYPE_NAME, TYPE and PFMN_ should be defined before including this header
#endif

#define PM_concat(first, second) first##second
#define _PM_concat(first, second) _##first##second

#define Pass_(name) _PM_concat(name, _pass)
#define Pm_(name) _PM_concat(name, _pm)
#define Pr_(name) _PM_concat(name, _pr)
#define PM_(name) PM_concat(name, PassMan)
#define PASS_(name) PM_concat(name, Pass)
#define PR_(name) PM_concat(name, PassRunner)


/*
 * They are all defined the same, but, different PassMan types
 * accepts different PassRunners types which in turn wraps different
 * passes, these different passes finally operates on one of bunch of
 * types as Function, Module, basicBlock...etc
 */
typedef struct Pm_(TYPE_NAME) PM_(TYPE_NAME);

/*
 * Always add elements to this structure at the bottom not at the begining,
 * so it is always backward compatible
 *
 * name : should be unique for every pass
 * registerDependencies: it register dependencies for the kind of passes
 * free_pass: Callback that gets called when is about to be destroyed
 * free_result: Callback that gets called when the invalidated cb returs new
 *		pointer that the one stored
 * customDataStructure: Arbitrary data stored for the pass
 */

typedef struct Pass_(TYPE_NAME) {
	char *name;
	void (*registerDependencies) (PM_(TYPE_NAME) *pm);
	void *(*run) (PM_(TYPE_NAME) *, struct Pass_(TYPE_NAME) *p, TYPE *object);
	void *(*invalidate) (PM_(TYPE_NAME) *pm, struct Pass_(TYPE_NAME) *p, TYPE *object);
	void (*free_pass) (struct Pass_(TYPE_NAME) *p);
	void (*free_result) (void *);
	void *customDataStructure;
	/*TODO  passes can come with their own set of commands*/
} PASS_(TYPE_NAME);

R_API PM_(TYPE_NAME) *PMFN_(new)();
R_API RAnal *PMFN_(get_anal)(PM_(TYPE_NAME) *pm);
R_API void PMFN_(invalidate)(PM_(TYPE_NAME) *pm, TYPE *object);
R_API void PMFN_(set_anal)(PM_(TYPE_NAME) *pm, RAnal *anal);
R_API void PMFN_(free)(PM_(TYPE_NAME) *pm);
R_API bool PMFN_(register_pass)(PM_(TYPE_NAME) *pm, PASS_(TYPE_NAME) *p);
R_API void *PMFN_(get_result)(PM_(TYPE_NAME) *pm, char *passName, TYPE *object);
R_API void *PMFN_(get_cached_result)(PM_(TYPE_NAME) *pm, char *passName, TYPE *object);
