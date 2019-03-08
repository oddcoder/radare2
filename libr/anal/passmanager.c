#define PASSMANAGER_IMPLEMENTATION_FOR_INTERNAL_USE_ONLY

#include <passmanager.h>


static PassRunner *newpassrunner(Pass *p) {
	PassRunner *pr = calloc(sizeof(PassRunner), 1);
	if (!pr) {
		return NULL;
	}
	pr->p = p;
	//XXX create better tuned hash table
	HtPPOptions opt = {0};
	pr->passResults = ht_pp_new_opt(&opt);
	return pr;
}

static bool invalidate(void *object, const char *k, const PassRunner *pr) {
	pr->p->invalidate(pr->parent, pr->p, object);
	return true;
}
static bool freePassCache1(Pass *p, const void *object, void *result) {
	p->free_result(result);
	free(result);
	return true;
}
static bool freePassCache2(Pass *p, const void *object, void *result) {
	free(result);
	return true;
}


static bool freePassRunner(void *object, const char *k, PassRunner *pr) {
	//first free the cache
	//second free the Pass
	//third free the PassRunner
	if (pr->p->free_result) {
		ht_pp_foreach(pr->passResults, (HtPPForeachCallback) freePassCache1, pr->p);
	} else {
		ht_pp_foreach(pr->passResults, (HtPPForeachCallback) freePassCache2, pr->p);
	}
	if (pr->p->free_pass) {
		pr->p->free_pass(pr->p);
	}
	free(pr->p);
	ht_pp_free(pr->passResults);
	free(pr);
	return true;
}
R_API PassManager *newPassManager(bool log, PassType t) {
	PassManager *pm = calloc(sizeof(PassManager), 1); //zero initialized;
	if (!pm) {
		return NULL;
	}
	pm->log = log;
	pm->t = t;
	pm->passes = ht_pp_new0();
	return pm;
}

R_API void PM_setRAnal(PassManager *pm, RAnal *anal) {
	pm->parent = anal;
}
R_API RAnal *PM_getRAnal(PassManager *pm) {
	return pm->parent;
}


R_API void PM_destroyPassManager(PassManager *pm) {
	ht_pp_foreach(pm->passes, (HtPPForeachCallback) freePassRunner, NULL);
	ht_pp_free(pm->passes);
	free(pm);
}

R_API bool PM_registerPass(PassManager *pm, Pass *pass) {
	bool pass_exist;
	if (!pass) {
		return false;
	}
	if (pm->t != pass->t) {
		return false;
	}
	if(!pass->run || !pass->invalidate) {
		return false;
	}
	ht_pp_find(pm->passes, pass->name, &pass_exist);
	if (pass_exist) {
		return true;
	}
	PassRunner *pr = newpassrunner(pass);
	pr->parent = pm;
	ht_pp_insert(pm->passes, pass->name, pr);
	if (pass->registerDependencies) {
		pass->registerDependencies(pm);	
	}
	return true;
}

R_API void *PM_getResult(PassManager *pm, char *passName, void *object) {
	void *result = PM_getCachedResult(pm, passName, object);
	if (result) {
		return result;
	}
	PassRunner *pr = ht_pp_find(pm->passes, passName, NULL);
	if (!pr) {
		return NULL;
	}
	result = pr->p->run(pm, pr->p, object);
	ht_pp_insert(pr->passResults, object, result);
	return result;
}

R_API void *PM_getCachedResult(PassManager *pm, char *passName, void *object) {
	PassRunner *pr = ht_pp_find(pm->passes, passName, NULL);
	if (!pr) {
		return NULL;
	}
	void *result = ht_pp_find(pr->passResults, object, NULL);
	return result;
}

R_API void PM_invalidate(PassManager *pm, void *object) {
	ht_pp_foreach(pm->passes, (HtPPForeachCallback) invalidate, object);
}
