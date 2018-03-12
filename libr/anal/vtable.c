/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "r_util.h"
#include "r_anal.h"

#define VTABLE_BUFF_SIZE 10

#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	static bool fname(RAnal *anal, ut64 addr, ut64 *buf) { \
		ut8 tmp[sz]; \
		if(!anal->iob.read_at(anal->iob.io, addr, tmp, sz)) { \
			return false; \
		} \
		*buf = read_fname(tmp); \
		return true; \
	}
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le8, r_read_le8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le16, r_read_le16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le32, r_read_le32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le64, r_read_le64, 8)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be8, r_read_be8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be16, r_read_be16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be32, r_read_be32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be64, r_read_be64, 8)



R_API void r_anal_vtable_info_fini(RVTableInfo *vtable) {
	RListIter* iter;
	RVTableMethodInfo *method;
	r_list_foreach (vtable->methods, iter, method) {
		free (method);
	}
	r_list_free (vtable->methods);
}

R_API ut64 r_anal_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable) {
	return (ut64)vtable->method_count * context->word_size;
}


R_API bool r_anal_vtable_begin(RAnal *anal, RVTableContext *context) {
	context->anal = anal;
	context->compiler = VTABLE_COMPILER_ITANIUM;
	context->word_size = (ut8)(anal->bits / 8);
	switch (anal->bits) {
		case 8:
			context->read_addr = anal->big_endian ? vtable_read_addr_be8 : vtable_read_addr_le8;
			break;
		case 16:
			context->read_addr = anal->big_endian ? vtable_read_addr_be16 : vtable_read_addr_le16;
			break;
		case 32:
			context->read_addr = anal->big_endian ? vtable_read_addr_be32 : vtable_read_addr_le32;
			break;
		case 64:
			context->read_addr = anal->big_endian ? vtable_read_addr_be64 : vtable_read_addr_le64;
			break;
		default:
			return false;
	}
	return true;
}

R_API RList *r_anal_vtable_get_methods(RVTableContext *context, RVTableInfo *table) {
	RAnal *anal = context->anal;
	RList* vtableMethods = r_list_new ();
	if (!table || !anal || !vtableMethods) {
		r_list_free (vtableMethods);
		return NULL;
	}

	int curMethod = 0;
	int totalMethods = table->method_count;
	ut64 startAddress = table->saddr;
	while (curMethod < totalMethods) {
		ut64 curAddressValue;
		RVTableMethodInfo *methodInfo;
		if (context->read_addr (context->anal, startAddress, &curAddressValue)
			&& (methodInfo = (RVTableMethodInfo *)malloc (sizeof (RVTableMethodInfo)))) {
			methodInfo->addr = curAddressValue;
			methodInfo->vtable_offset = startAddress - table->saddr;
			r_list_append (vtableMethods, methodInfo);
		}
		startAddress += context->word_size;
		curMethod++;
	}

	table->methods = vtableMethods;
	return vtableMethods;
}

static bool vtable_addr_in_text_section(RVTableContext *context, ut64 curAddress) {
	//section of the curAddress
	RBinSection* value = context->anal->binb.get_vsect_at (context->anal->binb.bin, curAddress);
	//If the pointed value lies in .text section
	return value && !strcmp (value->name, ".text");
}

static bool vtable_is_value_in_text_section(RVTableContext *context, ut64 curAddress) {
	//value at the current address
	ut64 curAddressValue;
	if (!context->read_addr (context->anal, curAddress, &curAddressValue)) {
		return false;
	}
	//if the value is in text section
	return vtable_addr_in_text_section (context, curAddressValue);
}

static bool vtable_section_can_contain_vtables(RVTableContext *context, RBinSection *section) {
	return !strcmp(section->name, ".rodata") ||
		   !strcmp(section->name, ".rdata") ||
		   !strcmp(section->name, ".data.rel.ro");
}


static int vtable_is_addr_vtable_start(RVTableContext *context, ut64 curAddress) {
	RAnalRef *xref;
	RListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (!vtable_is_value_in_text_section (context, curAddress)) {
		return false;
	}
	// total xref's to curAddress
	RList *xrefs = r_anal_xrefs_get (context->anal, curAddress);
	if (r_list_empty (xrefs)) {
		return false;
	}
	r_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section (context, xref->addr)) {
			ut8 buf[VTABLE_BUFF_SIZE];
			context->anal->iob.read_at (context->anal->iob.io, xref->addr, buf, sizeof(buf));

			RAnalOp analop = { 0 };
			r_anal_op (context->anal, &analop, xref->addr, buf, sizeof(buf));

			if (analop.type == R_ANAL_OP_TYPE_MOV
				|| analop.type == R_ANAL_OP_TYPE_LEA) {
				return true;
			}

			r_anal_op_fini (&analop);
		}
	}
	return false;
}

R_API RList *r_anal_vtable_search(RVTableContext *context) {
	RAnal *anal = context->anal;
	if (!anal) {
		return NULL;
	}

	RList *vtables = r_list_newf ((RListFree)free);
	if (!vtables) {
		return NULL;
	}

	RList *sections = anal->binb.get_sections (anal->binb.bin);
	if (!sections) {
		r_list_free (vtables);
		return NULL;
	}

	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (!vtable_section_can_contain_vtables (context, section)) {
			continue;
		}

		// ut8 *segBuff = calloc (1, section->vsize);
		// r_io_read_at (core->io, section->vaddr, segBuff, section->vsize);

		ut64 startAddress = section->vaddr;
		ut64 endAddress = startAddress + (section->vsize) - context->word_size;
		while (startAddress <= endAddress) {
			if (vtable_is_addr_vtable_start (context, startAddress)) {
				RVTableInfo *vtable = calloc (1, sizeof(RVTableInfo));
				vtable->saddr = startAddress;
				int noOfMethods = 0;
				while (vtable_is_value_in_text_section (context, startAddress)) {
					noOfMethods++;
					startAddress += context->word_size;

					// a ref means the vtable has ended
					if (!r_list_empty (r_anal_xrefs_get (context->anal, startAddress))) {
						break;
					}
				}
				vtable->method_count = noOfMethods;
				r_list_append (vtables, vtable);
				continue;
			}
			startAddress += 1;
		}
	}

	if (r_list_empty (vtables)) {
		// stripped binary?
		eprintf ("No virtual tables found\n");
		r_list_free (vtables);
		return NULL;
	}
	return vtables;
}

R_API void r_anal_list_vtables(RAnal *anal, int rad) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);

	RList *vtableMethods;
	const char *noMethodName = "No Name found";
	RListIter* vtableMethodNameIter;
	RVTableMethodInfo *curMethod;
	RListIter* vtableIter;
	RVTableInfo* table;

	RList* vtables = r_anal_vtable_search (&context);
	if (!vtables) {
		return;
	}

	if (rad == 'j') {
		bool isFirstElement = true;
		r_cons_print ("[");
		r_list_foreach (vtables, vtableIter, table) {
			if (!isFirstElement) {
				r_cons_print (",");
			}
			bool isFirstMethod = true;
			r_cons_printf ("{\"offset\":%"PFMT64d",\"methods\":[", table->saddr);
			vtableMethods = r_anal_vtable_get_methods (&context, table);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				if(!isFirstMethod)
					r_cons_print (",");
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char* const name = fcn ? fcn->name : NULL;
				r_cons_printf ("{\"offset\":%"PFMT64d",\"name\":\"%s\"}",
						curMethod->addr, name ? name : noMethodName);
				isFirstMethod = false;
			}
			r_cons_print ("]}");
			isFirstElement = false;
		}
		r_cons_println ("]");
	} else if (rad == '*') {
		r_list_foreach (vtables, vtableIter, table) {
			r_cons_printf ("f vtable.0x%08"PFMT64x" %"PFMT64d" @ 0x%08"PFMT64x"\n",
						   table->saddr,
						   r_anal_vtable_info_get_size (&context, table),
						   table->saddr);
			vtableMethods = r_anal_vtable_get_methods (&context, table);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", context.word_size, table->saddr + curMethod->vtable_offset);
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				if (name) {
					r_cons_printf ("f %s=0x%08"PFMT64x"\n", name, curMethod->addr);
				} else {
					r_cons_printf ("f method.virtual.0x%08"PFMT64x"=0x%08"PFMT64x"\n", curMethod->addr, curMethod->addr);
				}
			}
		}
	} else {
		r_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			vtableMethods = r_anal_vtable_get_methods (&context, table);
			r_cons_printf ("\nVtable Found at 0x%08"PFMT64x"\n", vtableStartAddress);
			r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char* const name = fcn ? fcn->name : NULL;
				r_cons_printf ("0x%08"PFMT64x" : %s\n", vtableStartAddress, name ? name : noMethodName);
				vtableStartAddress += context.word_size;
			}
			r_cons_newline ();
		}
	}
	r_list_foreach (vtables, vtableIter, table) {
			r_anal_vtable_info_fini (table);
	}
	r_list_free (vtables);
}

