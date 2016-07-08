/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

#if 0
#ifndef lint
#ident	"@(#)rpc_cout.c	1.14	93/07/05 SMI"
static char sccsid[] = "@(#)rpc_cout.c 1.13 89/02/22 (C) 1987 SMI";
#endif
#endif

#include <sys/cdefs.h>

/*
 * rpc_cout.c, XDR routine outputter for the RPC protocol compiler
 * Copyright (C) 1987, Sun Microsystems, Inc.
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "rpc_parse.h"
#include "rpc_scan.h"
#include "rpc_util.h"

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

static void print_header( definition * );
static void print_trailer( void );
static void print_default( void );
static void print_stat( int , declaration *, int cval, int last, 
			char *structval);
static void print_decl_list( decl_list *dl_first, const char * );
static void emit_enum( definition * );
static void emit_program( definition * );
static void emit_union( definition * );
static void emit_struct( definition * );
static void emit_typedef( definition * );
static void emit_inline( int, declaration *, int );
static void emit_single_in_line( int, declaration *, int, relation );

/*
 * Emit the C-routine for the given definition
 */
void
emit(def)
	definition *def;
{
	if (def->def_kind == DEF_CONST) {
		return;
	}
	if (def->def_kind == DEF_PROGRAM) {
		emit_program(def);
		return;
	}
	if (def->def_kind == DEF_TYPEDEF) {
		/*
		 * now we need to handle declarations like
		 * struct typedef foo foo;
		 * since we dont want this to be expanded into 2 calls
		 * to axdr_foo
		 */

		if (strcmp(def->def.ty.old_type, def->def_name) == 0)
			return;
	};
	print_header(def);
	switch (def->def_kind) {
	case DEF_UNION:
		emit_union(def);
		break;
	case DEF_ENUM:
		emit_enum(def);
		break;
	case DEF_STRUCT:
		emit_struct(def);
		break;
	case DEF_TYPEDEF:
		emit_typedef(def);
		break;
		/* DEF_CONST and DEF_PROGRAM have already been handled */
	default:
		break;
	}
	print_trailer();
}

static int
findtype(definition *def, char *type)
{

	if (def->def_kind == DEF_PROGRAM || def->def_kind == DEF_CONST) {
		return (0);
	} else {
		return (streq(def->def_name, type));
	}
}

static int
undefined(char *type)
{
	definition *def;

	def = (definition *) FINDVAL(defined, type, findtype);
	return (def == NULL);
}


static void
print_generic_header(char* procname, int pointerp)
{
	f_print(fout, "\n");
	if (streamflag) {
		f_print(fout, "axdr_ret_t\n");
	} else {
		f_print(fout, "bool_t\n");
	}
	f_print(fout, "axdr_%s(", procname);
	f_print(fout, "axdr_state_t *xdrs, ");
	f_print(fout, "%s ", procname);
	if (pointerp)
		f_print(fout, "*");
	f_print(fout, "objp)\n{\n");
}

static void
print_header(definition *def)
{
	print_generic_header(def->def_name,
			    def->def_kind != DEF_TYPEDEF ||
			    !isvectordef(def->def.ty.old_type,
					 def->def.ty.rel));
}

static void
print_prog_header(proc_list *plist)
{
	print_generic_header(plist->args.argname, 1);
}

static void
print_default(void)
{
	f_print(fout, "out:\n\treturn (%s);\n",
		streamflag ? "AXDR_DONE" : "TRUE");
}	

static void
print_trailer(void)
{
	f_print(fout, "}\n");
}

static void
print_stringify_close(int indent)
{
	tabify(fout, indent);
	f_print(fout, "if (xdrs->x_op == AXDR_STRINGIFY) {\n");
	tabify(fout, indent+1);
	f_print(fout, "rval = axdr_str_set_name(xdrs, NULL, "
		"FALSE, &off);\n");
	tabify(fout, indent+1);
	f_print(fout, "if (rval != AXDR_DONE) {\n");
	tabify(fout, indent+2);
	f_print(fout, "goto out;\n");
	tabify(fout, indent+1);
	f_print(fout, "}\n");
	tabify(fout, indent);
	f_print(fout, "}\n");
}


static void
print_callopen(char *name, int encap)
{
	if (encap) {
		f_print(fout, "axdr_encap(xdrs, (axdrproc_t)axdr_%s", name);
	} else {
		f_print(fout, "axdr_%s(xdrs", name);
	}
}

static void
print_callarg(char *arg)
{
	f_print(fout, ", %s", arg);
}

static void
print_callclose(void)
{
	f_print(fout, ")");
}

static void
print_callsizeof(int indent, char *prefix, char *type)
{
	if (indent) {
		f_print(fout, ",\n");
		tabify(fout, indent);
	} else  {
		f_print(fout, ", ");
	}
	if (streq(type, "bool")) {
		f_print(fout, "sizeof (bool_t), (axdrproc_t)axdr_bool");
	} else {
		f_print(fout, "sizeof (");
		if (undefined(type) && prefix) {
			f_print(fout, "%s ", prefix);
		}
		f_print(fout, "%s), (axdrproc_t)axdr_%s", type, type);
	}
}

static void
print_call(int indent, char *prefix, char *type, relation rel, 
	   int encap, char *amax, char *objname, char *name)
{
	char *alt = NULL;

	switch (rel) {
	case REL_POINTER:
		print_callopen("pointer", encap);
		print_callarg("(char **)");
		f_print(fout, "%s", objname);
		print_callsizeof(0, prefix, type);
		break;
	case REL_VECTOR:
		if (streq(type, "string")) {
			alt = "string";
		} else if (streq(type, "opaque")) {
			alt = "opaque";
		}
		if (alt) {
			print_callopen(alt, encap);
			print_callarg(objname);
		} else {
			print_callopen("vector", encap);
			print_callarg("(char *)");
			f_print(fout, "%s", objname);
		}
		print_callarg(amax);
		if (!alt) {
			print_callsizeof(indent + 1, prefix, type);
		}
		break;
	case REL_ARRAY:
		if (streq(type, "string")) {
			alt = "string";
		} else if (streq(type, "opaque")) {
			alt = "bytes";
		}
		if (streq(type, "string")) {
			print_callopen(alt, encap);
			print_callarg(objname);
		} else {
			if (alt) {
				print_callopen(alt, encap);
			} else {
				print_callopen("array", encap);
			}
			print_callarg("(char **)");
			if (*objname == '&') {
				f_print(fout, "%s.%s_val, (u_int *) %s.%s_len",
					objname, name, objname, name);
			} else {
				f_print(fout,
					"&%s->%s_val, (u_int *) &%s->%s_len",
					objname, name, objname, name);
			}
		}
		print_callarg(amax);
		if (!alt) {
			print_callsizeof(indent + 1, prefix, type);
		}
		break;
	case REL_ALIAS:
		print_callopen(type, encap);
		print_callarg(objname);
		break;
	}
	print_callclose();
}


static void
print_async_open(int indent, const char *procname)
{
	tabify(fout, indent);
	f_print(fout, "axdr_ret_t\trval;\n");
	tabify(fout, indent);
	f_print(fout, "bool_t\t\tcleanup;\n");
	tabify(fout, indent);
	f_print(fout, "int\t\tstate = 0;\n");
	tabify(fout, indent);
	f_print(fout, "rval = axdr_async_setup(xdrs, &axdr_%s, &cleanup,\n",
		procname);
	tabify(fout, indent);
	f_print(fout, "                       &state, 0, (void**) NULL);\n");
	tabify(fout, indent);
	f_print(fout, "if (rval != AXDR_DONE) {\n");
	tabify(fout, indent+1);
	f_print(fout, "return rval;\n");
	tabify(fout, indent);
	f_print(fout, "}\n");
	tabify(fout, indent);
	f_print(fout, "switch (state) {\n");
}

static void
print_async_close(int indent, const char *procname)
{
	tabify(fout, indent);
	f_print(fout, "default:\n");
	tabify(fout, indent+1);
	f_print(fout, "rval = AXDR_ERROR;\n");
	tabify(fout, indent);
	f_print(fout, "}\n");
	f_print(fout, "out:\n");
	tabify(fout, indent);
	f_print(fout, "axdr_async_teardown(xdrs, &axdr_%s, state, "
		"cleanup, rval);\n", procname);
	tabify(fout, indent);
	f_print(fout, "return rval;\n");
}

/* ARGSUSED */
static void
emit_enum(definition *def)
{
	enumval_list *vals;

	vals = def->def.en.vals;
	if (debugflag && vals) {
		tabify(fout, 1);
		f_print(fout, "if (xdrs->x_op == AXDR_STRINGIFY) {\n");
		tabify(fout, 2);
		f_print(fout, "const char *val;\n\n");
		tabify(fout, 2);
		f_print(fout, "switch (*objp) {\n");
		while (vals) {
			tabify(fout, 2);
			f_print(fout, "case %s:\n", vals->name);
			tabify(fout, 3);
			f_print(fout, "val = \"%s\";\n", vals->name);
			tabify(fout, 3);
			f_print(fout, "break;\n");
			vals = vals->next;
		}
		tabify(fout, 2);
		f_print(fout, "default:\n");
		tabify(fout, 3);
		f_print(fout, "val = NULL;\n");
		tabify(fout, 3);
		f_print(fout, "break;\n");
		tabify(fout, 2);
		f_print(fout, "}\n\n");
		tabify(fout, 2);
		f_print(fout, "if (val) {\n");
		tabify(fout, 3);
		f_print(fout, "return axdr_str_add_value(xdrs, val);\n");
		tabify(fout, 2);
		f_print(fout, "}\n");
		tabify(fout, 1);
		f_print(fout, "}\n\n");
	}
	tabify(fout, 1);
	f_print(fout, "return (");
	print_callopen("enum", FALSE);
	print_callarg("(enum_t *)objp");
	print_callclose();
	f_print(fout, ");\n");
}

static void
emit_program(definition *def)
{
	version_list *vlist;
	proc_list *plist;

	for (vlist = def->def.pr.versions; vlist != NULL; vlist = vlist->next)
		for (plist = vlist->procs; plist != NULL; plist = plist->next) {
			if (!newstyle || plist->arg_num < 2)
				continue; /* old style, or single argument */
			print_prog_header(plist);
			print_decl_list(plist->args.decls, plist->args.argname);
			print_trailer();
		}
}

static void
print_union_dec(int indent, definition *def, declaration *dec)
{
	char *object;
	char *vecformat = "objp->%s_u.%s";
	char *format = "&objp->%s_u.%s";

	if (!streq(dec->type, "void")) {
		object = xmalloc(strlen(def->def_name) +
				 strlen(format) + strlen(dec->name) + 1);
		if (isvectordef (dec->type, dec->rel)) {
			s_print(object, vecformat, def->def_name,
				dec->name);
		} else {
			s_print(object, format, def->def_name,
				dec->name);
		}

		if (streamflag) {
			tabify(fout, indent);
			f_print(fout, "rval = ");
		} else {
			tabify(fout, indent);
			f_print(fout, "if (!");
		}

		print_call(indent, dec->prefix, dec->type, dec->rel,
			   dec->encap, dec->array_max, object, dec->name);
		free(object);

		if (streamflag) {
			f_print(fout, ";\n");
			tabify(fout, indent);
			f_print(fout, "if (rval != AXDR_DONE) {\n");
			tabify(fout, indent+1);
			f_print(fout, "goto out;\n");
			tabify(fout, indent);
			f_print(fout, "}\n");
		} else {
			f_print(fout, ")\n");
			tabify(fout, indent);
			f_print(fout, "\treturn (FALSE);\n");
		}
	}
}


static void
emit_union(definition *def)
{
	declaration *dflt;
	case_list *cl;
	declaration *cs;
	int indent;

	if (debugflag) {
		tabify(fout, 1);
		f_print(fout, "int off;\n");
	}
	if (streamflag) {
		print_async_open(1, def->def_name);
		indent = 2;
	} else {
		indent = 1;
	}
	print_stat(indent, &def->def.un.enum_decl, 0, FALSE,
		   debugflag ? ".type" : NULL);
	if (streamflag) {
		tabify(fout, 1);
		f_print(fout, "case 1:\n");
	}
	if (debugflag) {
		tabify(fout, indent);
		f_print(fout, "if (xdrs->x_op == AXDR_STRINGIFY) {\n");
		tabify(fout, indent+1);
		f_print(fout, "rval = axdr_str_set_name(xdrs, \".value\", "
			"FALSE, &off);\n");
		tabify(fout, indent+1);
		f_print(fout, "if (rval != AXDR_DONE) {\n");
		tabify(fout, indent+2);
		f_print(fout, "goto out;\n");
		tabify(fout, indent+1);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
	}
	tabify(fout, indent);
	f_print(fout, "switch (objp->%s) {\n", def->def.un.enum_decl.name);
	for (cl = def->def.un.cases; cl != NULL; cl = cl->next) {
		tabify(fout, indent);
		f_print(fout, "case %s:\n", cl->case_name);
		if (cl->contflag == 1) /* a continued case statement */
			continue;
		cs = &cl->case_decl;
		print_union_dec(indent+1, def, cs);
		tabify(fout, indent+1);
		f_print(fout, "break;\n");
	}
	dflt = def->def.un.default_decl;
	if (dflt != NULL) {
		tabify(fout, indent);
		f_print(fout, "default:\n");
		print_union_dec(indent+1, def, dflt);
		tabify(fout, indent+1);
		f_print(fout, "break;\n");
	} else {
		tabify(fout, indent);
		f_print(fout, "default:\n");
		tabify(fout, indent+1);
		f_print(fout, "return (%s);\n", streamflag ? 
			"AXDR_ERROR" : "FALSE");
	}
	tabify(fout, indent);
	f_print(fout, "}\n");

	if (debugflag) {
		print_stringify_close(indent);
	}		

	if (streamflag) {
		tabify(fout, 1);
		f_print(fout, "break;\n");
		print_async_close(1, def->def_name);
	} else {
		print_default();
	}
}

static void
inline_run(int indent, int flag, decl_list *cur, 
	   decl_list *last, int idx, int *nextjump)
{
	int count;

	if (flag == PUT) {
		if (streamflag) {
			tabify(fout, indent-1);
			f_print(fout, "case AXDR_ENCODE_ASYNC:\n");
		}
		tabify(fout, indent-1);
		f_print(fout, "case XDR_ENCODE:\n");
	} else {
		if (streamflag) {
			tabify(fout, indent-1);
			f_print(fout, "case AXDR_DECODE_ASYNC:\n");
		}
		tabify(fout, indent-1);
		f_print(fout, "case AXDR_DECODE:\n");
	}

	for (count = 0; cur != last; cur = cur->next, count++) {
		emit_inline(indent, &cur->decl, flag);
	}

	if (streamflag) {
		tabify(fout, indent);
		f_print(fout, "rval = AXDR_DONE;\n");
		tabify(fout, indent);
		f_print(fout, "break;\n");
	} else {
		tabify(fout, indent);
		if (last == NULL) {
			f_print(fout, "return (TRUE);\n");
		} else {
			f_print(fout, "goto skip_to_case_%d;\n", idx+count+1);
			*nextjump = TRUE;
		}
	}
}


static void
inline_group(int indent, char *sizestr, int size, decl_list *cur, 
	     decl_list *last, int count, int *idxp, int *nextjump)
{
	int idx;

	idx = *idxp;

	if (sizestr == NULL && size < rpc_inline) {
		/*
		 * don't expand into inline code
		 * if size < inline
		 */
		if (*nextjump) {
			tabify(fout, indent-1);
			f_print(fout, "skip_to_case_%d:\n", idx);
			*nextjump = FALSE;
		}
		for (; cur != last; idx++, cur = cur->next) {
			print_stat(indent, &cur->decl, idx, 
				   cur->next ? FALSE : TRUE, NULL);
		}
		*idxp = idx;
		return;
	}

	if (streamflag) {
		tabify(fout, indent - 1);
		f_print(fout, "case %d:\n", idx);
	}

	if (*nextjump) {
		tabify(fout, indent-1);
		f_print(fout, "skip_to_case_%d:\n", idx);
		*nextjump = FALSE;
	}

	tabify(fout, indent);
	f_print(fout, "if (xdrs->x_op != XDR_FREE) {\n");
	tabify(fout, indent+1);
	if (sizestr == NULL) {
		f_print(fout, "buf = AXDR_INLINE(xdrs, %d * "
			"BYTES_PER_XDR_UNIT);\n", size);
	} else if (size == 0) {
		f_print(fout,
			"buf = AXDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);\n",
			sizestr);
	} else {
		f_print(fout,
			"buf = AXDR_INLINE(xdrs, (%d + (%s)) * "
			"BYTES_PER_XDR_UNIT);\n", size, sizestr);
	}
	tabify(fout, indent);
	f_print(fout, "} else {\n");
	tabify(fout, indent+1);
	f_print(fout, "buf = NULL;\n");
	tabify(fout, indent);
	f_print(fout, "}\n");
	tabify(fout, indent);
	f_print(fout, "if (buf) {\n");
	tabify(fout, indent+1);
	f_print(fout, "switch (xdrs->x_op) {\n");
	inline_run(indent+2, PUT, cur, last, idx, nextjump);
	inline_run(indent+2, GET, cur, last, idx, nextjump);
	if (streamflag) {
		tabify(fout, indent+1);
		f_print(fout, "default:\n");
		tabify(fout, indent+2);
		f_print(fout, "rval = AXDR_WAITING;\n");
		tabify(fout, indent+2);
		f_print(fout, "break;\n");
	}
	tabify(fout, indent+1);
	f_print(fout, "}\n");
	idx++;
	tabify(fout, indent);
	if (streamflag) {
		f_print(fout, "} else {\n");
		tabify(fout, indent+1);
		f_print(fout, "rval = AXDR_WAITING;\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "if (rval == AXDR_DONE) {\n");
		tabify(fout, indent+1);
		f_print(fout, "state = %d;\n", idx+count);
		tabify(fout, indent+1);
		if (last) {
			*nextjump = TRUE;
			f_print(fout, "goto skip_to_case_%d; "
				"/* continue with rest of structure */\n",
				idx+count);
		} else {
			f_print(fout, "break; /* done */\n");
		}
		tabify(fout, indent);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "state = %d;\n", idx);
	} else {
		f_print(fout, "}\n");
	}
	tabify(fout, indent);
	f_print(fout, "/* fallthrough */\n");

	for (; cur != last; cur = cur->next, idx++) {
		print_stat(indent, &cur->decl, idx, 
			   cur->next ? FALSE : TRUE, NULL);
	}

	*idxp = idx;
	return;
}


static void
inline_struct(int indent, definition *def)
{
	decl_list *dl;
	int i, size, idx;
	decl_list *cur;
	bas_type *ptr;
	int nextjump;
	char *sizestr, *plus;
	char ptemp[256];

	cur = NULL;
	i = 0;
	idx = 0;
	size = 0;
	sizestr = NULL;
	nextjump = FALSE;
	for (dl = def->def.st.decls; dl != NULL; dl = dl->next) { /* xxx */
		/* now walk down the list and check for basic types */
		if ((dl->decl.prefix == NULL) &&
		    ((ptr = find_type(dl->decl.type)) != NULL) &&
		    ((dl->decl.rel == REL_ALIAS) ||
		     (dl->decl.rel == REL_VECTOR))){
			if (i == 0) {
				cur = dl;
			}
			i++;

			if (dl->decl.rel == REL_ALIAS) {
				size += ptr->length;
			} else {
				/* this code is required to handle arrays */
				if (sizestr == NULL) {
					plus = "";
				} else {
					plus = " + ";
				}

				if (ptr->length != 1) {
					s_print(ptemp, "%s%s * %d",
						plus, dl->decl.array_max,
						ptr->length);
				} else {
					s_print(ptemp, "%s%s", plus,
						dl->decl.array_max);
				}

				/* now concatenate to sizestr !!!! */
				if (sizestr == NULL) {
					sizestr = xstrdup(ptemp);
				} else{
					sizestr = xrealloc(sizestr,
							  strlen(sizestr)
							  +strlen(ptemp)+1);
					sizestr = strcat(sizestr, ptemp);
					/* build up length of array */
				}
			}
		} else {
			if (i > 0) {
				inline_group(indent, sizestr, size, cur, 
					     dl, i, &idx, &nextjump);
			}
			size = 0;
			i = 0;
			if (sizestr) {
				free(sizestr);
			}
			sizestr = NULL;
			if (nextjump) {
				tabify(fout, indent-1);
				f_print(fout, "skip_to_case_%d:\n", idx);
				nextjump = FALSE;
			}
			print_stat(indent, &dl->decl, idx, 
				   dl->next ? FALSE : TRUE, NULL);
			idx++;
		}
	}

	if (i > 0) {
		inline_group(indent, sizestr, size, cur, NULL, i, &idx, 
			     &nextjump);
	}
	if (sizestr) {
		free(sizestr);
	}
	sizestr = NULL;

}


static void
emit_struct(definition *def)
{
	decl_list *dl;
	int size;
	bas_type *ptr;
	int indent;
	int can_inline;

	if (rpc_inline == 0 || debugflag) {
		/* No xdr_inlining at all */
		print_decl_list(def->def.st.decls, def->def_name);
		return;
	}

	for (dl = def->def.st.decls; dl != NULL; dl = dl->next)
		if (dl->decl.rel == REL_VECTOR){
			f_print(fout, "\tint i;\n");
			break;
		}

	size = 0;
	can_inline = 0;
	/*
	 * Make a first pass and see if inling is possible.
	 */
	for (dl = def->def.st.decls; dl != NULL; dl = dl->next)
		if ((dl->decl.prefix == NULL) &&
		    ((ptr = find_type(dl->decl.type)) != NULL) &&
		    ((dl->decl.rel == REL_ALIAS)||
		     (dl->decl.rel == REL_VECTOR))){
			if (dl->decl.rel == REL_ALIAS)
				size += ptr->length;
			else {
				can_inline = 1;
				break; /* can be inlined */
			}
		} else {
			if (size >= rpc_inline){
				can_inline = 1;
				break; /* can be inlined */
			}
			size = 0;
		}
	if (size >= rpc_inline)
		can_inline = 1;

	if (can_inline == 0){	/* can not inline, drop back to old mode */
		print_decl_list(def->def.st.decls, def->def_name);
		return;
	}

	tabify(fout, 1);
	f_print(fout, "int32_t\t\t*buf;\n");

	if (streamflag) {
		print_async_open(1, def->def_name);
		indent = 2;
	} else {
		f_print(fout, "\n");
		indent = 1;
	}

	inline_struct(indent, def);

	if (streamflag) {
		print_async_close(1, def->def_name);
	} else {
		print_default();
	}
}

static void
emit_typedef(definition *def)
{
	char *prefix = def->def.ty.old_prefix;
	char *type = def->def.ty.old_type;
	char *amax = def->def.ty.array_max;
	relation rel = def->def.ty.rel;
	int encap = def->def.ty.encap;

	tabify(fout, 1);

	f_print(fout, "return (");
	print_call(1, prefix, type, rel, encap, amax, "objp", def->def_name);
	f_print(fout, ");\n");
}

static void
print_calldec(int indent, declaration *dec, char *structval, int first)
{
	char *prefix = dec->prefix;
	char *type = dec->type;
	char *amax = dec->array_max;
	relation rel = dec->rel;
	int encap = dec->encap;
	char name[256];

	if (isvectordef(type, rel)) {
		s_print(name, "objp->%s", dec->name);
	} else {
		s_print(name, "&objp->%s", dec->name);
	}
	if (structval && dec->rel == REL_ALIAS) {
		/* do our own call print */
		f_print(fout, "axdr_element(xdrs, \"%s\", %s, "
			"(axdrproc_t)&axdr_%s, %s, &off)", structval,
			first ? "TRUE" : "FALSE", type, name);
	} else {
		print_call(indent, prefix, type, rel, encap, 
			   amax, name, dec->name);
	}
}


static void
print_stat(int indent, declaration *dec, int cval, int last, char *structval)
{
	char *lowersv;

	if (streamflag && cval >= 0) {
		tabify(fout, indent - 1);
		f_print(fout, "case %d:\n", cval);
	}

	lowersv = structval;
	if (structval && dec->rel != REL_ALIAS) {
		tabify(fout, indent);
		f_print(fout, "if (xdrs->x_op == AXDR_STRINGIFY) {\n");
		tabify(fout, indent+1);
		f_print(fout, "rval = axdr_str_set_name(xdrs, \"%s\", "
			"%s, &off);\n", structval, cval <= 0 ? 
			"TRUE" : "FALSE");
		tabify(fout, indent+1);
		f_print(fout, "if (rval != AXDR_DONE) {\n");
		tabify(fout, indent+2);
		f_print(fout, "goto out;\n");
		tabify(fout, indent+1);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
		lowersv = NULL;
	}
	tabify(fout, indent);
	if (streamflag) {
		f_print(fout, "rval = ");
	} else {
		f_print(fout, "if (!");
	}
	print_calldec(indent, dec, lowersv, cval <= 0 ? TRUE : FALSE);

	if (streamflag) {
		f_print(fout, ";\n");
		tabify(fout, indent);
		f_print(fout, "if (rval != AXDR_DONE) {\n");
		tabify(fout, indent+1);
		f_print(fout, "goto out;\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
		if (cval >= 0) {
			tabify(fout, indent);
			f_print(fout, "state = %d;\n", cval + 1);
		}

		if (structval && strcmp(structval, ".names") == 0) {
			fprintf(stderr, "last: %d\n", last);
		}

		if (last && structval != NULL) {
			print_stringify_close(indent);
		}

		if (cval >= 0) {
			tabify(fout, indent);
			if (last) {
				f_print(fout, "break; /* done */\n");
			} else {
				f_print(fout, "/* fallthrough */\n");
			}
		}
	} else {
		f_print(fout, ")\n");
		tabify(fout, indent);
		f_print(fout, "\treturn (FALSE);\n");
	}
}

static void
print_decl_list(decl_list *dl_first, const char *procname)
{
	char namebuf[256];
	decl_list *dl;
	int indent;
	int ecount;
	int idx;

	for (ecount = 0, dl = dl_first; dl != NULL; dl = dl->next) {
		ecount++;
	}

	if (ecount < 0) {
		print_default();
		return;
	}

	if (debugflag) {
		tabify(fout, 1);
		f_print(fout, "int\t\toff;\n");
	}

	if (ecount == 1) {
		snprintf(namebuf, sizeof(namebuf), ".%s", dl_first->decl.name);
		if (streamflag) {
			tabify(fout, 1);
			f_print(fout, "axdr_ret_t\trval;\n");
		}
		print_stat(1, &dl_first->decl, -1, TRUE, 
			   debugflag ? namebuf : NULL);

		if (streamflag) {
			f_print(fout, "out:\n");
			tabify(fout, 1);
			f_print(fout, "return rval;\n");
		} else {
			print_default();
		}
		return;
	}
	
	if (streamflag) {
		print_async_open(1, procname);
		indent = 2;
	} else {
		indent = 1;
	}

	for (idx = 0, dl = dl_first; dl != NULL; dl = dl->next, idx++) {
		snprintf(namebuf, sizeof(namebuf), ".%s", dl->decl.name);
		print_stat(indent, &dl->decl, idx, dl->next ? FALSE : TRUE, 
			   debugflag ? namebuf : NULL);
	}

	if (streamflag) {
		print_async_close(1, procname);
	} else {
		print_default();
	}
}

char *upcase(char *str);

static void
emit_inline(int indent, declaration *decl, int flag)
{
	switch (decl->rel) {
	case  REL_ALIAS :
		emit_single_in_line(indent, decl, flag, REL_ALIAS);
		break;
	case REL_VECTOR :
		tabify(fout, indent);
		f_print(fout, "{\n");
		tabify(fout, indent + 1);
		f_print(fout, "%s *genp;\n\n", decl->type);
		tabify(fout, indent + 1);
		f_print(fout,
			"for (i = 0, genp = objp->%s;\n", decl->name);
		tabify(fout, indent + 2);
		f_print(fout, "i < %s; i++) {\n", decl->array_max);
		emit_single_in_line(indent + 2, decl, flag, REL_VECTOR);
		tabify(fout, indent + 1);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
		break;
	default:
		break;
	}
}

static void
emit_single_in_line(int indent, declaration *decl, int flag, relation rel)
{
	char *upp_case;
	int freed = 0;

	tabify(fout, indent);
	if (flag == PUT)
		f_print(fout, "IAXDR_PUT_");
	else
		if (rel == REL_ALIAS)
			f_print(fout, "objp->%s = IAXDR_GET_", decl->name);
		else
			f_print(fout, "*genp++ = IAXDR_GET_");

	upp_case = upcase(decl->type);

	/* hack	 - XX */
	if (strcmp(upp_case, "INT") == 0)
	{
		free(upp_case);
		freed = 1;
		upp_case = "LONG";
	}

	if (strcmp(upp_case, "U_INT") == 0)
	{
		free(upp_case);
		freed = 1;
		upp_case = "U_LONG";
	}
	if (flag == PUT)
		if (rel == REL_ALIAS)
			f_print(fout,
				"%s(buf, objp->%s);\n", upp_case, decl->name);
		else
			f_print(fout, "%s(buf, *genp++);\n", upp_case);

	else
		f_print(fout, "%s(buf);\n", upp_case);
	if (!freed)
		free(upp_case);
}

char *upcase(char *str)
{
	char *ptr, *hptr;

	ptr = (char *)xmalloc(strlen(str)+1);

	hptr = ptr;
	while (*str != '\0')
		*ptr++ = toupper(*str++);

	*ptr = '\0';
	return (hptr);
}

/* 
 * Local Variables:
 * tab-width:8
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 * 
 */
