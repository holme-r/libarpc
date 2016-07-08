/*
 * Copyright (C) 2010  Pace Plc
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Pace Plc nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "compat.h"

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <libarpc/arpc.h>
#include <libarpc/stack.h>

struct astk_rec_s {
	/* saved basic state for stack record */
	int asr_state;

	/**
	 * Pointer to caller function.  Used to catch errors
	 */
	void *asr_id;

	/**
	 * Address of buffer for xtra space for this record. May be NULL.
	 */
	void *asr_xbuf;

	/**
	 * Offset in bytes from beginnging of xbuf to the location of xtra
	 * data for this record.
	 */
	int asr_xtra_off;

	/**
	 * Size of xtra area, rounded up for alignment.
	 */
	int asr_xtra_size;
};

/* no point growing a stack in increments smaller than this */
#define ASTK_BUF_GROW_SIZE     112 /* must be multiple of ASTK_XTRA_ALIGN */
/* alignement guarantee for xtra data */
#define ASTK_XTRA_ALIGN        4
/* record grow inc */
#define ASTK_STACK_GROW        5   /* stack grows in this increment */

int
astk_init(astk_t *stk)
{
	if (!stk) {
		return EINVAL;
	}
	stk->as_stack = NULL;
	stk->as_flags = 0;
	stk->as_stack_pos = 0;
	stk->as_stack_size = 0;
	stk->as_stack_max = 0;
	stk->as_base_buf = NULL;
	stk->as_base_bufsize = 0;
	stk->as_xtra_size = 0;
	stk->as_memuse = 0;
	stk->as_memuse_active = 0;
	stk->as_memuse_high = 0;
	return 0;
}

void
astk_cleanup(astk_t *stk)
{
	astk_rec_t *recp;
	int i;

	if (!stk) {
		return;
	}

	for (i = 0; i < stk->as_stack_size; i++) {
		recp = &stk->as_stack[i];
		if (recp->asr_xbuf && recp->asr_xbuf != stk->as_base_buf) {
			free(recp->asr_xbuf);
			recp->asr_xbuf = NULL;
		}
	}

	if ((void *)stk->as_stack != stk->as_base_buf) {
		if (stk->as_stack) {
			free(stk->as_stack);
			stk->as_stack = NULL;
		}
	}

	if ((stk->as_flags & ASTK_FLG_XMEM_BASE) == 0) {
		/* base stack allocated internally, free it up */
		if (stk->as_base_buf) {
			free(stk->as_base_buf);
			stk->as_base_buf = NULL;
		}
	}

	/* reset everything, just for sanity */
	astk_init(stk);
}

static void
astk_compress(astk_t *stk)
{
	astk_rec_t *nstack;
	astk_rec_t *recp;
	char *nbuf;
	int len;
	int xlen;
	int off;
	int i;

	if (!stk) {
		return;
	}

	if (stk->as_memuse_high <= stk->as_base_bufsize) {
		/* should all be in a single buffer. nothing to do */
		assert((void *)stk->as_stack == stk->as_base_buf);
		return;
	}

	/* do quick check to make sure it's safe */
	if (stk->as_stack_size > 0 && stk->as_xtra_size > 0 &&
	    stk->as_stack_pos > 0) {
		for (i = 0, xlen = 0; i < stk->as_stack_pos; i++) {
			if (stk->as_stack[i].asr_xtra_size > 0) {
				/* active xtra data.  Can't compress */
				return;
			}
		}
	}

	len = (stk->as_memuse_high + ASTK_BUF_GROW_SIZE +
	       (ASTK_STACK_GROW * sizeof(astk_rec_t)));
	nbuf = malloc(len);
	if (!nbuf) {
		/* have to live with what we have for now */
		return;
	}
	nstack = (astk_rec_t *)nbuf;

	if (stk->as_stack_size > 0) {
		off = stk->as_stack_size * sizeof(astk_rec_t);
		memcpy(nstack, stk->as_stack, off);

		for (i = 0, xlen = 0; i < stk->as_stack_size; i++) {
			xlen += nstack[i].asr_xtra_size;
		}

		assert(off + xlen < len);
		off = len;

		for (i = 0; i < stk->as_stack_size; i++) {
			recp = &nstack[i];
			if (recp->asr_xtra_size <= 0) {
				continue;
			}

			off -= recp->asr_xtra_size;

			memcpy(&nbuf[off], 
			       &((char *)recp->asr_xbuf)[recp->asr_xtra_off],
			       recp->asr_xtra_size);
			if (recp->asr_xbuf != stk->as_base_buf) {
				free(recp->asr_xbuf);
				recp->asr_xbuf = NULL;
				stk->as_xtra_size += recp->asr_xtra_size;
			}
			recp->asr_xbuf = nbuf;
			recp->asr_xtra_off = off;
		}
	} else {
		xlen = 0;
	}

	if (stk->as_stack && (void *)stk->as_stack != stk->as_base_buf) {
		free(stk->as_stack);
		stk->as_stack = NULL;
	}

	if (stk->as_base_buf != NULL &&
	    (stk->as_flags & ASTK_FLG_XMEM_BASE) == 0) {
		/* have old base buffer and it's not externally 
		 * provided memory, free it up.
		 */
		free(stk->as_base_buf);
		stk->as_base_buf = NULL;
	}

	/* setup new global state */
	stk->as_stack = nstack;
	stk->as_flags &= ~ASTK_FLG_XMEM_BASE;
	stk->as_stack_max = stk->as_stack_size;
	stk->as_base_buf = nbuf;
	stk->as_base_bufsize = len;
	assert(stk->as_xtra_size == xlen);
}


int
astk_enter(astk_t *stk, void *id, int *statep, int istate,
	   void **xtrap, size_t xtra)
{
	astk_rec_t *nstack;
	astk_rec_t *recp;
	int err;
	int len;

	if (!stk || !statep || (xtra != 0 && !xtrap)) {
		return EINVAL;
	}

	if (xtrap) {
		*xtrap = NULL;
	}

	/* round up xtra size to alignment */
	xtra = (xtra + (ASTK_XTRA_ALIGN - 1)) & (~(ASTK_XTRA_ALIGN - 1));

	if (stk->as_stack_pos != stk->as_stack_size) {
		/* Resuming. */
		recp = &stk->as_stack[stk->as_stack_pos];
		if (recp->asr_id != id) {
			return EINVAL;
		}
		if (xtra != recp->asr_xtra_size) {
			return EINVAL;
		}

		*statep = recp->asr_state;
		if (xtra > 0) {
			*xtrap = &((char *)recp->asr_xbuf)[recp->asr_xtra_off];
		}
		stk->as_stack_pos++;
		stk->as_memuse_active += sizeof(astk_rec_t) + xtra;
		return 0;
	}

	/* New frame. First get space for record */

	/* Check for init case (no buffers yet) */
	if (stk->as_base_buf == NULL) {
		/* setup base buf and stack, base on our needs 
		 * and grow sizes 
		 */
		len = (sizeof(astk_rec_t) * ASTK_STACK_GROW + xtra +
		       ASTK_BUF_GROW_SIZE);
		nstack = malloc(len);
		if (!nstack) {
			return ENOMEM;
		}
		stk->as_stack = nstack;
		stk->as_base_buf = nstack;
		stk->as_base_bufsize = len;
	}

	if ((void *)stk->as_stack != stk->as_base_buf) {
		/* stack is not in base buf.  See if we fit */
		if (stk->as_stack_size >= stk->as_stack_max) {
			len = ((stk->as_stack_max + ASTK_STACK_GROW) *
			       sizeof(astk_rec_t));
			nstack = realloc(stk->as_stack, len);
			if (!nstack) {
				return ENOMEM;
			}
			stk->as_stack_max += ASTK_STACK_GROW;
			stk->as_stack = nstack;
		}
	} else {
		len = ((stk->as_stack_size + 1) * sizeof(astk_rec_t));
		if ((len + stk->as_xtra_size) > stk->as_base_bufsize) {
			/* Since we can't realloc basebuf temporarily move the
			 * stack.
			 */
			len = ((stk->as_stack_size + ASTK_STACK_GROW) *
			       sizeof(astk_rec_t));
			nstack = malloc(len);
			if (!nstack) {
				return ENOMEM;
			}
			if (stk->as_stack_size > 0) {
				memcpy(nstack, stk->as_stack,
				       (stk->as_stack_size * 
					sizeof(astk_rec_t)));
			}
			stk->as_stack = nstack;
			stk->as_stack_max = (stk->as_stack_size + 
					     ASTK_STACK_GROW);
		} else {
			stk->as_stack_max = stk->as_stack_size + 1;
		}
	}

	recp = &stk->as_stack[stk->as_stack_size];
	stk->as_stack_size++;
	recp->asr_state = istate;
	recp->asr_id = id;

	/* now get xtra space if required */
	if (xtra > 0) {
		len = stk->as_xtra_size + xtra;
		if ((void *)stk->as_stack == stk->as_base_buf) {
			/* stack is in buffer too. Add that in */
			len += stk->as_stack_size * sizeof(astk_rec_t);
		}
		if (len > stk->as_base_bufsize) {
			/* no room, allocate indivdual buf */
			recp->asr_xbuf = malloc(xtra);
			if (!recp->asr_xbuf) {
				err = ENOMEM;
				goto cleanup;
			}
			recp->asr_xtra_off = 0;
		} else {
			/* just use the basebuf */
			recp->asr_xbuf = stk->as_base_buf;
			stk->as_xtra_size += xtra;
			recp->asr_xtra_off = 
				stk->as_base_bufsize - stk->as_xtra_size;
		}
		recp->asr_xtra_size = xtra;
	} else {
		recp->asr_xbuf = NULL;
		recp->asr_xtra_off = 0;
		recp->asr_xtra_size = 0;
	}

	/* update memory usage numbers */
	stk->as_memuse += sizeof(astk_rec_t) + xtra;
	stk->as_memuse_active += sizeof(astk_rec_t) + xtra;
	if (stk->as_memuse > stk->as_memuse_high) {
		stk->as_memuse_high = stk->as_memuse;
	}

	*statep = istate;
	if (xtra > 0) {
		*xtrap = &((char *)recp->asr_xbuf)[recp->asr_xtra_off];
		/* zero out buffer */
		memset(*xtrap, 0, xtra);
	}
	stk->as_stack_pos++;

	return 0;

cleanup:
	stk->as_stack_size--;
	if ((void *)stk->as_stack == stk->as_base_buf) {
		stk->as_stack_max = stk->as_stack_size;
	}
	return err;
}


int
astk_leave(astk_t *stk, void *id, int state, astk_boolean_t pausing)
{
	astk_rec_t *recp;

	if (!stk || stk->as_stack_pos <= 0) {
		return EINVAL;
	}

	/* have to be within the leaf function to pop */
	if (!pausing && stk->as_stack_pos != stk->as_stack_size) {
		return EBUSY;
	}

	recp = &stk->as_stack[stk->as_stack_pos - 1];
	if (recp->asr_id != id) {
		return EINVAL;
	}

	stk->as_stack_pos--;

	if (pausing) {
		recp->asr_state = state;
	} else {
		stk->as_stack_size--;
		if ((void *)stk->as_stack == stk->as_base_buf) {
			stk->as_stack_max = stk->as_stack_size;
		}

		stk->as_memuse -= sizeof(astk_rec_t) + recp->asr_xtra_size;

		if (recp->asr_xbuf == stk->as_base_buf) {
			stk->as_xtra_size -= recp->asr_xtra_size;
		} else if (recp->asr_xbuf != NULL) {
			free(recp->asr_xbuf);
			recp->asr_xbuf = NULL;
		}

		if (stk->as_stack_pos == 0) {
			assert(stk->as_xtra_size == 0);
			assert(stk->as_memuse == 0);
		}
	}

	stk->as_memuse_active -= sizeof(astk_rec_t) + recp->asr_xtra_size;

	if (stk->as_stack_pos == 0) {
		assert(stk->as_memuse_active == 0);
	}

	if ((stk->as_stack_pos * sizeof(astk_rec_t))
	    == stk->as_memuse_active) {
		/* doesn't look like we have outstanding xtra data (no active
		 * pointers into our stack data).  Do a compression check.
		 */
		astk_compress(stk);
	}

	return 0;
}
