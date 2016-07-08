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

#ifndef _LIBARPC_ASTK_H
#define _LIBARPC_ASTK_H 1

#include <sys/types.h>
#include <sys/cdefs.h>

typedef int astk_boolean_t;
typedef struct astk_s astk_t;
typedef struct astk_rec_s astk_rec_t;

/**
 * A stack for maintaining state of a pausable asynchronous operation.
 * Functions push their state information onto the stack, popping it off
 * when leaving for good. When pausing, they leave their information on the
 * stack with the expectation that the operation will follow the same call
 * sequence again later.
 *
 * @internal
 * <b>Invariants:</b>
 * <ul>
 * <li>0 &lt;= gs_stack_pos &lt;= gs_stack_size</li>
 * </ul>
 */
struct astk_s {
    /**
     * @internal 
     * Pointer to stack records.  We try to keep this at the beginning of
     * the gs_base_buf, but since that can't be realloc'd with non-paused
     * records, this can point at independent malloc'd memory.
     */
    astk_rec_t    *as_stack;

    /** @internal mode flags */
    int                 as_flags;

    /** @internal current stack pos, in records */
    int                 as_stack_pos;

    /** @internal total number of records */
    int                 as_stack_size;

    /** @internal available record space */
    int                 as_stack_max;

    /** @internal pointer to base buffer */
    void               *as_base_buf;

    /** @internal total allocation for base buffer */
    int                 as_base_bufsize;

    /** @internal size in bytes of all xtra data in base buffer */
    int                 as_xtra_size;

    /** @internal current total memory consumed */
    int                 as_memuse;

    /** @internal current active (non-paused) memory consumed */
    int                 as_memuse_active;

    /** @internal high water total memory consumed */
    int                 as_memuse_high;
};

#define ASTK_FLG_XMEM_BASE 0x00000001

__BEGIN_DECLS

/**
 * Initializes a stack.
 * @return 0 on success, error number on failure.
 */
extern int astk_init(astk_t *);

/**
 * Destroys a stack.
 * @return 0 on success, EBUSY if in use.
 */
extern void astk_cleanup(astk_t *);

/**
 * Enters a new function call.
 * Automatically determines if we're resuming a paused execution or
 * starting a new one.
 * @param stk
 * @param id        The address of the calling function, used for error
 *                  checking. It must match the next leave call and, if
 *                  resuming, the current stack frame.
 * @param statep    Current state pointer.  On exit, the value pointed 
 *                  to by statep will be updated to reflect paused state if
 *                  resuming, or initial state if not resuming.
 * @param istate    Initial state if that *statepp will take on if this is
 *                  the first call.
 * @param xtrap     Extra state information. On exit, *xtrap will point to
 *                  memory on the gnarl stack or NULL if xtra == 0.  If
 *                  *xtrap is non-null on return it is the initial call, the
 *                  memory will be zeroed.  If the stack entry is resumed, the
 *                  *xtrap data will have the previous value.
 * @param xtra      Size of the extra state information, 0 if none.
 * @return          0 on success, error number on failure.
 */
extern int astk_enter(astk_t *stk, void *id, int *statep,
                      int istate, void **xtrap, size_t xtra);

/**
 * Leaves a function call.
 * @param stk
 * @param id        An opaque identifier which must match the last
 *                  enter call.
 * @param state     The current state value, to be stored when pausing. 
 * @param pausing   TRUE if this execution will be resumed later,
 *                  FALSE otherwise.
 * @return          0 on success, error number on failure.
 */
extern int astk_leave(astk_t *stk, void *id, int state, 
                      astk_boolean_t pausing);

__END_DECLS

#endif /* !_LIBARPC_ASTK_H */
