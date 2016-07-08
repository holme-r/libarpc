#ifndef _TEST_RPC_H_
#define _TEST_RPC_H_

#include <sys/queue.h>

#define UN_TEST_PATH "/tmp/test_rpc"
#define TEST_INET_PORT 5733

/* Test types */
typedef enum {
	SOCK_TYPE_UNIX = 0,
	SOCK_TYPE_TCP,
	SOCK_TYPE_UDP,
	SOCK_TYPE_NUM
} sock_type_e;

/*
 * CLIENT-Side defines
 */
typedef enum {
	CLNT_MODE_SYNC = 0,
	CLNT_MODE_ASYNC_COPY,
	CLNT_MODE_ASYNC_INPLACE,
	CLNT_MODE_ARPCGEN_SYNC,
	CLNT_MODE_ARPCGEN_COPY,
        CLNT_MODE_NUM
} clnt_mode_e;

typedef enum { 
	CLNT_CMD_SEND = 0,
	CLNT_CMD_EXP,
	CLNT_CMD_CANCEL,

	CLNT_CMD_SET_DEF_CLNT,
	CLNT_CMD_ADD_CLNT,
	CLNT_CMD_DEL_CLNT,
	
	CLNT_CMD_SET_DEF_MODE,

	CLNT_CMD_REQ_CLEAR,
	CLNT_CMD_PRINT_INFO,
	CLNT_CMD_SLEEP,

	CLNT_CMD_LAST /* Ends a script/Num cmds */
} clnt_cmd_e;

typedef struct clnt_tst_s {
	clnt_cmd_e cmd;
	int val1;
	int val2;
	int val3;
	const void *data;       
} clnt_tst_t;

struct clnt_req_elem_s;
typedef TAILQ_HEAD(, clnt_req_elem_s) clnt_req_list_t;
typedef TAILQ_ENTRY(clnt_req_elem_s) clnt_req_listent_t;
typedef struct clnt_req_elem_s {
	clnt_req_listent_t req_listent;

	int reqno;
	ar_clnt_call_obj_t handle;
	test_data parg;
} clnt_req_elem_t;

struct client_elem_s;
typedef TAILQ_HEAD(, client_elem_s) client_list_t;
typedef TAILQ_ENTRY(client_elem_s) client_listent_t;
typedef struct client_elem_s {
	client_listent_t client_listent;

	void *addr;
	arpc_addr_t nb;
	ar_clnt_attr_t attr;
	ar_client_t *client;
	sock_type_e client_type;
} client_elem_t;


typedef struct clnt_state_s {
	client_list_t client_list;
	clnt_req_list_t req_list;

	struct timespec req_tout;

	ar_ioctx_t ctx;
	client_elem_t *def_clnt;
	clnt_mode_e def_mode;

	int tst_cmd_ctr;
	int tst_errs;
	int tst_done;
	clnt_tst_t tst_lst[];
} clnt_state_t;


/* 
 * SERVER-Side defines
 */
typedef enum {
	SVC_CMD_EXP = 0,
	SVC_CMD_RESP_NOW,
	SVC_CMD_DEFER,
	SVC_CMD_RESP_DEFER,

	SVC_CMD_REQ_CLEAR,
	SVC_CMD_PRINT_INFO,
	SVC_CMD_SLEEP,
	
	SVC_CMD_LAST /* Ends a script/Num cmds */
} svc_cmd_e;

typedef struct svc_tst_s {
	svc_cmd_e cmd;
	int val1;
	int val2;
	int val3;
	void *data;
} svc_tst_t;

struct svc_req_elem_s;
typedef TAILQ_HEAD(, svc_req_elem_s) svc_req_list_t;
typedef TAILQ_ENTRY(svc_req_elem_s) svc_req_listent_t;
typedef struct svc_req_elem_s {
	svc_req_listent_t req_listent;

	int reqno;
	ar_svc_call_obj_t sco;
} svc_req_elem_t;

struct service_elem_s;
typedef TAILQ_HEAD(, service_elem_s) service_list_t;
typedef TAILQ_ENTRY(service_elem_s) service_listent_t;
typedef struct service_elem_s {
	service_listent_t service_listent;

	void *addr;
	arpc_addr_t nb;
	ar_svc_attr_t attr;
	ar_svc_xprt_t *service;
	sock_type_e service_type;
} service_elem_t;

typedef struct svc_state_s {
	svc_req_list_t req_list;
	service_list_t service_list;

	int tst_cmd_ctr;
	int tst_errs;
	int tst_done;
	svc_tst_t tst_lst[];
} svc_state_t;

/* 
 * Script components 
 */
/* This script performs a basic back and forth without deferral */
#define CLNT_TST_SCR_SYNC			\
	{CLNT_CMD_SEND, 1, 91, 0, NULL},	\
	{CLNT_CMD_EXP, 11, 0, 0, NULL},		\
	{CLNT_CMD_SEND, 2, 92, 0, NULL},	\
	{CLNT_CMD_EXP, 12, 0, 0, NULL},		\
	{CLNT_CMD_SEND, 3, 93, 0, NULL},	\
	{CLNT_CMD_EXP, 13, 0, 0, NULL},		\
	{CLNT_CMD_SEND, 4, 94, 0, NULL},	\
	{CLNT_CMD_EXP, 14, 0, 0, NULL},		\
	{CLNT_CMD_REQ_CLEAR, 0, 0, 0, NULL}

#define SVC_TST_SCR_SYNC				\
	{SVC_CMD_EXP, 1, 0, 0, NULL},			\
	{SVC_CMD_RESP_NOW, 11, 0, 0, NULL},		\
	{SVC_CMD_EXP, 2, 0, 0, NULL},		        \
	{SVC_CMD_RESP_NOW, 12, 0, 0, NULL},		\
	{SVC_CMD_EXP, 3, 0, 0, NULL},		        \
	{SVC_CMD_RESP_NOW, 13, 0, 0, NULL},		\
	{SVC_CMD_EXP, 4, 0, 0, NULL},			\
	{SVC_CMD_RESP_NOW, 14, 0, 0, NULL},		\
	{SVC_CMD_REQ_CLEAR, 0, 0, 0, NULL}

/* This script tests for the ability for several requests to be marked
 * async and replied to at a later time (out of order)
 */
#define CLNT_TST_SCR_ASYNC			\
	{CLNT_CMD_SEND, 1, 91, 0, NULL},	\
        {CLNT_CMD_SEND, 2, 92, 0, NULL},	\
	{CLNT_CMD_SEND, 3, 93, 0, NULL},	\
	{CLNT_CMD_SEND, 4, 94, 0, NULL},	\
	{CLNT_CMD_SEND, 5, 95, 0, NULL},	\
	{CLNT_CMD_EXP, 12, 0, 0, NULL},		\
	{CLNT_CMD_EXP, 13, 0, 0, NULL},		\
	{CLNT_CMD_EXP, 11, 0, 0, NULL},		\
	{CLNT_CMD_EXP, 14, 0, 0, NULL},		\
	{CLNT_CMD_EXP, 15, 0, 0, NULL},		\
	{CLNT_CMD_REQ_CLEAR, 0, 0, 0, NULL}

#define SVC_TST_SCR_ASYNC				\
	{SVC_CMD_EXP, 1, 0, 0, NULL},			\
	{SVC_CMD_DEFER, 91, 0, 0, NULL},		\
	{SVC_CMD_EXP, 2, 0, 0, NULL},			\
	{SVC_CMD_DEFER, 92, 0, 0, NULL},		\
	{SVC_CMD_EXP, 3, 0, 0, NULL},			\
	{SVC_CMD_DEFER, 93, 0, 0, NULL},		\
	{SVC_CMD_EXP, 4, 0, 0, NULL},			\
	{SVC_CMD_DEFER, 94, 0, 0, NULL},		\
	{SVC_CMD_EXP, 5, 0, 0, NULL},			\
	{SVC_CMD_RESP_NOW, 15, 0, 0, NULL},		\
	{SVC_CMD_RESP_DEFER, 92, 12, 0, NULL},		\
	{SVC_CMD_RESP_DEFER, 93, 13, 0, NULL},		\
	{SVC_CMD_RESP_DEFER, 91, 11, 0, NULL},		\
	{SVC_CMD_RESP_DEFER, 94, 14, 0, NULL},		\
	{SVC_CMD_REQ_CLEAR, 0, 0, 0, NULL}

/* This script tests for the client's ability to cancel an in-flight request */
#define CLNT_TST_SCR_CANCEL			\
	{CLNT_CMD_SEND, 21, 96, 0, NULL},	\
	{CLNT_CMD_SEND, 22, 97, 0, NULL},	\
	{CLNT_CMD_EXP, 32, 0, 0, NULL},		\
	{CLNT_CMD_SEND, 23, 98, 0, NULL},	\
 	{CLNT_CMD_CANCEL, 96, 0, 0, NULL},	\
	{CLNT_CMD_EXP, 33, 0, 0, NULL},		\
        {CLNT_CMD_REQ_CLEAR, 0, 0, 0, NULL}

#define SVC_TST_SCR_CANCEL			\
	{SVC_CMD_EXP, 21, 0, 0, NULL},		\
	{SVC_CMD_DEFER, 96, 0, 0, NULL},	\
	{SVC_CMD_EXP, 22, 0, 0, NULL},		\
	{SVC_CMD_RESP_NOW, 32, 0, 0, NULL},	\
	{SVC_CMD_EXP, 23, 0, 0, NULL},		\
	{SVC_CMD_RESP_NOW, 33, 0, 0, NULL},	\
	{SVC_CMD_RESP_DEFER, 96, 31, 0, NULL},	\
	{SVC_CMD_REQ_CLEAR, 0, 0, 0, NULL}

/* Ensures that duplicate UDP svc calls are filtered out */
#define CLNT_TST_SCR_UDP_ASYNC_DUP_FILT					\
	{CLNT_CMD_SET_DEF_MODE, CLNT_MODE_ASYNC_COPY, 0, 0, NULL},	\
	{CLNT_CMD_SET_DEF_CLNT, SOCK_TYPE_UDP, 0, 0, NULL},		\
	{CLNT_CMD_SEND, 1, 0, 0, NULL},					\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"sleeping..."},	\
	{CLNT_CMD_SLEEP, 4, 0, 0, NULL},				\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"continuing"},	\
	{CLNT_CMD_SEND, 2, 0, 0, NULL},					\
	{CLNT_CMD_EXP, 12, 0, 0, NULL},					\
	{CLNT_CMD_SEND, 3, 0, 0, NULL},					\
	{CLNT_CMD_EXP, 11, 0, 0, NULL},					\
	{CLNT_CMD_EXP, 13, 0, 0, NULL}

#define SVC_TST_SCR_UDP_ASYNC_DUP_FILT		\
	{SVC_CMD_EXP, 1, 0, 0, NULL},		\
	{SVC_CMD_DEFER, 91, 0, 0, NULL},	\
	{SVC_CMD_EXP, 2, 0, 0, NULL},		\
	{SVC_CMD_RESP_NOW, 12, 0, 0, NULL},	\
	{SVC_CMD_EXP, 3, 0, 0, NULL},		\
	{SVC_CMD_RESP_DEFER, 91, 11, 0, NULL},	\
	{SVC_CMD_RESP_NOW, 13, 0, 0, NULL}

/* 
 * Script suites 
 */
#define CLNT_TST_SUITE_SYNC(test_mode, conn_type)			\
	{CLNT_CMD_SET_DEF_MODE, test_mode, 0, 0, NULL},			\
	{CLNT_CMD_SET_DEF_CLNT, conn_type, 0, 0, NULL},			\
	CLNT_TST_SCR_SYNC

#define SVC_TST_SUITE_SYNC			\
	SVC_TST_SCR_SYNC

#define CLNT_TST_SUITE_ASYNC(test_mode, conn_type)			\
	{CLNT_CMD_SET_DEF_MODE, test_mode, 0, 0, NULL},			\
	{CLNT_CMD_SET_DEF_CLNT, conn_type, 0, 0, NULL},			\
	CLNT_TST_SCR_ASYNC,					        \
	CLNT_TST_SCR_CANCEL

#define SVC_TST_SUITE_ASYNC			\
	SVC_TST_SCR_ASYNC,			\
	SVC_TST_SCR_CANCEL
	
/* 
 * Final Scripts 
 */
#define CLNT_TST_SCRIPT							\
        /* unix */						        \
        {CLNT_CMD_ADD_CLNT, SOCK_TYPE_UNIX, 0, 0, NULL},		\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"UNIX:\nsync"},	\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_SYNC, SOCK_TYPE_UNIX),	        \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen sync:"},	\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_ARPCGEN_SYNC, SOCK_TYPE_UNIX),	\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async copy:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_COPY, SOCK_TYPE_UNIX),     \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async inplace:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_INPLACE, SOCK_TYPE_UNIX),  \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen async copy:"}, \
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ARPCGEN_COPY, SOCK_TYPE_UNIX),	\
									\
	/* TCP */						        \
	{CLNT_CMD_ADD_CLNT, SOCK_TYPE_TCP, 0, 0, NULL},			\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"\nTCP:\nsync"},	\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_SYNC, SOCK_TYPE_TCP),	        \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen sync:"},	\
	{CLNT_CMD_DEL_CLNT, SOCK_TYPE_UNIX, 0, 0, NULL},		\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_ARPCGEN_SYNC, SOCK_TYPE_TCP),     \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async copy:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_COPY, SOCK_TYPE_TCP),      \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async inplace:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_INPLACE, SOCK_TYPE_TCP),   \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen async copy:"}, \
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ARPCGEN_COPY, SOCK_TYPE_TCP),	\
									\
	/* UDP */							\
	{CLNT_CMD_ADD_CLNT, SOCK_TYPE_UDP, 0, 0, NULL},			\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"\nUDP:\nsync"},	\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_SYNC, SOCK_TYPE_UDP),	        \
	{CLNT_CMD_DEL_CLNT, SOCK_TYPE_TCP, 0, 0, NULL},			\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen sync:"},	\
	CLNT_TST_SUITE_SYNC(CLNT_MODE_ARPCGEN_SYNC, SOCK_TYPE_UDP),	\
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async copy:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_COPY, SOCK_TYPE_UDP),      \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"async inplace:"},	\
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ASYNC_INPLACE, SOCK_TYPE_UDP),   \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"rpcgen async copy:"}, \
	CLNT_TST_SUITE_ASYNC(CLNT_MODE_ARPCGEN_COPY, SOCK_TYPE_UDP),    \
	{CLNT_CMD_PRINT_INFO, 0, 0, 0, (const void *)"dup filter:"},	\
	CLNT_TST_SCR_UDP_ASYNC_DUP_FILT,				\
									\
	{CLNT_CMD_LAST, 0, 0, 0, NULL}

#define SVC_TST_SCRIPT				\
        /* Unix */				\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
						\
        /* TCP */				\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
						\
        /* UDP */				\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_SYNC,			\
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SUITE_ASYNC,		        \
	SVC_TST_SCR_UDP_ASYNC_DUP_FILT,		\
						\
	{SVC_CMD_LAST, 0, 0, 0, NULL}

#endif /* !_TEST_RPC_H_ */
