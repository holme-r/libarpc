#include <atf-c.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libarpc/axdr.h>
#include <libarpc/arpc.h>
#include <libarpc/clnt.h>

#define _RPC_NETDB_H 1
#include <netdb.h>
#include <assert.h>

#include "testobjs_rpc.h"
#include "test_rpc.h"

#include <pthread.h>
#define NUM_PTHREADS 2 /* svc and clnt */

#define DEBUG_SVC_CMDS 0
#define DEBUG_SVC_RECV 0
#define DEBUG_CLNT_CMDS 0
#define DEBUG_CLNT_RECV 0
#define DEBUG_CLNT_STATUS 0

#define DEBUG_ENABLE_PRINT_INFO_CMD 1
#define DEBUG_PRINT_XTRA_INFO 0
#define DEBUG_CLNT_LINE 0
#define DEBUG_SVC_LINE 0

const char *conn_type_to_netid[] = {"local", "tcp", "udp" };
const char *client_mode_to_str[] = {"sync","async copy", "async inplace",
				    "arpcgen sync", "arpcgen async copy"};


/* Mutex's and conditions for svc/clnt */
bool_t client_rdy;
pthread_mutex_t client_rdy_mtx;
pthread_cond_t client_rdy_cv;

bool_t server_rdy;
pthread_mutex_t server_rdy_mtx;
pthread_cond_t server_rdy_cv;

/* Initialize the svc state */
svc_state_t svc_state = {
	.tst_cmd_ctr = 0,
	.tst_errs = 0,
	.tst_done = 0,
	.tst_lst = { SVC_TST_SCRIPT }
};

/* Initialize the clnt state */
clnt_state_t clnt_state = {
	.tst_cmd_ctr = 0,
	.tst_errs = 0,
	.tst_done = 0,
	.def_clnt = NULL,
	.req_tout = { 
		.tv_sec = 25,
		.tv_nsec = 0
	},
	.tst_lst = { CLNT_TST_SCRIPT }
};

/* Local functions */
static void test_clnt_statem(void);
static int test_client_create(ar_ioctx_t ctx, sock_type_e client_type);
static int test_client_destroy(sock_type_e client_type);
static int test_client_find(sock_type_e client_type, client_elem_t **ret_elem);

static int test_service_create(ar_ioctx_t ctx, sock_type_e svc_type);

static int test_clnt_req_cleanup(void);
static int test_svc_req_cleanup(void);


static void
test_svc_defer_request(struct ar_svc_req_s *rqstp, int reqno) 
{
	svc_req_elem_t *req_elem;
	int err;

	req_elem = (svc_req_elem_t *) malloc(sizeof(svc_req_elem_t));
	if (req_elem == NULL) {
		fprintf(stderr, "svc cannot alloc req\n");
		abort();
	}

	req_elem->reqno = reqno;

	err = ar_svc_async(rqstp, &req_elem->sco);
	if (err != 0) {
		fprintf(stderr, "svc error deferring\n");
		abort();
	}

	TAILQ_INSERT_TAIL(&svc_state.req_list, req_elem, req_listent);
}

static int
test_svc_resp_defered(int reqno, int response) 
{
	svc_req_elem_t *req_elem;
	test_data *rqst_resp;
	bool_t req_found;
	int err;

	req_found = FALSE;
	TAILQ_FOREACH(req_elem, &svc_state.req_list, req_listent) {
		if (req_elem->reqno == reqno) {
			req_found = TRUE;
			break;
		}
	}

	if (!req_found) {
		fprintf(stderr, "svc async request not found\n");
		abort();
		return ENOENT;
	}

	/* Get result pointer */
	err = ar_svc_async_get_resultptr(req_elem->sco, (void **) &rqst_resp);
	if (err != 0) {
		fprintf(stderr, "svc cannot get result ptr: %d\n", err);
		abort();
	}

	/* Send Response */
	rqst_resp->val = response;
	
	/* Mark async done */
	ar_svc_async_done(req_elem->sco, TRUE);
	
	/* Delete node */
	TAILQ_REMOVE(&svc_state.req_list, req_elem, req_listent);
	free(req_elem);
	/* Return EOK */
	return 0;
}

static int
test_svc_req_cleanup(void)
{
	svc_req_elem_t *req_elem;

	while ((req_elem = TAILQ_FIRST(&svc_state.req_list)) != NULL) {
		TAILQ_REMOVE(&svc_state.req_list, req_elem, req_listent);
		
		fprintf(stderr, "svc cleanup removing defered req: %d\n", 
			req_elem->reqno);
		free(req_elem);
	}

	return 0;
}


bool_t
test_rpc_1_svc(test_data argp, test_data *resp, ar_svc_req_t *rqstp)
{
	int *p_cmd_ctr;
	svc_tst_t *p_tst;

	p_cmd_ctr = &svc_state.tst_cmd_ctr;
	p_tst = &svc_state.tst_lst[*p_cmd_ctr];

#if DEBUG_SVC_RECV
	fprintf(stderr, "svc recv: %d (%u)\n", argp.val, rqstp->rq_xid);
#endif

	if (p_tst->cmd != SVC_CMD_EXP) {
		fprintf(stderr, "svc cmd (%d) is not EXP: %d\n", 
		    *p_cmd_ctr, p_tst->cmd);
		abort();
	}

	if (argp.val != p_tst->val1) {
		fprintf(stderr, "svc exp: %d, got: %d\n",
		    p_tst->val1, argp.val);
		svc_state.tst_errs++;
	}

	(*p_cmd_ctr)++;
	p_tst = &svc_state.tst_lst[*p_cmd_ctr];

	for (;;) {
#if DEBUG_SVC_CMDS
		fprintf(stderr, "svc: offset: %d, cmd: %d\n",
			*p_cmd_ctr, p_tst->cmd);
#endif

		switch(p_tst->cmd) {
		case SVC_CMD_EXP:
			/* Quit Handler */
			goto svc_statem_done;
			break;
		case SVC_CMD_RESP_NOW:
			/* Respond now */
			resp->val = p_tst->val1;
			break;
		case SVC_CMD_DEFER:
			/* Defer response */
			test_svc_defer_request(rqstp, p_tst->val1);
			break;
		case SVC_CMD_RESP_DEFER:
			/* Respond to deferred req */
			test_svc_resp_defered(p_tst->val1, p_tst->val2);
			break;
		case SVC_CMD_REQ_CLEAR:
			test_svc_req_cleanup();
			break;
		case SVC_CMD_PRINT_INFO:
#if DEBUG_ENABLE_PRINT_INFO_CMD
			fprintf(stderr, "%s\n", (char *)p_tst->data);
#endif
			break;
		case SVC_CMD_SLEEP:
			sleep(p_tst->val1); /* Sleep for x seconds */
			break;
		case SVC_CMD_LAST:
			/* Quit handler, mark done */
			svc_state.tst_done = 1;
			goto svc_statem_done;
			break;
		default:
			fprintf(stderr,
				"svc cmd (offset: %d) not handled: %d\n",
				*p_cmd_ctr, p_tst->cmd);
			abort();
			break;
		}

		(*p_cmd_ctr)++;
		p_tst = &svc_state.tst_lst[*p_cmd_ctr];
	}

svc_statem_done:
	return TRUE;
}

static void
test_clnt_callback(ar_clnt_call_obj_t handle, void *arg,
		   const arpc_err_t *stat, void *result)
{
	struct test_data *ret;
	int ctr = clnt_state.tst_cmd_ctr;
	clnt_tst_t *p_tst = &clnt_state.tst_lst[ctr];
	clnt_req_elem_t *req_elem;
	bool_t obj_found;
	
#if DEBUG_CLNT_STATUS
	fprintf(stderr, "clnt re_stat: %d\n", stat->re_status);
#endif

	if (!result) {
		fprintf(stderr, "no result\n");
		abort();
	}
	
	ret = (struct test_data *)result;
	
#if DEBUG_CLNT_RECV
	fprintf(stderr, "clnt recv: %d\n", ret->val);
#endif
	if (stat->re_status != ARPC_SUCCESS) {
		fprintf(stderr, "clnt status != ARPC_SUCCESS: %d\n",
		    stat->re_status);
		abort();
	}
	
	if (p_tst->cmd != CLNT_CMD_EXP) {
		fprintf(stderr, "clnt cmd (%d) is not EXP: %d\n",
		    ctr, p_tst->cmd);
		abort();
	}
	
	if (p_tst->val1 != ret->val) {
		fprintf(stderr, "clnt exp: %d, got: %d\n",
		    p_tst->val1, ret->val);
		clnt_state.tst_errs++;
	}
	
	/* Find current request */
	obj_found = FALSE;
	TAILQ_FOREACH(req_elem, &clnt_state.req_list, req_listent) {
		if (req_elem->handle == handle) {
			obj_found = TRUE;
			break;
		}
	}
	if (!obj_found) {
		fprintf(stderr, "clnt request not found\n");
		abort();
	}

	/* Delete the call object from the list */
	TAILQ_REMOVE(&clnt_state.req_list, req_elem, req_listent);
	free(req_elem);

	/* advance to the next cmd */
	clnt_state.tst_cmd_ctr++;
	test_clnt_statem(); /* Run the clnt state machine */
}

static void
test_clnt_sync_req(clnt_req_elem_t *req, client_elem_t *default_client,
		   bool_t use_arpcgen_call)
{
	test_data resp;
	arpc_err_t errp;
	ar_stat_t stat;
	clnt_tst_t *p_tst;
	int sync_exp;

	memset(&resp, 0, sizeof(resp));

	/* Read the expected value from next cmd */
	p_tst = &clnt_state.tst_lst[++clnt_state.tst_cmd_ctr];

	if (default_client == NULL) {
		fprintf(stderr, "clnt sync: default client null\n");
		abort();
	}
	if (p_tst->cmd != CLNT_CMD_EXP) {
		fprintf(stderr, "clnt sync cmd (%d) is not EXP: %d\n", 
		    clnt_state.tst_cmd_ctr, p_tst->cmd);
		abort();
	}
	sync_exp = p_tst->val1;
	
	if (use_arpcgen_call) {
		stat = test_rpc_1(req->parg, &resp, default_client->client);
	} else {
		stat = ar_clnt_call(
			default_client->client, (arpcproc_t)test_rpc,
			(axdrproc_t)axdr_test_data, (char *)&req->parg,
			(axdrproc_t)axdr_test_data, (char *)&resp,
			sizeof(resp), NULL, &errp);
	}
	if (stat != ARPC_SUCCESS) {
		fprintf(stderr, "clnt status != ARPC_SUCCESS: %d\n", stat);
		abort();
	}

#if DEBUG_CLNT_STATUS
	fprintf(stderr, "clnt re_stat (sync): %d\n", stat);
#endif

	if (sync_exp != resp.val) {
		fprintf(stderr, "clnt exp: %d, got: %d\n",
		    sync_exp, resp.val);
		clnt_state.tst_errs++;
	}

	axdr_free((axdrproc_t) &axdr_test_data, (char *)&resp);

	/* Remove the request and free memory */
	TAILQ_REMOVE(&clnt_state.req_list, req, req_listent);
	free(req);
}

static void
test_clnt_new_req(int send_val, int reqno)
{
	int err;
	clnt_req_elem_t *req;
	client_elem_t *default_client;
	ar_stat_t ar_stat;

	/* allocate a new request element */
	req = (clnt_req_elem_t *) malloc(sizeof(clnt_req_elem_t));
	if (req == NULL) {
		fprintf(stderr, "clnt cannot alloc req\n");
		abort();
	}

	/* Save the request number and send arg */
	req->reqno = reqno;
	req->parg.val = send_val;
	
	TAILQ_INSERT_TAIL(&clnt_state.req_list, req, req_listent);
	
	default_client = clnt_state.def_clnt;
	if (default_client == NULL) {
		fprintf(stderr, "default client not selected\n");
		abort();
	}

	switch(clnt_state.def_mode) {
	case CLNT_MODE_SYNC:
		test_clnt_sync_req(req, default_client, FALSE);
		break;

	case CLNT_MODE_ASYNC_COPY:
		err = ar_clnt_call_async_copy(
			default_client->client, (arpcproc_t)test_rpc,
			(axdrproc_t) &axdr_test_data, (char *)&req->parg,
			(axdrproc_t) &axdr_test_data,
			sizeof(struct test_data), test_clnt_callback,
			NULL, &clnt_state.req_tout, &req->handle);
		if (err != 0) {
			fprintf(stderr, "async call failed: %d\n", err);
			abort();
		}
		break;

	case CLNT_MODE_ASYNC_INPLACE:
		err = ar_clnt_call_async_inplace(
			default_client->client, (arpcproc_t)test_rpc,
			(axdrproc_t) &axdr_test_data, (char *)&req->parg,
			(axdrproc_t) &axdr_test_data,
			sizeof(struct test_data), test_clnt_callback,
			NULL, &clnt_state.req_tout, &req->handle);
		if (err != 0) {
			fprintf(stderr, "async call failed: %d\n", err);
			abort();
		}
		break;

	case CLNT_MODE_ARPCGEN_SYNC:
		test_clnt_sync_req(req, default_client, TRUE);
		break;

	case CLNT_MODE_ARPCGEN_COPY:
		ar_stat = test_rpc_1_async(
			req->parg, default_client->client,
			(test_rpc_1_cb_t) test_clnt_callback,
			NULL, &req->handle);

		if (ar_stat != ARPC_INPROGRESS) {
			fprintf(stderr, "arpcgen copy call failed: %d\n",
				ar_stat);
			abort();
		}
		break;
		
	default:
		fprintf(stderr, "client mode not supported: %d\n",
		    clnt_state.def_mode);
		abort();
	}

}

static void
test_clnt_cancel_req(int reqno) 
{
	bool_t req_found;
	clnt_req_elem_t *req_elem;

	req_found = FALSE;
	TAILQ_FOREACH(req_elem, &clnt_state.req_list, req_listent) {
		if (req_elem->reqno == reqno) {
			req_found = TRUE;
			break;
		}
	}
	if (!req_found) {
		fprintf(stderr, "clnt cannot find req (%d) to cancel\n", reqno);
		abort();
	}

	TAILQ_REMOVE(&clnt_state.req_list, req_elem, req_listent);

	/* Cancel the request */
	ar_clnt_call_cancel(req_elem->handle);

#if DEBUG_CLNT_STATUS
	fprintf(stderr, "clnt cancelled: %d\n", reqno);
#endif

	/* Remove the element and free the memory */
	free(req_elem);
}

static int
test_clnt_req_cleanup(void)
{
	clnt_req_elem_t *req_elem;

	while(!TAILQ_EMPTY(&clnt_state.req_list)) {
		req_elem = TAILQ_FIRST(&clnt_state.req_list);
		TAILQ_REMOVE(&clnt_state.req_list, req_elem, req_listent);
		
		fprintf(stderr, "clnt cleanup removing unanswered req: %d\n",
		    req_elem->reqno);

		/* Cancel the request */
		ar_clnt_call_cancel(req_elem->handle);

		/* Free the memory */
		free(req_elem);
	}

	return 0;
}

static void
test_clnt_statem(void)
{
	int err;
	client_elem_t *client_elem;
	int *p_cmd_ctr;
	clnt_tst_t *p_tst;

	p_cmd_ctr = &clnt_state.tst_cmd_ctr;
	p_tst = &clnt_state.tst_lst[*p_cmd_ctr];

	for (;;) {
#if DEBUG_CLNT_CMDS
		fprintf(stderr, "clnt: offset: %d, cmd: %d\n",
			*p_cmd_ctr, p_tst->cmd);
#endif

		switch(p_tst->cmd) {
		case CLNT_CMD_SEND:
			test_clnt_new_req(p_tst->val1, p_tst->val2);
			break;
		case CLNT_CMD_EXP:
			goto clnt_statem_done;
			break;
		case CLNT_CMD_CANCEL:
			test_clnt_cancel_req(p_tst->val1);
			break;
		case CLNT_CMD_ADD_CLNT:
			test_client_create(clnt_state.ctx, p_tst->val1);
			break;
		case CLNT_CMD_SET_DEF_CLNT:
			if ((p_tst->val1 < 0) ||
			    (p_tst->val1 >= SOCK_TYPE_NUM)) {
				fprintf(stderr,
					"sock type out of range %d [%d,%d)\n",
					p_tst->val1, 0, SOCK_TYPE_NUM);
				abort();
			}
			err = test_client_find(p_tst->val1, &client_elem);
			if (err != 0) { 
				fprintf(stderr,
					"cannot set default client to %d\n",
					p_tst->val1);
				abort();
			}
#if DEBUG_PRINT_XTRA_INFO
			fprintf(stderr, "setting default client to %s\n",
				conn_type_to_netid[p_tst->val1]);
#endif
			clnt_state.def_clnt = client_elem;
			break;
		case CLNT_CMD_DEL_CLNT:
			test_client_destroy(p_tst->val1);
			break;
		case CLNT_CMD_SET_DEF_MODE:
			if ((p_tst->val1 < 0) ||
			    (p_tst->val1 >= CLNT_MODE_NUM)) {
				fprintf(stderr,
					"clnt mode out of range %d [%d, %d)\n",
					p_tst->val1, 0, CLNT_MODE_NUM);
				abort();
			}
#if DEBUG_PRINT_XTRA_INFO
			fprintf(stderr, "setting default client mode to %s\n", 
			    client_mode_to_str[p_tst->val1]);
#endif
			clnt_state.def_mode = p_tst->val1;
			break;
		case CLNT_CMD_REQ_CLEAR:
			test_clnt_req_cleanup();
			break;
		case CLNT_CMD_SLEEP:
			sleep(p_tst->val1);
			break;
		case CLNT_CMD_PRINT_INFO:
#if DEBUG_ENABLE_PRINT_INFO_CMD
			fprintf(stderr, "%s\n", (const char *)p_tst->data);
#endif
			break;
		case CLNT_CMD_LAST:
			clnt_state.tst_done = 1;
			goto clnt_statem_done;
			break;
		default:
			fprintf(stderr,
				"clnt cmd (offset: %d) not handled: %d\n",
				*p_cmd_ctr, p_tst->cmd);
			abort();
			break;
		}

		(*p_cmd_ctr)++;
		p_tst = &clnt_state.tst_lst[*p_cmd_ctr];
	}

clnt_statem_done:
	return;
}

static int
test_client_find(sock_type_e client_type, client_elem_t **ret_elem)
{
	client_elem_t *client_elem;
	bool_t found_elem = FALSE;
	
	TAILQ_FOREACH(client_elem, &clnt_state.client_list, client_listent) {
		if (client_elem->client_type == client_type) {
			found_elem = TRUE;
			break;
		}
	}

	if (!found_elem) {
		*ret_elem = NULL;
		return ENOENT;
	}

	*ret_elem = client_elem;
	return 0;
}

static int
test_client_create(ar_ioctx_t ctx, sock_type_e client_type)
{
	int err;
	const char *netid;
	struct sockaddr_in *p_addr_in;
	struct sockaddr_un *p_addr_un;
	arpc_addr_t *p_nb;
	int len;
	struct hostent *hent;
	arpc_createerr_t errp;
	client_elem_t *client_elem;
	int port = TEST_INET_PORT;
	const char *hostname = "localhost";

	
	/* Set the netid */
	netid = conn_type_to_netid[client_type];
#if DEBUG_PRINT_XTRA_INFO
	fprintf(stderr, "client %s starting\n", netid);
#endif
	
	err = test_client_find(client_type, &client_elem);
	if (err == 0) {
		fprintf(stderr, "%s client already created\n", netid);
		return EINVAL;
	}

	client_elem = (client_elem_t *) malloc(sizeof(client_elem_t));
	if (client_elem == NULL) {
		fprintf(stderr, "cannot allocate client elem\n");
		abort();
	}

	/* Get the nb pointer */
	p_nb = &client_elem->nb;
		
	/* Setup the netbuf */
	switch(client_type) {
	case SOCK_TYPE_UNIX:
		p_addr_un = (struct sockaddr_un *) 
		    malloc(sizeof(struct sockaddr_un));
		if (p_addr_un == NULL) {
			fprintf(stderr, "cannot allocate addr_un\n");
			abort();
		}
		client_elem->addr = (void *) p_addr_un;
		
		p_addr_un->sun_family = AF_LOCAL;
		strcpy(p_addr_un->sun_path, UN_TEST_PATH);
		
		/* set nb len */
		len = sizeof(struct sockaddr_un);
		break;

	case SOCK_TYPE_TCP:
	case SOCK_TYPE_UDP:
		p_addr_in = (struct sockaddr_in *) 
		    malloc(sizeof(struct sockaddr_in));
		if (p_addr_in == NULL) {
			fprintf(stderr, "cannot allocate addr_in\n");
			abort();
		}
		client_elem->addr = (void *) p_addr_in;
		
		hent = gethostbyname(hostname);
		if (!hent) {
			fprintf(stderr, "unable to resolve %s\n", hostname);
			abort();
		}
		
		p_addr_in->sin_family = AF_INET;
		p_addr_in->sin_port = htons(port);
		memcpy(&p_addr_in->sin_addr, 
		    hent->h_addr_list[0], 
		    sizeof(p_addr_in->sin_addr));

		/* set nb len */
		len = sizeof(struct sockaddr_in);
		break;
	default:
		fprintf(stderr, "client connection type not supported: %d\n",
		    client_type);
		abort();
		break;
	}

	p_nb->buf = (char *) client_elem->addr;
	p_nb->len = len;
	p_nb->maxlen = len;

	ar_clnt_attr_init(&client_elem->attr);
#if DEBUG_CLNT_LINE
	ar_clnt_attr_set_debug(&client_elem->attr, stderr, "CLNT DBG: ");
#endif
	/* Create client */
	err = ar_clnt_tli_create(ctx, netid, p_nb, 
				 TEST_RPC, TEST_RPC_VERS,
				 &client_elem->attr, &errp,
				 &client_elem->client);
	if (err != 0) {
		fprintf(stderr, "unable to create ping client: %d\n", err);
		abort();
	}
	/* Add tailq client and client type */
	client_elem->client_type = client_type;

	TAILQ_INSERT_TAIL(&clnt_state.client_list, client_elem, client_listent);

	return 0;
}

static int
test_client_destroy(sock_type_e client_type)
{
	int err;
	client_elem_t *client_elem;

	err = test_client_find(client_type, &client_elem);
	if (err != 0) {
		fprintf(stderr, "%s client doesn't exist\n",
			conn_type_to_netid[client_type]);
		return EINVAL;
	}
	
	TAILQ_REMOVE(&clnt_state.client_list, client_elem, client_listent);
	
	/* Destroy the client */
	ar_clnt_destroy(client_elem->client);
	ar_clnt_attr_destroy(&client_elem->attr);
	
#if DEBUG_PRINT_XTRA_INFO
	fprintf(stderr, "%s client destroyed\n",
	    conn_type_to_netid[client_type]);
#endif
	
	/* mark the default client NULL if we're deleting it */
	if (clnt_state.def_clnt == client_elem) {
#if DEBUG_PRINT_XTRA_INFO
		fprintf(stderr, "\tsetting default client null\n");
#endif
		clnt_state.def_clnt = NULL;
	}

	free(client_elem->addr);
	free(client_elem);
	
	return 0;
}

static void *
client_thread(void *pt)
{
	client_elem_t *client_elem;
	ar_ioctx_t ctx;
	int err;

	/* Setup the client state */
	clnt_state.tst_done = 0;
	TAILQ_INIT(&clnt_state.req_list);
	TAILQ_INIT(&clnt_state.client_list);

	/* Wait for the server to start up 
	 * before we start looking for services 
	 */
	pthread_mutex_lock(&server_rdy_mtx);
	while (!server_rdy) {
		pthread_cond_wait(&server_rdy_cv, &server_rdy_mtx);
	}
	pthread_mutex_unlock(&server_rdy_mtx);

	
	/* Create Client CTX */
	err = ar_ioctx_create(&ctx);
	if (err != 0) {
		fprintf(stderr, "unable to create client ioctx: %d\n", err);
		abort();
	}
	clnt_state.ctx = ctx;

	/* Run the client state machine */
	test_clnt_statem();

	/* Test */
	while (!clnt_state.tst_done) {
		err = ar_ioctx_loop(ctx);
		if (err == EINTR) {
			continue;
		}
		assert(err == 0);
	}

	/* Clean up unanswered requests */
	test_clnt_req_cleanup();

	/* Remove all remaining clients */
	while(!TAILQ_EMPTY(&clnt_state.client_list)) {
		client_elem = TAILQ_FIRST(&clnt_state.client_list);
		test_client_destroy(client_elem->client_type);
	}
	
	/* Destroy the ioctx */
 	ar_ioctx_destroy(ctx);
	ctx = NULL;
	
	pthread_exit(NULL);	
}

static int
test_service_create(ar_ioctx_t ctx, sock_type_e svc_type)
{
	int err;
	struct sockaddr_in *p_addr_in;
	struct sockaddr_un *p_addr_un;
	const char *netid;
	bool_t found_svc;
	service_elem_t *svc_elem;
	arpc_addr_t *p_nb;
	int len;
	int port = TEST_INET_PORT;
	arpc_err_t errp;

	netid = conn_type_to_netid[svc_type];

	found_svc = FALSE;
	TAILQ_FOREACH(svc_elem, &svc_state.service_list, service_listent) {
		if (svc_elem->service_type == svc_type) {
			found_svc = TRUE;
		}
	}
	if (found_svc) {
		fprintf(stderr, "%s service already exists\n", netid);
		return EINVAL;
	}

	svc_elem = (service_elem_t *) malloc(sizeof(service_elem_t));
	if (svc_elem == NULL) {
		fprintf(stderr, "cannot allocate svc elem\n");
		abort();
	}

	p_nb = &svc_elem->nb;

	switch(svc_type) {
	case SOCK_TYPE_UNIX:
		p_addr_un = (struct sockaddr_un *)
		    malloc(sizeof(struct sockaddr_un));

		if (p_addr_un == NULL) {
			fprintf(stderr, "cannot allocate addr_un\n");
			abort();
		}
		svc_elem->addr = (void *) p_addr_un;

		p_addr_un->sun_family = AF_LOCAL;
		strcpy(p_addr_un->sun_path, UN_TEST_PATH);
		unlink(UN_TEST_PATH);

		/* set nb len */
		len = sizeof(struct sockaddr_un);
		break;
	case SOCK_TYPE_TCP:
	case SOCK_TYPE_UDP:
		p_addr_in = (struct sockaddr_in *)
		    malloc(sizeof(struct sockaddr_in));
		if (p_addr_in == NULL) {
			fprintf(stderr, "cannot allocate addr_in\n");
			abort();
		}
		svc_elem->addr = (void *) p_addr_in;

		p_addr_in->sin_family = AF_INET;
		p_addr_in->sin_port = htons(port);
		p_addr_in->sin_addr.s_addr = INADDR_ANY;

		len = sizeof(struct sockaddr_in);
		break;
	default:
		fprintf(stderr, "svc type not supported: %d\n",
		    svc_type);
		abort();
		break;
	}

	p_nb->buf = (char *) svc_elem->addr;
	p_nb->len = len;
	p_nb->maxlen = len;

	ar_svc_attr_init(&svc_elem->attr);
#if DEBUG_SVC_LINE
	ar_svc_attr_set_debug(&svc_elem->attr, stderr, "SVC_DBG: ");
#endif

	err = ar_svc_tli_create(ctx, netid, p_nb, &svc_elem->attr, 
	    &errp, &svc_elem->service);
	if (err != 0) {
		fprintf(stderr, "tli svc %s create failed: %d\n",
		    netid, err);
		abort();
	}

	err = ar_svc_reg(svc_elem->service, &test_rpc_1_lookup,
			 TEST_RPC, TEST_RPC_VERS);
	if (err != 0) {
		fprintf(stderr, "svc (%s) reg failed: %d\n",
		    netid, err);
		abort();
	}

	/* add service type */
	svc_elem->service_type = svc_type;
	TAILQ_INSERT_TAIL(&svc_state.service_list, svc_elem, service_listent);

	return 0;
}

static void *
server_thread(void *pt)
{
	int i;
	ar_ioctx_t ctx;
	int err;
	service_elem_t *svc_elem;

	/* Setup the svc state */
	svc_state.tst_done = 0;
	TAILQ_INIT(&svc_state.req_list);
	TAILQ_INIT(&svc_state.service_list);

	/* Setup Service CTX */
	err = ar_ioctx_create(&ctx);
	if (err != 0) {
		fprintf(stderr, "unable to create server ioctx: %d\n", err);
		abort();
	}

	/* start up all services */
	for (i=0; i < SOCK_TYPE_NUM; i++) {
		test_service_create(ctx, i);
	}

	/* Indicate to the client that we're ready */
	pthread_mutex_lock(&server_rdy_mtx);
	server_rdy = TRUE;
	pthread_cond_signal(&server_rdy_cv);
	pthread_mutex_unlock(&server_rdy_mtx);

	/* Now begin the test */
	while (!svc_state.tst_done) {
		err = ar_ioctx_loop(ctx);
		if (err == EINTR) {
			continue;
		}
		assert(err == 0);
	}

	/* Clean up defered requests */
	test_svc_req_cleanup();

	/* Unreg the services and destroy them */
	while ((svc_elem = TAILQ_FIRST(&svc_state.service_list)) != NULL) {
		svc_elem = TAILQ_FIRST(&svc_state.service_list);
		TAILQ_REMOVE(&svc_state.service_list,
			     svc_elem, service_listent);
		
		ar_svc_unreg(svc_elem->service, &test_rpc_1_lookup,
			     TEST_RPC, TEST_RPC_VERS);
		ar_svc_destroy(svc_elem->service);
		ar_svc_attr_destroy(&svc_elem->attr);
		
		if (svc_elem->service_type == SOCK_TYPE_UNIX) {
			unlink(UN_TEST_PATH);
		}

		free(svc_elem->addr);
		free(svc_elem);
	}

 	ar_ioctx_destroy(ctx);
	pthread_exit(NULL);
}

ATF_TC_WITHOUT_HEAD(test_arpc_ops);
ATF_TC_BODY(test_arpc_ops, tc)
{
	int tst_errs;
	pthread_t pthreads[NUM_PTHREADS];
	pthread_attr_t pt_attr;
	
	/* Setup the mutex vars, and conds */
	pthread_mutex_init(&client_rdy_mtx, NULL);
	pthread_mutex_init(&server_rdy_mtx, NULL);
	
	pthread_cond_init(&client_rdy_cv, NULL);
	pthread_cond_init(&server_rdy_cv, NULL);

	/* Create joinable threads */
	pthread_attr_init(&pt_attr);
	pthread_attr_setdetachstate(&pt_attr, PTHREAD_CREATE_JOINABLE);

	/* Reset the ready signal */
	client_rdy = FALSE;
	server_rdy = FALSE;
	
	/* Create threads */
	pthread_create(&pthreads[0], &pt_attr, server_thread, NULL);
	pthread_create(&pthreads[1], &pt_attr, client_thread, NULL);
	
	/* Wait for threads to join */
	pthread_join(pthreads[0], NULL);
	pthread_join(pthreads[1], NULL);
	
	pthread_attr_destroy(&pt_attr);

	/* Destroy mutex vars and conds */
	pthread_mutex_destroy(&client_rdy_mtx);
	pthread_mutex_destroy(&server_rdy_mtx);

	pthread_cond_destroy(&client_rdy_cv);
	pthread_cond_destroy(&server_rdy_cv);

	/* Add up the client and server errors */
	tst_errs = (clnt_state.tst_errs) + (svc_state.tst_errs);

	fprintf(stderr, "\nfinished with %d errors\n", tst_errs);
	ATF_REQUIRE(tst_errs == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_arpc_ops);
	return atf_no_error();
}
