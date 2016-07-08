struct string_s {
	string str<>;
};

union test_u switch (int which) {
case 8:
	encap string_s		string_s_list<>;
};

enum image_param_e {
	IMG_PARAM_NAME = 1,
	IMG_PARAM_OPERATION = 2,
	IMG_PARAM_FAILSTOP = 3,	/* critical */
	IMG_PARAM_ROLE = 4,
	IMG_PARAM_GROUP = 5,
	IMG_PARAM_PATH = 6,
	IMG_PARAM_VERSION = 7,
	IMG_PARAM_DEPENDENCIES = 8,
	IMG_PARAM_URL = 9,
	IMG_PARAM_SIZE = 10,
	IMG_PARAM_SHA1HASH = 11,
	IMG_PARAM_ERROR = 13,
	IMG_PARAM_TIMESTAMP = 14,
	IMG_PARAM_SEQUENCE = 15,
	IMG_PARAM_ID = 16,
	IMG_PARAM_PRIORITY = 17
};

enum image_err_e {
	IMG_ERR_OK = 0,
	IMG_ERR_DOWNLOAD_ERROR = 1,
	IMG_ERR_INSTALL_ERROR = 2
};

enum image_op_e {
	IMG_REMOVE_ARCHIVE = 1,		/* remove */
	IMG_INSTALL_ARCHIVE = 2,	/* 'install' */
	IMG_STREAM_ARCHIVE = 3		/* 'run' */
};

struct image_dep_s {
	string		role<>;
};

union image_param_u switch (image_param_e param_type) {
case IMG_PARAM_NAME:
	encap string		name<>;
case IMG_PARAM_OPERATION:
	encap image_op_e 	op;
case IMG_PARAM_FAILSTOP:
	encap bool		failstop;
case IMG_PARAM_ROLE:
	encap string		role<>;
case IMG_PARAM_GROUP:
	encap int		group;
case IMG_PARAM_PATH:
	encap string		path<>;
case IMG_PARAM_VERSION:
	encap string		version_<>;
case IMG_PARAM_DEPENDENCIES:
	encap image_dep_s	dependencies<>;
case IMG_PARAM_URL:
	encap string		url<>;
case IMG_PARAM_SIZE:
	encap int		size;
case IMG_PARAM_SHA1HASH:
	encap string		sha1<>;
case IMG_PARAM_ERROR:
	encap string		err<>;
case IMG_PARAM_TIMESTAMP:
	encap hyper		tstamp;
case IMG_PARAM_SEQUENCE:
	encap int		sequence;
case IMG_PARAM_ID:
	encap int		id;
case IMG_PARAM_PRIORITY:
	encap int		priority;
default:
	opaque 			extension<>;
};

struct image_s {
	image_param_u	params<>;
};

enum pkg_state {
	PKG_UNAVAIL = 1,
	PKG_EXTRACT_PENDING = 2,
	PKG_EXTRACTING = 3,
	PKG_AVAIL = 4,
	PKG_CLEAR_PENDING = 5,
	PKG_CLEARING = 6,
	PKG_MISSING = 7,
	PKG_ERROR = 8
};

enum pkg_rec_state {
	PKGR_NONE = 1,
	PKGR_INIT = 2,
	PKGR_PKG_DONE = 3,
	PKGR_SET_DONE = 4
};

enum pkg_pend_state {
	PKGP_NONE = 1,
	PKGP_WAITING = 2,
	PKGP_ACTIVE = 3,
	PKGP_DONE = 4,
	PKGP_ERROR = 5
};

struct ximg {
	image_s 	base;
	pkg_state	state;
	pkg_rec_state	rstate;
	pkg_pend_state	pstate;
	hyper		start;
	hyper		end;
	int		pcent;
};

struct pkg_role {
	string		name<>;
	int		roleid;
	ximg		installed<>;
	ximg		pending<>;
	ximg		history<>;
	pkg_state	state;
	image_op_e	type;
	int		depends<>;
	int		children<>;
};

struct pkgstatus {
	pkg_role	current<>;
	pkg_role	pending<>;
	ximg		schedule<>;
};

union pkgstatusr switch (int err) {	/* system error (0 = success) */
case 0:
	pkgstatus	status;
case 12:	/* = ENOMEM, hack for linux.  */
	void;
default:
	string		errstr<>;
};


struct op_entry {
	int oe_a;
	op_entry *oe_next;
	int oe_b;
};
