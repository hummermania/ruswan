use std::io;
use std::io::{File, FileMode, fs, stdio};

mod plutomain {
static mut pluto_name: String ="";	/* name (path) we were invoked with */
static ctlbase: String = "/var/run/pluto";
static mut pluto_listen: String = "";
static fork_desired: bool = true;

/* pulled from main for show_setup_plutomain() */
//static const struct lsw_conf_options *oco;
static mut coredir: String = "";
static nhelpers: int = -1;
//libreswan_passert_fail_t libreswan_passert_fail = passert_fail;

///////////////////////////////////////////////////////////////////////////////////////////////

pub fn free_pluto_main() {
	/* Some values can be NULL if not specified as pluto argument */
	pfree(coredir);
	pfreeany(pluto_stats_binary);
	pfreeany(pluto_listen);
	pfree(pluto_vendorid);
}

/*
 * invocation_fail - print diagnostic and usage hint message and exit
 *
 * @param mess String - diagnostic message to print
 */
pub fn invocation_fail(mess: &str) {
	if mess != Nil {
		stderr.write_str(mess);
	}
	let usage: String = format!("For usage information: {} --help\n Libreswan {}\n" + 
	                    		pluto_name +
	                    		ipsec_version_code());
	stderr.write_str(usage);
	/* not exit_pluto because we are not initialized yet */
	exit(1);
}

/* string naming compile-time options that have interop implications */
static compile_time_interop_options: String = 
//#ifdef NETKEY_SUPPORT
	" XFRM(netkey)" +

//#ifdef KLIPS
	" KLIPS" +

//#ifdef KLIPSMAST
	" MAST" +

//#ifdef HAVE_NO_FORK
	" NO_FORK" +

//#ifdef HAVE_BROKEN_POPEN
	" BROKEN_POPEN" +

	" NSS" +
//#ifdef DNSSEC
	" DNSSEC" +

//#ifdef FIPS_CHECK
	" FIPS_CHECK" +

//#ifdef HAVE_LABELED_IPSEC
	" LABELED_IPSEC" +

//#ifdef HAVE_LIBCAP_NG
	" LIBCAP_NG" +

//#ifdef USE_LINUX_AUDIT
	" LINUX_AUDIT" +

//#ifdef XAUTH_HAVE_PAM
	" XAUTH_PAM" +

//#ifdef HAVE_NM
	" NETWORKMANAGER" +

//#ifdef KLIPS_MAST
	" KLIPS_MAST" +

//#ifdef LIBCURL
	" CURL(non-NSS)" +

//#ifdef LDAP_VER
	" LDAP(non-NSS)";

/*
 * lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */
//static char pluto_lock[sizeof(ctl_addr.sun_path)] = DEFAULT_CTLBASE LOCK_SUFFIX;
static pluto_lock_created: bool = false;

/** create lockfile, or die in the attempt */
fn create_lock() -> int {
	
	let ctlbase = Path::new(".."); // TODO: set ctlbase path

	if File::mkdir(ctlbase, /*0755*/ io::UserDir) != 0  {
		if errno != EEXIST {
			println!(stderr,
				"pluto: FATAL: unable to create lock dir: {}: {}\n", 
				ctlbase, 
				strerror(errno));
			exit_pluto(10);
		}
	}

	let fd = File::open_mode(&pluto_lock, Open, Write);
	/*O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH */ 
	
	match fd {
		// TODO: write analyse error creating lock file
		Ok(()) => println!(""),
		Err(e) => fail!("pluto: FATAL: unable to create lock file {} ({})",pluto_lock, e)
	}

	/*
	if (fd < 0) {
		if (errno == EEXIST) {
			// if we did not fork, then we do't really need the pid to control, so wipe it 
			if (!fork_desired) {
				if (unlink(pluto_lock) == -1) {
					fprintf(stderr,
						"pluto: FATAL: lock file \"%s\" already exists and could not be removed (%d %s)\n",
						pluto_lock, errno,
						strerror(errno));
					exit_pluto(10);
				} else {
					// lock file removed, try creating it again 
					return create_lock();
				}
			} else {
				fprintf(stderr,
					"pluto: FATAL: lock file \"%s\" already exists\n",
					pluto_lock);
				exit_pluto(10);
			}
		} else {
			fprintf(stderr,
				"pluto: FATAL: unable to create lock file \"%s\" (%d %s)\n",
				pluto_lock, errno, strerror(errno));
			exit_pluto(1);
		}
	}
	
	// TODO avoid boolean variables
	pluto_lock_created = TRUE;
	*/
	
	fd

}

/*
 * fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
pub  fn fill_lock(lockfd: int, pid: pid_t) -> bool {
	let buf: &str = format!("{}",pid);	/* holds "<pid>\n" */

	lockfd.write_str(buf);
	lockfd.close();
}

/*
 * delete_lock - Delete the lock file
 */
pub fn delete_lock() {
	if (pluto_lock_created) {
		delete_ctl_socket();
		unlink(pluto_lock);	/* is noting failure useful? */
	}
}

/*
 * parser.l and keywords.c need these global variables
 * FIXME: move them to confread_load() parameters
 */
static verbose: int = 0;
static warningsarefatal: int = 0;

/* Read config file. exit() on error. */
struct starter_config;
/*struct starter_config {
	struct {
		ksf strings;
		knf options;
		str_set strings_set;
		int_set options_set;

		// derived types 
		char **interfaces;
	} setup;

	// conn %default 
	struct starter_conn conn_default;

	struct starter_conn conn_oedefault;
	bool got_oedefault;

	char *ctlbase;  // location of pluto control socket 

	// connections list (without %default) 
	TAILQ_HEAD(, starter_conn) conns;
}; */

pub fn read_cfg_file(configfile: &str) -> starter_config  {
	let mut cfg: starter_config = Nil;
	let mut err: err_t = Nil;

	cfg = confread_load(configfile, &err, FALSE, NULL, TRUE);
	if cfg == Nil {
		invocation_fail(err);
	}
	cfg
}

/* Helper function for config file mapper: set string option value */
pub fn set_cfg_string(target: &str, value: &str) {
	/* Do nothing if value is unset. */
	if value == Nil || *value == "\0" {
		return;
	}

	/* Don't free previous target, it might be statically set. */
	*target = strdup_uniq(value);
}

/* TODO: Check the status of crypto libs, and use it in the code
pub fn pluto_init_nss(confddir: &str) {
	SECStatus nss_init_status;

	loglog(RC_LOG_SERIOUS, "nss directory plutomain: %s", confddir);
	nss_init_status = NSS_Init(confddir);
	if (nss_init_status != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "FATAL: NSS readonly initialization (\"%s\") failed (err %d)\n",
			confddir, PR_GetError());
		exit_pluto(10);
	} else {
		libreswan_log("NSS Initialized");
		PK11_SetPasswordFunc(getNSSPassword);
	}
}
*/

/* by default the CRL policy is lenient */
static mut strict_crl_policy: bool = false;

/* 0 is special and default: do not check crls dynamically */
//deltatime_t crl_check_interval = { 0 };

/* by default pluto sends no cookies in ikev2 or ikev1 aggrmode */
static force_busy: bool = false;

/* whether or not to use klips */
//enum kernel_interface kern_interface = USE_NETKEY;	/* new default */

//#ifdef HAVE_LABELED_IPSEC
static secctx_attr_value: u16 = SECCTX;

/*
 * Table of Pluto command-line options.
 *
 * For getopt_ling(3), but with twists.
 *
 * We never find that letting getopt set an option makes sense
 * so flag is always NULL.
 *
 * Trick: we split the "name" string with a '\0'.
 * Before it is the option name, as seen by getopt_long.
 * After it is meta-information:
 * - _ means: obsolete due to _ in name: replace _ with -
 * - > means: obsolete spelling; use spelling from rest of string
 * - ! means: obsolete and ignored (no replacement)
 * - anything else is a description of the options argument (printed by --help)
 *   If it starts with ^, that means start a newline in the --help output.
 *
 * The table should be ordered to maximize the clarity of --help.
 *
 * val values free due to removal of options: '1', '3', '4', 'G'
 */
 
//#define DBG_OFFSET 256
struct option {
	name: &str,
	has_arg: has_arg,
	flag: int,
	val: &str
}

type Option = &[option];

static long_opts: Option = [
	/* name, has_arg, flag, val */
	{ "help\0"; no_argument; NULL; 'h' },
	{ "version\0"; no_argument; NULL; 'v' },
	{ "config\0<filename>"; required_argument; NULL; 'z' },
	{ "nofork\0"; no_argument; NULL; 'd' },
	{ "stderrlog\0"; no_argument; NULL; 'e' },
	{ "logfile\0<filename>"; required_argument; NULL; 'g' },
	{ "plutostderrlogtime\0"; no_argument; NULL; 't' },
	{ "force_busy\0_"; no_argument; NULL; 'D' },	/* _ */
	{ "force-busy\0"; no_argument; NULL; 'D' },
	{ "strictcrlpolicy\0"; no_argument; NULL; 'r' },
	{ "crlcheckinterval\0<seconds>"; required_argument; NULL; 'x' },
	{ "uniqueids\0"; no_argument; NULL; 'u' },
	{ "noklips\0>use-nostack"; no_argument; NULL; 'n' },	/* redundant spelling */
	{ "use-nostack\0";  no_argument; NULL; 'n' },
	{ "use-none\0>use-nostack"; no_argument; NULL; 'n' },	/* redundant spelling */
	{ "useklips\0>use-klips";  no_argument; NULL; 'k' },	/* redundant spelling */
	{ "use-klips\0";  no_argument; NULL; 'k' },
	{ "use-auto\0>use-netkey";  no_argument; NULL; 'K' },	/* rednundate spelling (sort of) */
	{ "usenetkey\0>use-netkey"; no_argument; NULL; 'K' },	/* redundant spelling */
	{ "use-netkey\0"; no_argument; NULL; 'K' },
	{ "use-mast\0";   no_argument; NULL; 'M' },
	{ "use-mastklips\0";   no_argument; NULL; 'M' },
	{ "use-bsdkame\0";   no_argument; NULL; 'F' },
	{ "interface\0<ifname|ifaddr>"; required_argument; NULL; 'i' },
	{ "listen\0<ifaddr>"; required_argument; NULL; 'L' },
	{ "ikeport\0<port-number>"; required_argument; NULL; 'p' },
	{ "natikeport\0<port-number>"; required_argument; NULL; 'q' },
	{ "ctlbase\0<path>"; required_argument; NULL; 'b' },
	{ "secretsfile\0<secrets-file>"; required_argument; NULL; 's' },
	{ "perpeerlogbase\0<path>"; required_argument; NULL; 'P' },
	{ "perpeerlog\0"; no_argument; NULL; 'l' },
	{ "noretransmits\0"; no_argument; NULL; 'R' },
	{ "coredir\0>dumpdir"; required_argument; NULL; 'C' },	/* redundant spelling */
	{ "dumpdir\0<dirname>"; required_argument; NULL; 'C' },
	{ "statsbin\0<filename>"; required_argument; NULL; 'S' },
	{ "ipsecdir\0<ipsec-dir>"; required_argument; NULL; 'f' },
	{ "ipsec_dir\0>ipsecdir"; required_argument; NULL; 'f' },	/* redundant spelling; _ */
	{ "foodgroupsdir\0>ipsecdir"; required_argument; NULL; 'f' },	/* redundant spelling */
	{ "adns\0<pathname>"; required_argument; NULL; 'a' },
	{ "nat_traversal\0!"; no_argument; NULL; 'h' },	/* obsolete; _ */
	{ "keep_alive\0_"; required_argument; NULL; '2' },	/* _ */
	{ "keep-alive\0<delay_secs>"; required_argument; NULL; '2' },
	{ "force_keepalive\0!"; no_argument; NULL; 'h' },	/* obsolete; _ */
	{ "disable_port_floating\0!"; no_argument; NULL; 'h' },	/* obsolete; _ */
	{ "virtual_private\0_"; required_argument; NULL; '6' },	/* _ */
	{ "virtual-private\0<network_list>"; required_argument; NULL; '6' },
	{ "nhelpers\0<number>"; required_argument; NULL; 'j' },
//#ifdef HAVE_LABELED_IPSEC
	{ "secctx_attr_value\0_"; required_argument; NULL; 'w' },	/* _ */
	{ "secctx-attr-value\0<number>"; required_argument; NULL; 'w' },
//#endif
	{ "vendorid\0<vendorid>"; required_argument; NULL; 'V' },

	{ "leak-detective\0"; no_argument; NULL; 'X' },
	{ "debug-nat_t\0>debug-nattraversal"; no_argument; NULL; '5' },	/* redundant spelling; _ */
	{ "debug-nat-t\0>debug-nattraversal"; no_argument; NULL; '5' },	/* redundant spelling */
	{ "debug-nattraversal\0"; no_argument; NULL; '5' },
	{ "debug-none\0^"; no_argument; NULL; 'N' },
	{ "debug-all\0"; no_argument; NULL; 'A' }

	/* --debug-* options (using D for shorthand) 
#define D(name, code) { "debug-" name, no_argument, NULL, (code) + DBG_OFFSET }
	D("raw\0", DBG_RAW_IX),
	D("crypt\0", DBG_CRYPT_IX),
	D("crypto\0>crypt", DBG_CRYPT_IX),	// redundant spelling 
	D("parsing\0", DBG_PARSING_IX),
	D("emitting\0", DBG_EMITTING_IX),
	D("control\0", DBG_CONTROL_IX),
	D("lifecycle\0", DBG_LIFECYCLE_IX),
	D("kernel\0", DBG_KERNEL_IX),
	D("klips\0>kernel", DBG_KERNEL_IX),	// redundant spelling 
	D("netkey\0>kernel", DBG_KERNEL_IX),	// redundant spelling 
	D("dns\0", DBG_DNS_IX),
	D("oppo\0", DBG_OPPO_IX),
	D("oppoinfo\0", DBG_OPPOINFO_IX),
	D("controlmore\0", DBG_CONTROLMORE_IX),
	D("dpd\0", DBG_DPD_IX),
	D("x509\0", DBG_X509_IX),
	D("private\0", DBG_PRIVATE_IX),
	D("pfkey\0", DBG_PFKEY_IX),
#undef D

	// --impair-* options (using I for shorthand) 
#define I(name, code) { "impair-" name, no_argument, NULL, (code) + DBG_OFFSET }
	I("delay-adns-key-answer\0^", IMPAIR_DELAY_ADNS_KEY_ANSWER_IX),
	I("delay-adns-txt-answer\0", IMPAIR_DELAY_ADNS_TXT_ANSWER_IX),
	I("bust-mi2\0", IMPAIR_BUST_MI2_IX),
	I("bust-mr2\0", IMPAIR_BUST_MR2_IX),
	I("sa-creation\0", IMPAIR_SA_CREATION_IX),
	I("die-oninfo\0", IMPAIR_DIE_ONINFO_IX),
	I("jacob-two-two\0", IMPAIR_JACOB_TWO_TWO_IX),
	I("major-version-bump\0", IMPAIR_MAJOR_VERSION_BUMP_IX),
	I("minor-version-bump\0", IMPAIR_MINOR_VERSION_BUMP_IX),
	I("retransmits\0", IMPAIR_RETRANSMITS_IX),
	I("send-bogus-isakmp-flag\0", IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX),
	I("send-ikev2-ke\0", IMPAIR_SEND_IKEv2_KE_IX),
	I("send-key-size-check\0", IMPAIR_SEND_KEY_SIZE_CHECK_IX),
#undef I
	{ 0, 0, 0, 0 } */
];

/* print full usage (from long_opts[]) */
pub fn usage() {
	let mut opt: option = Nil;
	let mut line: String;
	let lw: size_t;

	println("Usage: {}", pluto_name);
	lw = strlen(line);

	for (opt = long_opts; opt->name != NULL; opt++) {
		const char *nm = opt->name;
		const char *meta = nm + strlen(nm) + 1;
		bool force_nl = FALSE;
		char chunk[sizeof(line) - 1];
		int cw;

		switch (*meta) {
		case '_':
		case '>':
		case '!':
			/* ignore these entries */
			break;
		case '^':
			force_nl = TRUE;
			meta++;	/* eat ^ */
			/* fall through */
		default:
			if (*meta == '\0')
				snprintf(chunk, sizeof(chunk),  "[--%s]", nm);
			else
				snprintf(chunk, sizeof(chunk),  "[--%s %s]", nm, meta);
			cw = strlen(chunk);

			if (force_nl || lw + cw + 2 >= sizeof(line)) {
				fprintf(stderr, "%s\n", line);
				line[0] = '\t';
				lw = 1;
			} else {
				line[lw++] = ' ';
			}
			passert(lw + cw + 1 < sizeof(line));
			strcpy(&line[lw], chunk);
			lw += cw;
		}
	}

	stderr.write_str("{}\n", line);

	stderr.write_str("Libreswan {}\n", ipsec_version_code());
	/* not exit_pluto because we are not initialized yet */
	exit(0);
}


fn main() {
}

/*
 * leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void exit_pluto(int status)
{
	/* needed because we may be called in odd state */
	reset_globals();
	free_preshared_secrets();
	free_remembered_public_keys();
	delete_every_connection();

	/*
	 * free memory allocated by initialization routines.  Please don't
	 * forget to do this.
	 */

#if defined(LIBCURL) || defined(LDAP_VER)
	free_crl_fetch();	/* free chain of crl fetch requests */
#endif
	/* free chain of X.509 authority certificates */
	free_authcerts();
	free_crls();	/* free chain of X.509 CRLs */

	lsw_conf_free_oco();	/* free global_oco containing path names */

	free_myFQDN();	/* free myid FQDN */

	free_ifaces();	/* free interface list from memory */
	stop_adns();	/* Stop async DNS process (if running) */
	free_md_pool();	/* free the md pool */
	NSS_Shutdown();
	delete_lock();	/* delete any lock files */
	free_virtual_ip();	/* virtual_private= */
	free_pluto_main();	/* our static chars */

	/* report memory leaks now, after all free()s */
	if(leak_detective)
		report_leaks();

	close_log();	/* close the logfiles */
	exit(status);	/* exit, with our error code */
}

void show_setup_plutomain()
{
	whack_log(RC_COMMENT, "config setup options:");	/* spacer */
	whack_log(RC_COMMENT, " ");	/* spacer */
	whack_log(RC_COMMENT,
		"configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s, dumpdir=%s, statsbin=%s",
		oco->confdir,
		oco->conffile,
		pluto_shared_secrets_file,
		oco->confddir,
		coredir,
		match pluto_stats_binary {
			Nil => "unset",
			_ => pluto_stats_binary
		}
	);

	whack_log(RC_COMMENT, "sbindir=%s, libexecdir=%s",
		IPSEC_SBINDIR,
		IPSEC_EXECDIR
	);

	whack_log(RC_COMMENT, "pluto_version=%s, pluto_vendorid=%s",
		ipsec_version_code(),
		pluto_vendorid
	);

	whack_log(RC_COMMENT,
		"nhelpers=%d, uniqueids=%s, retransmits=%s, force-busy=%s",
		nhelpers,
		match uniqueIDs { true => "yes", false => "no"},
		match no_retransmits { true => "no", false => "yes"},
		match force_busy { true => "yes", false => "no"}
	);

	whack_log(RC_COMMENT,
		"ikeport=%d, strictcrlpolicy=%s, crlcheckinterval=%lu, listen=%s",
		pluto_port,
		match strict_crl_policy { true => "yes", false => "no"},
		deltasecs(crl_check_interval),
		match pluto_listen { true => pluto_listen, false => "<any>"}
	);

#ifdef HAVE_LABELED_IPSEC
	whack_log(RC_COMMENT, "secctx-attr-value=%d", secctx_attr_value);
#else
	whack_log(RC_COMMENT, "secctx-attr-value=<unsupported>");
#endif
}

} // end mod plutomain