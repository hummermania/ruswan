use std::io;
use std::io::{File, FileMode, fs};

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

	let fd = File::open_mode(&pluto_lock, Open, Write
		/*O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH */ ) {
		
		// TODO: write analyse error creating lock file
		Ok(()) => println(""),
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

fn exit_pluto(error: u32) {

}

/** fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
static fn fill_lock(lockfd: int, pid: pid_t) -> bool {
	char buf[30];   /* holds "<pid>\n" */
	int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
	bool ok = len > 0 && write(lockfd, buf, len) == len;

	close(lockfd);
	ok
}