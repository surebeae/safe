/*
 * Base directory to use when storing secrets. This can be overriden
 * with the $SAFE_DIR environment variable or -s flag.
 */
char safe_dir[] = ".secrets";

/*
 * Path to the executable to use when prompting user for the master
 * password, and no TTY is available.
 * This can be overriden with the $SAFE_ASKPASS environment variable.
 */
char askpass_path[] = "/usr/X11R6/bin/ssh-askpass";

/*
 * Name of the entry that will hold the master password
 * This entry must exist as it is used to ensure all passwords are
 * encrypted with the same key.
 */
char master_entry[] = "master";

/*
 * mkdtemp(3) template and snprintf(3) format to use to construct the
 * full path where the agent socket will be created.
 */
char agent_socktmp[] = "/tmp/safe-XXXXXX"; /* path MUST end with "XXXXXX" */
char agent_sockfmt[] = "agent.%d";         /* use %d to include agent pid */
