
static char safe_dir[] = ".secrets";


static char askpass_path[] = "/usr/bin/ssh-askpass";


static char master_entry[] = "master";


static char agent_socktmp[] = "/tmp/safe-XXXXXX";
static char agent_sockfmt[] = "/agent.%d";


#define SAFE_SANDBOX 1


#ifndef WL_COPY_PATH
#define WL_COPY_PATH "/usr/bin/wl-copy"
#endif


#ifndef AGENT_SOCK_PATH
#define AGENT_SOCK_PATH ""
#endif


#ifndef WL_CLEAR_DELAY_SEC
#define WL_CLEAR_DELAY_SEC 10
#endif


#ifndef DOAS_PATH
#define DOAS_PATH "/usr/bin/doas"
#endif


#ifndef HARDENED_SAFE_BIN
#define HARDENED_SAFE_BIN "/usr/local/bin/safe"
#endif
