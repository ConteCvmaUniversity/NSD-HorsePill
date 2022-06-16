#include "grabber.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/inotify.h>

//function
void handle_inotify_event(const struct inotify_event *);
int ret = 0;
int initrd_wd;
int fd;
int boot_wd;
char initrd_path[256];
//from example https://www.thegeekstuff.com/2010/04/inotify-c-program-example/
int grabber_main(void){
    
    int i;
    int length;
    char buffer[EVENT_BUF_LEN];

    fd = inotify_init();
    if ( fd < 0 ) {
        perror( "inotify_init" );
        return fd;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    //TODO can be more cases
    boot_wd = inotify_add_watch(fd,T_PATH, IN_ACCESS );
    if (boot_wd < 0 )
    {
        perror( "inotify_add_watch" );
        return boot_wd;
    }
    
    while (1)
    {   
        i = 0;
        length = read( fd, buffer, EVENT_BUF_LEN );
        if (length == -1 && errno != EAGAIN) {
			perror("[inotify] read error");
            ret = -1;
			break;
		}
        if ( length <= 0 && length != -1  ) {
            perror("[inotify] read error");
            ret = -1;
			break;
        }

        while ( i < length ) {     
            struct inotify_event *event = ( struct inotify_event * ) &buffer[i];
            handle_inotify_event(event);
            
            i += EVENT_SIZE + event->len;
           
        }
         if (ret != 0)
                break;
        sleep(3);
    }

    inotify_rm_watch( fd, boot_wd );
    close(fd);   
    return ret;

}


//TODO
void handle_inotify_event(const struct inotify_event *event){
    const char t[]="initrd.img";
    
    if ( event->len && event->mask & IN_ACCESS  ) {
        if ( (event->wd == boot_wd) &&
        !strncmp(event->name,t,sizeof(t)-1)) {
            char *name = (char*)(event->name);
            snprintf(initrd_path, sizeof(initrd_path) - 1, "/boot/%s", name);
            initrd_wd = inotify_add_watch(fd,initrd_path,IN_ALL_EVENTS);
            if (initrd_wd < 0 )
            {
                ret = -1;
                return;
            }
        }
        
    }
    else if ((event->wd == initrd_wd)&& event->mask & IN_CLOSE_NOWRITE){
        //initrd modified 
        ret = 2;
        return;
        
    }
}