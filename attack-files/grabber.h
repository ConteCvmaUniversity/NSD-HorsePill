#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN   ( 1024 * ( EVENT_SIZE + 16 ) )

#define T_PATH "/boot"
extern int grabber_main(void);