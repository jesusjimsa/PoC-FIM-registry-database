#include <time.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <stdbool.h>

#define debug_level 0
#define max_size 20000
#define SHA256_LEN 65
typedef struct fim_entry_data_poc {
    char *path; // Duda ~~~~~~

    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    char * hash_md5;
    char * hash_sha1;
    char * hash_sha256;

    // Options
    unsigned int mode;
    time_t last_event;
    int entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    char * checksum;
} fim_entry_data_poc;

typedef char os_md5[33];
typedef char os_sha1[65];
typedef char os_sha256[65];


static const char *FIM_EVENT_TYPE[] = {
    "added",
    "deleted",
    "modified"
};

static const char *FIM_EVENT_MODE[] = {
    "scheduled",
    "real-time",
    "whodata"
};

static const char *FIM_ENTRY_TYPE[] = {
    "file",
    "registry"
};

typedef enum fim_entry_type {
    FIM_FILE,
    FIM_REGISTRY
} fim_entry_type;

typedef enum fim_event_mode {
    FIM_SCHEDULED,
    FIM_REALTIME,
    FIM_WHODATA
} fim_event_mode;

typedef struct fim_entry_data {
    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;

    // Options
    fim_event_mode mode;
    time_t last_event;
    fim_entry_type entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    os_sha1 checksum;
} fim_entry_data;

typedef struct fim_entry {
    char ** path;
    fim_entry_data *data;
} fim_entry;



char **os_AddStrArray(const char *str, char **array);
int w_is_file(const char * const file);
int wdb_create_file(const char *path, const char *source, const bool type, sqlite3 ** fim_db);
void mdebug1(const char *msg, ...);
void mdebug2(const char *msg, ...);
void merror(const char *msg, ...);
uid_t Privsep_GetUser(const char *name) __attribute__((nonnull));
gid_t Privsep_GetGroup(const char *name) __attribute__((nonnull));
#define os_calloc(x,y,z) ((z = (__typeof__(z)) calloc(x,y)))?(void)1:exit(1)
#define os_strdup(x,y) ((y = strdup(x)))?(void)1:exit(1)
#define w_strdup(x,y) ({ int retstr = 0; if (x) { os_strdup(x, y);} else retstr = 1; retstr;})
#define os_free(x) if(x){free(x);x=NULL;}
void free_entry_data(fim_entry_data * data);
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }
#define w_rwlock_init(x, y) { int error = pthread_rwlock_init(x, y); if (error) exit(1); }
#define w_rwlock_rdlock(x) { int error = pthread_rwlock_rdlock(x); if (error) exit(1); }
#define w_rwlock_wrlock(x) { int error = pthread_rwlock_wrlock(x); if (error) exit(1); }
#define w_rwlock_unlock(x) { int error = pthread_rwlock_unlock(x); if (error) exit(1); }
#define w_mutex_init(x, y) { int error = pthread_mutex_init(x, y); if (error) exit(1); }
#define w_mutex_lock(x) { int error = pthread_mutex_lock(x); if (error) exit(1); }
#define w_mutex_unlock(x) { int error = pthread_mutex_unlock(x); if (error) exit(1); }
void gettime(struct timespec *ts);
double time_diff(const struct timespec * a, const struct timespec * b);
int file_sha256(int fd, char sum[SHA256_LEN]);
#define w_FreeArray(x) if (x) {char **x_it = x; for (; *x_it; (x_it)++) {os_free(*x_it);}}
void free_entry(fim_entry * entry);
#define os_realloc(x,y,z) ((z = (__typeof__(z))realloc(x,y)))?(void)1:merror("memory")
