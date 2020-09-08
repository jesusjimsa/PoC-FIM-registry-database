#include <time.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>

#include "error_messages/information_messages.h"
#include "error_messages/warning_messages.h"
#include "error_messages/debug_messages.h"
#include "error_messages/error_messages.h"

#define debug_level 0
#define max_size 20000
#define SHA256_LEN 65
#define PATH_MAX 1024

typedef enum fim_event_mode {
    FIM_SCHEDULED,
    FIM_REALTIME,
    FIM_WHODATA
} fim_event_mode;

typedef enum fdb_stmt {
    // Files
    FIMDB_STMT_INSERT_DATA,
    FIMDB_STMT_REPLACE_PATH,
    FIMDB_STMT_GET_PATH,
    FIMDB_STMT_UPDATE_DATA,
    FIMDB_STMT_UPDATE_PATH,
    FIMDB_STMT_GET_LAST_PATH,
    FIMDB_STMT_GET_FIRST_PATH,
    FIMDB_STMT_GET_ALL_ENTRIES,
    FIMDB_STMT_GET_NOT_SCANNED,
    FIMDB_STMT_SET_ALL_UNSCANNED,
    FIMDB_STMT_GET_PATH_COUNT,
    FIMDB_STMT_GET_DATA_ROW,
    FIMDB_STMT_GET_COUNT_RANGE,
    FIMDB_STMT_GET_PATH_RANGE,
    FIMDB_STMT_DELETE_PATH,
    FIMDB_STMT_DELETE_DATA,
    FIMDB_STMT_GET_PATHS_INODE,
    FIMDB_STMT_GET_PATHS_INODE_COUNT,
    FIMDB_STMT_SET_SCANNED,
    FIMDB_STMT_GET_INODE_ID,
    FIMDB_STMT_GET_COUNT_PATH,
    FIMDB_STMT_GET_COUNT_DATA,
    FIMDB_STMT_GET_INODE,
    // Registries
    FIMDB_STMT_REPLACE_REG_DATA,
    FIMDB_STMT_REPLACE_REG_KEY,
    FIMDB_STMT_GET_REG_KEY,
    FIMDB_STMT_GET_REG_DATA,
    FIMDB_STMT_UPDATE_REG_DATA,
    FIMDB_STMT_UPDATE_REG_KEY,
    FIMDB_STMT_GET_ALL_REG_ENTRIES,
    FIMDB_STMT_GET_REG_KEY_NOT_SCANNED,
    FIMDB_STMT_GET_REG_DATA_NOT_SCANNED,
    FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED,
    FIMDB_STMT_SET_REG_KEY_UNSCANNED,
    FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED,
    FIMDB_STMT_SET_REG_DATA_UNSCANNED,
    FIMDB_STMT_GET_REG_DATA_ID,
    FIMDB_STMT_DELETE_REG_KEY_PATH,
    FIMDB_STMT_DELETE_REG_DATA,
    FIMDB_STMT_DELETE_REG_DATA_PATH,
    FIMDB_STMT_GET_COUNT_REG_KEY,
    FIMDB_STMT_GET_COUNT_REG_DATA,
    FIMDB_STMT_GET_COUNT_REG_KEY_AND_DATA,
    FIMDB_STMT_GET_LAST_REG_KEY,
    FIMDB_STMT_GET_FIRST_REG_KEY,
    FIMDB_STMT_GET_REG_COUNT_RANGE,
    FIMDB_STMT_GET_REG_PATH_RANGE,
    FIMDB_STMT_SET_REG_KEY_SCANNED,
    FIMDB_STMT_SET_REG_DATA_SCANNED,
    FIMDB_STMT_SIZE
} fdb_stmt;

#define FIM_MODE(x) (x & WHODATA_ACTIVE ? FIM_WHODATA : x & REALTIME_ACTIVE ? FIM_REALTIME : FIM_SCHEDULED)

#if defined(WIN32) && defined(EVENTCHANNEL_SUPPORT)
#define WIN_WHODATA 1
#endif

#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128
#define SYSCHECK_WAIT   1
#define MAX_FILE_LIMIT  2147483647
#define MIN_COMP_ESTIM  0.4         // Minimum value to be taken by syscheck.comp_estimation_perc

/* Checking options */
#define CHECK_SIZE          00000001
#define CHECK_PERM          00000002
#define CHECK_OWNER         00000004
#define CHECK_GROUP         00000010
#define CHECK_MTIME         00000020
#define CHECK_INODE         00000040
#define CHECK_MD5SUM        00000100
#define CHECK_SHA1SUM       00000200
#define CHECK_SHA256SUM     00000400
// 0001000 0002000 0004000 Reserved for future hash functions
#define CHECK_ATTRS         00010000
#define CHECK_SEECHANGES    00020000
#define CHECK_FOLLOW        00040000
#define REALTIME_ACTIVE     00100000
#define WHODATA_ACTIVE      00200000
#define SCHEDULED_ACTIVE    00400000

#define ARCH_32BIT          0
#define ARCH_64BIT          1
#define ARCH_BOTH           2

#ifdef WIN32
/* Whodata  states */
#define WD_STATUS_FILE_TYPE 1
#define WD_STATUS_DIR_TYPE  2
#define WD_STATUS_UNK_TYPE  3
#define WD_SETUP_AUTO       0
#define WD_SETUP_SUCC       1
#define WD_SETUP_SUCC_FAIL  2
#define WD_STATUS_EXISTS    0x0000001
#define WD_CHECK_WHODATA    0x0000002
#define WD_CHECK_REALTIME   0x0000004
#define WD_IGNORE_REST      0x0000008
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

#define SK_CONF_UNPARSED    -2
#define SK_CONF_UNDEFINED   -1

#define FIM_DB_MEMORY       1
#define FIM_DB_DISK         0

//Max allowed value for recursion
#define MAX_DEPTH_ALLOWED 320

#ifdef WIN32
typedef struct whodata_dir_status whodata_dir_status;
#endif

typedef char os_md5[33];
typedef char os_sha1[65];
typedef char os_sha256[65];


typedef struct fim_tmp_file {
    union { //type_storage
        FILE *fd;
        int *list;
    };
    char *path;
    int elements;
} fim_tmp_file;

typedef enum fim_type {FIM_TYPE_FILE, FIM_TYPE_REGISTRY} fim_type;

typedef struct whodata_evt {
    char *user_id;
    char *user_name;
    char *process_name;
    char *path;
#ifndef WIN32
    char *group_id;  // Linux
    char *group_name;  // Linux
    char *audit_uid;  // Linux
    char *audit_name;  // Linux
    char *effective_uid;  // Linux
    char *effective_name;  // Linux
    char *inode;  // Linux
    char *dev;  // Linux
    char *parent_name; // Linux
    char *parent_cwd;
    int ppid;  // Linux
    char *cwd; // Linux
    unsigned int process_id;
#else
    unsigned __int64 process_id;
    unsigned int mask;
    char scan_directory;
    int config_node;
#endif
} whodata_evt;

#ifdef WIN32

typedef struct whodata_dir_status {
    int status;
    char object_type;
    SYSTEMTIME last_check;
} whodata_dir_status;

typedef ULARGE_INTEGER whodata_directory;

typedef struct whodata {
    OSHash *fd;                         // Open file descriptors
    OSHash *directories;                // Directories checked by whodata mode
    int interval_scan;                  // Time interval between scans of the checking thread
    whodata_dir_status *dirs_status;    // Status list
    char **device;                       // Hard disk devices
    char **drive;                        // Drive letter
} whodata;

#endif /* End WIN32*/

#ifdef WIN32

typedef struct registry {
    char *entry;
    int arch;
    char *tag;
} registry;

typedef struct registry_regex {
    OSMatch *regex;
    int arch;
} registry_regex;

#endif

typedef struct fim_file_data {
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
    unsigned long int dev;
    unsigned int scanned;
    int options;
    os_sha1 checksum;
} fim_file_data;

typedef struct fim_registry_value_data {
    char * name;
    unsigned int type;
    // char * data;
    unsigned int size;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;
    unsigned int mtime;
    time_t last_event;
    unsigned int scanned;

    // Options
    // int options;
    //type:size:hash_sh1:mtime
    os_sha1 checksum;
    fim_event_mode mode;
} fim_registry_value_data;

typedef struct fim_registry_key {
    char * path;
    unsigned int id;
    char * perm;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;

    // Options
    int options;
    unsigned int scanned;
    // path:perm:uid:user_name:gid:group_name
    os_sha1 checksum;
} fim_registry_key;

typedef struct fim_entry {
    fim_type type;
    union {
        struct {
            char *path;
            fim_file_data *data;
        } file_entry;
        struct {
            fim_registry_key *key;
            fim_registry_value_data *value;
        } registry_entry;
    };

} fim_entry;


typedef struct fim_inode_data {
    int items;
    char ** paths;
} fim_inode_data;

typedef struct fdb_transaction_t
{
    time_t last_commit;
    time_t interval;
} fdb_transaction_t;

typedef struct fdb_t
{
    sqlite3 *db;
    sqlite3_stmt *stmt[FIMDB_STMT_SIZE];
    fdb_transaction_t transaction;
} fdb_t;

typedef enum dbsync_msg {
    INTEGRITY_CHECK_LEFT,       ///< Splitted chunk: left part.
    INTEGRITY_CHECK_RIGHT,      ///< Splitted chunk: right part.
    INTEGRITY_CHECK_GLOBAL,     ///< Global chunk (all files).
    INTEGRITY_CLEAR             ///< Clear data (no files at all).
} dbsync_msg;


void randombytes(void *ptr, size_t length);
void srandom_init(void);
int os_random(void);

int IsDir(const char *file);

char **os_AddStrArray(const char *str, char **array);
int w_is_file(const char * const file);
int wdb_create_file(const char *path, const char *source, const bool type, sqlite3 ** fim_db);
void mdebug1(const char *msg, ...);
void mdebug2(const char *msg, ...);
void merror(const char *msg, ...);
void minfo(const char *msg, ...);
uid_t Privsep_GetUser(const char *name) __attribute__((nonnull));
gid_t Privsep_GetGroup(const char *name) __attribute__((nonnull));
#define os_calloc(x,y,z) ((z = (__typeof__(z)) calloc(x,y)))?(void)1:exit(1)
#define os_strdup(x,y) ((y = strdup(x)))?(void)1:exit(1)
#define w_strdup(x,y) ({ int retstr = 0; if (x) { os_strdup(x, y);} else retstr = 1; retstr;})
#define os_free(x) if(x){free(x);x=NULL;}
void free_entry_data(fim_file_data * data);
void free_registry_key(fim_registry_key *key);
void free_registry_value(fim_registry_value_data *data);
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

#define sqlite_strdup(x,y) ({ if (x) { os_strdup(x, y); } else (void)0; })
