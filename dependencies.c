#include "dependencies.h"

#include <sys/types.h>
#include <sqlite3.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#define BUFFER_SIZE 4096

/* COPIADA PARA LA PRUEBA */
int wdb_create_file(const char *path, const char *source, const bool MEM, sqlite3 **fim_db) {
    const char *ROOT = "root";
    const char *GROUPGLOBAL = "root";
    const char *sql;
    const char *tail;

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;
    uid_t uid;
    gid_t gid;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        printf("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            printf("Preparing statement: %s", sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return -1;
        }

        result = sqlite3_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            printf("Stepping statement: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    if (MEM == true) {
        *fim_db = db;
        return 0;
    }

    sqlite3_close_v2(db);

    switch (getuid()) {
    case -1:
        printf("getuid(): %s (%d)", strerror(errno), errno);
        return -1;

    case 0:
        uid = Privsep_GetUser(ROOT);
        gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            printf("USER_ERROR");
            return -1;
        }

        if (chown(path, uid, gid) < 0) {
            printf("CHOWN_ERROR");
            return -1;
        }

        break;

    default:
        mdebug1("Ignoring chown when creating file from SQL.");
        break;
    }

    if (chmod(path, 0660) < 0) {
        printf("CHMOD_ERROR");
        return -1;
    }

    return 0;
}

/* Check if a file exists */
int w_is_file(const char * const file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Add a string to an array */
char **os_AddStrArray(const char *str, char **array)
{
    size_t i = 0;
    char **ret = NULL;
    if (array) {
        while (array[i]) {
            i++;
        }
    }

    os_realloc(array, (i + 2)*sizeof(char *), ret);
    os_strdup(str, ret[i]);
    ret[i + 1] = NULL;

    return (ret);
}


void mdebug1(const char *msg, ...) {
    if (debug_level >= 1) {
        va_list ap;
        va_start(ap, msg);
        char buffer[max_size];
        vsnprintf(buffer, max_size, msg, ap);
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char timestamp[26];
        strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(stdout, "%s %s\n", timestamp, buffer);
        va_end(ap);
    }
}

void mdebug2(const char *msg, ...) {
    if (debug_level >= 2) {
        va_list ap;
        va_start(ap, msg);
        char buffer[max_size];
        vsnprintf(buffer, max_size, msg, ap);
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char timestamp[26];
        strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(stdout, "%s %s\n", timestamp, buffer);
        va_end(ap);
    }
}

void merror(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    char buffer[max_size];
    vsnprintf(buffer, max_size, msg, ap);
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stdout, "%s %s\n", timestamp, buffer);
    va_end(ap);
}

void minfo(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    char buffer[max_size];
    vsnprintf(buffer, max_size, msg, ap);
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stdout, "%s %s\n", timestamp, buffer);
    va_end(ap);
}

uid_t Privsep_GetUser(const char *name)
{
    struct passwd *pw;
    pw = getpwnam(name);
    if (pw == NULL) {
        return ((uid_t)-1);
    }

    return (pw->pw_uid);
}

gid_t Privsep_GetGroup(const char *name)
{
    struct group *grp;
    grp = getgrnam(name);
    if (grp == NULL) {
        return ((gid_t)-1);
    }

    return (grp->gr_gid);
}


void free_entry_data(fim_file_data * data) {
    if (!data) {
        return;
    }
    if (data->perm) {
        os_free(data->perm);
    }
    if (data->attributes) {
        os_free(data->attributes);
    }
    if (data->uid) {
        os_free(data->uid);
    }
    if (data->gid) {
        os_free(data->gid);
    }
    if (data->user_name) {
        os_free(data->user_name);
    }
    if (data->group_name) {
        os_free(data->group_name);
    }
    if (data->attributes) {
        os_free(data->attributes);
    }

    os_free(data);
}

void free_registry_key(fim_registry_key *key) {
    if (!key) {
        return;
    }

    if (key->path) {
        os_free(key->path);
    }

    if (key->perm) {
        os_free(key->perm);
    }

    if (key->uid) {
        os_free(key->uid);
    }

    if (key->gid) {
        os_free(key->gid);
    }

    if (key->user_name) {
        os_free(key->user_name);
    }

    if (key->group_name) {
        os_free(key->group_name);
    }
}

void free_registry_value(fim_registry_value_data *data) {
    if (!data) {
        return;
    }

    if (data->name) {
        os_free(data->name);
    }
}

void free_entry(fim_entry * entry) {
    if (entry) {
        free(entry->file_entry.path);
        free_entry_data(entry->file_entry.data);
        free_registry_key(entry->registry_entry.key);
        free_registry_value(entry->registry_entry.value);
        free(entry);
    }
}

void gettime(struct timespec *ts) {
    clock_gettime(CLOCK_REALTIME, ts);
}

double time_diff(const struct timespec * b, const struct timespec * a) {
    return b->tv_sec - a->tv_sec + (b->tv_nsec - a->tv_nsec) / 1e9;
}


int file_sha256(int fd, char sum[SHA256_LEN]) {
    static const char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    static EVP_MD_CTX * ctx;

    if (ctx == NULL) {
        ctx = EVP_MD_CTX_create();
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    char buffer[BUFFER_SIZE];
    ssize_t count;

    while ((count = read(fd, buffer, BUFFER_SIZE)) > 0) {
        EVP_DigestUpdate(ctx, buffer, count);
    }

    if (count == -1) {
        return -1;
    }

    unsigned char md[SHA256_DIGEST_LENGTH];
    EVP_DigestFinal_ex(ctx, md, NULL);

    unsigned int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        // sprintf(sum + i * 2, "%02x", md[i]);
        sum[i * 2] = HEX[md[i] >> 4];
        sum[i * 2 + 1] = HEX[md[i] & 0xF];
    }

    sum[SHA256_LEN - 1] = '\0';
    return 0;
}

void randombytes(void *ptr, size_t length) {
    char failed = 0;

#ifdef WIN32
    static HCRYPTPROV prov = 0;

    if (prov == 0) {
        if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0)) {
            if (GetLastError() == (DWORD)NTE_BAD_KEYSET) {
                mdebug1("No default container was found. Attempting to create default container.");

                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                    merror("CryptAcquireContext Flag: NewKeySet (1): (%lx)", GetLastError());
                    failed = 1;
                }
            }else if(GetLastError() == (DWORD)NTE_KEYSET_ENTRY_BAD){
                mwarn("The agent's RSA key container for the random generator is corrupt. Resetting container...");

                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET)){
                    merror("CryptAcquireContext Flag: DeleteKeySet: (%lx)", GetLastError());
                    failed = 1;
                }
                if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                    merror("CryptAcquireContext Flag: NewKeySet (2): (%lx)", GetLastError());
                    failed = 1;
                }
            } else {
                merror("CryptAcquireContext no Flag: (%lx)", GetLastError());
                failed = 1;
            }
        }
    }
    if (!failed && !CryptGenRandom(prov, length, ptr)) {
        failed = 1;
    }
#else
    static int fh = -1;
    ssize_t ret;

    if (fh < 0 && (fh = open("/dev/urandom", O_RDONLY | O_CLOEXEC), fh < 0 && (fh = open("/dev/random", O_RDONLY | O_CLOEXEC), fh < 0))) {
        failed = 1;
    } else {
        ret = read(fh, ptr, length);

        if (ret < 0 || (size_t)ret != length) {
            failed = 1;
        }
    }

#endif

    if (failed) {
        merror("randombytes failed for all possible methods for accessing random data");
        exit(EXIT_FAILURE);
    }
}

void srandom_init(void) {
    unsigned int seed;
    randombytes(&seed, sizeof seed);
    srandom(seed);
}

int os_random(void) {
	int myrandom;
	randombytes(&myrandom, sizeof(myrandom));
	return myrandom % RAND_MAX;
}

int IsDir(const char *file) {
    struct stat file_status;
    if (stat(file, &file_status) < 0) {
        return (-1);
    }
    if (S_ISDIR(file_status.st_mode)) {
        return (0);
    }
    return (-1);
}
