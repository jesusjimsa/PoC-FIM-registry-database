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


void free_entry_data(fim_entry_data * data) {
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

void free_entry(fim_entry * entry) {
    if (entry) {
        w_FreeArray(entry->path);
        free_entry_data(entry->data);
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
