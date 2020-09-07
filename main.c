#include "fim_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define TEST_PATH_START "/root/tiempos.csv"
#define TEST_PATH_END "/home/user/test/file_4"
#define PATH_MAX 4096

void fim_path(const char * path);
void fim_dir(int fd, const char * path);
void fim_file(int fd, const char * path, struct stat * statbuf);
#define loop_path(x) (x[0] == '.' && (x[1] == '\0' || (x[1] == '.' && x[2] == '\0')))


void get_all_callback(fim_entry *entry, void * arg) {
    //printf("Path: %s\n", entry->path);

    // Entry destructor call
    return;
}

void checksum_callback(fim_entry *entry, void * arg) {
    EVP_MD_CTX * ctx = arg;
    EVP_DigestUpdate(ctx, entry->data->checksum, strlen(entry->data->checksum));
    return;
}

static fim_entry_data *fill_entry_struct(
    unsigned int size,
    const char * perm,
    const char * attributes,
    const char * uid,
    const char * gid,
    const char * user_name,
    const char * group_name,
    unsigned int mtime,
    unsigned long int inode,
    const char * hash_md5,
    const char * hash_sha1,
    const char * hash_sha256,
    int mode,
    time_t last_event,
    fim_entry_type entry_type,
    unsigned long int dev,
    unsigned int scanned,
    int options,
    const char * checksum
) {
    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    data->size = size;
    data->perm = strdup(perm);
    data->attributes = strdup(attributes);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);;
    data->mtime = mtime;
    data->inode = inode;
    strncpy(data->hash_md5, hash_md5, sizeof(os_md5) - 1);
    strncpy(data->hash_sha1, hash_sha1, sizeof(hash_sha1) - 1);
    strncpy(data->hash_sha256, hash_sha256, sizeof(hash_sha256) - 1);
    data->mode = mode;
    data->last_event = last_event;
    data->entry_type = entry_type;
    data->dev = dev;
    data->scanned = scanned;
    data->options = options;
    strncpy(data->checksum, checksum, sizeof(hash_sha1) - 1);
    return data;
}

void announce_function(char *function) {
    printf("\n***Testing %s***\n", function);
}

int print_fim_entry_data_full(fim_entry *entry) {
    unsigned int i;
    for (i = 0; entry->path[i]; i++) {
        printf("PATH: %s\n", entry->path[i]);

        printf("SIZE: %i\n", entry->data->size);
        printf("PERM: %s\n", entry->data->perm);
        printf("ATTRB: %s\n", entry->data->attributes);
        printf("UID: %s\n", entry->data->uid);
        printf("GID: %s\n", entry->data->gid);
        printf("UNAME: %s\n", entry->data->user_name);
        printf("GNAME: %s\n", entry->data->group_name);
        printf("MTIME: %i\n", entry->data->mtime);
        printf("INODE: %lu\n", entry->data->inode);
        printf("MD5: %s\n", entry->data->hash_md5);
        printf("SHA1: %s\n", entry->data->hash_sha1);
        printf("SHA256: %s\n", entry->data->hash_sha256);
        printf("MODE: %i\n", entry->data->mode);
        printf("LAST: %lu\n", entry->data->last_event);
        printf("ENTRY: %i\n", entry->data->entry_type);
        printf("DEV: %lu\n", entry->data->dev);
        printf("SCANNED: %i\n", entry->data->scanned);
        printf("OPTIONS: %i\n", entry->data->options);
        printf("CHECKSUM: %s\n", entry->data->checksum);
    }
}

int print_fim_entry_data(fim_entry *entry) {
    unsigned int i;
    for (i = 0; entry->path[i]; i++) {
        printf("%s", entry->path[i]);

        printf("%i|", entry->data->size);
        printf("%s|", entry->data->perm ? entry->data->perm : "" );
        printf("%s|", entry->data->attributes ? entry->data->attributes : "" );
        printf("%s|", entry->data->uid ?  entry->data->uid : "" );
        printf("%s|", entry->data->gid ?  entry->data->gid : "" );
        printf("%s|", entry->data->user_name ? entry->data->user_name : "" );
        printf("%s|", entry->data->group_name ? entry->data->group_name : "" );
        printf("%i|", entry->data->mtime);
        printf("%lu|", entry->data->inode);
        printf("%s|", entry->data->hash_md5);
        printf("%s|", entry->data->hash_sha1);
        printf("%s|", entry->data->hash_sha256);
        printf("%i|", entry->data->mode);
        printf("%lu|", entry->data->last_event);
        printf("%i|", entry->data->entry_type);
        printf("%lu|", entry->data->dev);
        printf("%i|", entry->data->scanned);
        printf("%i|", entry->data->options );
        printf("%s\n", entry->data->checksum);
    }
}

int test_fim_db_update() {
    fim_entry *resp = fim_db_get_path(TEST_PATH_START);
    if (!resp) {
        return -1;
    }

    // Modify the current content
    resp->data->size +=100;
    free(resp->data->perm);
    os_strdup("!!!", resp->data->perm);
    strncpy(resp->data->hash_sha256, "new_sha256", sizeof(os_sha1) - 1);
    resp->data->scanned = 0;
    strncpy(resp->data->checksum, "new_checksum", sizeof(os_sha1) - 1);

    // Declaration of intentions
    printf("New attrs for '%s'\n" \
            " - Size: %u\n" \
            " - Perm: %s\n" \
            " - Sha256: %s\n" \
            " - Scanned: %u\n" \
            " - Checksum: %s\n",
            resp->path[0], resp->data->size, resp->data->perm, resp->data->hash_sha256, resp->data->scanned, resp->data->checksum);

    // Update the database
    if (fim_db_update(resp->data->inode, resp->data->dev, resp->data)) {
        free_entry(resp);
        return FIMDB_ERR;
    }

    // Confirm the change
    printf("Database content:\n");
    fim_entry *updated_entry = fim_db_get_path(TEST_PATH_START);

    if (!strcmp(updated_entry->path[0], resp->path[0]) &&
        updated_entry->data->inode == resp->data->inode &&
        updated_entry->data->dev == resp->data->dev) {
        print_fim_entry_data_full(updated_entry);

    }
    free_entry(resp);
    free_entry(updated_entry);

    return 0;
}

#define DEF_PATH "/home/user/test/file_"
int fill_entries_random(unsigned int num_entries) {

    unsigned int i = 0;
    for(i = 0; i < num_entries; i++) {
        fim_entry_data *data = fill_entry_struct(rand(), "rwxrwxrwx", "attrib", "0", "0", "root", "root", rand() % 1500000000, rand() % 200000, "ce6bb0ddf75be26c928ce2722e5f1625", "53bf474924c7876e2272db4a62fc64c8e2c18b51", "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c", rand() % 3, rand() % 1500000000, rand() % 3, rand() % 1024, 0, 137, "ce6bb0ddf75be26c928ce2722e5f1625");
        char *path = calloc(512, sizeof(char));
        snprintf(path, 512, "%s%i", DEF_PATH, i);

        if (fim_db_insert(path, data)) {
            printf("Error in fim_db_insert() function: %s\n", path);
            //print_fim_entry_data_full(data);
            return FIMDB_ERR;
        }
        free_entry_data(data);
        free(path);
    }

    return 0;
}


int fim_verify_sample_entries(const char *file_path, fim_entry_data *entry) {
   fim_entry *saved_file = fim_db_get_unique_file(file_path, entry->inode, entry->dev);

    if (!saved_file) {
        return FIMDB_ERR;
    }
    if (entry->size != saved_file->data->size ||
        entry->mtime != saved_file->data->mtime ||
        entry->inode != saved_file->data->inode ||
        entry->mode != saved_file->data->mode ||
        entry->last_event != saved_file->data->last_event ||
        entry->entry_type != saved_file->data->entry_type ||
        entry->dev != saved_file->data->dev ||
        entry->scanned != saved_file->data->scanned ||
        entry->options != saved_file->data->options ||
        strcmp(entry->perm, saved_file->data->perm) ||
        strcmp(entry->attributes, saved_file->data->attributes) ||
        strcmp(entry->uid, saved_file->data->uid) ||
        strcmp(entry->gid, saved_file->data->gid) ||
        strcmp(entry->user_name, saved_file->data->user_name) ||
        strcmp(entry->group_name, saved_file->data->group_name) ||
        strcmp(entry->hash_md5, saved_file->data->hash_md5) ||
        strcmp(entry->hash_sha1, saved_file->data->hash_sha1) ||
        strcmp(entry->hash_sha256, saved_file->data->hash_sha256) ||
        strcmp(entry->checksum, saved_file->data->checksum)) {
        free_entry(saved_file);
        return FIMDB_ERR;
    }

    free_entry(saved_file);
    return 0;
}
/*
int test_fim_insert() {
    if (process_sample_entries(fim_db_insert)) {
        return FIMDB_ERR;
    }

    if (process_sample_entries(fim_verify_sample_entries)) {
        return FIMDB_ERR;
    }

    return 0;
}*/


void fim_path(const char * path) {

    int fd = open(path, O_RDONLY | O_NONBLOCK);

    if (fd == -1) {
        printf("Cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    struct stat buf;

    if (fstat(fd, &buf) == -1) {
        printf("Cannot stat '%s': %s\n", path, strerror(errno));
        return;
    }

    switch (buf.st_mode & S_IFMT) {
    case S_IFDIR:
        fim_dir(fd, path);
        break;

    case S_IFREG:
        fim_file(fd, path, &buf);
        break;

    default:
        printf("Ignoring '%s': not a regular file\n", path);
        close(fd);
    }
}


int fim_scan(const char * path) {
    struct stat buf;

    if (lstat(path, &buf) == -1) {
        return -1;
    } else if ((buf.st_mode & S_IFMT) == S_IFLNK) {
        char real[PATH_MAX];

        if (realpath(path, real)) {
            fim_path(real);
        } else {
            return -1;
        }
    } else {
        fim_path(path);
    }

    return 0;
}


void fim_dir(int fd, const char * path) {
    DIR * dir = fdopendir(fd);

    if (dir == NULL) {
        printf("Cannot open directory '%s': %s\n", path, strerror(errno));
    } else {
        struct dirent * entry;

        while ((entry = readdir(dir))) {
            if (!loop_path(entry->d_name)) {
                char lpath[PATH_MAX];
                snprintf(lpath, PATH_MAX, "%s%s%s", path, (path[strlen(path) - 1] == '/') ? "" : "/", entry->d_name);
                //printf("%s\n", lpath);
                fim_path(lpath);
                sched_yield();
            }
        }
    }

    closedir(dir);
}

#define MAX_SIZE 1073741824
void fim_file(int fd, const char * path, struct stat * statbuf) {
    char sha256[65];
    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));


    /* Owner and group */
    struct passwd * owner = getpwuid(statbuf->st_uid);
    if (owner) {
        data->user_name = strdup(owner->pw_name);
    } else {
        data->user_name = strdup("unknown");
    }

    struct group * group = getgrgid(statbuf->st_gid);
    if (owner) {
        data->group_name = strdup(group->gr_name);
    } else {
        data->group_name = strdup("");
    }

    data->size = statbuf->st_size;
    char str_mode[128] = {0};
    snprintf(str_mode, 128, "%i", statbuf->st_mode);
    data->perm = strdup(str_mode);
    data->attributes = strdup("");
    char str_uid[128] = {0};
    snprintf(str_uid, 127, "%i", statbuf->st_uid);
    data->uid = strdup(str_uid);
    char str_gid[128] = {0};
    snprintf(str_gid, 127, "%i", statbuf->st_gid);
    data->gid = strdup(str_gid);

    data->mtime = statbuf->st_mtime;
    data->inode = statbuf->st_ino;
    strncpy(data->hash_md5, "1dd614869481a863afa22765ccb5be36", sizeof(os_md5) - 1);
    strncpy(data->hash_sha1, "b304095d3a8d81f7adbd1506e8b69a2dffab6b94", sizeof(os_sha1) - 1);

    data->mode = FIM_SCHEDULED;
    data->last_event = 0;
    data->entry_type = 0;
    data->dev = statbuf->st_dev;
    data->scanned = 1;
    data->options = 0;
    strncpy(data->checksum, "b304095d3a8d81f7adbd1506e8b69a2dffab6b94", sizeof(os_sha1) - 1);

    /* SHA256 */

    if (statbuf->st_size > 0) {
        if (statbuf->st_size > MAX_SIZE) {
            printf("Ignoring '%s' SHA256: file exceeds size limit", path);
        } else if (file_sha256(fd, sha256) == 0) {
            strncpy(data->hash_sha256, sha256, sizeof(os_sha256) - 1);
        } else {
            printf("Cannot calculate SHA256 sum of '%s'", path);
        }
    } else {
        strncpy(data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sizeof(os_sha256) - 1);
    }
    //print_fim_entry_data_full(data);
    if (fim_db_insert(path, data)) {
        printf("Error in fim_db_insert() function: %s\n", path);
        //print_fim_entry_data_full(data);
        exit(1);
    }
    free_entry_data(data);
    close(fd);
}


int basic_test() {

    struct timespec start, end, commit;
    // bajar nice
    nice(10);

    announce_function("fim_db_init");
    gettime(&start);
    if (fim_db_init(true) == FIMDB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("test_fim_insert");
    gettime(&start);

    //fim_scan("/bin");
    //fim_scan("/boot");
    //fim_scan("/etc");
    //fim_path("/lib");
    //fim_scan("/lib32");
    //fim_scan("/lib64");
    //fim_scan("/libx32");
    //fim_scan("/opt");
    //fim_scan("/root");
    //fim_scan("/sbin");
    //fim_scan("/usr");

    gettime(&end);

    fim_force_commit();

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_path");
    gettime(&start);
    fim_entry *respx = fim_db_get_path(TEST_PATH_START);

    if (!respx) {
        merror("Error in fim_db_get_path() function.");
        return 1;
    }
    gettime(&end);

    print_fim_entry_data(respx);
    free_entry(respx);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // sqlite3 fim.db "select dev, inode from entry_data where rowid in (select inode_id from entry_path group by inode_id having count(inode_id) > 2);"
    announce_function("fim_db_get_inode");
    gettime(&start);
    fim_entry *resp2 = fim_db_get_inode(26423, 2050);
    unsigned int j;
    if (!resp2) {
        merror("Error in fim_db_get_inode() function.");
        return 1;
    }

    gettime(&end);

    print_fim_entry_data(resp2);
    free_entry(resp2);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_update");
    gettime(&start);
    if (test_fim_db_update()) {
        merror("Error in fim_db_update() function.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_not_scanned");
    gettime(&start);
    if (fim_db_get_not_scanned(get_all_callback, NULL)) {
        merror("Error in fim_db_get_not_scanned() function.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_delete_unscanned");
    gettime(&start);
    if (fim_db_delete_unscanned()) {
        merror("Error in fim_db_delete_unscanned() function.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_not_scanned");
    gettime(&start);
    if (fim_db_get_not_scanned(get_all_callback, NULL)) {
        merror("Error in fim_db_get_not_scanned() function.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_set_all_unscanned");
    gettime(&start);
    if (fim_db_set_all_unscanned()) {
        merror("Error in fim_db_set_all_unscanned() function.");
        return 1;
    }
    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_all");
    gettime(&start);
    if (fim_db_get_all(get_all_callback, NULL)) {
        merror("Error in fim_db_get_all() function.");
        return 1;
    }
    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_range");
    gettime(&start);
    if (fim_db_get_range("/root/wazuh/wodles/oscap/content/cve-debian-8-oval.xml", "/root/wazuh/wodles/oscap/template_xccdf.xsl", get_all_callback, NULL)) {
        merror("Error in fim_db_get_range() function.");
        return 1;
    }
    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));


    return 0;
}


int main(int argc, char *argv[]) {

    if (argc < 4) {
        fprintf(stderr, "\n./fim_db <type> <number-rand-files> <loop-iterations> <test-file>\n\n"
                        "\t- types{mem|disk}\n");
        return 1;
    }

    nice(10);

    bool type     =  false;
    unsigned int num = atoi(argv[2]);
    int    loop   = atoi(argv[3]);
    char * file_test = argv[4];

    struct timespec start, end, commit;

    // Init DB
    announce_function("fim_db_init");
    gettime(&start);

    if (fim_db_init(type) == FIMDB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Scan
    announce_function("test_fim_insert");
    gettime(&start);

    //fim_scan(folder);
    fill_entries_random(num);

    gettime(&end);
    fim_force_commit();
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    //Search
    if (loop > 0) {
        int i;

        fim_entry *respx = NULL;

        gettime(&start);

        for (i = 0; i < loop; i++) {
            respx = fim_db_get_path(file_test);
            if (!respx) {
                merror("Error in fim_db_get_path() function.");
                return 1;
            }
            free_entry(respx);
        }

        gettime(&end);

        //print_fim_entry_data(respx);

        printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
    }

    // Integridad
    announce_function("test_integrity");
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    gettime(&start);

    fim_db_get_all(get_all_callback, ctx);

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
}
