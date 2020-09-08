#include "fim_db.h"
#include "dependencies.h"
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

#define loop_path(x) (x[0] == '.' && (x[1] == '\0' || (x[1] == '.' && x[2] == '\0')))

void announce_function(char *function) {
    printf("\n***Testing %s***\n", function);
}


static fim_registry_value_data *fill_registry_value_struct(char * name, unsigned int type, unsigned int size,
                                                           os_md5 hash_md5, os_sha1 hash_sha1, os_sha256 hash_sha256,
                                                           unsigned int mtime, time_t last_event, unsigned int scanned,
                                                           os_sha1 checksum, fim_event_mode mode) {

    fim_registry_value_data *data = calloc(1, sizeof(fim_registry_value_data));

    data->name = strdup(name);
    data->type = type;
    data->size = size;
    data->hash_md5 = strdup(hash_md5);
    data->hash_sha1 = strdup(hash_sha1);
    data->hash_sha256 = strdup(hash_sha256);
    data->mtime = mtime;
    data->last_event = last_event;
    data->scanned = scanned;
    data->checksum = strdup(checksum);
    data->mode = mode;

    return data;
}

static fim_registry_key *fill_registry_key_struct(char * path, char * perm, char * uid, char * gid, char * user_name,
                                                  char * group_name, int options, unsigned int scanned,
                                                  os_sha1 checksum) {

    fim_registry_key *data = calloc(1, sizeof(fim_registry_key));

    data->path = strdup(path);
    data->perm = strdup(perm);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);
    data->options = options;
    data->scanned = scanned;
    data->checksum = strdup(checksum);
}

int print_fim_file_data(fim_entry *entry) {
    unsigned int i;
    for (i = 0; entry->file_entry.path[i]; i++) {
        printf("%s", entry->file_entry.path);

        printf("%i|", entry->file_entry.data->size);
        printf("%s|", entry->file_entry.data->perm ? entry->file_entry.data->perm : "" );
        printf("%s|", entry->file_entry.data->attributes ? entry->file_entry.data->attributes : "" );
        printf("%s|", entry->file_entry.data->uid ?  entry->file_entry.data->uid : "" );
        printf("%s|", entry->file_entry.data->gid ?  entry->file_entry.data->gid : "" );
        printf("%s|", entry->file_entry.data->user_name ? entry->file_entry.data->user_name : "" );
        printf("%s|", entry->file_entry.data->group_name ? entry->file_entry.data->group_name : "" );
        printf("%i|", entry->file_entry.data->mtime);
        printf("%lu|", entry->file_entry.data->inode);
        printf("%s|", entry->file_entry.data->hash_md5);
        printf("%s|", entry->file_entry.data->hash_sha1);
        printf("%s|", entry->file_entry.data->hash_sha256);
        printf("%i|", entry->file_entry.data->mode);
        printf("%lu|", entry->file_entry.data->last_event);
        printf("%lu|", entry->file_entry.data->dev);
        printf("%i|", entry->file_entry.data->scanned);
        printf("%i|", entry->file_entry.data->options );
        printf("%s\n", entry->file_entry.data->checksum);
    }
}

void print_fim_registry_key_data(fim_entry *entry) {
    printf("\n~~~ Registry key ~~~\n");
    printf("\n---------------------------------\n");
    printf("Path: %s\n", entry->registry_entry.key->path);
    printf("Perm: %s\n", entry->registry_entry.key->perm);
    printf("UID: %s\n", entry->registry_entry.key->uid);
    printf("GID: %s\n", entry->registry_entry.key->gid);
    printf("User name: %s\n", entry->registry_entry.key->user_name);
    printf("Group name: %s\n", entry->registry_entry.key->group_name);
    printf("Options: %d\n", entry->registry_entry.key->options);
    printf("Scanned: %d\n", entry->registry_entry.key->scanned);
    printf("Checksum: %s\n", entry->registry_entry.key->checksum);
    printf("---------------------------------\n");
}

void print_fim_registry_value_data(fim_entry *entry) {
    printf("\n~~~ Registry value ~~~\n");
    printf("\n---------------------------------\n");
    printf("Name: %s\n", entry->registry_entry.value->name);
    printf("Type: %d\n", entry->registry_entry.value->type);
    printf("Size: %d\n", entry->registry_entry.value->size);
    printf("Hash MD5: %s\n", entry->registry_entry.value->hash_md5);
    printf("Hash SHA1: %s\n", entry->registry_entry.value->hash_sha1);
    printf("Hash SHA256: %s\n", entry->registry_entry.value->hash_sha256);
    printf("Mtime: %d\n", entry->registry_entry.value->mtime);
    printf("Last event: %lu\n", entry->registry_entry.value->last_event);
    printf("Scanned: %d\n", entry->registry_entry.value->scanned);
    printf("Checksum: %s\n", entry->registry_entry.value->checksum);
    printf("Mode: %i\n", entry->registry_entry.value->mode);
    printf("---------------------------------\n");
}

/**
 * TODO: Change this function to fill registries instead of files
 */
#define DEF_PATH "/home/user/test/file_"
int fill_entries_random(fdb_t *fim_sql, unsigned int num_entries) {

    unsigned int i = 0;
    for(i = 0; i < num_entries; i++) {
        fim_entry
        fim_file_data *data = fill_entry_struct(rand(), "rwxrwxrwx", "attrib", "0", "0", "root", "root",
                                                rand() % 1500000000, rand() % 200000,
                                                "ce6bb0ddf75be26c928ce2722e5f1625",
                                                "53bf474924c7876e2272db4a62fc64c8e2c18b51",
                                                "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c",
                                                rand() % 3, rand() % 1500000000, rand() % 3, rand() % 1024, 137,
                                                "ce6bb0ddf75be26c928ce2722e5f1625");
        char *path = calloc(512, sizeof(char));
        snprintf(path, 512, "%s%i", DEF_PATH, i);

        if (fim_db_insert(fim_sql, path, data, NULL)) {
            printf("Error in fim_db_insert() function: %s\n", path);
            //print_fim_file_data_full(data);
            return FIMDB_ERR;
        }

        free_entry_data(data);
        free(path);
    }

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc < 4) {
        fprintf(stderr, "\n./fim_db <type> <number-rand-files> <loop-iterations> <test-file>\n\n"
                        "\t- types{mem|disk}\n");
        return 1;
    }


    nice(10);

    bool type = false;
    unsigned int num = atoi(argv[2]);
    int loop = atoi(argv[3]);
    char * file_test = argv[4];

    struct timespec start, end, commit;

    // Init DB
    announce_function("fim_db_init");
    gettime(&start);

    fdb_t *fim_sql = fim_db_init(FIM_DB_DISK);

    // if (fim_db_init(type) == FIMDB_ERR) {
    //     merror("Could not init the database.");
    //     return 1;
    // }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
}
