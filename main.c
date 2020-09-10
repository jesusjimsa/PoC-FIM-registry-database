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
    // data->hash_md5 = hash_md5;
    snprintf(data->hash_md5, 33, "%s", hash_md5);
    // data->hash_sha1 = hash_sha1;
    snprintf(data->hash_sha1, 65, "%s", hash_sha1);
    // data->hash_sha256 = hash_sha256;
    snprintf(data->hash_sha256, 65, "%s", hash_sha256);

    data->last_event = last_event;
    data->scanned = scanned;
    // data->checksum = checksum;
    snprintf(data->checksum, 65, "%s", checksum);
    data->mode = mode;

    return data;
}

static fim_registry_key *fill_registry_key_struct(char * path, unsigned int id, char * perm, char * uid, char * gid,
                                                  char * user_name, char * group_name, unsigned int scanned,
                                                  os_sha1 checksum) {

    fim_registry_key *data = calloc(1, sizeof(fim_registry_key));

    data->path = strdup(path);
    data->id = id;
    data->perm = strdup(perm);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);
    data->scanned = scanned;
    // data->checksum = checksum;
    snprintf(data->checksum, 65, "%s", checksum);

    return data;
}

void print_fim_registry_key_data(fim_entry *entry) {
    printf("\n~~~ Registry key ~~~\n");
    printf("\n---------------------------------\n");
    printf("Path: %s\n", entry->registry_entry.key->path);
    printf("ID: %d\n", entry->registry_entry.key->id);
    printf("Perm: %s\n", entry->registry_entry.key->perm);
    printf("UID: %s\n", entry->registry_entry.key->uid);
    printf("GID: %s\n", entry->registry_entry.key->gid);
    printf("User name: %s\n", entry->registry_entry.key->user_name);
    printf("Group name: %s\n", entry->registry_entry.key->group_name);
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
    printf("Last event: %lu\n", entry->registry_entry.value->last_event);
    printf("Scanned: %d\n", entry->registry_entry.value->scanned);
    printf("Checksum: %s\n", entry->registry_entry.value->checksum);
    printf("Mode: %i\n", entry->registry_entry.value->mode);
    printf("---------------------------------\n");
}

#define DEF_REG_NAME "reg_name_"
#define DEF_REG_PATH "HKEY_LOCAL_MACHINE\\TEST\\"
int fill_entries_random(fdb_t *fim_sql, unsigned int num_entries) {
    unsigned int i = 0;

    char *reg_path = calloc(512, sizeof(char));
    snprintf(reg_path, 512, "%s", DEF_REG_PATH);

    for(i = 0; i < num_entries; i++) {
        char *reg_name = calloc(512, sizeof(char));
        snprintf(reg_name, 512, "%s%i", DEF_REG_NAME, i);

        fim_registry_value_data *value = fill_registry_value_struct(reg_name, rand() % 15, rand() % 256,
                                                                   "ce6bb0ddf75be26c928ce2722e5f1625",
                                                                   "53bf474924c7876e2272db4a62fc64c8e2c18b51",
                                                                   "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c",
                                                                   rand() % 1500000000, rand() % 1500000000, 1,
                                                                   "53bf474924c7876e2272db4a62fc64c8e2c18b51",
                                                                   FIM_SCHEDULED);

        fim_registry_key *key = fill_registry_key_struct(reg_path, 0, "rwxrwxrwx", "0", "0", "root", "root", 1,
                                                         "53bf474924c7876e2272db4a62fc64c8e2c18b51");

        fim_entry *entry = calloc(1, sizeof(fim_entry));

        entry->type = FIM_TYPE_REGISTRY;
        entry->registry_entry.key = key;
        entry->registry_entry.value = value;

        if (fim_db_insert_registry(fim_sql, entry)) {
            printf("Error in fim_db_insert_registry() function: %s\n", reg_name);
            //print_fim_file_data_full(data);
            return FIMDB_ERR;
        }


        free_entry(entry);
        free_registry_key(key);
        free_registry_value(value);
        free(reg_name);
    }

    free(reg_path);

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr, "\n./fim_db <number-rand-files>\n\n"
                        "\t- types{mem|disk}\n");
        return 1;
    }


    nice(10);

    // bool type = false;
    unsigned int num = atoi(argv[1]);
    // int loop = atoi(argv[3]);
    // char * file_test = argv[4];

    struct timespec start, end, commit;

    // Init DB
    announce_function("fim_db_init");
    gettime(&start);

    fdb_t *fim_sql = fim_db_init(FIM_DB_DISK);

    if (fim_sql == NULL) {
        merror("Could not init the database.");
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Insert random entries
    announce_function("fim_db_insert_registry");
    gettime(&start);

    fill_entries_random(fim_sql, num);

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
}
