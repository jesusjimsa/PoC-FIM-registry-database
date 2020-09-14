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

#define DEF_REG_NAME "reg_name_"
#define DEF_REG_PATH "HKEY_LOCAL_MACHINE\\TEST"
#define DEF_PERM "-rwxrwxrwx"
#define DEF_UID "0"
#define DEF_GID "0"
#define DEF_USER_NAME "root"
#define DEF_GROUP_NAME "root"
#define DEF_MD5_HASH "ce6bb0ddf75be26c928ce2722e5f1625"
#define DEF_SHA1_HASH "53bf474924c7876e2272db4a62fc64c8e2c18b51"
#define DEF_SHA256_HASH "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c"

#define loop_path(x) (x[0] == '.' && (x[1] == '\0' || (x[1] == '.' && x[2] == '\0')))

void announce_function(char *function) {
    printf("\n***Testing %s***\n", function);
}


static fim_registry_value_data *fill_registry_value_struct(unsigned int id, char *name, unsigned int type,
                                                           unsigned int size, os_md5 hash_md5, os_sha1 hash_sha1,
                                                           os_sha256 hash_sha256, unsigned int scanned,
                                                           time_t last_event, os_sha1 checksum, fim_event_mode mode) {

    fim_registry_value_data *data = calloc(1, sizeof(fim_registry_value_data));

    data->id = id;
    data->name = strdup(name);
    data->type = type;
    data->size = size;
    snprintf(data->hash_md5, 33, "%s", hash_md5);
    snprintf(data->hash_sha1, 65, "%s", hash_sha1);
    snprintf(data->hash_sha256, 65, "%s", hash_sha256);
    data->scanned = scanned;
    data->last_event = last_event;
    snprintf(data->checksum, 65, "%s", checksum);
    data->mode = mode;

    return data;
}



static fim_registry_key *fill_registry_key_struct(unsigned int id, char *path, char *perm, char *uid, char *gid,
                                                  char *user_name, char *group_name, unsigned int mtime, int arch,
                                                  unsigned int scanned, os_sha1 checksum) {

    fim_registry_key *data = calloc(1, sizeof(fim_registry_key));

    data->id = id;
    data->path = strdup(path);
    data->perm = strdup(perm);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);
    data->mtime = mtime;
    data->arch = arch;
    data->scanned = scanned;
    snprintf(data->checksum, 65, "%s", checksum);

    return data;
}

void print_fim_registry_key_data(fim_entry *entry) {
    if (entry->registry_entry.key == NULL) {
        return;
    }

    printf("\n~~~ Registry key ~~~\n");
    printf("\n---------------------------------\n");
    printf("ID: %d\n", entry->registry_entry.key->id);
    printf("Path: %s\n", entry->registry_entry.key->path);
    printf("Perm: %s\n", entry->registry_entry.key->perm);
    printf("UID: %s\n", entry->registry_entry.key->uid);
    printf("GID: %s\n", entry->registry_entry.key->gid);
    printf("User name: %s\n", entry->registry_entry.key->user_name);
    printf("Group name: %s\n", entry->registry_entry.key->group_name);
    print("Modification time: %d\n", entry->registry_entry.key->mtime);
    printf("Architecture: %d\n", entry->registry_entry.key->arch);
    printf("Scanned: %d\n", entry->registry_entry.key->scanned);
    printf("Checksum: %s\n", entry->registry_entry.key->checksum);
    printf("---------------------------------\n");
}

void print_fim_registry_value_data(fim_entry *entry) {
    if (entry->registry_entry.value == NULL) {
        return ;
    }

    printf("\n~~~ Registry value ~~~\n");
    printf("\n---------------------------------\n");
    printf("ID: %d\n", entry->registry_entry.value->id);
    printf("Name: %s\n", entry->registry_entry.value->name);
    printf("Type: %d\n", entry->registry_entry.value->type);
    printf("Size: %d\n", entry->registry_entry.value->size);
    printf("Hash MD5: %s\n", entry->registry_entry.value->hash_md5);
    printf("Hash SHA1: %s\n", entry->registry_entry.value->hash_sha1);
    printf("Hash SHA256: %s\n", entry->registry_entry.value->hash_sha256);
    printf("Scanned: %d\n", entry->registry_entry.value->scanned);
    printf("Last event: %lu\n", entry->registry_entry.value->last_event);
    printf("Checksum: %s\n", entry->registry_entry.value->checksum);
    printf("Mode: %i\n", entry->registry_entry.value->mode);
    printf("---------------------------------\n");
}

/* Callback para printar entry */
void print_entry(__attribute__((unused))fdb_t *fim_sql,
                 fim_entry *entry,
                 __attribute__((unused))pthread_mutex_t *mutex,
                 __attribute__((unused))void *alert,
                 __attribute__((unused))void *mode,
                 __attribute__((unused))void *w_event) {

    print_fim_registry_key_data(entry);
    print_fim_registry_value_data(entry);
}

int fill_entries_random(fdb_t *fim_sql, unsigned int num_keys, unsigned int num_entries) {
    unsigned int i, j;
    fim_entry *entry = NULL;

    for(i = 0; i < num_keys; i++) {
        char *reg_path = calloc(512, sizeof(char));
        snprintf(reg_path, 512, "%s_%i\\", DEF_REG_PATH, i);

        fim_registry_key *key = fill_registry_key_struct(i, reg_path, DEF_PERM, DEF_UID, DEF_GID, DEF_USER_NAME,
                                                         DEF_GROUP_NAME, rand() % 1500000000, rand() % 2, 1,
                                                         DEF_SHA1_HASH);

        for (j = 0; j < num_entries; j++) {
            char *reg_name = calloc(512, sizeof(char));
            snprintf(reg_name, 512, "%s%i", DEF_REG_NAME, j);

            fim_registry_value_data *value = fill_registry_value_struct(i, reg_name, rand() % 11, rand() % 256,
                                                                        DEF_MD5_HASH, DEF_SHA1_HASH, DEF_SHA256_HASH, 1,
                                                                        rand() % 1500000000, DEF_SHA1_HASH,
                                                                        FIM_SCHEDULED);

            entry = calloc(1, sizeof(fim_entry));

            entry->type = FIM_TYPE_REGISTRY;
            entry->registry_entry.key = key;
            entry->registry_entry.value = value;

            if (fim_db_insert_registry(fim_sql, entry)) {
                printf("Error in fim_db_insert_registry() function: %s\n", reg_name);
                return FIMDB_ERR;
            }

            free_registry_value(value);
            free(reg_name);
        }

        free(entry);
        free_registry_key(key);
        free(reg_path);
    }

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "\n./fim_db <number-rand-keys> <number-rand-values>\n\n");
        return 1;
    }

    nice(10);

    unsigned int num_keys = atoi(argv[1]);
    unsigned int num_values = atoi(argv[2]);

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

    fill_entries_random(fim_sql, num_keys, num_values);

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    printf("Number of registries %d\n", fim_db_get_count_registry_key(fim_sql));
    printf("Number of registries %d\n", fim_db_get_count_registry_data(fim_sql));

    fim_tmp_file * file, *file2;
    fim_db_get_registry_keys_not_scanned(fim_sql, &file, FIM_DB_DISK);

    fim_db_get_registry_data_not_scanned(fim_sql, &file2, FIM_DB_DISK);

    fim_entry * entry;
    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_REGISTRY;

    announce_function("fim_db_get_registry_key_using_id");
    entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, 1);
    print_fim_registry_key_data(entry);
    fim_db_force_commit(fim_sql);

    announce_function("fim_db_process_read_registry_data_file");
    int res = fim_db_process_read_registry_data_file(fim_sql, file2, NULL, print_entry, FIM_DB_DISK, NULL, NULL, NULL);

    announce_function("fim_db_get_registry_data");
    entry->registry_entry.value = fim_db_get_registry_data(fim_sql, entry->registry_entry.key->id, "reg_name_0");
    announce_function("fim_db_remove_registry_value_data");
    fim_db_remove_registry_value_data(fim_sql, entry->registry_entry.value);
    fim_db_force_commit(fim_sql);

    entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, 2);
    announce_function("fim_db_remove_registry_key");
    fim_db_remove_registry_key(fim_sql, entry);
    fim_db_force_commit(fim_sql);
}
