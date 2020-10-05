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
#define DEF_REG_PATH "HKEY_LOCAL_MACHINE\\TEST 1"
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

int fill_entries_random(fdb_t *fim_sql, unsigned int num_keys, unsigned int num_entries) {
    unsigned int i, j;
    fim_entry *entry = NULL;

    entry = calloc(1, sizeof(fim_entry));
    entry->type = FIM_TYPE_REGISTRY;

    for(i = 0; i < num_keys; i++) {
        char *reg_path = calloc(512, sizeof(char));
        snprintf(reg_path, 512, "%s_%i\\", DEF_REG_PATH, i);
        fim_registry_key *key = fill_registry_key_struct(i, reg_path, DEF_PERM, DEF_UID, DEF_GID, DEF_USER_NAME,
                                                         DEF_GROUP_NAME, rand() % 1500000000, rand() % 2, rand() % 2,
                                                         DEF_SHA1_HASH);
        entry->registry_entry.key = key;
        for (j = 0; j < num_entries; j++) {
            char *reg_name = calloc(512, sizeof(char));
            snprintf(reg_name, 512, "%s%i", DEF_REG_NAME, j);

            fim_registry_value_data *value = fill_registry_value_struct(i, reg_name, rand() % 11, rand() % 256,
                                                                        DEF_MD5_HASH, DEF_SHA1_HASH, DEF_SHA256_HASH, rand() % 2,
                                                                        rand() % 1500000000, DEF_SHA1_HASH,
                                                                        FIM_SCHEDULED);
            entry->registry_entry.value = value;

            if (fim_db_insert_registry(fim_sql, entry)) {
                printf("Error in fim_db_insert_registry() function: %s\n", reg_name);
                free_registry_value(value);
                return FIMDB_ERR;
            }
            free_registry_value(value);
            free(reg_name);
        }

        free_registry_key(key);
        free(reg_path);
    }
    free(entry);

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

    int res = 0;

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
    fim_db_force_commit(fim_sql);

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Count registry keys
    announce_function("fim_db_get_count_registry_key");
    gettime(&start);

    res = fim_db_get_count_registry_key(fim_sql);

    if (res == FIMDB_ERR) {
        merror("Could not get count of registry keys.");
        fim_db_force_commit(fim_sql);
        return 1;
    }

    printf("Number of registry keys %d\n", res);

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Count registry values
    announce_function("fim_db_get_count_registry_data");
    gettime(&start);

    res = fim_db_get_count_registry_data(fim_sql);

    if (res == FIMDB_ERR) {
        merror("Could not get count of registry values.");
        fim_db_force_commit(fim_sql);
        return 1;
    }

    printf("Number of registry values %d\n", res);

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Get registry keys not scanned
    announce_function("fim_db_get_registry_keys_not_scanned");
    gettime(&start);

    fim_tmp_file *file, *file2;

    res = fim_db_get_registry_keys_not_scanned(fim_sql, &file, FIM_DB_DISK);

    if (res == FIMDB_ERR) {
        merror("Could not get not scanned registry keys.");
        fim_db_force_commit(fim_sql);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    fim_db_delete_registry_keys_not_scanned(fim_sql, file, NULL, FIM_DB_DISK);
    return 1;
    // Get registry values not scanned
    announce_function("fim_db_get_registry_data_not_scanned");
    gettime(&start);

    res = fim_db_get_registry_data_not_scanned(fim_sql, &file2, FIM_DB_DISK);

    if (res == FIMDB_ERR) {
        merror("Could not get not scanned registry values.");
        fim_db_force_commit(fim_sql);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    fim_entry *entry;
    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_REGISTRY;

    // Get registry key using id
    announce_function("fim_db_get_registry_key_using_id");
    gettime(&start);

    entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, 1);

    if (entry->registry_entry.key == NULL) {
        merror("Could not get registry key using id.");
        fim_db_force_commit(fim_sql);
        free_entry(entry);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    print_fim_registry_key_data(entry);

    // Read registry data file
    announce_function("fim_db_process_read_registry_data_file");
    gettime(&start);
    if (file2 != NULL) {
        res = fim_db_process_read_registry_data_file(fim_sql, file2, NULL, print_entry, FIM_DB_DISK, NULL, NULL, NULL);

        if (res == FIMDB_ERR) {
            merror("Could not read registry data file.");
            fim_db_force_commit(fim_sql);
            free_entry(entry);
            return 1;
        }

        gettime(&end);
        printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
    }
    // Get registry data
    announce_function("fim_db_get_registry_data");
    gettime(&start);

    entry->registry_entry.value = fim_db_get_registry_data(fim_sql, entry->registry_entry.key->id, "reg_name_0");

    if (entry->registry_entry.value == NULL) {
        merror("Could not get registry data from id and name.");
        fim_db_force_commit(fim_sql);
        free_entry(entry);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Remove registry value
    announce_function("fim_db_remove_registry_value_data");
    gettime(&start);

    res = fim_db_remove_registry_value_data(fim_sql, entry->registry_entry.value);

    if (res == FIMDB_ERR) {
        merror("Could not remove registry value.");
        fim_db_force_commit(fim_sql);
        free_entry(entry);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Get registry key using id
    announce_function("fim_db_get_registry_key_using_id");
    gettime(&start);
    free_registry_key(entry->registry_entry.key);
    entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, 2);

    if (entry->registry_entry.key == NULL) {
        merror("Could not get registry key using id.");
        fim_db_force_commit(fim_sql);
        free_entry(entry);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // Remove registry key
    announce_function("fim_db_remove_registry_key");
    gettime(&start);

    res = fim_db_remove_registry_key(fim_sql, entry);

    if (res == FIMDB_ERR) {
        merror("Could not remove registry key.");
        fim_db_force_commit(fim_sql);
        free_entry(entry);
        return 1;
    }

    gettime(&end);
    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    free_entry(entry);

    fim_tmp_file *file3;
    res = fim_db_get_values_from_registry_key(fim_sql, &file3, FIM_DB_DISK, 1);

    fim_db_force_commit(fim_sql);
    fim_db_clean_file(&file3, FIM_DB_DISK);
    fim_db_close(fim_sql);
    free(fim_sql);
}
