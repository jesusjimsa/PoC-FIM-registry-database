/**
 * @file fim_sync.c
 * @brief Definition of FIM data synchronization library
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

#include "fim_db.h"
#define FIM_DB_DECODE_TYPE(_func) (void *(*)(sqlite3_stmt *))(_func)
#define FIM_DB_CALLBACK_TYPE(_func) (void (*)(fdb_t *, void *, int,  void *))(_func)

#define fim_db_decode_registry_value_full_row(stmt) _fim_db_decode_registry_value(stmt, 11)
static const char *SQL_STMT[] = {
    // Files
#ifdef WIN32
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#else
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#endif
    [FIMDB_STMT_REPLACE_PATH] = "INSERT OR REPLACE INTO file_entry (path, inode_id, mode, last_event, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_entry INNER JOIN file_data ON path = ? AND file_data.rowid = file_entry.inode_id;",
    [FIMDB_STMT_UPDATE_DATA] = "UPDATE file_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE rowid = ?;",
    [FIMDB_STMT_UPDATE_PATH] = "UPDATE file_entry SET inode_id = ?, mode = ?, last_event = ? = ?, scanned = ?, options = ?, checksum = ? WHERE path = ?;",
    [FIMDB_STMT_GET_LAST_PATH] = "SELECT path FROM file_entry ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_PATH] = "SELECT path FROM file_entry ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_data INNER JOIN file_entry ON inode_id = file_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_data INNER JOIN file_entry ON inode_id = file_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE file_entry SET scanned = 0;",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(inode_id), inode_id FROM file_entry WHERE inode_id = (select inode_id from file_entry where path = ?);",
#ifndef WIN32
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM file_data WHERE inode = ? AND dev = ?;",
#else
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT inode_id FROM file_entry WHERE path = ?",
#endif
    [FIMDB_STMT_GET_COUNT_RANGE] = "SELECT count(*) FROM file_entry INNER JOIN file_data ON file_data.rowid = file_entry.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_GET_PATH_RANGE] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_entry INNER JOIN file_data ON file_data.rowid = file_entry.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM file_entry WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA] = "DELETE FROM file_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_PATHS_INODE] = "SELECT path FROM file_entry INNER JOIN file_data ON file_data.rowid=file_entry.inode_id WHERE file_data.inode=? AND file_data.dev=?;",
    [FIMDB_STMT_GET_PATHS_INODE_COUNT] = "SELECT count(*) FROM file_entry INNER JOIN file_data ON file_data.rowid=file_entry.inode_id WHERE file_data.inode=? AND file_data.dev=?;",
    [FIMDB_STMT_SET_SCANNED] = "UPDATE file_entry SET scanned = 1 WHERE path = ?;",
    [FIMDB_STMT_GET_INODE_ID] = "SELECT inode_id FROM file_entry WHERE path = ?",
    [FIMDB_STMT_GET_COUNT_PATH] = "SELECT count(*) FROM file_entry",
    [FIMDB_STMT_GET_COUNT_DATA] = "SELECT count(*) FROM file_data",
    [FIMDB_STMT_GET_INODE] = "SELECT inode FROM file_data where rowid=(SELECT inode_id FROM file_entry WHERE path = ?)",
    // Registries
// #ifdef WIN32

    [FIMDB_STMT_REPLACE_REG_DATA] = "INSERT OR REPLACE INTO registry_data (key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_REPLACE_REG_KEY] = "INSERT OR REPLACE INTO registry_key (id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_REG_KEY] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE path = ? and arch = ?;",
    [FIMDB_STMT_GET_REG_DATA] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_UPDATE_REG_DATA] = "UPDATE registry_data SET type = ?, size = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, scanned = ?, last_event = ?, checksum = ? WHERE key_id = ? AND name = ?;",
    [FIMDB_STMT_UPDATE_REG_KEY] = "UPDATE registry_key SET perm = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, mtime = ?, arch = ?, scanned = ?, checksum = ? WHERE path = ? and arch = ?;",
    [FIMDB_STMT_GET_ALL_REG_ENTRIES] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, registry_key.scanned, registry_key.checksum, key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, registry_data.scanned, last_event, registry_data.checksum FROM registry_data INNER JOIN registry_key ON registry_key.id = registry_data.key_id ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_REG_KEY_NOT_SCANNED] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE scanned = 0;",
    [FIMDB_STMT_GET_REG_DATA_NOT_SCANNED] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE scanned = 0;",
    [FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED] = "UPDATE registry_key SET scanned = 0;",
    [FIMDB_STMT_SET_REG_KEY_UNSCANNED] = "UPDATE registry_key SET scanned = 0 WHERE path = ? and arch = ?;",
    [FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED] = "UPDATE registry_data SET scanned = 0;",
    [FIMDB_STMT_SET_REG_DATA_UNSCANNED] = "UPDATE registry_data SET scanned = 0 WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_GET_REG_ROWID] = "SELECT id FROM registry_key WHERE path = ?;",
    [FIMDB_STMT_DELETE_REG_KEY_PATH] = "DELETE FROM registry_key WHERE path = ? and arch = ?;",
    [FIMDB_STMT_DELETE_REG_DATA] = "DELETE FROM registry_data WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_DELETE_REG_DATA_PATH] = "DELETE FROM registry_data WHERE key_id = (SELECT id FROM registry_key WHERE path = ? and arch = ?);",
    [FIMDB_STMT_GET_COUNT_REG_KEY] = "SELECT count(*) FROM registry_key;",
    [FIMDB_STMT_GET_COUNT_REG_DATA] = "SELECT count(*) FROM registry_data;",
    [FIMDB_STMT_GET_COUNT_REG_KEY_AND_DATA] = "SELECT count(*) FROM registry_key INNER JOIN registry_data WHERE registry_data.key_id = registry_key.id;",
    [FIMDB_STMT_GET_LAST_REG_KEY] = "SELECT path FROM registry_key ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_REG_KEY] = "SELECT path FROM registry_key ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_REG_COUNT_RANGE] = "SELECT count(*) FROM registry_key INNER JOIN registry_data ON registry_data.key_id = registry_key.id WHERE arch = ? and (path BETWEEN ? and ?) ORDER BY path;",
    [FIMDB_STMT_GET_REG_PATH_RANGE] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, registry_key.scanned, registry_key.checksum, key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, registry_data.scanned, last_event, registry_data.checksum FROM registry_key INNER JOIN registry_data ON registry_data.key_id = registry_key.id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_SET_REG_DATA_SCANNED] = "UPDATE registry_data SET scanned = 1 WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_SET_REG_KEY_SCANNED] = "UPDATE registry_key SET scanned = 1 WHERE path = ? and arch = ?;",
    [FIMDB_STMT_GET_REG_KEY_ROWID] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE id = ?;",
    [FIMDB_STMT_GET_REG_DATA_ROWID] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE key_id = ?;",
};

const char *arch_to_str[] = {
    [ARCH_32BIT] = "[x32]",
    [ARCH_64BIT] = "[x64]"
};

/**
 * @brief Decodes a row from the database to be saved in a fim_entry structure.
 *
 * @param stmt The statement to be decoded.
 * @return fim_entry* The filled structure.
 */
static fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt);


/**
 * @brief Executes a simple query in a given database.
 *
 * @param fim_sql The FIM database structure where the database is.
 * @param query The query to be executed.
 * @return int 0 on success, -1 on error.
 */
static int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query);


/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param registry Variable to indicate if the query is for registries or for files. 0 (FIM_TYPE_FILE) for files
 *  1 (FIM_TYPE_REGISTRY) for registries.
 * @param index
 * @param callback
 * @param arg
 * @param pos
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
static int fim_db_process_get_query(fdb_t *fim_sql, int registry, int index,
                                    void (*callback)(fdb_t *, fim_entry *, int, void *),
                                    int memory, void * arg);


/**
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_insert_data(fdb_t *fim_sql, fim_file_data *entry);


/**
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 */
void fim_db_bind_range(fdb_t *fim_sql, int index, const char *start, const char *top);


/**
 * @brief Binds a range of paths.
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 * @param row_id Row id to be bound.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path,
                                    int row_id, fim_file_data *entry);


/**
 * @brief Binds a path into a statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param file_path File name of the file to insert.
 */
static void fim_db_bind_path(fdb_t *fim_sql, int index,
                             const char * file_path);


/**
 * @brief Binds data into a get inode statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param inode Inode of the file.
 * @param dev dev of the file.
 */
static void fim_db_bind_get_inode(fdb_t *fim_sql, int index,
                                  const unsigned long int inode,
                                  const unsigned long int dev);


/**
 * @brief Binds data into an update entry data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 * @param row_id Row id in file_data table.
 */
static void fim_db_bind_update_data(fdb_t *fim_sql,
                                    fim_file_data *entry,
                                    int *row_id);

/**
 * @brief Binds data into a delete data id statement.
 *
 * @param fim_sql FIM database structure.
 * @param row The especific row.
 */
static void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row);


/**
 * @brief Create a new database.
 * @param path New database path.
 * @param source SQlite3 schema file.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param fim_db Database pointer.
 *
 */
static int fim_db_create_file(const char *path, const char *source, const int storage, sqlite3 **fim_db);


/**
 * @brief Read paths which are stored in a temporal storage.
 *
 * @param fim_sql FIM database structure.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param callback Function to call within a step.
 * @param mode FIM mode for callback function.
 * @param w_evt Whodata information for callback function.
 *
 */
 static int fim_db_process_read_file(fdb_t *fim_sql, fim_tmp_file *file, int type, pthread_mutex_t *mutex,
                                     void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                     int storage, void * alert, void * mode, void * w_evt);


/**
 * @brief Create a new temporal storage to save all the files' paths.
 * @param size Number of paths(Only if memory is 1)
 * @return New file structure.
 */
static fim_tmp_file *fim_db_create_temp_file(int storage);



/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Binds data into a select inode_id statement
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to select.
 */
void fim_db_bind_get_inode_id(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Binds data into a select inode statement
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to select.
 */
void fim_db_bind_get_path_inode(fdb_t *fim_sql, const char *file_path);

// #ifdef WIN32

/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param index
 * @param callback
 * @param arg
 * @param pos
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
static int fim_db_process_get_registry_query(fdb_t *fim_sql, int index,void (*callback)(fdb_t *, fim_registry_key *, int, void *),
                                    int memory, void * arg);

/**
 * @brief Binds name and key_id to a statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param name Registry name.
 * @param key_id Key id of the registry.
*/
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, const int index, const char *name, const int key_id);


/**
 * @brief Binds path into registry statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param path Path to registry.
*/
static void fim_db_bind_registry_path_arch(fdb_t *fim_sql, const unsigned int index, const char *path, int arch);


/**
 * @brief Binds start and top paths into select range statements
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param start First entry of the range.
 * @param top Last entry of the range.
*/
static void fim_db_bind_registry_path_range(fdb_t *fim_sql, const int index, const char *start, const char *top);

/**
 * @brief Bind registry data into an insert registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param data Structure that contains the fields of the inserted data.
 * @param key_id Identifier of the key.
 */
static void fim_db_bind_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, const unsigned int key_id);

/**
 * @brief Bind registry data into an insert registry key statement
 *
 * @param fim_sql FIM database structure.
 * @param registry_key Structure that contains the fields of the inserted key.
 * @param rowid Row identifier.
 */
static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, const unsigned int rowid);

/**
 * @brief Bind registry data into a update registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param data Registy data structure with that will be updated.
 * @param key_id Identifier of the registry key.
 */
static void fim_db_bind_update_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, const unsigned int key_id);

/**
 * @brief Bind registry key into a update registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param registry_key Structure that will be updated.
 */
static void fim_db_bind_update_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key);

/**
 * @brief Bind id into get registry key statement.
 *
 * @param fim_sql FIM database structure.
 * @param id ID of the registry key.
 */
static void fim_db_bind_get_registry_key_id(fdb_t *fim_sql, const unsigned int id);

static void fim_db_bind_get_registry_data_key_id(fdb_t *fim_sql, const unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA_ROWID], 1, key_id);
}

/**
 * @brief Bind id into get registry value statement.
 *
 * @param fim_sql FIM database structure.
 * @param key_id ID of the registry key.
 */
static void fim_db_bind_get_registry_data_key_id(fdb_t *fim_sql, const unsigned int key_id);

char * wstr_escape_json(const char * string) {
    const char escape_map[] = {
        ['\b'] = 'b',
        ['\t'] = 't',
        ['\n'] = 'n',
        ['\f'] = 'f',
        ['\r'] = 'r',
        ['\"'] = '\"',
        ['\\'] = '\\'
    };

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char * output;
    os_calloc(31232, sizeof(char), output);

    do {
        z = strcspn(string + i, "\b\t\n\f\r\"\\");

        if (string[i + z] == '\0') {
            // End of string
            os_realloc(output, j + z + 1, output);
            strncpy(output + j, string + i, z);
        } else {
            // Reserved character
            os_realloc(output, j + z + 3, output);
            strncpy(output + j, string + i, z);
            output[j + z] = '\\';
            output[j + z + 1] = escape_map[(int)string[i + z]];
            z++;
            j++;
        }

        j += z;
        i += z;
    } while (string[i] != '\0');

    output[j] = '\0';
    return output;
}

char * wstr_unescape_json(const char * string) {
    const char UNESCAPE_MAP[] = {
        ['b'] = '\b',
        ['t'] = '\t',
        ['n'] = '\n',
        ['f'] = '\f',
        ['r'] = '\r',
        ['\"'] = '\"',
        ['\\'] = '\\'
    };

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char * output;
    os_calloc(1, sizeof(char*), output);

    do {
        z = strcspn(string + i, "\\");

        // Extend output and copy
        os_realloc(output, j + z + 3, output);
        strncpy(output + j, string + i, z);

        i += z;
        j += z;

        if (string[i] != '\0') {
            // Peek byte following '\'
            switch (string[++i]) {
            case '\0':
                // End of string
                output[j++] = '\\';
                break;

            case 'b':
            case 't':
            case 'n':
            case 'f':
            case 'r':
            case '\"':
            case '\\':
                // Escaped character
                output[j++] = UNESCAPE_MAP[(int)string[i++]];
                break;

            default:
                // Bad escape
                output[j++] = '\\';
                output[j++] = string[i++];
            }
        }
    } while (string[i] != '\0');

    output[j] = '\0';
    return output;
}
// #endif

fdb_t *fim_db_init(int storage) {
    fdb_t *fim;
    char *path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;

    os_calloc(1, sizeof(fdb_t), fim);
    fim->transaction.interval = COMMIT_INTERVAL;

    if (storage == FIM_DB_DISK) {
        fim_db_clean();
    }

    if (fim_db_create_file(path, schema_fim_sql, storage, &fim->db) < 0) {
        goto free_fim;
    }

    if (!storage &&
        sqlite3_open_v2(path, &fim->db, SQLITE_OPEN_READWRITE, NULL)) {
        goto free_fim;
    }

    if (fim_db_cache(fim)) {
        goto free_fim;
    }

    char *error;
    sqlite3_exec(fim->db, "PRAGMA synchronous = OFF", NULL, NULL, &error);

    if (error) {
        merror("SQL error turning off synchronous mode: %s", error);
        fim_db_finalize_stmt(fim);
        sqlite3_free(error);
        goto free_fim;
    }

    if (fim_db_exec_simple_wquery(fim, "BEGIN;") == FIMDB_ERR) {
        fim_db_finalize_stmt(fim);
        goto free_fim;
    }

    return fim;

free_fim:
    if (fim->db){
        sqlite3_close_v2(fim->db);
    }
    os_free(fim);
    return NULL;
}

void fim_db_close(fdb_t *fim_sql) {
    fim_db_force_commit(fim_sql);
    fim_db_finalize_stmt(fim_sql);
    sqlite3_close_v2(fim_sql->db);
}


void fim_db_clean(void) {

    if (w_is_file(FIM_DB_DISK_PATH)) {
        // If the file is being used by other processes, wait until
        // it's unlocked in order to remove it. Wait at most 5 seconds.
        int i, rm;
        for (i = 1; i <= FIMDB_RM_MAX_LOOP && (rm = remove(FIM_DB_DISK_PATH)); i++) {
            mdebug2(FIM_DELETE_DB_TRY, FIM_DB_DISK_PATH, i);
#ifdef WIN32
            Sleep(FIMDB_RM_DEFAULT_TIME * i); //milliseconds
#else
            usleep(FIMDB_RM_DEFAULT_TIME * i); //milliseconds
#endif
        }

        //Loop endlessly until the file can be removed. (60s)
        if (rm == FIMDB_ERR) {
            while (remove(FIM_DB_DISK_PATH)) {
                // LCOV_EXCL_START
                mdebug2(FIM_DELETE_DB, FIM_DB_DISK_PATH);
#ifdef WIN32
                Sleep(60000); //milliseconds
#else
                sleep(60); //seconds
#endif
                // LCOV_EXCL_STOP
            }
        }
    }

}


int fim_db_cache(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        if (sqlite3_prepare_v2(fim_sql->db, SQL_STMT[index], -1,
            &fim_sql->stmt[index], NULL) != SQLITE_OK) {
            merror("Error preparing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    return retval;
}

int fim_db_create_file(const char *path, const char *source, const int storage, sqlite3 **fim_db) {
    const char *sql;
    const char *tail;

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        merror("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            merror("Error preparing statement '%s': %s", sql, sqlite3_errmsg(db));
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
            merror("Error stepping statement '%s': %s", sql, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    if (storage == FIM_DB_MEMORY) {
        *fim_db = db;
        return 0;
    }

    sqlite3_close_v2(db);

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return -1;
    }

    return 0;
}

fim_tmp_file *fim_db_create_temp_file(int storage) {
    fim_tmp_file *file;
    os_calloc(1, sizeof(fim_tmp_file), file);

    if (storage == FIM_DB_DISK) {
        os_calloc(PATH_MAX, sizeof(char), file->path);
        //Create random name unique to this thread
        sprintf(file->path, "%stmp_%lu%d%u", FIM_DB_TMPDIR,
                    (unsigned long)time(NULL),
                    getpid(),
                    os_random());

        file->fd = fopen(file->path, "w+");
        if (file->fd == NULL) {
            merror("Failed to create temporal storage '%s': %s (%d)", file->path, strerror(errno), errno);
            os_free(file->path);
            os_free(file);
            return NULL;
        }
    } else {
        file->list = NULL;  // Here, there was a W_Vector_init(100)
    }

    return file;
}

void fim_db_clean_file(fim_tmp_file **file, int storage) {
    if (storage == FIM_DB_DISK) {
        fclose((*file)->fd);
        if (remove((*file)->path) < 0) {
            merror("Failed to remove '%s': %s (%d)", (*file)->path, strerror(errno), errno);
        }
        os_free((*file)->path);
    } else {
        free((*file)->list);
    }

    os_free((*file));
}

int fim_db_finalize_stmt(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        fim_db_clean_stmt(fim_sql, index);
        if (sqlite3_finalize(fim_sql->stmt[index]) != SQLITE_OK) {
            merror("Error finalizing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    return retval;
}

void fim_db_check_transaction(fdb_t *fim_sql) {
    time_t now = time(NULL);

    if (fim_sql->transaction.last_commit + fim_sql->transaction.interval <= now) {
        if (!fim_sql->transaction.last_commit) {
            fim_sql->transaction.last_commit = now;
            return;
        }

        // If the completion of the transaction fails, we do not update the timestamp
        if (fim_db_exec_simple_wquery(fim_sql, "END;") != FIMDB_ERR) {
            mdebug1("Database transaction completed.");
            fim_sql->transaction.last_commit = now;
            while (fim_db_exec_simple_wquery(fim_sql, "BEGIN;") == FIMDB_ERR);
        }
    }
}

void fim_db_force_commit(fdb_t *fim_sql) {
    fim_sql->transaction.last_commit = 1;
    fim_db_check_transaction(fim_sql);
}

int fim_db_clean_stmt(fdb_t *fim_sql, int index) {
    if (sqlite3_reset(fim_sql->stmt[index]) != SQLITE_OK || sqlite3_clear_bindings(fim_sql->stmt[index]) != SQLITE_OK) {
        sqlite3_finalize(fim_sql->stmt[index]);

        if (sqlite3_prepare_v2(fim_sql->db, SQL_STMT[index], -1, &fim_sql->stmt[index], NULL) != SQLITE_OK) {
            merror("Error preparing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}


//wrappers

int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_FILE, FIMDB_STMT_GET_PATH_RANGE, fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_get_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_FILE, FIMDB_STMT_GET_NOT_SCANNED, fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;

}

int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_ALL_ENTRIES);
    return fim_db_process_get_query(fim_sql, FIM_TYPE_FILE, FIMDB_STMT_GET_ALL_ENTRIES, fim_db_callback_calculate_checksum, 0, arg);
}

int fim_db_process_get_query(fdb_t *fim_sql, int type, int index, void (*callback)(fdb_t *, fim_entry *, int , void *),
                             int storage, void * arg) {
    int result;
    int i;
    for (i = 0; result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW; i++) {
        fim_entry *entry = type == FIM_TYPE_REGISTRY ? fim_db_decode_registry(index, fim_sql->stmt[index])
                                                     : fim_db_decode_full_row(fim_sql->stmt[index]);
        callback(fim_sql, entry, storage, arg);
        free_entry(entry);
    }

    fim_db_check_transaction(fim_sql);

    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
}

int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query) {
    char *error = NULL;

    sqlite3_exec(fim_sql->db, query, NULL, NULL, &error);

    if (error) {
        merror("Error executing simple query '%s': %s", query, error);
        sqlite3_free(error);
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_sync_path_range(fdb_t * fim_sql, pthread_mutex_t *mutex, fim_tmp_file *file, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_callback_sync_path_range, storage,
                                    NULL, NULL, NULL);
}

int fim_db_delete_not_scanned(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) false, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode, whodata_evt * w_evt) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) (fim_event_mode) mode, (void *) w_evt);
}

int fim_db_process_read_file(fdb_t *fim_sql, fim_tmp_file *file, int type, pthread_mutex_t *mutex,
                             void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                             int storage, void * alert, void * mode, void * w_evt) {
    char line[PATH_MAX + 1];
    char *path = line;
    char *split = NULL;
    int i = 0;

    if (storage == FIM_DB_DISK) {
        fseek(file->fd, SEEK_SET, 0);
    }

    do {

        if (storage == FIM_DB_DISK) {
            // fgets() adds \n(newline) to the end of the string,
            // so it must be removed.
            if (fgets(line, sizeof(line), file->fd)) {
                size_t len = strlen(line);

                if (len > 2 && line[len - 1] == '\n') {
                    line[len - 1] = '\0';
                }
                else {
                    merror("Temporary path file '%s' is corrupt: missing line end.", file->path);
                    continue;
                }

                path = wstr_unescape_json(line);
            }
        } else {
            //path = wstr_unescape_json((char *) W_Vector_get(file->list, i));
        }

        if (path) {
            w_mutex_lock(mutex);
            fim_entry *entry;

            if (type == FIM_TYPE_FILE) {
                entry = fim_db_get_path(fim_sql, path);
            }
            else {
                os_calloc(1, sizeof(fim_entry), entry);
                unsigned int arch =  strtoul(path, &split, 10);
                if (*split != ' ') {
                    merror("ERROR EN LA BD");
                    continue;
                }
                split++;
                entry->type = FIM_TYPE_REGISTRY;
                entry->registry_entry.key = fim_db_get_registry_key(fim_sql, split, arch);
            }

            w_mutex_unlock(mutex);

            if (entry != NULL) {
                callback(fim_sql, entry, mutex, alert, mode, w_evt);
                free_entry(entry);
            }
        }

        i++;
    } while (i < file->elements);

    fim_db_clean_file(&file, storage);

    return FIMDB_OK;
}

fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt) {

    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_FILE;
    os_strdup((char *)sqlite3_column_text(stmt, 0), entry->file_entry.path);

    os_calloc(1, sizeof(fim_file_data), entry->file_entry.data);
    entry->file_entry.data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->file_entry.data->last_event = (time_t)sqlite3_column_int(stmt, 3);
    entry->file_entry.data->scanned = (time_t)sqlite3_column_int(stmt, 4);
    entry->file_entry.data->options = (time_t)sqlite3_column_int(stmt, 5);
    strncpy(entry->file_entry.data->checksum, (char *)sqlite3_column_text(stmt, 6), sizeof(os_sha1) - 1);
    entry->file_entry.data->dev = (unsigned long int)sqlite3_column_int(stmt, 7);
    entry->file_entry.data->inode = (unsigned long int)sqlite3_column_int64(stmt, 8);
    entry->file_entry.data->size = (unsigned int)sqlite3_column_int(stmt, 9);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 10), entry->file_entry.data->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 11), entry->file_entry.data->attributes);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 12), entry->file_entry.data->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 13), entry->file_entry.data->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 14), entry->file_entry.data->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 15), entry->file_entry.data->group_name);
    strncpy(entry->file_entry.data->hash_md5, (char *)sqlite3_column_text(stmt, 16), sizeof(os_md5) - 1);
    strncpy(entry->file_entry.data->hash_sha1, (char *)sqlite3_column_text(stmt, 17), sizeof(os_sha1) - 1);
    strncpy(entry->file_entry.data->hash_sha256, (char *)sqlite3_column_text(stmt, 18), sizeof(os_sha256) - 1);
    entry->file_entry.data->mtime = (unsigned int)sqlite3_column_int(stmt, 19);

    return entry;
}

/* No needed bind FIMDB_STMT_GET_LAST_ROWID, FIMDB_STMT_GET_ALL_ENTRIES, FIMDB_STMT_GET_NOT_SCANNED,
   FIMDB_STMT_SET_ALL_UNSCANNED, FIMDB_STMT_DELETE_UNSCANNED */

/* FIMDB_STMT_INSERT_DATA */
void fim_db_bind_insert_data(fdb_t *fim_sql, fim_file_data *entry) {
#ifndef WIN32
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 1, entry->dev);
    sqlite3_bind_int64(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 2, entry->inode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 3, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 4, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 5, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 6, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 7, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 8, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 9, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 10, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 11, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 12, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 13, entry->mtime);
#else
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 1, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 2, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 4, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 5, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 11, entry->mtime);
#endif
}

/* FIMDB_STMT_REPLACE_PATH */
void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path, int row_id, fim_file_data *entry) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 1, file_path, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 2, row_id);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 3, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 4, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 5, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 6, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 7, entry->checksum, -1, NULL);
}

/* FIMDB_STMT_GET_PATH, FIMDB_STMT_GET_PATH_COUNT, FIMDB_STMT_DELETE_PATH, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_path(fdb_t *fim_sql, int index, const char *file_path) {
    if (index == FIMDB_STMT_GET_PATH || index == FIMDB_STMT_GET_PATH_COUNT
       || index == FIMDB_STMT_DELETE_PATH || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, file_path, -1, NULL);
    }
}

/* FIMDB_STMT_GET_PATHS_INODE, FIMDB_STMT_GET_PATHS_INODE_COUNT, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_get_inode(fdb_t *fim_sql, int index, const unsigned long int inode, const unsigned long int dev) {
    if (index == FIMDB_STMT_GET_PATHS_INODE || index == FIMDB_STMT_GET_PATHS_INODE_COUNT
        || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_int64(fim_sql->stmt[index], 1, inode);
        sqlite3_bind_int(fim_sql->stmt[index], 2, dev);
    }
}

/* FIMDB_STMT_UPDATE_file_data */
void fim_db_bind_update_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 1, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 2, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 4, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 5, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 11, entry->mtime);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 12, *row_id);
}

/* FIMDB_STMT_DELETE_DATA */
void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_DELETE_DATA], 1, row);
}

/* FIMDB_STMT_SET_SCANNED */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_SET_SCANNED], 1, file_path, -1, NULL);
}

/* FIMDB_STMT_GET_INODE_ID */
void fim_db_bind_get_inode_id(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_GET_INODE_ID], 1, file_path, -1, NULL);
}

/* FIMDB_STMT_GET_INODE */
void fim_db_bind_get_path_inode(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_GET_INODE], 1, file_path, -1, NULL);
}

void fim_db_bind_range(fdb_t *fim_sql, int index, const char *start, const char *top) {
    if (index == FIMDB_STMT_GET_PATH_RANGE ||
        index == FIMDB_STMT_GET_COUNT_RANGE ) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, start, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, top, -1, NULL);
    }
}

// #ifdef WIN32
// Registry sql queries bindings
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, const int index, const char *name, const int key_id) {
    if (index == FIMDB_STMT_SET_REG_DATA_UNSCANNED ||
        index == FIMDB_STMT_DELETE_REG_DATA ||
        index == FIMDB_STMT_SET_REG_DATA_SCANNED ||
        index == FIMDB_STMT_GET_REG_DATA) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, name, -1, NULL);
        sqlite3_bind_int(fim_sql->stmt[index], 2, key_id);
    }
}

static void fim_db_bind_registry_path_arch(fdb_t *fim_sql, const unsigned int index, const char *path, int arch) {
    if (index == FIMDB_STMT_GET_REG_KEY ||
        index == FIMDB_STMT_SET_REG_KEY_UNSCANNED ||
        index == FIMDB_STMT_GET_REG_ROWID ||
        index == FIMDB_STMT_DELETE_REG_KEY_PATH ||
        index == FIMDB_STMT_DELETE_REG_DATA_PATH ||
        index == FIMDB_STMT_SET_REG_KEY_SCANNED) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, path, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, arch_to_str[arch], -1, NULL);
    }
}

static void fim_db_bind_registry_path_range(fdb_t *fim_sql, const int index, const char *start, const char *top) {
    if (index == FIMDB_STMT_GET_REG_COUNT_RANGE ||
        index == FIMDB_STMT_GET_REG_PATH_RANGE) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, start, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, top, -1, NULL);
    }
}

static void fim_db_bind_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, const unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 1, key_id);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 2, data->name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 3, data->type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 4, data->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 5, data->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 6, data->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 7, data->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 8, data->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 9, data->last_event);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 10, data->checksum, -1, NULL);
}

static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, const unsigned int id) {
    if (id == 0) {
        sqlite3_bind_null(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 1);
    } else {
        sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 1, id);
    }

    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 2, registry_key->path, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 3, registry_key->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 4, registry_key->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 5, registry_key->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 6, registry_key->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 7, registry_key->group_name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 8, registry_key->mtime);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 9, arch_to_str[registry_key->arch], -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 10, registry_key->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 11, registry_key->checksum, -1, NULL);
}

static void fim_db_bind_update_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, const unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 1, data->type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 2, data->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 3, data->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 4, data->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 5, data->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 6, data->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 7, data->last_event);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 8, data->checksum, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 9, key_id);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 10, data->name, -1, NULL);
}

static void fim_db_bind_update_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 1, registry_key->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 2, registry_key->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 3, registry_key->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 4, registry_key->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 5, registry_key->group_name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 6, registry_key->mtime);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 7, arch_to_str[registry_key->arch], -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 8, registry_key->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 9, registry_key->checksum, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 10, registry_key->path, -1, NULL);
}

static void fim_db_bind_get_registry_key_id(fdb_t *fim_sql, const unsigned int id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID], 1, id);
}
// #endif

fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path) {
    fim_entry *entry = NULL;

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH, file_path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH]) == SQLITE_ROW) {
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH]);
    }

    return entry;
}

char **fim_db_get_paths_from_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev) {
    char **paths = NULL;

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATHS_INODE);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATHS_INODE_COUNT);

    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_PATHS_INODE_COUNT, inode, dev);

    if(sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE_COUNT]) == SQLITE_ROW) {
        int result = 0;
        int i = 0;
        int rows = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE_COUNT], 0);

        os_calloc(rows + 1, sizeof(char *), paths);
        fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_PATHS_INODE, inode, dev);

        while (result = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE]), result == SQLITE_ROW) {
            if (i >= rows) {
                minfo("The count returned is smaller than the actual elements. This shouldn't happen.");
                break;
            }
            os_strdup((char *)sqlite3_column_text(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE], 0), paths[i]);
            i++;
        }
    }

    fim_db_check_transaction(fim_sql);

    return paths;
}

int fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *count) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_COUNT_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_COUNT_RANGE, start, top);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_COUNT_RANGE]) != SQLITE_ROW) {
        merror("Step error getting count range 'start %s' 'top %s': %s", start, top,  sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    *count = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_RANGE], 0);

    return FIMDB_OK;
}

int fim_db_insert_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id) {
    int res;

    if(*row_id == 0) {
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_INSERT_DATA);

        fim_db_bind_insert_data(fim_sql, entry);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_INSERT_DATA]), res != SQLITE_DONE) {
            merror("Step error inserting data row_id '%d': %s", *row_id, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }

        *row_id = sqlite3_last_insert_rowid(fim_sql->db);
    } else {
        // Update file_data
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_UPDATE_DATA);
        fim_db_bind_update_data(fim_sql, entry, row_id);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA]), res != SQLITE_DONE) {
            merror("Step error updating data row_id '%d': %s", *row_id, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}

int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_file_data *entry, int inode_id) {
    int res;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_PATH);
    fim_db_bind_replace_path(fim_sql, file_path, inode_id, entry);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH]), res != SQLITE_DONE) {
            merror("Step error replacing path '%s': %s", file_path, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_file_data *new, fim_file_data *saved) {
    int inode_id;
    int res, res_data, res_path;
    unsigned int nodes_count;

    // Add event
    // if (!saved) {
    //     if (syscheck.file_limit_enabled) {
    //         nodes_count = fim_db_get_count_file_entry(syscheck.database);
    //         if (nodes_count >= syscheck.file_limit) {
    //             mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.",
    //                     file_path);
    //             return FIMDB_FULL;
    //         }
    //     }
    // }
    // Modified event
#ifndef WIN32
    // else
    if (new->inode != saved->inode) {
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
        fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, file_path);

        sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT]);

        res = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 0);
        inode_id = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 1);
        if (res == 1) {
            // The inode has only one entry, delete the entry data.
            fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
            fim_db_bind_delete_data_id(fim_sql, inode_id);

            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_DATA]) != SQLITE_DONE) {
                merror("Step error deleting data: %s", sqlite3_errmsg(fim_sql->db));
                return FIMDB_ERR;
            }
            fim_db_force_commit(fim_sql);
        }
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_DATA_ROW);
    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_DATA_ROW, new->inode, new->dev);
#else
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_DATA_ROW);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_DATA_ROW, file_path);
#endif

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW]);

    switch(res) {
    case SQLITE_ROW:
        inode_id = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW], 0);
    break;

    case SQLITE_DONE:
        inode_id = 0;
    break;

    default:
        merror("Step error getting data row: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    res_data = fim_db_insert_data(fim_sql, new, &inode_id);
    res_path = fim_db_insert_path(fim_sql, file_path, new, inode_id);

    fim_db_check_transaction(fim_sql);

    return res_data || res_path;
}

void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))int storage, void *arg) {

    // EVP_MD_CTX *ctx = (EVP_MD_CTX *)arg;
    // if (entry->type == FIM_TYPE_FILE) {
    //     EVP_DigestUpdate(ctx, entry->file_entry.data->checksum, strlen(entry->file_entry.data->checksum));
    // } else {
    //     EVP_DigestUpdate(ctx, entry->registry_entry.value->checksum, strlen(entry->registry_entry.value->checksum));
    // }
}

int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n, pthread_mutex_t *mutex) {
    fim_entry *entry = NULL;
    int m = n / 2;
    int i;
    int retval = FIMDB_ERR;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_size = 0;
    os_sha1 hexdigest;
    char *str_pathlh = NULL;
    char *str_pathuh = NULL;
    char *plain      = NULL;

    // EVP_MD_CTX *ctx_left = EVP_MD_CTX_create();
    // EVP_MD_CTX *ctx_right = EVP_MD_CTX_create();

    // EVP_DigestInit(ctx_left, EVP_sha1());
    // EVP_DigestInit(ctx_right, EVP_sha1());

    w_mutex_lock(mutex);

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);

    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    // Calculate checksum of the first half
    for (i = 0; i < m; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("Step error getting path range, first half 'start %s' 'top %s' (i:%d): %s", start, top, i,
                   sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == (m - 1) && entry->file_entry.path) {
            os_strdup(entry->file_entry.path, str_pathlh);
        }
        //Type of storage not required
        // fim_db_callback_calculate_checksum(fim_sql, entry, FIM_DB_DISK, (void *)ctx_left);
        free_entry(entry);
    }

    //Calculate checksum of the second half
    for (i = m; i < n; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("Step error getting path range, second half 'start %s' 'top %s' (i:%d): %s", start, top, i,
                   sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == m && entry->file_entry.path) {
            os_free(str_pathuh);
            os_strdup(entry->file_entry.path, str_pathuh);
        }
        //Type of storage not required
        // fim_db_callback_calculate_checksum(fim_sql, entry, FIM_DB_DISK, (void *)ctx_right);
        free_entry(entry);
    }

    w_mutex_unlock(mutex);

    if (!str_pathlh || !str_pathuh) {
        merror("Failed to obtain required paths in order to form message");
        goto end;
    }

    retval = FIMDB_OK;

end:
    // EVP_MD_CTX_destroy(ctx_left);
    // EVP_MD_CTX_destroy(ctx_right);
    os_free(str_pathlh);
    os_free(str_pathuh);
    return retval;
}

void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
     __attribute__((unused))void *alert,
     __attribute__((unused))void *fim_ev_mode,
     __attribute__((unused))void *w_evt) {

    int *send_alert = (int *) alert;
    fim_event_mode mode = (fim_event_mode) fim_ev_mode;
    int rows = 0;
    int conf;

    if(entry->type == FIM_TYPE_FILE) {

        // conf = fim_configuration_directory(entry->file_entry.path, "file");

        if(conf > -1) {
            // switch (mode) {
            /* Don't send alert if received mode and mode in configuration aren't the same */
            // case FIM_REALTIME:
            //     if (!(syscheck.opts[conf] & REALTIME_ACTIVE)) {
            //         return;     // LCOV_EXCL_LINE
            //     }
            //     break;

            // case FIM_WHODATA:
            //     if (!(syscheck.opts[conf] & WHODATA_ACTIVE)) {
            //         return;     // LCOV_EXCL_LINE
            //     }
            //     break;

            // case FIM_SCHEDULED:
            //     if (!(syscheck.opts[conf] & SCHEDULED_ACTIVE)) {
            //         return;     // LCOV_EXCL_LINE
            //     }
            //     break;

            // }
        } else {
            mdebug2(FIM_DELETE_EVENT_PATH_NOCONF, entry->file_entry.path);
            return;
        }
    }

    w_mutex_lock(mutex);

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, entry->file_entry.path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT]) == SQLITE_ROW) {
        rows = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 0);
        int rowid = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 1);

        switch (rows) {
        case 0:
            // No entries with this path.
            break;
        case 1:
            // The inode has only one entry, delete the entry data.
            fim_db_bind_delete_data_id(fim_sql, rowid);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_DATA]) != SQLITE_DONE) {
                w_mutex_unlock(mutex);
                goto end;
            }
            //Fallthrough
        default:
            // The inode has more entries, delete only this path.
            fim_db_bind_path(fim_sql, FIMDB_STMT_DELETE_PATH, entry->file_entry.path);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_PATH]) != SQLITE_DONE) {
                w_mutex_unlock(mutex);
                goto end;
            }
            break;
        }
    }

    w_mutex_unlock(mutex);


    if (send_alert && rows >= 1) {
        whodata_evt *whodata_event = (whodata_evt *) w_evt;
        // cJSON * json_event      = NULL;
        char * json_formatted    = NULL;
        int pos = 0;
        const char *FIM_ENTRY_TYPE[] = {"file", "registry"};

        // Obtaining the position of the directory, in @syscheck.dir, where @entry belongs
        // if (pos = fim_configuration_directory(entry->file_entry.path,
        //     FIM_ENTRY_TYPE[entry->type]), pos < 0) {
        //     goto end;
        // }

        // json_event = fim_json_event(entry->file_entry.path, NULL, entry->file_entry.data, pos, FIM_DELETE, mode,
        //                             whodata_event, NULL);

        // if (!strcmp(FIM_ENTRY_TYPE[entry->type], "file") && syscheck.opts[pos] & CHECK_SEECHANGES) {
        //     if (syscheck.disk_quota_enabled) {
        //         char *full_path;
                // full_path = seechanges_get_diff_path(entry->file_entry.path);

                // if (full_path != NULL && IsDir(full_path) == 0) {
                    // syscheck.diff_folder_size -= (DirSize(full_path) / 1024);   // Update diff_folder_size

                    // if (!syscheck.disk_quota_full_msg) {
                    //     syscheck.disk_quota_full_msg = true;
                    // }
                // }

                // os_free(full_path);
            // }

            // delete_target_file(entry->file_entry.path);
        // }

        /* if (json_event) {
            mdebug2(FIM_FILE_MSG_DELETE, entry->file_entry.path);
            json_formatted = cJSON_PrintUnformatted(json_event);
            send_syscheck_msg(json_formatted);

            os_free(json_formatted);
            cJSON_Delete(json_event);
        } */
    }

end:
    w_mutex_lock(mutex);
    fim_db_check_transaction(fim_sql);
    w_mutex_unlock(mutex);
}

int fim_db_get_row_path(fdb_t * fim_sql, int mode, char **path) {
    int index = (mode)? FIMDB_STMT_GET_FIRST_PATH : FIMDB_STMT_GET_LAST_PATH;
    int result;

    fim_db_clean_stmt(fim_sql, index);

    if (result = sqlite3_step(fim_sql->stmt[index]), result != SQLITE_ROW && result != SQLITE_DONE) {
        merror("Step error getting row path '%s': %s", *path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    if (result == SQLITE_ROW) {
        os_strdup((char *)sqlite3_column_text(fim_sql->stmt[index], 0), *path);
    }

    return FIMDB_OK;
}

int fim_db_set_all_unscanned(fdb_t *fim_sql) {
    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_UNSCANNED]);
    fim_db_check_transaction(fim_sql);
    return retval;
}

int fim_db_set_scanned(fdb_t *fim_sql, char *path) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_SCANNED);
    fim_db_bind_set_scanned(fim_sql, path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned path '%s': %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

void fim_db_callback_save_path(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage, void *arg) {
    char *path = entry->type == FIM_TYPE_FILE ? entry->file_entry.path : entry->registry_entry.key->path;
    char *base = NULL;
    char *write_buffer;
    size_t line_length;


    if(base = wstr_escape_json(path), base == NULL) {
        merror("Error escaping '%s'", path);
        return;
    }

    if (entry->type == FIM_TYPE_FILE) {
        write_buffer = base;
        line_length = strlen(write_buffer);
    } else {
        os_calloc(MAX_DIR_SIZE, sizeof(char), write_buffer);
        line_length = snprintf(write_buffer, MAX_DIR_SIZE, "%d %s", entry->registry_entry.key->arch, base);
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", write_buffer) != (line_length + sizeof(char))) {
            merror("%s - %s", path, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else {
        //W_Vector_insert(((fim_tmp_file *) arg)->list, write_buffer);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(write_buffer);
    os_free(base);
}

void fim_db_callback_sync_path_range(__attribute__((unused))fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))pthread_mutex_t *mutex, __attribute__((unused))void *alert,
    __attribute__((unused))void *mode, __attribute__((unused))void *w_event) {

}

int fim_db_get_count_file_data(fdb_t * fim_sql) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_COUNT_DATA);
    int res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_COUNT_DATA]);

    if(res == SQLITE_ROW) {
        return sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_DATA], 0);
    }
    else {
        merror("Step error getting count entry data: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }
}

int fim_db_get_count_file_entry(fdb_t * fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_PATH);

    if(res != FIMDB_ERR) {
        return res;
    }
    else {
        merror("Step error getting count entry path: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }
}

int fim_db_get_count(fdb_t *fim_sql, int index) {

    if (index == FIMDB_STMT_GET_COUNT_REG_KEY || index == FIMDB_STMT_GET_COUNT_REG_DATA ||
        index == FIMDB_STMT_GET_COUNT_PATH    || index == FIMDB_STMT_GET_COUNT_DATA) {
        fim_db_clean_stmt(fim_sql, index);

        if (sqlite3_step(fim_sql->stmt[index]) == SQLITE_ROW) {
            return sqlite3_column_int(fim_sql->stmt[index], 0);
        } else {
            return FIMDB_ERR;
        }
    }
    return FIMDB_ERR;
}

// #ifdef WIN32

int fim_db_get_registry_key_rowid(fdb_t *fim_sql, const char *path, unsigned int *rowid, int arch) {
    int res;
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_ROWID);
    fim_db_bind_registry_path_arch(fim_sql, FIMDB_STMT_GET_REG_ROWID, path, arch);

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_ROWID]);

    if (res == SQLITE_ROW) {
        *rowid = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_REG_ROWID], 0);
    }
    else if (res == SQLITE_DONE) {
        printf("key not founded in DB\n");
        *rowid = 0;

    }
    else {
        merror("Step error getting registry rowid %s: %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

fim_registry_key *fim_db_decode_registry_key(sqlite3_stmt *stmt) {
    fim_registry_key *entry;
    os_calloc(1, sizeof(fim_registry_key), entry);
    char *str_arch;

    entry->id = (unsigned int)sqlite3_column_int(stmt, 0);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 1), entry->path);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 2), entry->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 3), entry->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 4), entry->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 5), entry->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 6), entry->group_name);
    entry->mtime = (unsigned int)sqlite3_column_int(stmt, 7);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 8), str_arch);
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, 9);
    strncpy(entry->checksum, (char *)sqlite3_column_text(stmt, 10), sizeof(os_sha1) - 1);
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, 11);

    if (strncmp(str_arch, "[x32]", 6) == 0) {
        entry->arch = ARCH_32BIT;
    } else {
        entry->arch = ARCH_64BIT;
    }
    free(str_arch);
    return entry;
}

fim_registry_value_data *_fim_db_decode_registry_value(sqlite3_stmt *stmt, int offset) {
    fim_registry_value_data *entry;
    os_calloc(1, sizeof(fim_registry_value_data), entry);

    entry->id = (unsigned int)sqlite3_column_int(stmt, offset + 0);
    sqlite_strdup((char *)sqlite3_column_text(stmt, offset + 1), entry->name);
    entry->type = (unsigned int)sqlite3_column_int(stmt, offset + 2);
    entry->size = (unsigned int)sqlite3_column_int(stmt, offset + 3);
    strncpy(entry->hash_md5, (char *)sqlite3_column_text(stmt, offset + 4), sizeof(os_md5) - 1);
    strncpy(entry->hash_sha1, (char *)sqlite3_column_text(stmt, offset + 5), sizeof(os_sha1) - 1);
    strncpy(entry->hash_sha256, (char *)sqlite3_column_text(stmt, offset + 6), sizeof(os_sha256) - 1);
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, offset + 7);
    entry->last_event = (unsigned int)sqlite3_column_int(stmt, offset + 8);
    strncpy(entry->checksum, (char *)sqlite3_column_text(stmt, offset + 9), sizeof(os_sha1) - 1);

    return entry;
}

fim_entry *fim_db_decode_registry(int index, sqlite3_stmt *stmt) {
    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);

    entry->type = FIM_TYPE_REGISTRY;
    entry->registry_entry.key = NULL;
    entry->registry_entry.value = NULL;

    // Registry key
    if (index == FIMDB_STMT_GET_REG_KEY_NOT_SCANNED ||
        index == FIMDB_STMT_GET_REG_KEY_ROWID ||
        index == FIMDB_STMT_GET_REG_KEY) {

        entry->registry_entry.key = fim_db_decode_registry_key(stmt);
    }

    if (index == FIMDB_STMT_GET_REG_DATA || index == FIMDB_STMT_GET_REG_DATA_NOT_SCANNED) {
        entry->registry_entry.value = fim_db_decode_registry_value(stmt);
    }

    return entry;
}

// Registry callbacks

void fim_db_callback_save_reg_data_name(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage, void *arg) {
    if (entry->type != FIM_TYPE_REGISTRY) {
        return ;
    }

    char *base = entry->registry_entry.value->name;
    char *buffer = NULL;
    os_calloc(MAX_DIR_SIZE, sizeof(char), buffer);

    if (base == NULL) {
        merror("Error escaping '%s'", entry->registry_entry.value->name);
        return;
    }

    snprintf(buffer, MAX_DIR_SIZE, "%d %s", entry->registry_entry.value->id, base);

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", buffer) != (strlen(buffer) + sizeof(char))) {
            merror("%s - %s", entry->registry_entry.value->name, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else {
        //W_Vector_insert(((fim_tmp_file *) arg)->list, buffer);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(buffer);
}

// Registry functions
int fim_db_set_all_registry_data_unscanned(fdb_t *fim_sql) {
    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED]);
    fim_db_check_transaction(fim_sql);

    return retval;
}

int fim_db_set_all_registry_key_unscanned(fdb_t *fim_sql) {
    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED]);
    fim_db_check_transaction(fim_sql);

    return retval;
}

int fim_db_set_registry_key_scanned(fdb_t *fim_sql, char *path, int arch) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED);
    fim_db_bind_registry_path_arch(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED, path, arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_KEY_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned key path '%s': %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_set_registry_data_scanned(fdb_t *fim_sql, char *name, unsigned int key_id) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED, name, key_id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_DATA_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned data name '%s': %s", name, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage){
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_KEY_NOT_SCANNED,
                                       fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_get_registry_data_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_DATA_NOT_SCANNED,
                                       fim_db_callback_save_reg_data_name, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

fim_registry_value_data *fim_db_get_registry_data(fdb_t *fim_sql, const unsigned int key_id, const char *name) {
    fim_registry_value_data *value = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_DATA);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_GET_REG_DATA, name, key_id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA]) == SQLITE_ROW) {
        value = fim_db_decode_registry_value(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA]);
    }

    return value;
}

fim_registry_key *fim_db_get_registry_key(fdb_t *fim_sql, const char *path, int arch) {
    fim_registry_key *reg_key = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_KEY);
    fim_db_bind_registry_path_arch(fim_sql, FIMDB_STMT_GET_REG_KEY, path, arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY]) == SQLITE_ROW) {
        reg_key = fim_db_decode_registry_key(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY]);
    }

    return reg_key;
}

int fim_db_get_registry_keys_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_REG_PATH_RANGE, start, top);

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_PATH_RANGE,
                                       fim_db_callback_save_reg_data_name, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_remove_registry_key(fdb_t *fim_sql, fim_entry *entry) {

    if (entry->type != FIM_TYPE_REGISTRY) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_DATA_PATH);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_KEY_PATH);
    fim_db_bind_registry_path_arch(fim_sql, FIMDB_STMT_DELETE_REG_KEY_PATH, entry->registry_entry.key->path, entry->registry_entry.key->arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_DATA_PATH]) != SQLITE_DONE) {
        merror("Step error deleting data value from key '%s': %s", entry->registry_entry.key->path,
               sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_KEY_PATH]) != SQLITE_DONE) {
        merror("Step error deleting key path '%s': %s", entry->registry_entry.key->path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

void fim_db_remove_registry_key1(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *a, void *b, void *c, void *d) {

    if (entry->type != FIM_TYPE_REGISTRY) {
        return ;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_DATA_PATH);

    fim_db_bind_registry_path_arch(fim_sql, FIMDB_STMT_DELETE_REG_KEY_PATH, entry->registry_entry.key->path, entry->registry_entry.key->arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_KEY_PATH]) != SQLITE_DONE) {
        merror("Step error deleting key path '%s': %s", entry->registry_entry.key->path, sqlite3_errmsg(fim_sql->db));
        return ;
    }

    fim_db_check_transaction(fim_sql);

    return ;
}


int fim_db_get_count_registry_key(fdb_t *fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_REG_KEY);

    if(res == FIMDB_ERR) {
        merror("Step error getting count registry key: %s", sqlite3_errmsg(fim_sql->db));
    }

    return res;
}

int fim_db_get_count_registry_data(fdb_t *fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_REG_DATA);

    if(res == FIMDB_ERR) {
        merror("Step error getting count registry data: %s", sqlite3_errmsg(fim_sql->db));
    }

    return res;
}


int fim_db_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id) {
    int res = 0;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_DATA);
    fim_db_bind_insert_registry_data(fim_sql, data, key_id);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA]), res != SQLITE_DONE) {
        merror("Step error replacing registry data '%d': %s", key_id, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry, unsigned int rowid) {
    int res = 0;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_KEY);
    fim_db_bind_insert_registry_key(fim_sql, entry, rowid);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY]), res != SQLITE_DONE) {
        merror("Step error replacing registry key '%s': %s", entry->path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry(fdb_t *fim_sql, fim_entry *new) {
    int res_data = 0;
    int res_key = 0;

    res_key = fim_db_insert_registry_key(fim_sql, new->registry_entry.key, new->registry_entry.key->id);
    fim_db_get_registry_key_rowid(fim_sql, new->registry_entry.key->path, &new->registry_entry.key->id, new->registry_entry.key->arch);
    res_data = fim_db_insert_registry_data(fim_sql, new->registry_entry.value, new->registry_entry.key->id);

    fim_db_check_transaction(fim_sql);

    return res_data || res_key;
}

int fim_db_remove_registry_value_data(fdb_t *fim_sql, fim_registry_value_data *entry) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_DATA);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_DELETE_REG_DATA, entry->name, entry->id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_DATA]) != SQLITE_DONE) {
        merror("Step error deleting entry name '%s': %s", entry->name, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}


int fim_db_process_read_registry_data_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
                                     void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                     int storage, void * alert, void * mode, void * w_evt) {

    char line[PATH_MAX + 1];
    char *name = NULL;
    unsigned int id;
    int i;
    char *split;

    if (storage == FIM_DB_DISK) {
        if (fseek(file->fd, SEEK_SET, 0) != 0) {
            merror("Failed fseek in %s", file->path);
            return FIMDB_ERR;
        }
    }

    for (i = 0; i < file->elements; i++) {
        if (storage == FIM_DB_DISK) {
            /* fgets() adds \n(newline) to the end of the string,
             So it must be removed. */
            if (fgets(line, sizeof(line), file->fd)) {
                size_t len = strlen(line);

                if (len > 2 && line[len - 1] == '\n') {
                    line[len - 1] = '\0';
                } else {
                    merror("Temporary path file '%s' is corrupt: missing line end.", file->path);
                    continue;
                }

                //name = wstr_unescape_json(line);
            }
        } else {
            //name = wstr_unescape_json((char *) W_Vector_get(file->list, i));
        }
        os_strdup(line, name);
        if (name == NULL) {
            continue;
        }
        // Readed line has to be: 234(row id of the key) some_reg(name of the registry). Get the rowid and the name
        id = strtoul(name, &split, 10);

        // Skip if the fields couldn't be extracted.
        if (*split != ' ' || id == 0) {
            //mwarn("Temporary path file '%s' is corrupt: wrong line format", file->path);
            continue;
        }

        fim_entry *entry;

        split++; // ignore the whitespace

        os_calloc(1, sizeof(fim_entry), entry);

        entry->type = FIM_TYPE_REGISTRY;
        //w_mutex_lock(mutex);
        entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, id);
        entry->registry_entry.value = fim_db_get_registry_data(fim_sql, id, split);

        //w_mutex_unlock(mutex);

        if (entry != NULL) {
            callback(fim_sql, entry, mutex, alert, mode, w_evt);
            free_entry(entry);
        }

        os_free(name);
    }
    fim_db_clean_file(&file, storage);

    return FIMDB_OK;
}

fim_registry_key *fim_db_get_registry_key_using_id(fdb_t *fim_sql, unsigned int id) {
    fim_registry_key *reg_key = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_KEY_ROWID);
    fim_db_bind_get_registry_key_id(fim_sql, id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID]) == SQLITE_ROW) {
        reg_key = fim_db_decode_registry_key(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID]);
    }

    return reg_key;
}

fim_registry_value_data * fim_db_decode_registry_value(sqlite3_stmt *stmt) {
    return _fim_db_decode_registry_value(stmt, 0);
}

char *fim_db_decode_value_not_scanned(sqlite3_stmt *stmt) {
    char buffer[256];
        char *ret;

    snprintf(buffer, 256, "%d %s", sqlite3_column_int(stmt, 0), (char *)sqlite3_column_text(stmt, 1));
    os_strdup(buffer, ret);

    return ret;
}

void fim_db_callback_save_string(__attribute__((unused))fdb_t * fim_sql, char *path, int storage, void *arg) {
    char *base = path;
    if (base == NULL) {
        merror("Error escaping '%s'", path);
        return;
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", base) != (strlen(base) + sizeof(char))) {
            merror("%s - %s", path, strerror(errno));
        }

             fflush(((fim_tmp_file *) arg)->fd);

    } else {
        //W_Vector_insert(((fim_tmp_file *) arg)->list, base);
    }

    ((fim_tmp_file *) arg)->elements++;
}

int fim_db_get_values_from_registry_key(fdb_t * fim_sql, fim_tmp_file **file, int storage, unsigned long int key_id) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_DATA_ROWID);
    fim_db_bind_get_registry_data_key_id(fim_sql, key_id);

    int ret = fim_db_multiple_row_query(fim_sql, FIMDB_STMT_GET_REG_DATA_ROWID, FIM_DB_DECODE_TYPE(fim_db_decode_value_not_scanned), free,
                                       FIM_DB_CALLBACK_TYPE(fim_db_callback_save_string), storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_delete_registry_keys_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_REGISTRY, mutex, print_entry, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_delete_registry_data_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_REGISTRY, mutex, NULL, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_multiple_row_query(fdb_t *fim_sql, int index, void *(*decode)(sqlite3_stmt *), void (*free_row)(void *),
                              void (*callback)(fdb_t *, void *, int, void *), int storage, void *arg) {
    int result;
    int i;

    if (decode == NULL || callback == NULL || free_row == NULL) {
        return FIMDB_ERR;
    }

    for (i = 0; result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW; i++) {
        void *decoded_row = decode(fim_sql->stmt[index]);
        if (decoded_row != NULL) {
            callback(fim_sql, decoded_row, storage, arg);
            free_row(decoded_row);
        }
    }

    fim_db_check_transaction(fim_sql);

    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
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
    printf("Modification time: %d\n", entry->registry_entry.key->mtime);
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
