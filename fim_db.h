/**
 * @file fim_sync.c
 * @brief Definition of FIM data synchronization library
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */


#include "syscheck-config.h"

#define FIM_DB_MEMORY_PATH  ":memory:"

#define DEFAULTDIR "."

#ifndef WIN32
#define FIM_DB_DISK_PATH    DEFAULTDIR "/fim.db"
#define FIM_DB_TMPDIR       DEFAULTDIR "/"
#else
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"
#define FIM_DB_TMPDIR       "tmp/"
#endif

#ifndef COMMIT_INTERVAL
#define COMMIT_INTERVAL     2
#endif

#define FIMDB_OK 0   // Successful result.
#define FIMDB_ERR -1 // Generic error.
#define FIMDB_FULL -2 // DB is full.

#define FIMDB_RM_MAX_LOOP 10 // Max number of loop iterations
#define FIMDB_RM_DEFAULT_TIME 100 //miliseconds

#define FIM_LAST_ROW 0
#define FIM_FIRST_ROW 1

#define EVP_MAX_MD_SIZE 64

#define FIM_DB_PATHS    100

extern const char *schema_fim_sql;

/**
 * @brief Clean and free resources
 * @param file Storage structure
 * @param storage Type of storage (memory or disk)
 */
void fim_db_clean_file(fim_tmp_file **file, int storage);

/**
 * @brief Initialize FIM databases.
 * Checks if the databases exists.
 * If it exists deletes the previous version and creates a new one.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
fdb_t *fim_db_init(int storage);

/**
 * @brief Finalize stmt and close DB
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_close(fdb_t *fim_sql);

/**
 * @brief Clean the FIM databases.
 *
 */
void fim_db_clean(void);

/**
 * @brief Compile all statement associated with FIM queries.
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_cache(fdb_t *fim_sql);

/**
 * @brief Finalize all statements
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_finalize_stmt(fdb_t *fim_sql);

/**
 * @brief End transaction and commit.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_check_transaction(fdb_t *fim_sql);

/**
 * @brief Force the commit in the database.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_force_commit(fdb_t *fim_sql);

/**
 * @brief Reset statement and clean bindings parameters
 *
 * @param fim_sql FIM database struct.
 * @param index Statement index.
 */
int fim_db_clean_stmt(fdb_t *fim_sql, int index);

/**
 * @brief Get checksum of all file_data.
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get entry data using path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Get list of all paths by storing them in a temporal file.
 *
 * @param fim_sql FIM database struct.
 * @param index Type of query.
 * @param fd    File where all paths will be stored.
 * @return FIM entry struct on success, NULL on error.
 */
int fim_db_get_multiple_path(fdb_t *fim_sql, int index, FILE *fd);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 * @return char** An array of the paths asociated to the inode.
 */
char **fim_db_get_paths_from_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev);

/**
 * @brief Insert or update entry data.
 *
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param row_id
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id);

/**
 * @brief Insert or update entry path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @param inode_id
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_file_data *entry, int inode_id);

/**
 * @brief Insert an entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param new Entry data to be inserted.
 * @param saved Entry with existing data.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_file_data *new, fim_file_data *saved);

/**
 * @brief Send sync message for all entries.
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param fd    Structure of temporal storage which contains all the paths.
 */
int fim_db_sync_path_range(fdb_t *fim_sql, pthread_mutex_t *mutex,
                            fim_tmp_file *file, int storage);

/**
 * @brief Callback function: Entry checksum calculation.
 *
 */
void fim_db_callback_calculate_checksum( fdb_t *fim_sql, fim_entry *entry, int storage,
                                         void *arg);

/**
 * @brief Calculate checksum of data entries between @start and @top.
 * Said range will be splitted into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n, pthread_mutex_t *mutex);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Delete entry using file path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param mutex
 * @param alert False don't send alert, True send delete alert.
 * @param fim_ev_mode FIM Mode (scheduled/realtime/whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
                        __attribute__((unused))void *alert,
                        __attribute__((unused))void *fim_ev_mode,
                        __attribute__((unused))void *w_evt);

/**
 * @brief Get the last/first row from file_entry.
 *
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_path(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Set all entries from database to unscanned.
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(fdb_t *fim_sql);

/**
 * @brief
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
* @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_scanned(fdb_t *fim_sql, char *path);

/**
 * @brief Get all the unscanned files by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param File    Structure of the file which contains all the paths.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned(fdb_t * fim_sql,fim_tmp_file **file, int storage);

/**
 * @brief Write an entry path into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param args    Storage which contains all the paths.
 * @param pos     If memory is 1, pos indicates the position in the array.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_path(fdb_t *fim_sql, fim_entry *entry, int storage, void *arg);

/**
 * @brief Callback function to send a sync message for a sole entry.
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param mode  Unused argument.
 * @param w_event Unused argument.
 */
void fim_db_callback_sync_path_range(__attribute__((unused))fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))pthread_mutex_t *mutex, __attribute__((unused))void *alert,
    __attribute__((unused))void *mode, __attribute__((unused))void *w_event);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @param file    Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_not_scanned(fdb_t *fim_sql, fim_tmp_file *file,
                                pthread_mutex_t *mutex, int storage);

/**
 * @brief Get path list between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the storage which contains all the paths.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top,
                         fim_tmp_file **file, int storage) ;

/**
 * @brief Removes a range of paths from the database.
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file,
                        pthread_mutex_t *mutex, int storage);

/**
 * @brief Remove a range of paths from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file,
                                 pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode,
                                 whodata_evt * w_evt);

/**
 * @brief Get count of all entries in file_data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_data table.
 */
int fim_db_get_count_file_data(fdb_t * fim_sql);

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_entry table.
 */
int fim_db_get_count_file_entry(fdb_t * fim_sql);

/**
 * @brief Get count of all entries in the database.
 *
 * The database to count is chosen with the index variable.
 *
 * @param fim_sql FIM database struct.
 * @param index Index to SQL statement.
 *
 * @return Number of entries in selected database.
*/
int fim_db_get_count(fdb_t *fim_sql, int index);

// #ifdef WIN32

// Registry callbacks

/**
 * @brief Write an entry path into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param args    Storage which contains all the paths.
 * @param pos     If memory is 1, pos indicates the position in the array.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_registry_path(fdb_t *fim_sql, fim_registry_key *key_entry, int storage, void *arg);

// Registry functions.

/**
 * @brief Get checksum of all registry key.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get checksum of all registry data.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get registry data using its key_id and name.
 *
 * @param fim_sql FIM database struct.
 * @param key_id ID of the registry.
 * @param name Name of the registry value.
 *
 * @return FIM registry data struct on success, NULL on error.
 */
fim_registry_value_data *fim_db_get_registry_data(fdb_t *fim_sql, const unsigned int key_id, const char *name);

/**
 * @brief Get a registry key using its path.
 *
 * @param fim_sql FIM database struct.
 * @param path Path to registry key.
 *
 * @return FIM registry key struct on success, NULL on error.
*/
fim_registry_key *fim_db_get_registry_key(fdb_t *fim_sql, const char *path, int arch);

/**
 * @brief Get all the key paths
 *
 * @param fim_sql FIM databse struct.
 * @param key_id key_id of the registry data table.
 *
 * @return char** An array of the paths asociated to the key_id.
 */
char **fim_db_get_all_registry_key(fdb_t *fim_sql, const unsigned long int key_id);

/**
 * @brief Insert or update registry data.
 *
 * @param fim_sql FIM database struct.
 * @param data Registry data to be inserted.
 * @param key_id Registry key ID.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id);

/**
 * @brief Insert or update registry key.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry key to be inserted.
 * @param rowid Row id of the registry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry, unsigned int rowid);

/**
 * @brief Insert a registry entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param new FIM entry data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry(fdb_t *fim_sql, fim_entry *new);

/**
 * @brief Calculate checksum of registry keys between @start and @top.
 *
 * Said range will be splitted into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_registry_key_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                       const long id, const int n, pthread_mutex_t *mutex);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Count the number of registry data entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */

int fim_db_get_registry_data_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Get the last/first row from registry_key table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_key(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Get the last/first row from registry_data table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_data(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Set all entries from registry_key table to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_key_unscanned(fdb_t *fim_sql);

/**
 * @brief Set all entries from registry_data table to unscanned.
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_data_unscanned(fdb_t *fim_sql);

/**
 * @brief Set a registry key as scanned
 * @param fim_sql FIM database struct.
 * @param path Registry key path.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_key_scanned(fdb_t *fim_sql, char *path, int arch);

/**
 * @brief Set a registry data as scanned
 * @param fim_sql FIM database struct.
 * @param name Value name.
 * @param key_id key_id of the registry data table.
 * @param file_path File path.
* @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_data_scanned(fdb_t *fim_sql, char *name, unsigned int key_id);

/**
 * @brief Get all the unscanned registries keys by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param File    Structure of the file which contains all the paths.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Get all the unscanned registries values by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param File    Structure of the file which contains all the paths.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Delete not scanned registry keys from database.
 *
 * @param fim_sql FIM database struct.
 * @param file    Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_keys_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);

/**
 * @brief Get registry keys between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the storage which contains all the paths.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_registry_keys_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) ;

/**
 * @brief Get registry keys between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the storage which contains all the paths.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_registry_value_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) ;

/**
 * @brief Removes a range of registry keys from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_key_range(fdb_t * fim_sql, fim_tmp_file *file,
                        pthread_mutex_t *mutex, int storage);

/**
 * @brief Removes a range of registry data from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_value_range(fdb_t * fim_sql, fim_tmp_file *file,
                        pthread_mutex_t *mutex, int storage);
/**
 * @brief Remove a range of registry keys from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_key_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode,
                                 whodata_evt * w_evt);

/**
 * @brief Remove a range of registry data from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_data_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode,
                                 whodata_evt * w_evt);


/**
 * @brief Get count of all entries in registry key table.
 *
 * @param fim_sql FIM database struct.
 * @return Number of entries in registry key table.
 */
int fim_db_get_count_registry_key(fdb_t *fim_sql);

/**
 * @brief Get count of all entries in registry data table.
 *
 * @param fim_sql FIM database struct.
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_data(fdb_t * fim_sql);

// #endif
/**
 * @brief Get the rowid of a key path.
 * @param fim_sql FIM database struct
 * @param path Path of the key to look for
 * @param rowid Variable where the rowid will be stored
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_rowid(fdb_t *fim_sql, const char *path, unsigned int *rowid, int arch);

fim_registry_key *fim_db_decode_registry_key(sqlite3_stmt *stmt);

fim_registry_value_data * fim_db_decode_registry_value(sqlite3_stmt *stmt);

fim_entry *fim_db_decode_registry(int index, sqlite3_stmt *stmt);

fim_registry_key *fim_db_get_registry_key_using_id(fdb_t *fim_sql, unsigned int id);

int fim_db_process_read_registry_data_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
                                     void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                     int storage, void * alert, void * mode, void * w_evt);

int fim_db_remove_registry_value_data(fdb_t *fim_sql, fim_registry_value_data *entry);
int fim_db_remove_registry_key(fdb_t *fim_sql, fim_entry *entry);
void fim_db_remove_registry_key1(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *, void *, void *, void *);

/**
 * @brief Write a string into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param str     String to be saved into storage.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg     Storage which contains all the strings.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_string(fdb_t * fim_sql, char *str, int storage, void *arg);

/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param index
 * @param decode
 * @param free_row
 * @param callback
 * @param storage
 * @param arg
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_multiple_row_query(fdb_t *fim_sql,
                              int index,
                              void *(*decode)(sqlite3_stmt *),
                              void (*free_row)(void *),
                              void (*callback)(fdb_t *, void *, int, void *),
                              int storage,
                              void *arg);
int fim_db_get_values_from_registry_key(fdb_t * fim_sql, fim_tmp_file **file, int storage, unsigned long int key_id);

char *fim_db_decode_value_not_scanned(sqlite3_stmt *stmt) ;

void print_entry(__attribute__((unused))fdb_t *fim_sql,
                 fim_entry *entry,
                 __attribute__((unused))pthread_mutex_t *mutex,
                 __attribute__((unused))void *alert,
                 __attribute__((unused))void *mode,
                 __attribute__((unused))void *w_event);

void print_fim_registry_value_data(fim_entry *entry);
void print_fim_registry_key_data(fim_entry *entry);
