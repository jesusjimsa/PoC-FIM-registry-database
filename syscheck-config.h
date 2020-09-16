/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSCHECKC_H
#define SYSCHECKC_H

#include "dependencies.h"

typedef enum fim_event_mode {
    FIM_SCHEDULED,
    FIM_REALTIME,
    FIM_WHODATA
} fim_event_mode;

typedef char os_md5[33];
typedef char os_sha1[65];
typedef char os_sha256[65];

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
    FIMDB_STMT_GET_REG_ROWID,
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
    FIMDB_STMT_SET_REG_DATA_SCANNED,
    FIMDB_STMT_SET_REG_KEY_SCANNED,
    FIMDB_STMT_GET_REG_KEY_ROWID,
    FIMDB_STMT_GET_REG_DATA_ROWID,
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

// typedef struct _rtfim {
//     int fd;
//     OSHash *dirtb;
// #ifdef WIN32
//     HANDLE evt;
// #endif
// } rtfim;

typedef enum fim_type {FIM_TYPE_FILE = 0, FIM_TYPE_REGISTRY} fim_type;

typedef struct registry {
    char *entry;
    int arch;
    int opts;
    int recursion_level;
    int diff_size_limit;
    char *tag;
} registry;

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

typedef struct fim_registry_key {
    unsigned int id;
    char * path;
    char * perm;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    int arch;

    unsigned int scanned;
    // path:perm:uid:user_name:gid:group_name
    os_sha1 checksum;
} fim_registry_key;

typedef struct fim_registry_value_data {
    unsigned int id;
    char *name;
    unsigned int type;
    unsigned int size;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;

    unsigned int scanned;
    time_t last_event;
    //type:size:hash_sh1:mtime
    os_sha1 checksum;
    fim_event_mode mode;
} fim_registry_value_data;

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

/**
 * @brief Organizes syscheck directories and related data according to their priority (whodata-realtime-scheduled) and in alphabetical order
 *
 * @param syscheck Syscheck configuration structure
 */
// void organize_syscheck_dirs(syscheck_config *syscheck) __attribute__((nonnull(1)));

/**
 * @brief Converts the value written in the configuration to a determined data unit in KB
 *
 * @param content Read content from the configuration
 *
 * @return Read value on success, -1 on failure
 */
int read_data_unit(const char *content);

/**
 * @brief Read diff configuration
 *
 * Read disk_quota, file_size and nodiff options
 *
 * @param xml XML structure containing Wazuh's configuration
 * @param syscheck Syscheck configuration structure
 * @param node XML node to continue reading the configuration file
 */
// void parse_diff(const OS_XML *xml, syscheck_config * syscheck, XML_NODE node);

/**
 * @brief Adds (or overwrite if exists) an entry to the syscheck configuration structure
 *
 * @param syscheck Syscheck configuration structure
 * @param entry Entry to be dumped
 * @param vals Indicates the system arch for registries and the attributes for folders to be set
 * @param reg 1 if it's a registry, 0 if not
 * @param restrictfile The restrict regex to be set
 * @param recursion_level The recursion level to be set
 * @param tag The tag to be set
 * @param link If the added entry is pointed by a symbolic link
 * @param diff_size Maximum size to calculate diff for files in the directory
 */
// void dump_syscheck_entry(syscheck_config *syscheck, char *entry, int vals, int reg, const char *restrictfile,
                            // int recursion_level, const char *tag, const char *link,
                            // int diff_size) __attribute__((nonnull(1, 2)));

/**
 * @brief Converts a bit mask with syscheck options to a human readable format
 *
 * @param [out] buf The buffer to write the check options in
 * @param [in] buflen The size of the buffer
 * @param [in] opts The bit mask of the options
 * @return A text version of the directory check option bits
 */
char *syscheck_opts2str(char *buf, int buflen, int opts);

/**
 * @brief Frees the memory of a syscheck configuration structure
 *
 * @param [out] config The syscheck configuration to free
 */
// void Free_Syscheck(syscheck_config *config);

/**
 * @brief Transforms an ASCII text to HEX
 *
 * @param input The input text to transform
 * @return The HEX string on success, the original string on failure
 */
char *check_ascci_hex(char *input);

/**
 * @brief Logs the real time engine status
 *
 */
void log_realtime_status(int);

void free_entry_data(fim_file_data * data);
void free_registry_key(fim_registry_key *key);
void free_registry_value(fim_registry_value_data *data);
void free_entry(fim_entry * entry);

#endif /* SYSCHECKC_H */
