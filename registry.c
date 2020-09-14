/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// #include "registry.h"
#include "syscheck-config.h"
#include "fim_db.h"


#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winreg_wrappers.h"

extern int _base_line;
#else
static int _base_line = 0;
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_KEY 2048
#define MAX_VALUE_NAME 16383

registry *fim_registry_configuration(const char *key, int arch) {
    int it = 0;
    int top = 0;
    int match;
    registry *ret = NULL;

    os_calloc(1, sizeof(registry), ret);

    return ret;
}

void fim_registry_free_key(fim_registry_key *key) {
    if (key) {
        os_free(key->path);
        os_free(key->perm);
        os_free(key->uid);
        os_free(key->gid);
        os_free(key->user_name);
        os_free(key->group_name);
        free(key);
    }
}

void fim_registry_free_value_data(fim_registry_value_data *data) {
    if (data) {
        os_free(data->name);
        free(data);
    }
}

void fim_registry_process_value_delete_event(fdb_t *fim_sql,
                                             fim_entry *data,
                                             pthread_mutex_t *mutex,
                                             void *_alert,
                                             void *_ev_mode,
                                             __attribute__((unused)) void *_w_evt) {
    int alert = *(int *)_alert;
    fim_event_mode event_mode = *(fim_event_mode *)_ev_mode;
    registry *configuration;
    char full_path[MAX_KEY];

    snprintf(full_path, MAX_KEY, "%s\\%s", data->registry_entry.key->path, data->registry_entry.value->name);

    // configuration = fim_registry_configuration(full_path, data->registry_entry.key->arch);

    // if (alert && configuration) {
    //     cJSON *json_event = fim_registry_event(data, NULL, configuration, event_mode, FIM_DELETE, NULL, NULL);

    //     if (json_event) {
    //         char *json_formated = cJSON_PrintUnformatted(json_event);
    //         send_syscheck_msg(json_formated);
    //         os_free(json_formated);

    //         cJSON_Delete(json_event);
    //     }
    // }

    fim_db_remove_registry_value_data(fim_sql, data->registry_entry.value);
}

void fim_registry_process_key_delete_event(fdb_t *fim_sql, fim_entry *data, pthread_mutex_t *mutex, void *_alert, void *_ev_mode, void *_w_evt) {
    int alert = *(int *)_alert;
    fim_event_mode event_mode = *(fim_event_mode *)_ev_mode;
    fim_tmp_file *file;
    registry *configuration;

    // configuration = fim_registry_configuration(data->registry_entry.key->path, data->registry_entry.key->arch);

    // if (alert && configuration) {
    //     cJSON *json_event = fim_registry_event(data, NULL, configuration, event_mode, FIM_DELETE, NULL, NULL);

    //     if (json_event) {
    //         char *json_formated = cJSON_PrintUnformatted(json_event);
    //         send_syscheck_msg(json_formated);
    //         os_free(json_formated);

    //         cJSON_Delete(json_event);
    //     }
    // }

    if (fim_db_get_values_from_registry_key(fim_sql, &file, FIM_DB_DISK, data->registry_entry.key->id) == FIMDB_OK) {
        fim_db_process_read_file(fim_sql, file, FIM_TYPE_REGISTRY, mutex, fim_registry_process_value_delete_event, FIM_DB_DISK,
                                 _alert, _ev_mode, _w_evt);
    }

    fim_db_remove_registry_key(fim_sql, data);
}

void fim_registry_process_unscanned_entries(fdb_t *fim_sql) {
    fim_tmp_file *file;
    fim_event_mode event_mode = FIM_SCHEDULED;

    fim_db_set_all_unscanned(fim_sql);

    if (fim_db_get_registry_keys_not_scanned(fim_sql, &file, FIM_DB_DISK) == FIMDB_OK) {
        fim_db_process_read_file(fim_sql, file, FIM_TYPE_REGISTRY, NULL, fim_registry_process_key_delete_event,
                                 FIM_DB_DISK, &_base_line, &event_mode, NULL);
    } else {
        // mwarn("Failed to get unscanned registry keys");
    }

    if (fim_db_get_registry_data_not_scanned(fim_sql, &file, FIM_DB_DISK) == FIMDB_OK) {
        fim_db_process_read_file(fim_sql, file, FIM_TYPE_REGISTRY, NULL, fim_registry_process_value_delete_event,
                                 FIM_DB_DISK, &_base_line, &event_mode, NULL);
    } else {
        // mwarn("Failed to get unscanned registry values");
    }
}
