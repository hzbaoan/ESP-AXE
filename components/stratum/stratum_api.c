/******************************************************************************
 * *
 * References:
 * 1. Stratum Protocol - [link](https://reference.cash/mining/stratum-protocol)
 *****************************************************************************/

#include "stratum_api.h"
#include "cJSON.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "lwip/sockets.h"
#include "utils.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define STRATUM_TX_BUFFER_MIN_SIZE (BUFFER_SIZE * 2)
static const char * TAG = "stratum_api";

static char * json_rpc_buffer = NULL;
static size_t json_rpc_buffer_size = 0;
static char * stratum_tx_buffer = NULL;
static size_t stratum_tx_buffer_size = 0;
static pthread_mutex_t stratum_tx_lock = PTHREAD_MUTEX_INITIALIZER;

static void debug_stratum_tx(const char *);
static void * stratum_buffer_alloc(size_t size);
static bool stratum_tx_buffer_ensure_locked(size_t size);
static int stratum_write_all_locked(int socket, const char *buffer, size_t length);
static int stratum_writef(int socket, const char *format, ...);
static void stratum_message_prepare(StratumApiV1Message *message);
static void stratum_message_set_error(StratumApiV1Message *message, const char *error_str);
static void stratum_message_set_out_of_memory(StratumApiV1Message *message);

bool STRATUM_V1_initialize_buffer(void)
{
    if (json_rpc_buffer == NULL) {
        json_rpc_buffer = stratum_buffer_alloc(BUFFER_SIZE);
        json_rpc_buffer_size = BUFFER_SIZE;
        if (json_rpc_buffer == NULL) {
            ESP_LOGE(TAG, "Failed to allocate RX buffer");
            return false;
        }
        memset(json_rpc_buffer, 0, BUFFER_SIZE);
    }

    pthread_mutex_lock(&stratum_tx_lock);
    if (!stratum_tx_buffer_ensure_locked(STRATUM_TX_BUFFER_MIN_SIZE)) {
        pthread_mutex_unlock(&stratum_tx_lock);
        ESP_LOGE(TAG, "Failed to allocate TX buffer");
        return false;
    }
    pthread_mutex_unlock(&stratum_tx_lock);
    return true;
}

static bool realloc_json_buffer(size_t len)
{
    size_t old, new;

    old = strlen(json_rpc_buffer);
    new = old + len + 1;

    if (new < json_rpc_buffer_size) {
        return true;
    }

    new = new + (BUFFER_SIZE - (new % BUFFER_SIZE));
    void * new_sockbuf = stratum_buffer_alloc(new);

    if (new_sockbuf == NULL) {
        ESP_LOGE(TAG, "Failed to grow RX buffer to %u bytes", (unsigned int)new);
        return false;
    }

    memset(new_sockbuf, 0, new);
    memcpy(new_sockbuf, json_rpc_buffer, old);
    free(json_rpc_buffer);
    json_rpc_buffer = new_sockbuf;
    json_rpc_buffer_size = new;
    return true;
}

char * STRATUM_V1_receive_jsonrpc_line(int sockfd)
{
    if (json_rpc_buffer == NULL) {
        if (!STRATUM_V1_initialize_buffer()) {
            errno = ENOMEM;
            return NULL;
        }
    }
    char *line = NULL;
    char recv_buffer[BUFFER_SIZE];
    int nbytes;
    size_t buflen = 0;

    if (!strchr(json_rpc_buffer, '\n')) {
        do {
            memset(recv_buffer, 0, BUFFER_SIZE);
            nbytes = recv(sockfd, recv_buffer, BUFFER_SIZE - 1, 0);
            
            if (nbytes <= 0) {
                ESP_LOGW(TAG, "Socket closed or error: recv returned %d (errno %d: %s)", nbytes, errno, strerror(errno));
                if (json_rpc_buffer) {
                    free(json_rpc_buffer);
                    json_rpc_buffer = NULL;
                    json_rpc_buffer_size = 0;
                }
                return NULL; 
            }

            if (!realloc_json_buffer(nbytes)) {
                free(json_rpc_buffer);
                json_rpc_buffer = NULL;
                json_rpc_buffer_size = 0;
                errno = ENOMEM;
                return NULL;
            }
            strncat(json_rpc_buffer, recv_buffer, nbytes);
        } while (!strchr(json_rpc_buffer, '\n'));
    }
    
    buflen = strlen(json_rpc_buffer);
    
    char *newline_ptr = strchr(json_rpc_buffer, '\n');
    if (newline_ptr) {
        *newline_ptr = '\0';
        line = strdup(json_rpc_buffer);
        if (line == NULL) {
            strcpy(json_rpc_buffer, "");
            errno = ENOMEM;
            return NULL;
        }
        int len = strlen(line);
        if (buflen > len + 1) {
            memmove(json_rpc_buffer, json_rpc_buffer + len + 1, buflen - len + 1);
        } else {
            strcpy(json_rpc_buffer, "");
        }
    }
    
    return line;
}

void STRATUM_V1_parse(StratumApiV1Message * message, const char * stratum_json)
{
    stratum_message_prepare(message);

    cJSON * json = cJSON_Parse(stratum_json);

    if (json == NULL) {
        ESP_LOGE(TAG, "Error parsing JSON payload: %s", stratum_json);
        message->method = STRATUM_UNKNOWN;
        message->response_success = false;
        return;
    }

    cJSON * id_json = cJSON_GetObjectItem(json, "id");
    int64_t parsed_id = -1;
    if (id_json != NULL && cJSON_IsNumber(id_json)) {
        parsed_id = id_json->valueint;
    }
    message->message_id = parsed_id;

    cJSON * method_json = cJSON_GetObjectItem(json, "method");
    stratum_method result = STRATUM_UNKNOWN;

    if (method_json != NULL && cJSON_IsString(method_json)) {
        if (strcmp("mining.notify", method_json->valuestring) == 0) {
            result = MINING_NOTIFY;
        } else if (strcmp("mining.set_difficulty", method_json->valuestring) == 0) {
            result = MINING_SET_DIFFICULTY;
        } else if (strcmp("mining.set_version_mask", method_json->valuestring) == 0) {
            result = MINING_SET_VERSION_MASK;
        } else if (strcmp("client.reconnect", method_json->valuestring) == 0) {
            result = CLIENT_RECONNECT;
        } else {
            ESP_LOGI(TAG, "unhandled method in stratum message: %s", stratum_json);
        }
    } else {
        cJSON * result_json = cJSON_GetObjectItem(json, "result");
        cJSON * error_json = cJSON_GetObjectItem(json, "error");
        cJSON * reject_reason_json = cJSON_GetObjectItem(json, "reject-reason");

        if (result_json == NULL) {
            message->response_success = false;
            stratum_message_set_error(message, "unknown");
        } else if (!cJSON_IsNull(error_json)) {
            message->response_success = false;
            stratum_message_set_error(message, "unknown");
            if (parsed_id < 5) {
                result = STRATUM_RESULT_SETUP;
            } else {
                result = STRATUM_RESULT;
            }
            if (cJSON_IsArray(error_json)) {
                int len = cJSON_GetArraySize(error_json);
                if (len >= 2) {
                    cJSON * error_msg = cJSON_GetArrayItem(error_json, 1);
                    if (cJSON_IsString(error_msg)) {
                        stratum_message_set_error(message, cJSON_GetStringValue(error_msg));
                    }
                }
            }
        } else if (cJSON_IsBool(result_json)) {
            if (parsed_id < 5) {
                result = STRATUM_RESULT_SETUP;
            } else {
                result = STRATUM_RESULT;
            }
            if (cJSON_IsTrue(result_json)) {
                message->response_success = true;
            } else {
                message->response_success = false;
                stratum_message_set_error(message, "unknown");
                if (cJSON_IsString(reject_reason_json)) {
                    stratum_message_set_error(message, cJSON_GetStringValue(reject_reason_json));
                }                
            }
        } else if (parsed_id == STRATUM_ID_SUBSCRIBE) {
            result = STRATUM_RESULT_SUBSCRIBE;

            cJSON * extranonce2_len_json = cJSON_GetArrayItem(result_json, 2);
            if (extranonce2_len_json == NULL) {
                ESP_LOGE(TAG, "Unable to parse extranonce2_len: %s", result_json->valuestring);
                message->response_success = false;
                goto done;
            }
            message->extranonce_2_len = extranonce2_len_json->valueint;

            cJSON * extranonce_json = cJSON_GetArrayItem(result_json, 1);
            if (extranonce_json == NULL) {
                ESP_LOGE(TAG, "Unable parse extranonce: %s", result_json->valuestring);
                message->response_success = false;
                goto done;
            }
            
            message->extranonce_str = malloc(strlen(extranonce_json->valuestring) + 1);
            if (message->extranonce_str == NULL) {
                stratum_message_set_out_of_memory(message);
                goto done;
            }
            strcpy(message->extranonce_str, extranonce_json->valuestring);
            
            // [极致优化 2: 全局缓存二进制化]
            message->extranonce_bin_len = strlen(extranonce_json->valuestring) / 2;
            message->extranonce_bin = malloc(message->extranonce_bin_len);
            if (message->extranonce_bin == NULL) {
                free(message->extranonce_str);
                message->extranonce_str = NULL;
                stratum_message_set_out_of_memory(message);
                goto done;
            }
            hex2bin(extranonce_json->valuestring, message->extranonce_bin, message->extranonce_bin_len);

            message->response_success = true;

            ESP_LOGI(TAG, "extranonce_str: %s", message->extranonce_str);
            ESP_LOGI(TAG, "extranonce_2_len: %d", message->extranonce_2_len);

        } else if (parsed_id == STRATUM_ID_CONFIGURE) {
            cJSON * mask = cJSON_GetObjectItem(result_json, "version-rolling.mask");
            if (mask != NULL) {
                result = STRATUM_RESULT_VERSION_MASK;
                message->version_mask = strtoul(mask->valuestring, NULL, 16);
                ESP_LOGI(TAG, "Set version mask: %08lx", message->version_mask);
            } else {
                ESP_LOGI(TAG, "error setting version mask: %s", stratum_json);
            }

        } else {
            ESP_LOGI(TAG, "unhandled result in stratum message: %s", stratum_json);
        }
    }

    message->method = result;

    if (message->method == MINING_NOTIFY) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        
        if (params == NULL || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 8) {
            ESP_LOGE(TAG, "Malformed mining.notify params received!");
            goto done;
        }

        mining_notify * new_work = malloc(sizeof(mining_notify));
        if (new_work == NULL) {
            stratum_message_set_out_of_memory(message);
            goto done;
        }

        memset(new_work, 0, sizeof(*new_work));
        new_work->job_id = strdup(cJSON_GetArrayItem(params, 0)->valuestring);
        if (new_work->job_id == NULL) {
            STRATUM_V1_free_mining_notify(new_work);
            stratum_message_set_out_of_memory(message);
            goto done;
        }
        
        // [极致优化 1: 落地即二进制，消除 strdup]
        hex2bin(cJSON_GetArrayItem(params, 1)->valuestring, new_work->prev_block_hash_bin, 32);
        flip32bytes(new_work->prev_block_hash, new_work->prev_block_hash_bin);
        memcpy(new_work->prev_block_hash_be, new_work->prev_block_hash_bin, sizeof(new_work->prev_block_hash_be));
        reverse_bytes(new_work->prev_block_hash_be, sizeof(new_work->prev_block_hash_be));
        
        const char *cb1_str = cJSON_GetArrayItem(params, 2)->valuestring;
        new_work->coinbase_1_len = strlen(cb1_str) / 2;
        new_work->coinbase_1_bin = malloc(new_work->coinbase_1_len);
        if (new_work->coinbase_1_bin == NULL) {
            STRATUM_V1_free_mining_notify(new_work);
            stratum_message_set_out_of_memory(message);
            goto done;
        }
        hex2bin(cb1_str, new_work->coinbase_1_bin, new_work->coinbase_1_len);
        
        const char *cb2_str = cJSON_GetArrayItem(params, 3)->valuestring;
        new_work->coinbase_2_len = strlen(cb2_str) / 2;
        new_work->coinbase_2_bin = malloc(new_work->coinbase_2_len);
        if (new_work->coinbase_2_bin == NULL) {
            STRATUM_V1_free_mining_notify(new_work);
            stratum_message_set_out_of_memory(message);
            goto done;
        }
        hex2bin(cb2_str, new_work->coinbase_2_bin, new_work->coinbase_2_len);

        cJSON * merkle_branch = cJSON_GetArrayItem(params, 4);
        new_work->n_merkle_branches = cJSON_GetArraySize(merkle_branch);
        if (new_work->n_merkle_branches > MAX_MERKLE_BRANCHES) {
            ESP_LOGE(TAG, "Too many Merkle branches.");
            STRATUM_V1_free_mining_notify(new_work); 
            goto done;
        }
        
        if (new_work->n_merkle_branches > 0) {
            new_work->merkle_branches = malloc(HASH_SIZE * new_work->n_merkle_branches);
            if (new_work->merkle_branches == NULL) {
                STRATUM_V1_free_mining_notify(new_work);
                stratum_message_set_out_of_memory(message);
                goto done;
            }
        }
        for (size_t i = 0; i < new_work->n_merkle_branches; i++) {
            hex2bin(cJSON_GetArrayItem(merkle_branch, i)->valuestring, new_work->merkle_branches + HASH_SIZE * i, HASH_SIZE);
        }

        new_work->version = strtoul(cJSON_GetArrayItem(params, 5)->valuestring, NULL, 16);
        new_work->target = strtoul(cJSON_GetArrayItem(params, 6)->valuestring, NULL, 16);
        new_work->ntime = strtoul(cJSON_GetArrayItem(params, 7)->valuestring, NULL, 16);

        message->mining_notification = new_work;

        int paramsLength = cJSON_GetArraySize(params);
        int value = cJSON_IsTrue(cJSON_GetArrayItem(params, paramsLength - 1));
        message->should_abandon_work = value;
        
    } else if (message->method == MINING_SET_DIFFICULTY) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        uint32_t difficulty = cJSON_GetArrayItem(params, 0)->valueint;
        message->new_difficulty = difficulty;
    } else if (message->method == MINING_SET_VERSION_MASK) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        uint32_t version_mask = strtoul(cJSON_GetArrayItem(params, 0)->valuestring, NULL, 16);
        message->version_mask = version_mask;
    }
    
    done:
    cJSON_Delete(json);
}

// 释放替换为了二进制的指针
void STRATUM_V1_free_mining_notify(mining_notify * params)
{
    if (params == NULL) {
        return;
    }
    free(params->job_id);
    free(params->coinbase_1_bin);
    free(params->coinbase_2_bin);
    free(params->merkle_branches);
    free(params);
}

int STRATUM_V1_subscribe(int socket, int send_uid, char * model)
{
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const char *version = app_desc->version;

    return stratum_writef(socket,
                          "{\"id\": %d, \"method\": \"mining.subscribe\", \"params\": [\"bitaxe/%s/%s\"]}\n",
                          send_uid, model, version);
}

int STRATUM_V1_suggest_difficulty(int socket, int send_uid, uint32_t difficulty)
{
    return stratum_writef(socket,
                          "{\"id\": %d, \"method\": \"mining.suggest_difficulty\", \"params\": [%lu]}\n",
                          send_uid, (unsigned long)difficulty);
}

int STRATUM_V1_authorize(int socket, int send_uid, const char * username, const char * pass)
{
    return stratum_writef(socket,
                          "{\"id\": %d, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}\n",
                          send_uid, username, pass);
}

int STRATUM_V1_submit_share(int socket, int send_uid, const char * username, const char * jobid,
                            const char * extranonce_2, const uint32_t ntime,
                            const uint32_t nonce, const uint32_t version)
{
    return stratum_writef(socket,
                          "{\"id\": %d, \"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%08lx\", \"%08lx\", \"%08lx\"]}\n",
                          send_uid, username, jobid, extranonce_2,
                          (unsigned long)ntime, (unsigned long)nonce, (unsigned long)version);
}

int STRATUM_V1_configure_version_rolling(int socket, int send_uid, uint32_t * version_mask)
{
    uint32_t requested_mask = STRATUM_DEFAULT_VERSION_MASK;

    if (version_mask != NULL) {
        requested_mask = *version_mask & STRATUM_DEFAULT_VERSION_MASK;
    }

    return stratum_writef(socket,
                          "{\"id\": %d, \"method\": \"mining.configure\", \"params\": [[\"version-rolling\"], {\"version-rolling.mask\": "
                          "\"%08lx\"}]}\n",
                          send_uid,
                          (unsigned long)requested_mask);
}

static void debug_stratum_tx(const char * msg)
{
    char * newline = strchr(msg, '\n');
    if (newline != NULL) *newline = '\0';
    ESP_LOGI(TAG, "tx: %s", msg);
    if (newline != NULL) *newline = '\n';
}

static void * stratum_buffer_alloc(size_t size)
{
    void *buffer = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (buffer == NULL) {
        buffer = malloc(size);
    }

    return buffer;
}

static bool stratum_tx_buffer_ensure_locked(size_t size)
{
    if (stratum_tx_buffer != NULL && stratum_tx_buffer_size >= size) {
        return true;
    }

    size_t new_size = size;
    if (new_size < STRATUM_TX_BUFFER_MIN_SIZE) {
        new_size = STRATUM_TX_BUFFER_MIN_SIZE;
    }
    if ((new_size % BUFFER_SIZE) != 0) {
        new_size += BUFFER_SIZE - (new_size % BUFFER_SIZE);
    }

    void *new_buffer = stratum_buffer_alloc(new_size);
    if (new_buffer == NULL) {
        return false;
    }

    free(stratum_tx_buffer);
    stratum_tx_buffer = new_buffer;
    stratum_tx_buffer_size = new_size;
    return true;
}

static int stratum_write_all_locked(int socket, const char *buffer, size_t length)
{
    size_t written_total = 0;

    while (written_total < length) {
        int written = write(socket, buffer + written_total, length - written_total);

        if (written > 0) {
            written_total += (size_t)written;
            continue;
        }

        if (written < 0 && errno == EINTR) {
            continue;
        }

        if (written == 0) {
            errno = ECONNRESET;
        }
        return -1;
    }

    return (int)written_total;
}

static int stratum_writef(int socket, const char *format, ...)
{
    int message_len;
    int ret;

    pthread_mutex_lock(&stratum_tx_lock);

    if (!stratum_tx_buffer_ensure_locked(STRATUM_TX_BUFFER_MIN_SIZE)) {
        pthread_mutex_unlock(&stratum_tx_lock);
        errno = ENOMEM;
        return -1;
    }

    while (1) {
        va_list args;
        va_start(args, format);
        message_len = vsnprintf(stratum_tx_buffer, stratum_tx_buffer_size, format, args);
        va_end(args);

        if (message_len < 0) {
            pthread_mutex_unlock(&stratum_tx_lock);
            errno = EINVAL;
            return -1;
        }

        if ((size_t)message_len < stratum_tx_buffer_size) {
            break;
        }

        if (!stratum_tx_buffer_ensure_locked((size_t)message_len + 1)) {
            pthread_mutex_unlock(&stratum_tx_lock);
            errno = ENOMEM;
            return -1;
        }
    }

    debug_stratum_tx(stratum_tx_buffer);
    ret = stratum_write_all_locked(socket, stratum_tx_buffer, (size_t)message_len);

    pthread_mutex_unlock(&stratum_tx_lock);
    return ret;
}

static void stratum_message_prepare(StratumApiV1Message *message)
{
    free(message->error_str);
    message->error_str = NULL;
    message->extranonce_str = NULL;
    message->extranonce_bin = NULL;
    message->extranonce_bin_len = 0;
    message->extranonce_2_len = 0;
    message->message_id = -1;
    message->method = STRATUM_UNKNOWN;
    message->should_abandon_work = 0;
    message->mining_notification = NULL;
    message->new_difficulty = 0;
    message->version_mask = 0;
    message->response_success = false;
}

static void stratum_message_set_error(StratumApiV1Message *message, const char *error_str)
{
    free(message->error_str);
    message->error_str = NULL;

    if (error_str != NULL) {
        message->error_str = strdup(error_str);
    }
}

static void stratum_message_set_out_of_memory(StratumApiV1Message *message)
{
    message->response_success = false;
    stratum_message_set_error(message, "out_of_memory");
}
