#ifndef STRATUM_API_H
#define STRATUM_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#define MAX_MERKLE_BRANCHES 32
#define HASH_SIZE 32
#define COINBASE_SIZE 100
#define COINBASE2_SIZE 128

typedef enum
{
    STRATUM_UNKNOWN,
    MINING_NOTIFY,
    MINING_SET_DIFFICULTY,
    MINING_SET_VERSION_MASK,
    STRATUM_RESULT,
    STRATUM_RESULT_SETUP,
    STRATUM_RESULT_VERSION_MASK,
    STRATUM_RESULT_SUBSCRIBE,
    CLIENT_RECONNECT
} stratum_method;

static const int STRATUM_ID_CONFIGURE = 1;
static const int STRATUM_ID_SUBSCRIBE = 2;

typedef struct
{
    char *job_id;
    uint8_t prev_block_hash_bin[32];
    uint8_t prev_block_hash[32];
    uint8_t prev_block_hash_be[32];
    uint8_t *coinbase_1_bin;
    size_t coinbase_1_len;
    uint8_t *coinbase_2_bin;
    size_t coinbase_2_len;
    uint8_t *merkle_branches;
    size_t n_merkle_branches;
    uint32_t version;
    uint32_t target;
    uint32_t ntime;
} mining_notify;

typedef struct
{
    char *extranonce_str;
    uint8_t *extranonce_bin;
    size_t extranonce_bin_len;
    int extranonce_2_len;

    int64_t message_id;
    stratum_method method;

    int should_abandon_work;
    mining_notify *mining_notification;
    uint32_t new_difficulty;
    uint32_t version_mask;
    bool response_success;
    char *error_str;
} StratumApiV1Message;

void STRATUM_V1_initialize_buffer(void);

char *STRATUM_V1_receive_jsonrpc_line(int sockfd);

int STRATUM_V1_subscribe(int socket, int send_uid, char *model);

void STRATUM_V1_parse(StratumApiV1Message *message, const char *stratum_json);

void STRATUM_V1_free_mining_notify(mining_notify *params);

int STRATUM_V1_authorize(int socket, int send_uid, const char *username, const char *pass);

int STRATUM_V1_configure_version_rolling(int socket, int send_uid, uint32_t *version_mask);

int STRATUM_V1_suggest_difficulty(int socket, int send_uid, uint32_t difficulty);

int STRATUM_V1_submit_share(int socket, int send_uid, const char *username, const char *jobid,
                            const char *extranonce_2, uint32_t ntime, uint32_t nonce,
                            uint32_t version);

#endif // STRATUM_API_H
