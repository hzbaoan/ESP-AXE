#ifndef GLOBAL_STATE_H_
#define GLOBAL_STATE_H_

#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "asic_task.h"
#include "bm1370.h"
#include "bm1368.h"
#include "bm1366.h"
#include "common.h"
#include "power_management_task.h"
#include "serial.h"
#include "stratum_api.h"
#include "work_queue.h"

#define STRATUM_USER CONFIG_STRATUM_USER
#define FALLBACK_STRATUM_USER CONFIG_FALLBACK_STRATUM_USER

#define STRATUM_PROTOCOL_V1 1
#define STRATUM_PROTOCOL_V2 2

#define HISTORY_LENGTH 100
#define DIFF_STRING_SIZE 10

typedef enum
{
    DEVICE_UNKNOWN = -1,
    DEVICE_ULTRA,
    DEVICE_SUPRA,
    DEVICE_GAMMA,
    DEVICE_GAMMATURBO,
    DEVICE_HEX,
    DEVICE_SUPRAHEX
} DeviceModel;

typedef enum
{
    ASIC_UNKNOWN = -1,
    ASIC_BM1366,
    ASIC_BM1368,
    ASIC_BM1370,
} AsicModel;

typedef struct {
    char message[64];
    uint32_t count;
} RejectedReasonStat;

typedef struct
{
    double duration_start;
    int historical_hashrate_rolling_index;
    double historical_hashrate_time_stamps[HISTORY_LENGTH];
    double historical_hashrate[HISTORY_LENGTH];
    int historical_hashrate_init;
    double current_hashrate;
    int64_t start_time;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    RejectedReasonStat rejected_reason_stats[10];
    int rejected_reason_stats_count;
    int screen_page;
    uint64_t best_nonce_diff;
    uint8_t best_target[32];
    bool best_target_valid;
    char best_diff_string[DIFF_STRING_SIZE];
    uint64_t best_session_nonce_diff;
    uint8_t best_session_target[32];
    bool best_session_target_valid;
    char best_session_diff_string[DIFF_STRING_SIZE];
    bool FOUND_BLOCK;
    char ssid[32];
    char wifi_status[20];
    char ip_addr_str[16]; // IP4ADDR_STRLEN_MAX
    char ap_ssid[32];
    bool ap_enabled;
    char * pool_url;
    char * fallback_pool_url;
    uint16_t pool_port;
    uint16_t fallback_pool_port;
    char * pool_user;
    char * fallback_pool_user;
    char * pool_pass;
    char * fallback_pool_pass;
    uint16_t pool_protocol;
    uint16_t fallback_pool_protocol;
    char * sv2_host;
    uint16_t sv2_port;
    char * sv2_authority_public_key;
    char * fallback_sv2_host;
    uint16_t fallback_sv2_port;
    char * fallback_sv2_authority_public_key;
    bool socks5_proxy_enabled;
    char * socks5_proxy_host;
    uint16_t socks5_proxy_port;
    char * socks5_proxy_user;
    char * socks5_proxy_pass;
    bool is_using_fallback;
    uint16_t overheat_mode;
    uint16_t power_fault;
    uint32_t lastClockSync;
    bool trusted_time_available;
    bool is_screen_active;
    bool is_firmware_update;
    char firmware_update_filename[20];
    char firmware_update_status[20];
    char * asic_status;
} SystemModule;

typedef struct
{
    bool active;
    char *message;
    bool result;
    bool finished;
} SelfTestModule;

typedef struct
{
    DeviceModel device_model;
    char * device_model_str;
    int board_version;
    AsicModel asic_model;
    char * asic_model_str;
    double asic_job_frequency_ms;
    uint32_t ASIC_difficulty;

    work_queue stratum_queue;
    work_queue ASIC_jobs_queue;

    SystemModule SYSTEM_MODULE;
    AsicTaskModule ASIC_TASK_MODULE;
    PowerManagementModule POWER_MANAGEMENT_MODULE;
    SelfTestModule SELF_TEST_MODULE;

    char * extranonce_str;
    uint8_t * extranonce_bin;
    size_t extranonce_bin_len;
    int extranonce_2_len;
    uint32_t extranonce_generation;
    
    int abandon_work;
    pthread_mutex_t stratum_state_lock;
    pthread_mutex_t stratum_socket_lock;

    uint8_t valid_jobs[ASIC_ACTIVE_JOB_SLOTS];
    pthread_mutex_t valid_jobs_lock;

    uint32_t stratum_difficulty;
    bool new_set_mining_difficulty_msg;
    uint32_t version_mask;
    uint32_t pending_version_mask;
    bool new_stratum_version_rolling_msg;

    int sock;
    QueueHandle_t stratum_submit_queue;

    int send_uid;

    bool ASIC_initalized;
    bool psram_is_available;
    bool job_queue_initalized;

    bool is_multichip;
    uint8_t detected_asic_count;
    uint32_t chip_submit[6];
    char chip_submit_srt[128];
} GlobalState;

#endif /* GLOBAL_STATE_H_ */
