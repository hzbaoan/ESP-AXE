#ifndef ASIC_H
#define ASIC_H

#include <esp_err.h>
#include "global_state.h"
#include "common.h"

#define BITAXE_ULTRA_ASIC_COUNT 1
#define BITAXE_SUPRA_ASIC_COUNT 1
#define BITAXE_GAMMA_ASIC_COUNT 1
#define BITAXE_GAMMATURBO_ASIC_COUNT 2
#define BITAXE_HEX_ASIC_COUNT 6
#define BITAXE_SUPRAHEX_ASIC_COUNT 6
#define ASIC_EXTRANONCE2_COUNTER_MAX_BYTES 16

typedef enum
{
    ASIC_VERSION_MODE_NONE = 0,
    ASIC_VERSION_MODE_INTERNAL_BITS,
    ASIC_VERSION_MODE_SOFTWARE_MIDSTATES,
} asic_version_mode_t;

typedef struct
{
    asic_version_mode_t version_mode;
    uint8_t active_job_slots;
    uint8_t job_midstate_capacity;
    uint16_t nonce_partition_count;
    bool host_expands_nonce;
    bool host_expands_version;
    bool host_expands_extranonce2;
} asic_header_schedule_policy_t;

typedef struct
{
    uint8_t bytes[ASIC_EXTRANONCE2_COUNTER_MAX_BYTES];
} asic_extranonce2_counter_t;

typedef struct
{
    asic_extranonce2_counter_t extranonce2_counter;
    uint32_t version_window_index;
    uint16_t nonce_partition_index;
} asic_header_cursor_t;

typedef struct
{
    asic_extranonce2_counter_t extranonce2_counter;
    uint32_t version_window_index;
    uint16_t nonce_partition_index;
    uint32_t starting_nonce;
} asic_header_schedule_snapshot_t;

uint8_t ASIC_init(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE);
uint16_t ASIC_get_small_core_count(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_active_job_slot_count(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_nonce_partition_count(GlobalState * GLOBAL_STATE);
asic_version_mode_t ASIC_get_version_mode(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_job_starting_nonce(GlobalState * GLOBAL_STATE, uint32_t dispatch_index);
asic_header_schedule_policy_t ASIC_get_header_schedule_policy(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_header_schedule_version_window_count(const asic_header_schedule_policy_t *policy,
                                                       uint32_t version_mask);
void ASIC_normalize_header_cursor(asic_header_cursor_t *cursor,
                                  const asic_header_schedule_policy_t *policy,
                                  uint32_t version_window_count);
asic_header_schedule_snapshot_t ASIC_snapshot_header_cursor(const asic_header_cursor_t *cursor,
                                                           const asic_header_schedule_policy_t *policy,
                                                           uint32_t version_window_count);
void ASIC_advance_header_cursor(asic_header_cursor_t *cursor,
                                const asic_header_schedule_policy_t *policy,
                                uint32_t version_window_count,
                                bool strict_header_coverage);
task_result * ASIC_process_work(GlobalState * GLOBAL_STATE);
int ASIC_set_max_baud(GlobalState * GLOBAL_STATE);
void ASIC_set_job_difficulty_mask(GlobalState * GLOBAL_STATE, uint8_t mask);
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job);
void ASIC_set_version_mask(GlobalState * GLOBAL_STATE, uint32_t mask);
void ASIC_sync_version_mask_state(GlobalState * GLOBAL_STATE, uint32_t mask);
uint8_t ASIC_get_job_midstate_capacity(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_supported_version_mask(GlobalState * GLOBAL_STATE);
bool ASIC_copy_active_job(GlobalState * GLOBAL_STATE, uint8_t job_id, bm_job *job_snapshot);
void ASIC_set_dispatch_interval(GlobalState * GLOBAL_STATE, uint32_t interval_us);
bool ASIC_set_frequency(GlobalState * GLOBAL_STATE, float target_frequency);
void ASIC_refresh_job_interval(GlobalState * GLOBAL_STATE);
esp_err_t ASIC_set_device_model(GlobalState * GLOBAL_STATE);

#endif // ASIC_H
