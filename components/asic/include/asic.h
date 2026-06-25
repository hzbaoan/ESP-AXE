#ifndef ASIC_H
#define ASIC_H

#include <esp_err.h>
#include <stddef.h>
#include "global_state.h"
#include "common.h"

#define BITAXE_ULTRA_ASIC_COUNT 1
#define BITAXE_SUPRA_ASIC_COUNT 1
#define BITAXE_GAMMA_ASIC_COUNT 1
#define BITAXE_GAMMATURBO_ASIC_COUNT 2
#define BITAXE_HEX_ASIC_COUNT 6
#define BITAXE_SUPRAHEX_ASIC_COUNT 6
#define ASIC_MAX_CHIP_COUNT 6
#define ASIC_EXTRANONCE2_COUNTER_MAX_BYTES 16

typedef enum
{
    ASIC_VERSION_MODE_NONE = 0,
    ASIC_VERSION_MODE_INTERNAL_BITS,
} asic_version_mode_t;

typedef enum
{
    CMD_PACKET = 0,
    JOB_PACKET,
} packet_type_t;

typedef struct
{
    asic_version_mode_t version_mode;
    uint8_t active_job_slots;
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
} asic_header_cursor_t;

typedef struct
{
    asic_extranonce2_counter_t extranonce2_counter;
    uint32_t version_window_index;
} asic_header_schedule_snapshot_t;

uint8_t ASIC_init(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE);
uint16_t ASIC_get_small_core_count(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_active_job_slot_count(GlobalState * GLOBAL_STATE);
asic_version_mode_t ASIC_get_version_mode(GlobalState * GLOBAL_STATE);
asic_header_schedule_policy_t ASIC_get_header_schedule_policy(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_header_schedule_version_window_count(const asic_header_schedule_policy_t *policy,
                                                       uint32_t version_mask);
uint32_t ASIC_get_header_schedule_host_version_mask(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask);
uint32_t ASIC_get_header_schedule_asic_version_mask(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask);
uint32_t ASIC_get_header_schedule_host_version_bits(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask,
                                                    uint32_t version_window_index);
bool ASIC_extranonce2_counter_has_overflowed_len(const asic_extranonce2_counter_t *counter,
                                                 size_t extranonce2_len);
void ASIC_normalize_header_cursor(asic_header_cursor_t *cursor,
                                  const asic_header_schedule_policy_t *policy,
                                  uint32_t version_window_count);
asic_header_schedule_snapshot_t ASIC_snapshot_header_cursor(const asic_header_cursor_t *cursor,
                                                           const asic_header_schedule_policy_t *policy,
                                                           uint32_t version_window_count);
void ASIC_advance_header_cursor(asic_header_cursor_t *cursor,
                                const asic_header_schedule_policy_t *policy,
                                uint32_t version_window_count);
void ASIC_advance_header_cursor_by(asic_header_cursor_t *cursor,
                                   const asic_header_schedule_policy_t *policy,
                                   uint32_t version_window_count,
                                   uint8_t steps);
void ASIC_init_partitioned_header_cursors(asic_header_cursor_t *cursors,
                                          uint8_t cursor_count,
                                          const asic_header_schedule_policy_t *policy,
                                          uint32_t version_window_count);
task_result * ASIC_process_work(GlobalState * GLOBAL_STATE);
int ASIC_set_max_baud(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_report_difficulty(uint32_t pool_difficulty);
void ASIC_set_job_difficulty_mask(GlobalState * GLOBAL_STATE, uint32_t difficulty);
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job);
void ASIC_set_version_mask(GlobalState * GLOBAL_STATE, uint32_t mask);
void ASIC_sync_version_mask_state(GlobalState * GLOBAL_STATE, uint32_t mask);
uint32_t ASIC_get_supported_version_mask(GlobalState * GLOBAL_STATE);
bool ASIC_copy_active_job(GlobalState * GLOBAL_STATE, uint8_t job_id, bm_job *job_snapshot);
bool ASIC_begin_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *next_job, bm_job **replaced_job);
void ASIC_finish_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *sent_job, bm_job *replaced_job, bool send_ok);
void ASIC_set_dispatch_interval(GlobalState * GLOBAL_STATE, uint32_t interval_us);
bool ASIC_set_frequency(GlobalState * GLOBAL_STATE, float target_frequency);
void ASIC_refresh_job_interval(GlobalState * GLOBAL_STATE);
esp_err_t ASIC_set_device_model(GlobalState * GLOBAL_STATE);

#endif // ASIC_H
