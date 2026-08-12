#ifndef ASIC_H
#define ASIC_H

#include <esp_err.h>
#include <stddef.h>
#include "extranonce.h"
#include "global_state.h"
#include "common.h"

#define BITAXE_ULTRA_ASIC_COUNT 1
#define BITAXE_SUPRA_ASIC_COUNT 1
#define BITAXE_GAMMA_ASIC_COUNT 1
#define BITAXE_GAMMATURBO_ASIC_COUNT 2
#define BITAXE_HEX_ASIC_COUNT 6
#define BITAXE_SUPRAHEX_ASIC_COUNT 6
typedef enum
{
    CMD_PACKET = 0,
    JOB_PACKET,
} packet_type_t;

typedef struct
{
    uint32_t target_interval_us;
    uint32_t current_interval_us;
    uint16_t queue_low_water_mark;
    uint16_t queue_high_water_mark;
} ASICDispatchConfig;

uint8_t ASIC_init(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_expected_asic_count(GlobalState *GLOBAL_STATE);
uint16_t ASIC_get_small_core_count(GlobalState * GLOBAL_STATE);
size_t ASIC_generate_extranonce2(uint8_t *dest, size_t extranonce2_len, uint32_t random_seed);
task_result * ASIC_process_work(GlobalState * GLOBAL_STATE);
int ASIC_set_max_baud(GlobalState * GLOBAL_STATE);
uint32_t ASIC_get_report_difficulty(uint32_t pool_difficulty);
bool ASIC_set_job_difficulty_mask(GlobalState * GLOBAL_STATE, uint32_t difficulty);
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job);
bool ASIC_set_version_mask(GlobalState * GLOBAL_STATE, uint32_t mask);
uint32_t ASIC_get_supported_version_mask(GlobalState * GLOBAL_STATE);
uint8_t ASIC_get_minimum_pool_version_bits(GlobalState *GLOBAL_STATE);
void ASIC_update_job_pool_target(GlobalState *GLOBAL_STATE, const uint8_t pool_target[32],
                                 uint32_t pool_difficulty);
size_t ASIC_copy_job_candidates(GlobalState *GLOBAL_STATE, uint8_t job_id,
                                bm_job *job_snapshots, size_t snapshot_capacity,
                                uint32_t *history_revision);
void ASIC_clear_job_history(GlobalState *GLOBAL_STATE);
bool ASIC_begin_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *next_job, bm_job **replaced_job);
void ASIC_finish_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *sent_job, bm_job *replaced_job, bool send_ok);
bool ASIC_set_frequency(GlobalState * GLOBAL_STATE, float target_frequency);
double ASIC_get_hcn_search_multiplier(GlobalState *GLOBAL_STATE, uint32_t version_mask);
void ASIC_get_dispatch_config(const GlobalState *GLOBAL_STATE, ASICDispatchConfig *config);
void ASIC_refresh_job_interval(GlobalState * GLOBAL_STATE);
esp_err_t ASIC_set_device_model(GlobalState * GLOBAL_STATE);

#endif // ASIC_H
