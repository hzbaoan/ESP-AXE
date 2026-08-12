#ifndef SYSTEM_H_
#define SYSTEM_H_

#include <stdbool.h>

#include "esp_err.h"
#include "global_state.h"

bool SYSTEM_init_hashrate_lock(GlobalState *GLOBAL_STATE);
void SYSTEM_init_system(GlobalState * GLOBAL_STATE);
esp_err_t SYSTEM_init_peripherals(GlobalState * GLOBAL_STATE);

void SYSTEM_notify_accepted_share(GlobalState * GLOBAL_STATE);
void SYSTEM_notify_rejected_share(GlobalState * GLOBAL_STATE, char * error_msg);
bool SYSTEM_is_potential_best_nonce(GlobalState * GLOBAL_STATE, const uint8_t hash[32]);
void SYSTEM_notify_found_nonce(GlobalState *GLOBAL_STATE, bool found_block, double found_diff,
                               uint32_t validated_difficulty, uint32_t work_epoch);
void SYSTEM_notify_mining_started(GlobalState * GLOBAL_STATE);
void SYSTEM_notify_new_ntime(GlobalState * GLOBAL_STATE, uint32_t ntime);
void SYSTEM_start_trusted_time_sync(GlobalState *GLOBAL_STATE);
bool SYSTEM_has_trusted_time(GlobalState *GLOBAL_STATE);
void SYSTEM_reset_hashrate_estimate(GlobalState * GLOBAL_STATE);
void SYSTEM_update_hashrate_estimate(GlobalState * GLOBAL_STATE);
double SYSTEM_get_current_hashrate(GlobalState *GLOBAL_STATE);

#endif /* SYSTEM_H_ */
