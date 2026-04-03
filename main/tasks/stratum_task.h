#ifndef STRATUM_TASK_H_
#define STRATUM_TASK_H_

#include "global_state.h"

#define STRATUM_SUBMIT_SKIPPED 0

bool stratum_is_abandoning_work(GlobalState *GLOBAL_STATE);
int stratum_next_uid(GlobalState *GLOBAL_STATE);
int stratum_submit_share(GlobalState *GLOBAL_STATE, const char *username, const char *jobid,
                         const char *extranonce_2, uint32_t ntime,
                         uint32_t nonce, uint32_t version);
void stratum_set_abandon_work(GlobalState *GLOBAL_STATE, int abandon_work);
void stratum_task(void *pvParameters);
void stratum_close_connection(GlobalState * GLOBAL_STATE);

#endif
