#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <lwip/tcpip.h>

#include "asic.h"
#include "esp_log.h"
#include "stratum_task.h"
#include "system.h"

static const char *TAG = "asic_result";
static recent_share_cache recent_shares;
static pthread_mutex_t recent_shares_lock = PTHREAD_MUTEX_INITIALIZER;

void ASIC_result_reset_recent_shares(void)
{
    pthread_mutex_lock(&recent_shares_lock);
    recent_share_cache_clear(&recent_shares);
    pthread_mutex_unlock(&recent_shares_lock);
}

void ASIC_result_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    while (1)
    {
        task_result *asic_result = ASIC_process_work(GLOBAL_STATE);
        if (asic_result == NULL) {
            continue;
        }

        bm_job active_job = asic_result->active_job;

        uint8_t hash_result[32];
        bool is_share;
        bool found_block;
        bool needs_diff;
        double nonce_diff = -1.0;

        calculate_nonce_hash(&active_job, asic_result->nonce, asic_result->rolled_version, hash_result);

        is_share = hash_meets_target(hash_result, active_job.pool_target);
        found_block = hash_meets_target(hash_result, active_job.network_target);
        needs_diff = is_share || SYSTEM_is_potential_best_nonce(GLOBAL_STATE, hash_result);
        if (needs_diff) {
            nonce_diff = hash_to_diff(hash_result);
            ESP_LOGI(TAG, "ID: %s, ver: %08" PRIX32 " Nonce %08" PRIX32 " diff %.1f of %.1f.",
                     active_job.jobid, asic_result->rolled_version, asic_result->nonce, nonce_diff, (double)active_job.pool_diff);
        }

        if (is_share)
        {
            uint32_t version_bits = submit_version_bits(asic_result->rolled_version, active_job.version_mask);
            bool should_submit;
            char *user = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ? GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_user : GLOBAL_STATE->SYSTEM_MODULE.pool_user;

            pthread_mutex_lock(&recent_shares_lock);
            should_submit = recent_share_cache_add(&recent_shares,
                                                   active_job.jobid,
                                                   active_job.extranonce2,
                                                   active_job.ntime,
                                                   asic_result->nonce,
                                                   version_bits);
            pthread_mutex_unlock(&recent_shares_lock);

            if (!should_submit) {
                ESP_LOGW(TAG, "Dropping duplicate share: id=%s nonce=%08" PRIX32 " ver=%08" PRIX32,
                         active_job.jobid, asic_result->nonce, version_bits);
            } else {
                int ret = stratum_submit_share(
                    GLOBAL_STATE,
                    user,
                    active_job.jobid,
                    active_job.extranonce2,
                    active_job.ntime,
                    asic_result->nonce,
                    version_bits);

                if (ret < 0) {
                    ESP_LOGI(TAG, "Unable to write share to socket. Closing connection. Ret: %d (errno %d: %s)", ret, errno, strerror(errno));
                    stratum_close_connection(GLOBAL_STATE);
                } else if (ret == STRATUM_SUBMIT_SKIPPED) {
                    ESP_LOGW(TAG, "Socket unavailable or abandoning work, dropping share to prevent crash...");
                }
            }
        }

        SYSTEM_notify_found_nonce(GLOBAL_STATE, found_block, nonce_diff);
    }
}
