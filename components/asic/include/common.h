#ifndef COMMON_H_
#define COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "mining.h"

#define ASIC_RECENT_RESULT_CACHE_SIZE 32

typedef struct
{
    uint8_t job_id;
    uint32_t nonce;
    uint32_t rolled_version;
    bm_job active_job;
} task_result;

typedef struct
{
    bool valid;
    uint8_t raw_job_id;
    uint32_t nonce;
    uint16_t version;
    uint8_t midstate_num;
} recent_result_entry;

typedef struct
{
    recent_result_entry entries[ASIC_RECENT_RESULT_CACHE_SIZE];
    uint8_t next_index;
} recent_result_cache;

unsigned char _reverse_bits(unsigned char num);
int _largest_power_of_two(int num);

int count_asic_chips(uint16_t asic_count, uint16_t chip_id, int chip_id_response_length);
esp_err_t receive_work(uint8_t * buffer, int buffer_size);
void recent_result_cache_clear(recent_result_cache *cache);
bool recent_result_cache_add(recent_result_cache *cache, uint8_t raw_job_id, uint32_t nonce, uint16_t version, uint8_t midstate_num);

#endif /* COMMON_H_ */
