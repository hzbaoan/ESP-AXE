#ifndef COMMON_H_
#define COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "mining.h"

// HCN may extend beyond the nominal partition only as a dispatch-jitter guard.
#define ASIC_HCN_MAX_SEARCH_SCALE 1.20

typedef struct
{
    uint8_t job_id;
    uint32_t nonce;
    uint32_t version_bits;
} task_result;

unsigned char _reverse_bits(unsigned char num);
uint32_t _largest_power_of_two_u32(uint32_t num);
uint32_t _next_power_of_two_u32(uint32_t num);
bool calculate_hcn(float frequency_mhz, uint16_t core_count, uint16_t asic_count,
                   uint16_t hcn_correction, double nonce_scale, uint32_t *hcn_out);
bool calculate_pll_parameters(float target_frequency, uint16_t fb_divider_min,
                              uint16_t fb_divider_max, uint8_t *fb_divider,
                              uint8_t *ref_divider, uint8_t *post_divider1,
                              uint8_t *post_divider2, float *actual_frequency);
double calculate_bm_full_space_ms(float frequency_mhz, uint16_t asic_count,
                                  uint16_t small_core_count, uint16_t core_count,
                                  uint32_t version_count);

int count_asic_chips(uint16_t asic_count, uint16_t chip_id, int chip_id_response_length);
esp_err_t receive_work(uint8_t * buffer, int buffer_size);
#endif /* COMMON_H_ */
