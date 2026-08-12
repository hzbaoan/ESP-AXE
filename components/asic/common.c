#include <string.h>
#include <stdbool.h>
#include <float.h>
#include <math.h>

#include "common.h"
#include "serial.h"
#include "esp_log.h"
#include "crc.h"

#define PREAMBLE 0xAA55
#define PREAMBLE_FIRST_BYTE 0xAA
#define PREAMBLE_SECOND_BYTE 0x55
#define RECEIVE_WORK_TIMEOUT_MS 10000
#define RECEIVE_WORK_RESYNC_MAX_BYTES 256
#define ASIC_NONCE_SPACE 4294967296.0
#define ASIC_REFERENCE_FREQUENCY_MHZ 25.0

static const char * TAG = "common";

unsigned char _reverse_bits(unsigned char num)
{
    unsigned char reversed = 0;
    int i;

    for (i = 0; i < 8; i++) {
        reversed <<= 1;      // Left shift the reversed variable by 1
        reversed |= num & 1; // Use bitwise OR to set the rightmost bit of reversed to the current bit of num
        num >>= 1;           // Right shift num by 1 to get the next bit
    }

    return reversed;
}

uint32_t _largest_power_of_two_u32(uint32_t num)
{
    uint32_t power = 1;

    if (num <= 1U) {
        return 1U;
    }

    while (num > 1U) {
        num >>= 1U;
        power <<= 1U;
    }

    return power;
}

uint32_t _next_power_of_two_u32(uint32_t num)
{
    uint32_t power = 1U;

    if (num <= 1U) {
        return 1U;
    }

    while (power < num && power <= (UINT32_MAX >> 1U)) {
        power <<= 1U;
    }

    return power;
}

bool calculate_hcn(float frequency_mhz, uint16_t core_count, uint16_t asic_count,
                   uint16_t hcn_correction, double nonce_scale, uint32_t *hcn_out)
{
    uint32_t rounded_cores;
    uint16_t asic_partitions;
    double hcn_max;
    double hcn_value;

    if (hcn_out == NULL || frequency_mhz <= 0.0f || core_count == 0 || asic_count == 0 ||
            nonce_scale <= 0.0 || nonce_scale > ASIC_HCN_MAX_SEARCH_SCALE) {
        return false;
    }

    rounded_cores = _next_power_of_two_u32(core_count);
    asic_partitions = asic_count;
    hcn_max = (ASIC_NONCE_SPACE / (double)rounded_cores / (double)asic_partitions) *
              ASIC_REFERENCE_FREQUENCY_MHZ / (double)frequency_mhz * 0.5;
    if (hcn_max <= (double)hcn_correction) {
        return false;
    }

    hcn_value = nonce_scale * (hcn_max - (double)hcn_correction);
    if (hcn_value < 1.0 || hcn_value > (double)UINT32_MAX) {
        return false;
    }

    *hcn_out = (uint32_t)hcn_value;
    return true;
}

bool calculate_pll_parameters(float target_frequency, uint16_t fb_divider_min,
                              uint16_t fb_divider_max, uint8_t *fb_divider,
                              uint8_t *ref_divider, uint8_t *post_divider1,
                              uint8_t *post_divider2, float *actual_frequency)
{
    const float epsilon = 0.0001f;
    float best_difference = FLT_MAX;
    float best_vco_frequency = FLT_MAX;
    uint16_t best_post_divider = UINT16_MAX;
    bool found = false;

    if (target_frequency <= 0.0f || fb_divider_min > fb_divider_max ||
            fb_divider == NULL || ref_divider == NULL ||
            post_divider1 == NULL || post_divider2 == NULL ||
            actual_frequency == NULL) {
        return false;
    }

    for (uint8_t ref = 2; ref > 0; ref--) {
        for (uint8_t post1 = 7; post1 > 0; post1--) {
            for (uint8_t post2 = 7; post2 > 0; post2--) {
                uint16_t divider = (uint16_t)ref * post1 * post2;
                uint16_t feedback = (uint16_t)lroundf(
                    target_frequency / ASIC_REFERENCE_FREQUENCY_MHZ * divider);

                if (post1 <= post2 || feedback < fb_divider_min ||
                        feedback > fb_divider_max) {
                    continue;
                }

                float frequency = ASIC_REFERENCE_FREQUENCY_MHZ * feedback / divider;
                float difference = fabsf(target_frequency - frequency);
                float vco_frequency = ASIC_REFERENCE_FREQUENCY_MHZ * feedback / ref;
                uint16_t post_product = (uint16_t)post1 * post2;

                if (difference < best_difference ||
                        (fabsf(difference - best_difference) < epsilon &&
                         vco_frequency < best_vco_frequency) ||
                        (fabsf(difference - best_difference) < epsilon &&
                         fabsf(vco_frequency - best_vco_frequency) < epsilon &&
                         post_product < best_post_divider)) {
                    *fb_divider = (uint8_t)feedback;
                    *ref_divider = ref;
                    *post_divider1 = post1;
                    *post_divider2 = post2;
                    *actual_frequency = frequency;
                    best_difference = difference;
                    best_vco_frequency = vco_frequency;
                    best_post_divider = post_product;
                    found = true;
                }
            }
        }
    }

    return found;
}

double calculate_bm_full_space_ms(float frequency_mhz, uint16_t asic_count,
                                  uint16_t small_core_count, uint16_t core_count,
                                  uint32_t version_count)
{
    uint32_t rounded_cores;
    uint32_t rounded_small_cores;
    uint16_t asic_partitions;
    double parallel_midstates;
    double serial_version_batches;
    double serial_nonces;

    if (frequency_mhz <= 0.0f || asic_count == 0 || small_core_count == 0 ||
            core_count == 0 || version_count == 0) {
        return 0.0;
    }

    rounded_cores = _next_power_of_two_u32(core_count);
    rounded_small_cores = _next_power_of_two_u32(small_core_count);
    asic_partitions = asic_count;
    if (rounded_small_cores < rounded_cores) {
        return 0.0;
    }

    parallel_midstates = (double)rounded_small_cores / (double)rounded_cores;
    // Small cores evaluate different rolled versions in parallel. When the
    // negotiated version count does not fill every parallel slot, the ASIC
    // still needs one complete HCN pass to cover the 32-bit nonce space.
    // Counts above the parallel capacity are powers of two in normal use, but
    // ceil() also keeps this correct for sparse/non-standard masks.
    serial_version_batches = ceil((double)version_count / parallel_midstates);
    serial_nonces = ASIC_NONCE_SPACE / (double)rounded_cores / (double)asic_partitions;

    return serial_version_batches * serial_nonces / ((double)frequency_mhz * 1000.0);
}

static int receive_exact(uint8_t *buffer, int buffer_size, uint16_t timeout_ms)
{
    int total_received = 0;

    while (total_received < buffer_size) {
        int received = SERIAL_rx(buffer + total_received, buffer_size - total_received, timeout_ms);
        if (received < 0) {
            return -1;
        }
        if (received == 0) {
            break;
        }
        total_received += received;
    }

    return total_received;
}

static int receive_preamble_frame(uint8_t *buffer, int buffer_size,
                                  uint16_t timeout_ms, int max_scan_bytes)
{
    uint8_t previous = 0;

    if (buffer == NULL || buffer_size < 2 || max_scan_bytes < 2) {
        return -1;
    }

    for (int scanned = 0; scanned < max_scan_bytes; scanned++) {
        uint8_t byte = 0;
        int received = SERIAL_rx(&byte, 1, timeout_ms);

        if (received < 0) {
            return -1;
        }
        if (received == 0) {
            return 0;
        }
        if (previous == PREAMBLE_FIRST_BYTE && byte == PREAMBLE_SECOND_BYTE) {
            buffer[0] = previous;
            buffer[1] = byte;

            received = receive_exact(buffer + 2, buffer_size - 2, timeout_ms);
            if (received < 0) {
                return -1;
            }
            return received + 2;
        }
        previous = byte;
    }

    return 0;
}

int count_asic_chips(uint16_t asic_count, uint16_t chip_id, int chip_id_response_length)
{
    uint8_t buffer[11] = {0};

    if (chip_id_response_length < 4 ||
            chip_id_response_length > (int)sizeof(buffer)) {
        ESP_LOGE(TAG, "Unsupported CHIP_ID response length: %d", chip_id_response_length);
        return 0;
    }

    int chip_counter = 0;
    while (true) {
        int received = receive_preamble_frame(buffer,
                                              chip_id_response_length,
                                              1000,
                                              RECEIVE_WORK_RESYNC_MAX_BYTES);
        if (received == 0) break;

        if (received == -1) {
            ESP_LOGE(TAG, "Error reading CHIP_ID");
            break;
        }

        if (received != chip_id_response_length) {
            ESP_LOGE(TAG, "Invalid CHIP_ID response length: expected %d, got %d", chip_id_response_length, received);
            ESP_LOG_BUFFER_HEX(TAG, buffer, received);
            break;
        }

        uint16_t received_preamble = (buffer[0] << 8) | buffer[1];
        if (received_preamble != PREAMBLE) {
            ESP_LOGW(TAG, "Preamble mismatch: expected 0x%04x, got 0x%04x", PREAMBLE, received_preamble);
            ESP_LOG_BUFFER_HEX(TAG, buffer, received);
            continue;
        }

        uint16_t received_chip_id = (buffer[2] << 8) | buffer[3];
        if (received_chip_id != chip_id) {
            ESP_LOGW(TAG, "CHIP_ID response mismatch: expected 0x%04x, got 0x%04x", chip_id, received_chip_id);
            ESP_LOG_BUFFER_HEX(TAG, buffer, received);
            continue;
        }

        if (crc5(buffer + 2, received - 2) != 0) {
            ESP_LOGW(TAG, "Checksum failed on CHIP_ID response");
            ESP_LOG_BUFFER_HEX(TAG, buffer, received);
            continue;
        }

        ESP_LOGI(TAG, "Chip %d detected: CORE_NUM: 0x%02x ADDR: 0x%02x", chip_counter, buffer[4], buffer[5]);

        chip_counter++;
    }    
    
    if (chip_counter != asic_count) {
        ESP_LOGW(TAG, "%i chip(s) detected on the chain, expected %i", chip_counter, asic_count);
    }

    return chip_counter;
}

esp_err_t receive_work(uint8_t * buffer, int buffer_size)
{
    bool preamble_found = false;

    if (buffer == NULL || buffer_size < 3) {
        return ESP_FAIL;
    }

    buffer[0] = 0;
    for (int scanned = 0; scanned < RECEIVE_WORK_RESYNC_MAX_BYTES; scanned++) {
        uint8_t byte = 0;
        int received = SERIAL_rx(&byte, 1, RECEIVE_WORK_TIMEOUT_MS);

        if (received < 0) {
            ESP_LOGE(TAG, "UART error in serial RX");
            return ESP_FAIL;
        }

        if (received == 0) {
            ESP_LOGD(TAG, "UART timeout in serial RX");
            return ESP_FAIL;
        }

        if (buffer[0] == PREAMBLE_FIRST_BYTE && byte == PREAMBLE_SECOND_BYTE) {
            buffer[1] = byte;
            preamble_found = true;
            break;
        }

        buffer[0] = byte == PREAMBLE_FIRST_BYTE ? byte : 0;
    }

    if (!preamble_found) {
        ESP_LOGE(TAG, "Failed to find response preamble");
        return ESP_FAIL;
    }

    int received = receive_exact(buffer + 2, buffer_size - 2, RECEIVE_WORK_TIMEOUT_MS);
    if (received < 0) {
        ESP_LOGE(TAG, "UART error in serial RX");
        return ESP_FAIL;
    }

    if (received != buffer_size - 2) {
        ESP_LOGE(TAG, "Invalid response length %i", received + 2);
        ESP_LOG_BUFFER_HEX(TAG, buffer, received + 2);
        return ESP_FAIL;
    }

    uint16_t received_preamble = (uint16_t)((buffer[0] << 8) | buffer[1]);
    if (received_preamble != PREAMBLE) {
        ESP_LOGE(TAG, "Preamble mismatch: got 0x%04x, expected 0x%04x", received_preamble, PREAMBLE);
        ESP_LOG_BUFFER_HEX(TAG, buffer, buffer_size);
        return ESP_FAIL;
    }

    if (crc5(buffer + 2, buffer_size - 2) != 0) {
        ESP_LOGE(TAG, "Checksum failed on response");        
        ESP_LOG_BUFFER_HEX(TAG, buffer, buffer_size);
        return ESP_FAIL;
    }

    return ESP_OK;
}
