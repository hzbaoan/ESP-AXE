#include <string.h>
#include <stdbool.h>

#include "common.h"
#include "serial.h"
#include "esp_log.h"
#include "crc.h"

#define PREAMBLE 0xAA55

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

static bool recent_result_entry_matches(const recent_result_entry *entry, uint8_t raw_job_id, uint32_t nonce, uint16_t version, uint8_t midstate_num)
{
    return entry->valid &&
           entry->raw_job_id == raw_job_id &&
           entry->nonce == nonce &&
           entry->version == version &&
           entry->midstate_num == midstate_num;
}

void recent_result_cache_clear(recent_result_cache *cache)
{
    if (cache == NULL) {
        return;
    }

    memset(cache, 0, sizeof(*cache));
}

bool recent_result_cache_add(recent_result_cache *cache, uint8_t raw_job_id, uint32_t nonce, uint16_t version, uint8_t midstate_num)
{
    if (cache == NULL) {
        return true;
    }

    for (int i = 0; i < ASIC_RECENT_RESULT_CACHE_SIZE; i++) {
        if (recent_result_entry_matches(&cache->entries[i], raw_job_id, nonce, version, midstate_num)) {
            return false;
        }
    }

    cache->entries[cache->next_index].valid = true;
    cache->entries[cache->next_index].raw_job_id = raw_job_id;
    cache->entries[cache->next_index].nonce = nonce;
    cache->entries[cache->next_index].version = version;
    cache->entries[cache->next_index].midstate_num = midstate_num;
    cache->next_index = (cache->next_index + 1) % ASIC_RECENT_RESULT_CACHE_SIZE;

    return true;
}

int count_asic_chips(uint16_t asic_count, uint16_t chip_id, int chip_id_response_length)
{
    uint8_t buffer[11] = {0};

    int chip_counter = 0;
    while (true) {
        int received = SERIAL_rx(buffer, chip_id_response_length, 1000);
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
    int received = SERIAL_rx(buffer, buffer_size, 10000);

    if (received < 0) {
        ESP_LOGE(TAG, "UART error in serial RX");
        return ESP_FAIL;
    }

    if (received == 0) {
        ESP_LOGD(TAG, "UART timeout in serial RX");
        return ESP_FAIL;
    }

    if (received != buffer_size) {
        ESP_LOGE(TAG, "Invalid response length %i", received);
        ESP_LOG_BUFFER_HEX(TAG, buffer, received);
        SERIAL_clear_buffer();
        return ESP_FAIL;
    }

    uint16_t received_preamble = (buffer[0] << 8) | buffer[1];
    if (received_preamble != PREAMBLE) {
        ESP_LOGE(TAG, "Preamble mismatch: got 0x%04x, expected 0x%04x", received_preamble, PREAMBLE);
        ESP_LOG_BUFFER_HEX(TAG, buffer, received);
        SERIAL_clear_buffer();
        return ESP_FAIL;
    }

    if (crc5(buffer + 2, buffer_size - 2) != 0) {
        ESP_LOGE(TAG, "Checksum failed on response");        
        ESP_LOG_BUFFER_HEX(TAG, buffer, received);
        SERIAL_clear_buffer();
        return ESP_FAIL;
    }

    return ESP_OK;
}
