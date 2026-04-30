#include <math.h>
#include <string.h>

#include "unity.h"

#include "asic.h"
#include "utils.h"

static void set_extranonce2_counter_u64(asic_extranonce2_counter_t *counter, uint64_t value)
{
    size_t i;

    memset(counter, 0, sizeof(*counter));
    for (i = 0; i < sizeof(counter->bytes); ++i) {
        counter->bytes[i] = (uint8_t)(value & 0xFFU);
        value >>= 8;
    }
}

static void assert_extranonce2_counter_u64(const asic_extranonce2_counter_t *counter, uint64_t expected)
{
    asic_extranonce2_counter_t expected_counter = {0};

    set_extranonce2_counter_u64(&expected_counter, expected);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_counter.bytes, counter->bytes, sizeof(counter->bytes));
}

static uint32_t expected_guarded_interval_us(double selected_hashrate_hps, uint8_t dispatch_span, uint8_t active_job_slots)
{
    double interval_ms = 1.0;

    if (selected_hashrate_hps > 0.0 && dispatch_span > 0 && active_job_slots > 0) {
        interval_ms = (4294967296.0 * 1000.0) / selected_hashrate_hps;
        interval_ms *= (double)dispatch_span;
        interval_ms /= (double)active_job_slots;
        if (interval_ms < 1.0) {
            interval_ms = 1.0;
        }
    }

    interval_ms *= 1.0 + ((double)CONFIG_ASIC_DISPATCH_SAFETY_MARGIN_PERCENT / 100.0);

    return (uint32_t)llround(interval_ms * 1000.0);
}

static void assert_internal_bits_sequence(DeviceModel device_model)
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    uint32_t version_window_count;

    global_state.device_model = device_model;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, 0x0000E000);

    TEST_ASSERT_EQUAL_UINT8(ASIC_VERSION_MODE_INTERNAL_BITS, policy.version_mode);
    TEST_ASSERT_EQUAL_UINT8(16, policy.active_job_slots);
    TEST_ASSERT_EQUAL_UINT8(1, policy.job_midstate_capacity);
    TEST_ASSERT_EQUAL_UINT16(1, policy.nonce_partition_count);
    TEST_ASSERT_FALSE(policy.host_expands_nonce);
    TEST_ASSERT_FALSE(policy.host_expands_version);
    TEST_ASSERT_TRUE(policy.host_expands_extranonce2);
    TEST_ASSERT_EQUAL_UINT32(1, version_window_count);

    for (uint64_t step_index = 0; step_index < 8; step_index++) {
        asic_header_schedule_snapshot_t snapshot =
            ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

        assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, step_index);
        TEST_ASSERT_EQUAL_UINT32(0, snapshot.version_window_index);
        TEST_ASSERT_EQUAL_UINT16(0, snapshot.nonce_partition_index);
        TEST_ASSERT_EQUAL_HEX32(0x00000000, snapshot.starting_nonce);

        ASIC_advance_header_cursor(&cursor, &policy, version_window_count, false);
    }
}

TEST_CASE("Supported ASIC models keep host nonce partitioning disabled", "[asic]")
{
    GlobalState global_state = {0};
    const DeviceModel internal_bits_models[] = {
        DEVICE_ULTRA,
        DEVICE_HEX,
        DEVICE_SUPRA,
        DEVICE_SUPRAHEX,
        DEVICE_GAMMA,
        DEVICE_GAMMATURBO,
    };
    size_t i;

    for (i = 0; i < (sizeof(internal_bits_models) / sizeof(internal_bits_models[0])); ++i) {
        memset(&global_state, 0, sizeof(global_state));
        global_state.device_model = internal_bits_models[i];

        TEST_ASSERT_EQUAL_UINT8(ASIC_VERSION_MODE_INTERNAL_BITS, ASIC_get_version_mode(&global_state));
        TEST_ASSERT_EQUAL_UINT8(16, ASIC_get_active_job_slot_count(&global_state));
        TEST_ASSERT_EQUAL_UINT8(1, ASIC_get_nonce_partition_count(&global_state));
        TEST_ASSERT_EQUAL_HEX32(0x00000000, ASIC_get_job_starting_nonce(&global_state, 0));
        TEST_ASSERT_EQUAL_HEX32(0x00000000, ASIC_get_job_starting_nonce(&global_state, 15));
    }
}

TEST_CASE("BM1366 BM1368 and BM1370 advance extranonce2 on every generated job", "[asic]")
{
    assert_internal_bits_sequence(DEVICE_ULTRA);
    assert_internal_bits_sequence(DEVICE_SUPRA);
    assert_internal_bits_sequence(DEVICE_GAMMA);
}

TEST_CASE("Version mask state sync normalizes the active ASIC mask only", "[asic]")
{
    GlobalState global_state = {0};

    global_state.device_model = DEVICE_ULTRA;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 500.0;
    global_state.version_mask = 0;
    global_state.pending_version_mask = 0xffffffffU;
    global_state.new_stratum_version_rolling_msg = true;

    ASIC_sync_version_mask_state(&global_state, 0xffffffffU);

    TEST_ASSERT_EQUAL_HEX32(STRATUM_DEFAULT_VERSION_MASK, global_state.version_mask);
    TEST_ASSERT_EQUAL_HEX32(0xffffffffU, global_state.pending_version_mask);
    TEST_ASSERT_TRUE(global_state.new_stratum_version_rolling_msg);
}

TEST_CASE("Pool difficulty maps to the highest safe ASIC report difficulty", "[asic]")
{
    TEST_ASSERT_EQUAL_UINT32(1, ASIC_get_report_difficulty(0));
    TEST_ASSERT_EQUAL_UINT32(1, ASIC_get_report_difficulty(1));
    TEST_ASSERT_EQUAL_UINT32(2, ASIC_get_report_difficulty(2));
    TEST_ASSERT_EQUAL_UINT32(8, ASIC_get_report_difficulty(15));
    TEST_ASSERT_EQUAL_UINT32(8192, ASIC_get_report_difficulty(10000));
    TEST_ASSERT_EQUAL_UINT32(65536, ASIC_get_report_difficulty(65536));
    TEST_ASSERT_EQUAL_UINT32(16777216, ASIC_get_report_difficulty(16777217));
}

TEST_CASE("Header cursor normalization clears unsupported host-expanded indices", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    asic_header_schedule_snapshot_t snapshot;
    uint32_t version_window_count;

    set_extranonce2_counter_u64(&cursor.extranonce2_counter, 7);
    cursor.version_window_index = 5;
    cursor.nonce_partition_index = 49;

    global_state.device_model = DEVICE_ULTRA;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, 0x0000E000);

    ASIC_normalize_header_cursor(&cursor, &policy, version_window_count);
    snapshot = ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

    assert_extranonce2_counter_u64(&cursor.extranonce2_counter, 7);
    TEST_ASSERT_EQUAL_UINT32(0, cursor.version_window_index);
    TEST_ASSERT_EQUAL_UINT16(0, cursor.nonce_partition_index);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 7);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.version_window_index);
    TEST_ASSERT_EQUAL_UINT16(0, snapshot.nonce_partition_index);
    TEST_ASSERT_EQUAL_HEX32(0x00000000, snapshot.starting_nonce);
}

TEST_CASE("Extranonce2 counter carries beyond 64 bits", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    asic_header_schedule_snapshot_t snapshot;
    asic_extranonce2_counter_t expected = {0};
    uint32_t version_window_count;

    global_state.device_model = DEVICE_ULTRA;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, 0);

    memset(cursor.extranonce2_counter.bytes, 0xFF, 8);
    cursor.extranonce2_counter.bytes[8] = 0x34;

    ASIC_advance_header_cursor(&cursor, &policy, version_window_count, false);
    snapshot = ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

    expected.bytes[8] = 0x35;
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.bytes,
                                  cursor.extranonce2_counter.bytes,
                                  ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.bytes,
                                  snapshot.extranonce2_counter.bytes,
                                  ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
}

TEST_CASE("Dispatch interval includes configured safety margin", "[asic]")
{
    GlobalState global_state = {0};
    uint32_t expected_interval_us;
    double nominal_hashrate_hps;

    global_state.device_model = DEVICE_ULTRA;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 100.0;

    ASIC_refresh_job_interval(&global_state);

    nominal_hashrate_hps = 100.0 * 1000000.0 * (double)BM1366_SMALL_CORE_COUNT;
    expected_interval_us = expected_guarded_interval_us(nominal_hashrate_hps, 1, 16);

    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_current_us);
}

TEST_CASE("Observed hashrate slows dispatch after enough samples", "[asic]")
{
    GlobalState global_state = {0};
    uint32_t expected_interval_us;
    double observed_hashrate_hps = 70.0 * 1000000000.0;

    global_state.device_model = DEVICE_ULTRA;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 100.0;
    global_state.SYSTEM_MODULE.current_hashrate = 70.0;
    global_state.SYSTEM_MODULE.historical_hashrate_init = CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES;

    ASIC_refresh_job_interval(&global_state);

    expected_interval_us = expected_guarded_interval_us(observed_hashrate_hps, 1, 16);

    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
}

TEST_CASE("Observed hashrate does not speed dispatch beyond nominal", "[asic]")
{
    GlobalState global_state = {0};
    uint32_t expected_interval_us;
    double nominal_hashrate_hps = 100.0 * 1000000.0 * (double)BM1366_SMALL_CORE_COUNT;

    global_state.device_model = DEVICE_ULTRA;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 100.0;
    global_state.SYSTEM_MODULE.current_hashrate = 120.0;
    global_state.SYSTEM_MODULE.historical_hashrate_init = CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES;

    ASIC_refresh_job_interval(&global_state);

    expected_interval_us = expected_guarded_interval_us(nominal_hashrate_hps, 1, 16);

    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
}
