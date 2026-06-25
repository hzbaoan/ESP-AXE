#include <math.h>
#include <string.h>

#include "unity.h"

#include "asic.h"
#include "utils.h"

#ifndef CONFIG_ASIC_HOST_VERSION_BITS
#define CONFIG_ASIC_HOST_VERSION_BITS 10
#endif

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

static uint8_t count_mask_bits(uint32_t mask)
{
    uint8_t count = 0;

    while (mask != 0) {
        count += (uint8_t)(mask & 1U);
        mask >>= 1;
    }

    return count;
}

static uint32_t take_lowest_mask_bits(uint32_t mask, uint8_t bit_count)
{
    uint32_t selected_mask = 0;

    for (uint8_t bit = 0; bit < 32 && bit_count > 0; bit++) {
        uint32_t mask_bit = UINT32_C(1) << bit;

        if ((mask & mask_bit) == 0) {
            continue;
        }

        selected_mask |= mask_bit;
        bit_count--;
    }

    return selected_mask;
}

static uint8_t expected_host_version_bits(uint32_t version_mask)
{
    uint8_t mask_bits = count_mask_bits(version_mask);

    return mask_bits > CONFIG_ASIC_HOST_VERSION_BITS ? CONFIG_ASIC_HOST_VERSION_BITS : mask_bits;
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
    uint8_t host_version_bits;
    uint32_t expected_host_version_mask;
    uint32_t expected_version_windows;
    uint64_t steps_to_check;

    global_state.device_model = device_model;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, STRATUM_DEFAULT_VERSION_MASK);
    host_version_bits = expected_host_version_bits(STRATUM_DEFAULT_VERSION_MASK);
    expected_host_version_mask = take_lowest_mask_bits(STRATUM_DEFAULT_VERSION_MASK, host_version_bits);
    expected_version_windows = UINT32_C(1) << host_version_bits;
    steps_to_check = expected_version_windows < 20U ? (uint64_t)expected_version_windows + 4U : 20U;

    TEST_ASSERT_EQUAL_UINT8(ASIC_VERSION_MODE_INTERNAL_BITS, policy.version_mode);
    TEST_ASSERT_EQUAL_UINT8(6, policy.active_job_slots);
    TEST_ASSERT_TRUE(policy.host_expands_version);
    TEST_ASSERT_TRUE(policy.host_expands_extranonce2);
    TEST_ASSERT_EQUAL_UINT32(expected_version_windows, version_window_count);
    TEST_ASSERT_EQUAL_HEX32(expected_host_version_mask,
                            ASIC_get_header_schedule_host_version_mask(&policy, STRATUM_DEFAULT_VERSION_MASK));
    TEST_ASSERT_EQUAL_HEX32(STRATUM_DEFAULT_VERSION_MASK & ~expected_host_version_mask,
                            ASIC_get_header_schedule_asic_version_mask(&policy, STRATUM_DEFAULT_VERSION_MASK));

    for (uint64_t step_index = 0; step_index < steps_to_check; step_index++) {
        asic_header_schedule_snapshot_t snapshot =
            ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

        assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, step_index / expected_version_windows);
        TEST_ASSERT_EQUAL_UINT32((uint32_t)(step_index % expected_version_windows), snapshot.version_window_index);

        ASIC_advance_header_cursor(&cursor, &policy, version_window_count);
    }
}

TEST_CASE("Supported ASIC models do not expose host nonce partitioning", "[asic]")
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
        TEST_ASSERT_EQUAL_UINT8(6, ASIC_get_active_job_slot_count(&global_state));
    }
}

TEST_CASE("BM1366 BM1368 and BM1370 reuse extranonce2 across host version slots", "[asic]")
{
    assert_internal_bits_sequence(DEVICE_ULTRA);
    assert_internal_bits_sequence(DEVICE_SUPRA);
    assert_internal_bits_sequence(DEVICE_GAMMA);
}

TEST_CASE("Header cursor advances extranonce2 only after host version windows wrap", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    uint32_t version_mask = 0x00006000;
    uint32_t version_window_count;

    global_state.device_model = DEVICE_ULTRA;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, version_mask);

    for (uint64_t step_index = 0; step_index < (uint64_t)version_window_count + 2U; step_index++) {
        asic_header_schedule_snapshot_t snapshot =
            ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

        assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, step_index / version_window_count);
        TEST_ASSERT_EQUAL_UINT32((uint32_t)(step_index % version_window_count), snapshot.version_window_index);

        ASIC_advance_header_cursor(&cursor, &policy, version_window_count);
    }
}

TEST_CASE("Header cursors partition work across detected chips", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursors[3] = {0};
    asic_header_schedule_snapshot_t snapshot;
    uint32_t version_mask = 0x00006000;
    uint32_t version_window_count;

    global_state.device_model = DEVICE_HEX;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, version_mask);

    TEST_ASSERT_EQUAL_UINT32(4, version_window_count);

    ASIC_init_partitioned_header_cursors(cursors, 3, &policy, version_window_count);

    snapshot = ASIC_snapshot_header_cursor(&cursors[0], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 0);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.version_window_index);

    snapshot = ASIC_snapshot_header_cursor(&cursors[1], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 0);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.version_window_index);

    snapshot = ASIC_snapshot_header_cursor(&cursors[2], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 0);
    TEST_ASSERT_EQUAL_UINT32(2, snapshot.version_window_index);

    for (uint8_t chip_index = 0; chip_index < 3; chip_index++) {
        ASIC_advance_header_cursor_by(&cursors[chip_index], &policy, version_window_count, 3);
    }

    snapshot = ASIC_snapshot_header_cursor(&cursors[0], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 0);
    TEST_ASSERT_EQUAL_UINT32(3, snapshot.version_window_index);

    snapshot = ASIC_snapshot_header_cursor(&cursors[1], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 1);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.version_window_index);

    snapshot = ASIC_snapshot_header_cursor(&cursors[2], &policy, version_window_count);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 1);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.version_window_index);
}

TEST_CASE("Header cursors expose all six chip partitions", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursors[ASIC_MAX_CHIP_COUNT] = {0};
    uint32_t version_window_count;

    global_state.device_model = DEVICE_HEX;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, STRATUM_DEFAULT_VERSION_MASK);

    TEST_ASSERT_EQUAL_UINT8(6, ASIC_MAX_CHIP_COUNT);
    TEST_ASSERT_TRUE(version_window_count >= ASIC_MAX_CHIP_COUNT);

    ASIC_init_partitioned_header_cursors(cursors, ASIC_MAX_CHIP_COUNT, &policy, version_window_count);

    for (uint8_t chip_index = 0; chip_index < ASIC_MAX_CHIP_COUNT; chip_index++) {
        asic_header_schedule_snapshot_t snapshot =
            ASIC_snapshot_header_cursor(&cursors[chip_index], &policy, version_window_count);

        assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 0);
        TEST_ASSERT_EQUAL_UINT32(chip_index, snapshot.version_window_index);
    }
}

TEST_CASE("Version mask state sync stores the full submit mask only", "[asic]")
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

TEST_CASE("Header cursor normalization keeps supported host version slot", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    asic_header_schedule_snapshot_t snapshot;
    uint32_t version_window_count;
    uint32_t expected_version_window_index;

    set_extranonce2_counter_u64(&cursor.extranonce2_counter, 7);
    cursor.version_window_index = 5;

    global_state.device_model = DEVICE_ULTRA;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, 0x0000E000);
    expected_version_window_index = 5 % version_window_count;

    ASIC_normalize_header_cursor(&cursor, &policy, version_window_count);
    snapshot = ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

    assert_extranonce2_counter_u64(&cursor.extranonce2_counter, 7);
    TEST_ASSERT_EQUAL_UINT32(expected_version_window_index, cursor.version_window_index);
    assert_extranonce2_counter_u64(&snapshot.extranonce2_counter, 7);
    TEST_ASSERT_EQUAL_UINT32(expected_version_window_index, snapshot.version_window_index);
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

    ASIC_advance_header_cursor(&cursor, &policy, version_window_count);
    snapshot = ASIC_snapshot_header_cursor(&cursor, &policy, version_window_count);

    expected.bytes[8] = 0x35;
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.bytes,
                                  cursor.extranonce2_counter.bytes,
                                  ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.bytes,
                                  snapshot.extranonce2_counter.bytes,
                                  ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
}

TEST_CASE("Extranonce2 overflow detection respects the active pool length", "[asic]")
{
    asic_extranonce2_counter_t counter = {0};

    counter.bytes[0] = 0xff;
    counter.bytes[1] = 0xff;
    TEST_ASSERT_FALSE(ASIC_extranonce2_counter_has_overflowed_len(&counter, 2));

    counter.bytes[2] = 0x01;
    TEST_ASSERT_TRUE(ASIC_extranonce2_counter_has_overflowed_len(&counter, 2));
    TEST_ASSERT_FALSE(ASIC_extranonce2_counter_has_overflowed_len(&counter, ASIC_EXTRANONCE2_COUNTER_MAX_BYTES));
    TEST_ASSERT_FALSE(ASIC_extranonce2_counter_has_overflowed_len(NULL, 2));
}

TEST_CASE("Extranonce2 overflow is detectable after host version windows wrap", "[asic]")
{
    GlobalState global_state = {0};
    asic_header_schedule_policy_t policy;
    asic_header_cursor_t cursor = {0};
    uint32_t version_window_count;

    global_state.device_model = DEVICE_ULTRA;
    policy = ASIC_get_header_schedule_policy(&global_state);
    version_window_count = ASIC_get_header_schedule_version_window_count(&policy, 0x00006000);

    cursor.extranonce2_counter.bytes[0] = 0xff;
    cursor.extranonce2_counter.bytes[1] = 0xff;

    TEST_ASSERT_FALSE(ASIC_extranonce2_counter_has_overflowed_len(&cursor.extranonce2_counter, 2));
    for (uint32_t i = 1; i < version_window_count; i++) {
        ASIC_advance_header_cursor(&cursor, &policy, version_window_count);
        TEST_ASSERT_EQUAL_UINT32(i, cursor.version_window_index);
        TEST_ASSERT_FALSE(ASIC_extranonce2_counter_has_overflowed_len(&cursor.extranonce2_counter, 2));
    }

    ASIC_advance_header_cursor(&cursor, &policy, version_window_count);

    TEST_ASSERT_EQUAL_UINT32(0, cursor.version_window_index);
    TEST_ASSERT_TRUE(ASIC_extranonce2_counter_has_overflowed_len(&cursor.extranonce2_counter, 2));
    TEST_ASSERT_EQUAL_UINT8(0x01, cursor.extranonce2_counter.bytes[2]);
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
    expected_interval_us = expected_guarded_interval_us(nominal_hashrate_hps, 1, 6);

    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_current_us);
}

TEST_CASE("Detected partial ASIC chain reduces dispatch rate", "[asic]")
{
    GlobalState global_state = {0};
    uint32_t expected_interval_us;
    double detected_hashrate_hps;

    global_state.device_model = DEVICE_HEX;
    global_state.detected_asic_count = 5;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 100.0;

    ASIC_refresh_job_interval(&global_state);

    detected_hashrate_hps = 100.0 * 1000000.0 * (double)BM1366_SMALL_CORE_COUNT * 5.0;
    expected_interval_us = expected_guarded_interval_us(detected_hashrate_hps, 1, 6);

    TEST_ASSERT_EQUAL_UINT8(5, ASIC_get_asic_count(&global_state));
    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
}

TEST_CASE("Observed hashrate below nominal does not slow dispatch", "[asic]")
{
    GlobalState global_state = {0};
    uint32_t expected_interval_us;
    double nominal_hashrate_hps = 100.0 * 1000000.0 * (double)BM1366_SMALL_CORE_COUNT;

    global_state.device_model = DEVICE_ULTRA;
    global_state.POWER_MANAGEMENT_MODULE.frequency_value = 100.0;
    global_state.SYSTEM_MODULE.current_hashrate = 70.0;
    global_state.SYSTEM_MODULE.historical_hashrate_init = CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES;

    ASIC_refresh_job_interval(&global_state);

    expected_interval_us = expected_guarded_interval_us(nominal_hashrate_hps, 1, 6);

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

    expected_interval_us = expected_guarded_interval_us(nominal_hashrate_hps, 1, 6);

    TEST_ASSERT_EQUAL_UINT32(expected_interval_us, global_state.ASIC_TASK_MODULE.dispatch_interval_target_us);
}
