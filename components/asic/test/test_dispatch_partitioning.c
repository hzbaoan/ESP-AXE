#include <math.h>
#include <string.h>

#include "unity.h"

#include "asic.h"
#include "utils.h"

static void init_state(GlobalState *state, DeviceModel model, uint8_t detected_chips,
                       float frequency)
{
    memset(state, 0, sizeof(*state));
    state->device_model = model;
    state->detected_asic_count = detected_chips;
    state->POWER_MANAGEMENT_MODULE.frequency_value = frequency;
    state->POWER_MANAGEMENT_MODULE.actual_frequency = frequency;
    state->version_mask = STRATUM_DEFAULT_VERSION_MASK;
}

static uint32_t version_mask_with_bits(uint8_t bits)
{
    return bits == 0 ? 0 : ((UINT32_C(1) << bits) - 1U) << 13U;
}

static size_t count_nonzero_hex_positions(const uint8_t *value, size_t value_len)
{
    size_t count = 0;

    for (size_t i = 0; i < value_len; i++) {
        count += (value[i] & 0xf0U) != 0U;
        count += (value[i] & 0x0fU) != 0U;
    }
    return count;
}

TEST_CASE("Pool negotiation fills each model's parallel version capacity", "[asic]")
{
    static GlobalState state;

    init_state(&state, DEVICE_ULTRA, 1, 485.0f);
    TEST_ASSERT_EQUAL_UINT8(3, ASIC_get_minimum_pool_version_bits(&state));

    init_state(&state, DEVICE_HEX, 6, 485.0f);
    TEST_ASSERT_EQUAL_UINT8(3, ASIC_get_minimum_pool_version_bits(&state));

    init_state(&state, DEVICE_SUPRA, 1, 490.0f);
    TEST_ASSERT_EQUAL_UINT8(4, ASIC_get_minimum_pool_version_bits(&state));

    init_state(&state, DEVICE_SUPRAHEX, 6, 490.0f);
    TEST_ASSERT_EQUAL_UINT8(4, ASIC_get_minimum_pool_version_bits(&state));

    init_state(&state, DEVICE_GAMMA, 1, 525.0f);
    TEST_ASSERT_EQUAL_UINT8(4, ASIC_get_minimum_pool_version_bits(&state));

    init_state(&state, DEVICE_GAMMATURBO, 2, 400.0f);
    TEST_ASSERT_EQUAL_UINT8(4, ASIC_get_minimum_pool_version_bits(&state));
}

TEST_CASE("Random extranonce2 fills between two and every hex position", "[asic]")
{
    uint8_t extranonce2[EXTRANONCE2_MIN_BYTES] = {0};
    bool generated_with_minimum_fill = false;

    for (uint32_t seed = 1; seed <= 128; seed++) {
        memset(extranonce2, 0xff, sizeof(extranonce2));
        size_t filled = ASIC_generate_extranonce2(extranonce2,
                                                  sizeof(extranonce2),
                                                  seed);

        TEST_ASSERT_TRUE(filled >= 2U);
        TEST_ASSERT_TRUE(filled <= sizeof(extranonce2) * 2U);
        TEST_ASSERT_TRUE(count_nonzero_hex_positions(extranonce2, sizeof(extranonce2)) <= filled);
        generated_with_minimum_fill |= filled == 2U;
    }

    TEST_ASSERT_TRUE(generated_with_minimum_fill);
}

TEST_CASE("Random extranonce2 is deterministic for a supplied seed", "[asic]")
{
    uint8_t first[EXTRANONCE2_MAX_BYTES] = {0};
    uint8_t second[EXTRANONCE2_MAX_BYTES] = {0};
    size_t first_filled = ASIC_generate_extranonce2(first, sizeof(first), 0xabcdef01U);
    size_t second_filled = ASIC_generate_extranonce2(second, sizeof(second), 0xabcdef01U);

    TEST_ASSERT_EQUAL_UINT32(first_filled, second_filled);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, second, sizeof(first));
}

TEST_CASE("Random extranonce2 rejects unsupported lengths", "[asic]")
{
    uint8_t extranonce2[EXTRANONCE2_MAX_BYTES + 1U] = {0};

    TEST_ASSERT_EQUAL_UINT32(0, ASIC_generate_extranonce2(extranonce2, 0, 1U));
    TEST_ASSERT_EQUAL_UINT32(0, ASIC_generate_extranonce2(extranonce2, 1, 1U));
    TEST_ASSERT_EQUAL_UINT32(
        0,
        ASIC_generate_extranonce2(extranonce2, sizeof(extranonce2), 1U));
}

TEST_CASE("HCN calculation follows core chip and BM1370 correction topology", "[asic]")
{
    uint32_t bm1366_hcn = 0;
    uint32_t bm1370_hcn = 0;
    uint32_t six_chip_hcn = 0;
    uint32_t six_chip_headroom_hcn = 0;

    TEST_ASSERT_TRUE(calculate_hcn(500.0f, 112, 1, 0, 1.0, &bm1366_hcn));
    TEST_ASSERT_TRUE(calculate_hcn(500.0f, 128, 1, 268, 1.0, &bm1370_hcn));
    TEST_ASSERT_TRUE(calculate_hcn(500.0f, 112, 6, 0, 1.0, &six_chip_hcn));
    TEST_ASSERT_TRUE(calculate_hcn(500.0f, 112, 6, 0, 1.2, &six_chip_headroom_hcn));
    TEST_ASSERT_EQUAL_UINT32(838860, bm1366_hcn);
    TEST_ASSERT_EQUAL_UINT32(838592, bm1370_hcn);
    TEST_ASSERT_EQUAL_UINT32(139810, six_chip_hcn);
    TEST_ASSERT_EQUAL_UINT32(167772, six_chip_headroom_hcn);
    TEST_ASSERT_FALSE(calculate_hcn(0.0f, 112, 1, 0, 1.0, &bm1366_hcn));
    TEST_ASSERT_FALSE(calculate_hcn(500.0f, 112, 6, 0, 1.21, &six_chip_hcn));
}

TEST_CASE("HCN headroom is limited to a single parallel version batch", "[asic]")
{
    static GlobalState state;
    const struct {
        DeviceModel model;
        uint8_t detected_chips;
        uint8_t parallel_version_bits;
    } cases[] = {
        {DEVICE_ULTRA, 1, 3},
        {DEVICE_HEX, 6, 3},
        {DEVICE_SUPRA, 1, 4},
        {DEVICE_SUPRAHEX, 6, 4},
        {DEVICE_GAMMA, 1, 4},
        {DEVICE_GAMMATURBO, 2, 4},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        init_state(&state, cases[i].model, cases[i].detected_chips, 500.0f);

        TEST_ASSERT_DOUBLE_WITHIN(
            0.0001, 1.2, ASIC_get_hcn_search_multiplier(&state, 0));
        TEST_ASSERT_DOUBLE_WITHIN(
            0.0001,
            1.2,
            ASIC_get_hcn_search_multiplier(
                &state, version_mask_with_bits(cases[i].parallel_version_bits)));
        TEST_ASSERT_DOUBLE_WITHIN(
            0.0001,
            1.0,
            ASIC_get_hcn_search_multiplier(
                &state, version_mask_with_bits(cases[i].parallel_version_bits + 1U)));
        TEST_ASSERT_DOUBLE_WITHIN(
            0.0001,
            1.0,
            ASIC_get_hcn_search_multiplier(&state, STRATUM_DEFAULT_VERSION_MASK));
    }
}

TEST_CASE("PLL resolver uses valid strict post dividers across supported range", "[asic]")
{
    const struct {
        float target;
        uint16_t feedback_min;
        uint16_t feedback_max;
    } cases[] = {
        {50.0f, 144, 235},
        {485.0f, 144, 235},
        {490.0f, 144, 235},
        {525.0f, 160, 239},
        {800.0f, 160, 239},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t feedback = 0;
        uint8_t reference = 0;
        uint8_t post1 = 0;
        uint8_t post2 = 0;
        float actual = 0.0f;

        TEST_ASSERT_TRUE(calculate_pll_parameters(
            cases[i].target,
            cases[i].feedback_min,
            cases[i].feedback_max,
            &feedback,
            &reference,
            &post1,
            &post2,
            &actual));
        TEST_ASSERT_TRUE(post1 > post2);
        TEST_ASSERT_TRUE(feedback >= cases[i].feedback_min);
        TEST_ASSERT_TRUE(feedback <= cases[i].feedback_max);
        TEST_ASSERT_FLOAT_WITHIN(0.01f, cases[i].target, actual);
    }
}

TEST_CASE("Full search time uses at least one complete parallel version batch", "[asic]")
{
    double one_chip_one_version = calculate_bm_full_space_ms(500.0f, 1, 894, 112, 1);
    double two_chip_one_version = calculate_bm_full_space_ms(500.0f, 2, 894, 112, 1);
    double six_chip_one_version = calculate_bm_full_space_ms(500.0f, 6, 894, 112, 1);
    double six_chip_eight_versions = calculate_bm_full_space_ms(500.0f, 6, 894, 112, 8);
    double six_chip_sixteen_versions = calculate_bm_full_space_ms(500.0f, 6, 894, 112, 16);
    double six_chip_256_versions = calculate_bm_full_space_ms(500.0f, 6, 894, 112, 256);
    double bm1368_one_version = calculate_bm_full_space_ms(500.0f, 6, 1276, 80, 1);
    double bm1368_sixteen_versions = calculate_bm_full_space_ms(500.0f, 6, 1276, 80, 16);
    double bm1368_thirty_two_versions = calculate_bm_full_space_ms(500.0f, 6, 1276, 80, 32);

    TEST_ASSERT_DOUBLE_WITHIN(0.001, one_chip_one_version / 2.0, two_chip_one_version);
    TEST_ASSERT_DOUBLE_WITHIN(0.001, one_chip_one_version / 6.0, six_chip_one_version);
    TEST_ASSERT_DOUBLE_WITHIN(0.001, six_chip_one_version, six_chip_eight_versions);
    TEST_ASSERT_DOUBLE_WITHIN(0.001, six_chip_one_version * 2.0, six_chip_sixteen_versions);
    TEST_ASSERT_DOUBLE_WITHIN(0.01, six_chip_one_version * 32.0, six_chip_256_versions);
    TEST_ASSERT_DOUBLE_WITHIN(0.001, bm1368_one_version, bm1368_sixteen_versions);
    TEST_ASSERT_DOUBLE_WITHIN(
        0.001, bm1368_one_version * 2.0, bm1368_thirty_two_versions);
}

TEST_CASE("Dispatch interval is bounded by model timeout and available ASIC space", "[asic]")
{
    static GlobalState state;
    ASICDispatchConfig dispatch_config;
    init_state(&state, DEVICE_HEX, 6, 485.0f);
    uint32_t full_mask_interval;

    ASIC_refresh_job_interval(&state);
    ASIC_get_dispatch_config(&state, &dispatch_config);
    full_mask_interval = state.ASIC_TASK_MODULE.dispatch_interval_target_us;
    TEST_ASSERT_EQUAL_UINT32(2000000U, full_mask_interval);
    TEST_ASSERT_EQUAL_UINT32(full_mask_interval,
                             state.ASIC_TASK_MODULE.dispatch_interval_current_us);
    TEST_ASSERT_EQUAL_UINT32(full_mask_interval, dispatch_config.target_interval_us);
    TEST_ASSERT_EQUAL_UINT32(full_mask_interval, dispatch_config.current_interval_us);
    TEST_ASSERT_EQUAL_UINT16(state.ASIC_TASK_MODULE.queue_low_water_mark,
                             dispatch_config.queue_low_water_mark);
    TEST_ASSERT_EQUAL_UINT16(state.ASIC_TASK_MODULE.queue_high_water_mark,
                             dispatch_config.queue_high_water_mark);

    state.version_mask = 0;
    ASIC_refresh_job_interval(&state);
    TEST_ASSERT_UINT32_WITHIN(
        1U, 11531U, state.ASIC_TASK_MODULE.dispatch_interval_target_us);
    TEST_ASSERT_TRUE(state.ASIC_TASK_MODULE.dispatch_interval_target_us < full_mask_interval);
}

TEST_CASE("Every supported topology dispatches one-version work after a full nonce pass", "[asic]")
{
    static GlobalState state;
    const struct {
        DeviceModel model;
        uint8_t detected_chips;
        float frequency;
        uint8_t parallel_version_bits;
        uint32_t expected_interval_us;
        uint32_t expected_model_limit_us;
    } cases[] = {
        {DEVICE_ULTRA, 1, 485.0f, 3, 69184U, 2000000U},
        {DEVICE_HEX, 6, 550.0f, 3, 10168U, 2000000U},
        {DEVICE_SUPRA, 1, 490.0f, 4, 68478U, 500000U},
        {DEVICE_SUPRAHEX, 6, 575.0f, 4, 9726U, 500000U},
        {DEVICE_GAMMA, 1, 525.0f, 4, 63913U, 500000U},
        {DEVICE_GAMMATURBO, 2, 525.0f, 4, 31957U, 500000U},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        init_state(&state,
                   cases[i].model,
                   cases[i].detected_chips,
                   cases[i].frequency);
        state.version_mask = 0;

        ASIC_refresh_job_interval(&state);

        TEST_ASSERT_UINT32_WITHIN(
            1U,
            cases[i].expected_interval_us,
            state.ASIC_TASK_MODULE.dispatch_interval_target_us);
        TEST_ASSERT_TRUE(
            state.ASIC_TASK_MODULE.dispatch_interval_target_us > 880U);

        state.version_mask = version_mask_with_bits(cases[i].parallel_version_bits);
        ASIC_refresh_job_interval(&state);
        TEST_ASSERT_UINT32_WITHIN(
            1U,
            cases[i].expected_interval_us,
            state.ASIC_TASK_MODULE.dispatch_interval_target_us);

        state.version_mask = STRATUM_DEFAULT_VERSION_MASK;
        ASIC_refresh_job_interval(&state);
        TEST_ASSERT_EQUAL_UINT32(
            cases[i].expected_model_limit_us,
            state.ASIC_TASK_MODULE.dispatch_interval_target_us);
    }
}

TEST_CASE("Slow clocks cannot be truncated by a shorter model timeout", "[asic]")
{
    static GlobalState state;
    const struct {
        DeviceModel model;
        uint8_t detected_chips;
        uint32_t expected_interval_us;
    } cases[] = {
        {DEVICE_ULTRA, 1, 671089U},
        {DEVICE_HEX, 6, 111848U},
        {DEVICE_SUPRA, 1, 671089U},
        {DEVICE_SUPRAHEX, 6, 111848U},
        {DEVICE_GAMMA, 1, 671089U},
        {DEVICE_GAMMATURBO, 2, 335544U},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        init_state(&state, cases[i].model, cases[i].detected_chips, 50.0f);
        state.version_mask = 0;

        ASIC_refresh_job_interval(&state);

        TEST_ASSERT_UINT32_WITHIN(
            1U,
            cases[i].expected_interval_us,
            state.ASIC_TASK_MODULE.dispatch_interval_target_us);
    }
}

TEST_CASE("Job history retains successful generations and rolls back failed send", "[asic]")
{
    static GlobalState state;
    static bm_job first_job;
    static bm_job second_job;
    static bm_job failed_job;
    static bm_job snapshots[ASIC_JOB_CANDIDATE_COUNT];
    bm_job *replaced = NULL;
    uint32_t history_revision = UINT32_MAX;

    memset(&state, 0, sizeof(state));
    memset(&first_job, 0, sizeof(first_job));
    memset(&second_job, 0, sizeof(second_job));
    memset(&failed_job, 0, sizeof(failed_job));
    memset(snapshots, 0, sizeof(snapshots));
    pthread_mutex_init(&state.job_history_lock, NULL);
    strncpy(first_job.jobid, "first", sizeof(first_job.jobid) - 1);
    strncpy(second_job.jobid, "second", sizeof(second_job.jobid) - 1);
    strncpy(failed_job.jobid, "failed", sizeof(failed_job.jobid) - 1);

    TEST_ASSERT_TRUE(ASIC_begin_active_job_send(&state, 8, &first_job, &replaced));
    TEST_ASSERT_NULL(replaced);
    ASIC_finish_active_job_send(&state, 8, &first_job, replaced, true);
    TEST_ASSERT_EQUAL_UINT32(1, ASIC_copy_job_candidates(
                                      &state, 8, snapshots, ASIC_JOB_CANDIDATE_COUNT,
                                      &history_revision));
    TEST_ASSERT_EQUAL_UINT32(1, history_revision);

    TEST_ASSERT_TRUE(ASIC_begin_active_job_send(&state, 8, &second_job, &replaced));
    TEST_ASSERT_EQUAL_PTR(&first_job, replaced);
    ASIC_finish_active_job_send(&state, 8, &second_job, replaced, true);

    TEST_ASSERT_EQUAL_UINT32(2, ASIC_copy_job_candidates(
                                      &state, 8, snapshots, ASIC_JOB_CANDIDATE_COUNT,
                                      &history_revision));
    TEST_ASSERT_EQUAL_UINT32(2, history_revision);
    TEST_ASSERT_EQUAL_STRING("second", snapshots[0].jobid);
    TEST_ASSERT_EQUAL_STRING("first", snapshots[1].jobid);

    TEST_ASSERT_TRUE(ASIC_begin_active_job_send(&state, 8, &failed_job, &replaced));
    TEST_ASSERT_EQUAL_PTR(&second_job, replaced);
    ASIC_finish_active_job_send(&state, 8, &failed_job, replaced, false);

    memset(snapshots, 0, sizeof(snapshots));
    TEST_ASSERT_EQUAL_UINT32(2, ASIC_copy_job_candidates(
                                      &state, 8, snapshots, ASIC_JOB_CANDIDATE_COUNT,
                                      &history_revision));
    TEST_ASSERT_EQUAL_UINT32(2, history_revision);
    TEST_ASSERT_EQUAL_STRING("second", snapshots[0].jobid);
    TEST_ASSERT_EQUAL_STRING("first", snapshots[1].jobid);

    ASIC_clear_job_history(&state);
    TEST_ASSERT_EQUAL_UINT32(0, ASIC_copy_job_candidates(
                                      &state, 8, snapshots, ASIC_JOB_CANDIDATE_COUNT,
                                      &history_revision));
    TEST_ASSERT_EQUAL_UINT32(3, history_revision);
}

TEST_CASE("SV2 target updates only channel-tracking job history", "[asic]")
{
    static GlobalState state;
    static bm_job tracking_job;
    static bm_job stable_job;
    bm_job *replaced = NULL;
    uint8_t old_target[32] = {0};
    uint8_t new_target[32] = {0};

    memset(&state, 0, sizeof(state));
    memset(&tracking_job, 0, sizeof(tracking_job));
    memset(&stable_job, 0, sizeof(stable_job));
    pthread_mutex_init(&state.job_history_lock, NULL);

    old_target[0] = 0x11;
    new_target[0] = 0x22;
    memcpy(tracking_job.pool_target, old_target, sizeof(old_target));
    memcpy(stable_job.pool_target, old_target, sizeof(old_target));
    tracking_job.pool_target_tracks_channel = true;
    tracking_job.pool_diff = 20000;
    tracking_job.asic_report_difficulty = 16384;
    stable_job.pool_diff = 20000;
    stable_job.asic_report_difficulty = 16384;

    TEST_ASSERT_TRUE(ASIC_begin_active_job_send(&state, 8, &tracking_job, &replaced));
    ASIC_finish_active_job_send(&state, 8, &tracking_job, replaced, true);
    TEST_ASSERT_TRUE(ASIC_begin_active_job_send(&state, 16, &stable_job, &replaced));
    ASIC_finish_active_job_send(&state, 16, &stable_job, replaced, true);

    ASIC_update_job_pool_target(&state, new_target, 10000);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(new_target, tracking_job.pool_target, sizeof(new_target));
    TEST_ASSERT_EQUAL_UINT32(10000, tracking_job.pool_diff);
    TEST_ASSERT_EQUAL_UINT32(8192, tracking_job.asic_report_difficulty);
    TEST_ASSERT_EQUAL_UINT32(2, state.ASIC_TASK_MODULE.job_history_revision[8]);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(old_target, stable_job.pool_target, sizeof(old_target));
    TEST_ASSERT_EQUAL_UINT32(20000, stable_job.pool_diff);
    TEST_ASSERT_EQUAL_UINT32(16384, stable_job.asic_report_difficulty);
    TEST_ASSERT_EQUAL_UINT32(1, state.ASIC_TASK_MODULE.job_history_revision[16]);
}

TEST_CASE("Pool difficulty maps to the highest safe ASIC report difficulty", "[asic]")
{
    TEST_ASSERT_EQUAL_UINT32(1, ASIC_get_report_difficulty(0));
    TEST_ASSERT_EQUAL_UINT32(1, ASIC_get_report_difficulty(1));
    TEST_ASSERT_EQUAL_UINT32(2, ASIC_get_report_difficulty(2));
    TEST_ASSERT_EQUAL_UINT32(8, ASIC_get_report_difficulty(15));
    TEST_ASSERT_EQUAL_UINT32(8192, ASIC_get_report_difficulty(10000));
    TEST_ASSERT_EQUAL_UINT32(65536, ASIC_get_report_difficulty(65536));
}
