#include "sv2_noise.h"
#include "sv2_protocol.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_transport.h"

#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/chachapoly.h"

#include "secp256k1.h"
#include "secp256k1_ellswift.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_extrakeys.h"

static const char *TAG = "sv2_noise";

#define TRANSPORT_TIMEOUT_MS    5000
#define RECV_TIMEOUT_MS         (60 * 3 * 1000)
#define HANDSHAKE_TIMEOUT_MS    10000
#define SV2_CERT_TIME_LEEWAY_SECONDS 10U
#define SV2_NOISE_MAX_SEND_PAYLOAD 1024
#define SV2_NOISE_MAX_RECV_PAYLOAD 4096

// Noise protocol name used to initialize h and ck
static const char NOISE_PROTOCOL_NAME[] = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";

struct sv2_noise_ctx {
    uint8_t h[32];              // handshake hash
    uint8_t ck[32];             // chaining key
    uint8_t e_priv[32];         // ephemeral private key (zeroed after handshake)
    uint8_t e_pub_encoded[64];  // ElligatorSwift-encoded ephemeral pubkey
    uint8_t send_key[32];       // c1: initiator -> responder
    uint8_t recv_key[32];       // c2: responder -> initiator
    uint8_t send_buf[SV2_NOISE_MAX_SEND_PAYLOAD + 16];
    uint8_t recv_buf[SV2_NOISE_MAX_RECV_PAYLOAD + 16];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    bool handshake_complete;
    secp256k1_context *secp_ctx;
};

// --- Transport helpers ---

static int noise_recv_exact(esp_transport_handle_t transport, uint8_t *buf, int len, int timeout_ms)
{
    int received = 0;
    while (received < len) {
        int r = esp_transport_read(transport, (char *)buf + received, len - received, timeout_ms);
        if (r <= 0) {
            ESP_LOGE(TAG, "recv failed: r=%d received=%d/%d timeout_ms=%d",
                     r, received, len, timeout_ms);
            return -1;
        }
        received += r;
    }
    return 0;
}

static int noise_send_all(esp_transport_handle_t transport, const uint8_t *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int ret = esp_transport_write(transport, (const char *)buf + sent, len - sent,
                                      TRANSPORT_TIMEOUT_MS);
        if (ret <= 0) {
            ESP_LOGE(TAG, "send failed: ret=%d sent=%d/%d", ret, sent, len);
            return -1;
        }
        sent += ret;
    }
    return 0;
}

static inline uint16_t read_u16_le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// --- Crypto helpers ---

// h = SHA-256(h || data)
static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len)
{
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, h, 32);
    mbedtls_sha256_update(&sha, data, len);
    mbedtls_sha256_finish(&sha, h);
    mbedtls_sha256_free(&sha);
}

// HMAC-SHA256
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md, key, key_len);
    mbedtls_md_hmac_update(&md, data, data_len);
    mbedtls_md_hmac_finish(&md, out);
    mbedtls_md_free(&md);
}

// Noise HKDF-2: derive two 32-byte keys from chaining key and input key material
static void hkdf2(uint8_t ck[32], const uint8_t *ikm, size_t ikm_len,
                  uint8_t out1[32], uint8_t out2[32])
{
    uint8_t prk[32];
    hmac_sha256(ck, 32, ikm, ikm_len, prk);

    // out1 = HMAC(prk, 0x01)
    uint8_t one = 0x01;
    hmac_sha256(prk, 32, &one, 1, out1);

    // out2 = HMAC(prk, out1 || 0x02)
    uint8_t buf[33];
    memcpy(buf, out1, 32);
    buf[32] = 0x02;
    hmac_sha256(prk, 32, buf, 33, out2);
}

// Build 12-byte nonce: 4 zero bytes + 8-byte LE counter
static void build_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (i * 8));
    }
}

// ChaCha20-Poly1305 encrypt
// out must have room for pt_len + 16 bytes
static int noise_encrypt(const uint8_t key[32], uint64_t nonce_counter,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t pt_len,
                         uint8_t *out)
{
    uint8_t nonce[12];
    build_nonce(nonce_counter, nonce);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, key);

    int ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len,
                                                  nonce, aad, aad_len,
                                                  plaintext, out,
                                                  out + pt_len); // 16-byte tag appended
    mbedtls_chachapoly_free(&ctx);

    if (ret != 0) {
        ESP_LOGE(TAG, "encrypt failed: %d", ret);
        return -1;
    }
    return 0;
}

// ChaCha20-Poly1305 decrypt
// ciphertext includes 16-byte tag at end. out receives ct_len - 16 bytes.
static int noise_decrypt(const uint8_t key[32], uint64_t nonce_counter,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t *out)
{
    if (ct_len < 16) return -1;

    uint8_t nonce[12];
    build_nonce(nonce_counter, nonce);

    size_t pt_len = ct_len - 16;
    const uint8_t *tag = ciphertext + pt_len;

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, key);

    int ret = mbedtls_chachapoly_auth_decrypt(&ctx, pt_len,
                                               nonce, aad, aad_len,
                                               tag, ciphertext, out);
    mbedtls_chachapoly_free(&ctx);

    if (ret != 0) {
        ESP_LOGE(TAG, "decrypt failed: %d", ret);
        return -1;
    }
    return 0;
}

// --- Public API ---

sv2_noise_ctx_t *sv2_noise_create(void)
{
    sv2_noise_ctx_t *ctx = calloc(1, sizeof(sv2_noise_ctx_t));
    if (!ctx) return NULL;

    ctx->secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx->secp_ctx) {
        free(ctx);
        return NULL;
    }

    // Randomize the context for side-channel protection
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    if (!secp256k1_context_randomize(ctx->secp_ctx, seed)) {
        ESP_LOGE(TAG, "Failed to randomize secp256k1 context");
        secp256k1_context_destroy(ctx->secp_ctx);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void sv2_noise_destroy(sv2_noise_ctx_t *ctx)
{
    if (!ctx) return;

    // Securely zero sensitive material
    memset(ctx->e_priv, 0, 32);
    memset(ctx->send_key, 0, 32);
    memset(ctx->recv_key, 0, 32);
    memset(ctx->send_buf, 0, sizeof(ctx->send_buf));
    memset(ctx->recv_buf, 0, sizeof(ctx->recv_buf));

    if (ctx->secp_ctx) {
        secp256k1_context_destroy(ctx->secp_ctx);
    }
    free(ctx);
}

int sv2_noise_handshake(sv2_noise_ctx_t *ctx, esp_transport_handle_t transport,
                        const uint8_t *authority_pubkey,
                        sv2_cert_time_check_t cert_time_check)
{
    int64_t hs_start_us = esp_timer_get_time();

    if (!ctx || transport == NULL) {
        ESP_LOGE(TAG, "Noise handshake requires transport");
        return -1;
    }

    // Step 1: Initialize h and ck = SHA-256(protocol_name)
    mbedtls_sha256((const uint8_t *)NOISE_PROTOCOL_NAME,
                   strlen(NOISE_PROTOCOL_NAME), ctx->h, 0);
    memcpy(ctx->ck, ctx->h, 32);

    // Verify initial hash matches known reference value
    static const uint8_t expected_h[32] = {
        46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
        169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16
    };
    if (memcmp(ctx->h, expected_h, 32) != 0) {
        ESP_LOGE(TAG, "Initial protocol hash mismatch! SHA-256 implementation issue.");
        return -1;
    }

    // MixHash(prologue): SV2 uses an empty prologue, so h = SHA-256(h || "")
    // This is required by the Noise framework before processing any handshake tokens
    mix_hash(ctx->h, (const uint8_t *)"", 0);

    // Step 2: Generate ephemeral keypair
    ESP_LOGI(TAG, "Generating Noise ephemeral key");
    esp_fill_random(ctx->e_priv, 32);

    uint8_t auxrand[32];
    esp_fill_random(auxrand, sizeof(auxrand));

    if (!secp256k1_ellswift_create(ctx->secp_ctx, ctx->e_pub_encoded,
                                    ctx->e_priv, auxrand)) {
        ESP_LOGE(TAG, "Failed to generate ephemeral key");
        return -1;
    }

    // Step 3: mix_hash(h, e_pub_encoded) — process 'e' token
    mix_hash(ctx->h, ctx->e_pub_encoded, 64);

    // Step 3b: Noise pattern requires EncryptAndHash(empty_payload) after 'e' token
    // Since k=None at this point, this is just mix_hash(h, empty) = h = SHA-256(h)
    mix_hash(ctx->h, (const uint8_t *)"", 0);

    // Step 4: Send our 64-byte encoded ephemeral pubkey (-> Act 1)
    ESP_LOGI(TAG, "Sending Noise initiator message");
    if (noise_send_all(transport, ctx->e_pub_encoded, 64) != 0) {
        ESP_LOGE(TAG, "Failed to send ephemeral key");
        return -1;
    }

    // Step 5: Receive 234 bytes (responder's message = Act 2)
    uint8_t resp[234];
    ESP_LOGI(TAG, "Waiting for Noise responder message");
    if (noise_recv_exact(transport, resp, 234, HANDSHAKE_TIMEOUT_MS) != 0) {
        ESP_LOGE(TAG, "Failed to receive server Noise response");
        return -1;
    }

    // Step 6: Parse responder ephemeral (bytes 0-63), mix into hash
    const uint8_t *re_pub = resp;
    mix_hash(ctx->h, re_pub, 64);

    // Step 7: ECDH #1 — our ephemeral with responder ephemeral
    uint8_t shared[32];
    if (!secp256k1_ellswift_xdh(ctx->secp_ctx, shared,
                                 ctx->e_pub_encoded, re_pub,
                                 ctx->e_priv, 0,
                                 secp256k1_ellswift_xdh_hash_function_bip324,
                                 NULL)) {
        ESP_LOGE(TAG, "ECDH key exchange #1 failed");
        return -1;
    }

    // Step 8: HKDF to derive ck and temp_k
    uint8_t temp_k[32];
    hkdf2(ctx->ck, shared, 32, ctx->ck, temp_k);

    // Step 9: Decrypt responder's encrypted static key (bytes 64-143 = 80 bytes)
    // 80 bytes = 64 bytes ciphertext + 16 bytes MAC
    uint8_t rs_static[64]; // responder static key (ElligatorSwift encoded)
    if (noise_decrypt(temp_k, 0, ctx->h, 32, resp + 64, 80, rs_static) != 0) {
        ESP_LOGE(TAG, "Failed to decrypt server static key (MAC verification failed)");
        return -1;
    }
    ESP_LOGI(TAG, "Decrypted server static key");

    // Step 10: mix_hash with the raw ciphertext+MAC (before decryption)
    mix_hash(ctx->h, resp + 64, 80);

    // Step 11: ECDH #2 — our ephemeral with responder static
    uint8_t shared2[32];
    ESP_LOGI(TAG, "Running Noise ECDH #2 with server static key");
    if (!secp256k1_ellswift_xdh(ctx->secp_ctx, shared2,
                                 ctx->e_pub_encoded, rs_static,
                                 ctx->e_priv, 0,
                                 secp256k1_ellswift_xdh_hash_function_bip324,
                                 NULL)) {
        ESP_LOGE(TAG, "ECDH key exchange #2 failed");
        return -1;
    }
    ESP_LOGI(TAG, "Noise ECDH #2 complete");

    // Step 12: HKDF to derive ck and temp_k2
    uint8_t temp_k2[32];
    hkdf2(ctx->ck, shared2, 32, ctx->ck, temp_k2);

    // Step 13: Decrypt signature message (bytes 144-233 = 90 bytes)
    // 90 bytes = 74 bytes plaintext + 16 bytes MAC
    uint8_t sig_msg[74];
    ESP_LOGI(TAG, "Decrypting server certificate");
    if (noise_decrypt(temp_k2, 0, ctx->h, 32, resp + 144, 90, sig_msg) != 0) {
        ESP_LOGE(TAG, "Failed to decrypt server certificate (MAC verification failed)");
        return -1;
    }
    mix_hash(ctx->h, resp + 144, 90);
    ESP_LOGI(TAG, "Server certificate decrypted");

    // Step 14: Parse signature message
    // version(u16 LE) + valid_from(u32 LE) + not_valid_after(u32 LE) + schnorr_sig(64B)
    uint16_t cert_version = read_u16_le(sig_msg);
    uint32_t valid_from = read_u32_le(sig_msg + 2);
    uint32_t not_valid_after = read_u32_le(sig_msg + 6);
    const uint8_t *schnorr_sig = sig_msg + 10;

    ESP_LOGI(TAG, "Server certificate: version=%d, valid_from=%lu, not_valid_after=%lu",
             cert_version,
             (unsigned long)valid_from,
             (unsigned long)not_valid_after);

    bool enforce_cert_time = cert_time_check == SV2_CERT_TIME_CHECK_SYSTEM_CLOCK;
    time_t now = enforce_cert_time ? time(NULL) : 0;

    // Step 15: Verify Schnorr signature if authority pubkey provided
    if (authority_pubkey) {
        ESP_LOGI(TAG, "Verifying server certificate (Schnorr/BIP-340)...");
        if (enforce_cert_time) {
            uint32_t now_u32 = (uint32_t)now;
            uint32_t valid_from_with_leeway =
                valid_from > SV2_CERT_TIME_LEEWAY_SECONDS ? valid_from - SV2_CERT_TIME_LEEWAY_SECONDS : 0;
            uint32_t not_valid_after_with_leeway =
                UINT32_MAX - not_valid_after < SV2_CERT_TIME_LEEWAY_SECONDS ?
                UINT32_MAX : not_valid_after + SV2_CERT_TIME_LEEWAY_SECONDS;
            if (valid_from_with_leeway > now_u32 ||
                    not_valid_after_with_leeway < now_u32) {
                ESP_LOGE(TAG,
                         "Server certificate is outside local clock window (now=%lu)",
                         (unsigned long)now_u32);
                return -1;
            }
        } else {
            ESP_LOGW(TAG,
                     "Skipping SV2 certificate time-window check; authority signature is still verified");
        }

        // Decode the responder's static public key from ElligatorSwift to get x-only bytes
        uint8_t sig_hash[32];
        {
            mbedtls_sha256_context sha;
            mbedtls_sha256_init(&sha);
            mbedtls_sha256_starts(&sha, 0);
            mbedtls_sha256_update(&sha, sig_msg, 10); // version(2) + valid_from(4) + not_valid_after(4)
            // Decode rs_static to get the actual 32-byte x-only pubkey
            secp256k1_pubkey decoded_pubkey;
            secp256k1_ellswift_decode(ctx->secp_ctx, &decoded_pubkey, rs_static);
            secp256k1_xonly_pubkey xonly_pk;
            int pk_parity;
            if (!secp256k1_xonly_pubkey_from_pubkey(ctx->secp_ctx, &xonly_pk, &pk_parity, &decoded_pubkey)) {
                ESP_LOGE(TAG, "Failed to extract x-only pubkey from server key");
                mbedtls_sha256_free(&sha);
                return -1;
            }
            uint8_t xonly_bytes[32];
            secp256k1_xonly_pubkey_serialize(ctx->secp_ctx, xonly_bytes, &xonly_pk);
            mbedtls_sha256_update(&sha, xonly_bytes, 32);
            mbedtls_sha256_finish(&sha, sig_hash);
            mbedtls_sha256_free(&sha);
        }

        // Parse authority pubkey
        secp256k1_xonly_pubkey auth_pk;
        if (!secp256k1_xonly_pubkey_parse(ctx->secp_ctx, &auth_pk, authority_pubkey)) {
            ESP_LOGE(TAG, "Invalid authority public key");
            return -1;
        }

        // Verify Schnorr signature
        if (!secp256k1_schnorrsig_verify(ctx->secp_ctx, schnorr_sig,
                                          sig_hash, 32, &auth_pk)) {
            ESP_LOGE(TAG, "Server certificate INVALID - Schnorr signature verification failed!");
            return -1;
        }
        ESP_LOGI(TAG, "Server certificate verified OK");
    } else {
        ESP_LOGW(TAG, "No authority key is configured; server identity is not verified");
        if (enforce_cert_time && ((uint32_t)now < valid_from || (uint32_t)now > not_valid_after)) {
            ESP_LOGW(TAG,
                     "Server certificate is outside local clock window but no authority key is configured; continuing without server identity verification");
        }
    }

    // Step 16: Key split — derive send_key and recv_key
    hkdf2(ctx->ck, (const uint8_t *)"", 0, ctx->send_key, ctx->recv_key);

    // Step 17: Zero ephemeral private key and temporaries
    memset(ctx->e_priv, 0, 32);
    memset(ctx->ck, 0, 32);
    memset(ctx->h, 0, 32);
    memset(shared, 0, sizeof(shared));
    memset(shared2, 0, sizeof(shared2));
    memset(temp_k, 0, sizeof(temp_k));
    memset(temp_k2, 0, sizeof(temp_k2));
    memset(sig_msg, 0, sizeof(sig_msg));
    memset(rs_static, 0, sizeof(rs_static));

    ctx->send_nonce = 0;
    ctx->recv_nonce = 0;
    ctx->handshake_complete = true;

    float hs_elapsed_ms = (float)(esp_timer_get_time() - hs_start_us) / 1000.0f;
    ESP_LOGI(TAG, "Noise handshake complete (%.0f ms)", hs_elapsed_ms);
    return 0;
}

int sv2_noise_send(sv2_noise_ctx_t *ctx, esp_transport_handle_t transport,
                   const uint8_t *frame, int frame_len)
{
    if (!ctx || !ctx->handshake_complete || transport == NULL ||
            frame_len < SV2_FRAME_HEADER_SIZE) {
        return -1;
    }
    int payload_len = frame_len - SV2_FRAME_HEADER_SIZE;
    uint64_t header_nonce = ctx->send_nonce;
    if (payload_len > SV2_NOISE_MAX_SEND_PAYLOAD) {
        ESP_LOGE(TAG, "SV2 send payload too large: %d > %d",
                 payload_len, SV2_NOISE_MAX_SEND_PAYLOAD);
        return -1;
    }

    // Encrypt header (6 bytes -> 22 bytes)
    uint8_t enc_hdr[22];
    if (noise_encrypt(ctx->send_key, header_nonce, NULL, 0,
                      frame, SV2_FRAME_HEADER_SIZE, enc_hdr) != 0) {
        return -1;
    }

    // Encrypt payload if present
    if (payload_len > 0) {
        if (noise_encrypt(ctx->send_key, header_nonce + 1, NULL, 0,
                          frame + SV2_FRAME_HEADER_SIZE, payload_len,
                          ctx->send_buf) != 0) {
            return -1;
        }
    }

    if (noise_send_all(transport, enc_hdr, 22) != 0) {
        return -1;
    }

    if (payload_len > 0 && noise_send_all(transport, ctx->send_buf, payload_len + 16) != 0) {
        return -1;
    }

    ctx->send_nonce = header_nonce + (payload_len > 0 ? 2U : 1U);
    return 0;
}

int sv2_noise_recv(sv2_noise_ctx_t *ctx, esp_transport_handle_t transport,
                   uint8_t hdr_out[6], uint8_t *payload_out,
                   int max_payload_len, int *payload_len_out)
{
    if (!ctx || !ctx->handshake_complete || transport == NULL) {
        return -1;
    }

    *payload_len_out = 0;

    // Receive and decrypt header (22 bytes -> 6 bytes)
    uint8_t enc_hdr[22];
    if (noise_recv_exact(transport, enc_hdr, 22, RECV_TIMEOUT_MS) != 0) {
        return -1;
    }

    if (noise_decrypt(ctx->recv_key, ctx->recv_nonce++, NULL, 0,
                      enc_hdr, 22, hdr_out) != 0) {
        ESP_LOGE(TAG, "Failed to decrypt frame header");
        return -1;
    }

    // Parse header to get msg_length
    sv2_frame_header_t hdr;
    sv2_parse_frame_header(hdr_out, &hdr);

    if (hdr.msg_length == 0) {
        return 0;
    }

    if (max_payload_len > SV2_NOISE_MAX_RECV_PAYLOAD) {
        ESP_LOGE(TAG, "Configured SV2 receive buffer too large: %d > %d",
                 max_payload_len, SV2_NOISE_MAX_RECV_PAYLOAD);
        return -1;
    }

    if ((int)hdr.msg_length > max_payload_len) {
        ESP_LOGE(TAG, "Payload too large: %lu > %d",
                 (unsigned long)hdr.msg_length,
                 max_payload_len);
        return -1;
    }

    // Receive and decrypt payload
    int enc_len = hdr.msg_length + 16;

    if (noise_recv_exact(transport, ctx->recv_buf, enc_len, RECV_TIMEOUT_MS) != 0) {
        return -1;
    }

    if (noise_decrypt(ctx->recv_key, ctx->recv_nonce++, NULL, 0,
                      ctx->recv_buf, enc_len, payload_out) != 0) {
        ESP_LOGE(TAG, "Failed to decrypt payload");
        return -1;
    }

    *payload_len_out = hdr.msg_length;
    return 0;
}
