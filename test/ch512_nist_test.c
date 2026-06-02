#include "../include/ch512.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define TEST_SAMPLES 1000000
#define BINS 256

static double frequency_test(const uint8_t *data, size_t len) {
    long long sum = 0;
    for (size_t i = 0; i < len; i++) {
        for (int b = 0; b < 8; b++) {
            if (data[i] & (1 << b)) sum++;
            else sum--;
        }
    }
    double s_obs = fabs(sum) / sqrt(len * 8);
    double p_value = erfc(s_obs / sqrt(2));
    return p_value;
}

static double chi_square_test(const uint8_t *data, size_t len) {
    long long counts[BINS] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double chi2 = 0;
    double expected = (double)len / BINS;
    for (int i = 0; i < BINS; i++) {
        double diff = counts[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

static void generate_test_samples(uint8_t *output, size_t len) {
    uint8_t key[KEY_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    uint8_t plain[16];
    ch512_ctx ctx;
    memset(key, 0, KEY_SIZE);
    memset(iv, 0, GCM_IV_SIZE);
    memset(plain, 0, 16);
    ch512_init(&ctx, key);
    for (size_t i = 0; i < len; i += 16) {
        plain[0] = (i >> 0) & 0xFF;
        plain[1] = (i >> 8) & 0xFF;
        plain[2] = (i >> 16) & 0xFF;
        plain[3] = (i >> 24) & 0xFF;
        ch512_encrypt_block(&ctx, plain, output + i);
    }
}

int main(void) {
    printf("CH512 NIST Statistical Tests\n");
    printf("=============================\n\n");
    
    uint8_t *samples = malloc(TEST_SAMPLES);
    if (!samples) { printf("MEMORY ERROR\n"); return 1; }
    
    printf("Generating %d random samples...\n", TEST_SAMPLES);
    generate_test_samples(samples, TEST_SAMPLES);
    
    printf("\n[TEST 1] Frequency (Monobit) Test\n");
    double p_freq = frequency_test(samples, TEST_SAMPLES);
    printf("P-value: %f\n", p_freq);
    printf("Result: %s (threshold 0.01)\n\n", (p_freq > 0.01) ? "PASS" : "FAIL");
    
    printf("[TEST 2] Chi-Square Distribution Test\n");
    double chi2 = chi_square_test(samples, TEST_SAMPLES);
    double chi2_threshold = 293.25;
    printf("Chi-square: %f (threshold %f)\n", chi2, chi2_threshold);
    printf("Result: %s\n\n", (chi2 < chi2_threshold) ? "PASS" : "FAIL");
    
    printf("[TEST 3] Entropy Estimate (Shannon)\n");
    long long counts[BINS] = {0};
    for (int i = 0; i < TEST_SAMPLES; i++) counts[samples[i]]++;
    double entropy = 0;
    for (int i = 0; i < BINS; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / TEST_SAMPLES;
            entropy -= p * log2(p);
        }
    }
    printf("Entropy: %f bits per byte (ideal 8.0)\n", entropy);
    printf("Result: %s\n\n", (entropy > 7.99) ? "EXCELLENT" : (entropy > 7.9) ? "GOOD" : "POOR");
    
    free(samples);
    printf("=============================\n");
    printf("ALL TESTS COMPLETED\n");
    return 0;
}