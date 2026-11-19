/* Research fixed-fixture microbenchmark. See docs/METHODOLOGY.md.
 * Primary pair includes local checks and replay; SRv6-Sec is MAC-only.
 * IPsec-like is CBC/HMAC work, not measured shared-SA AES-GCM/ESP.
 * On x86 timings are RDTSC ticks, not necessarily core cycles.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "siphash.h"
#include "sha256.h"
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#  include <cpuid.h>
#  define HAVE_CPUID 1
#endif

/* 鈹€鈹€ RDTSC 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
#if defined(_MSC_VER)
#  include <intrin.h>
#  define RDTSC() __rdtsc()
#elif defined(__i386__) || defined(__x86_64__)
static inline uint64_t RDTSC(void){
    uint32_t lo,hi;
    __asm__ __volatile__("lfence\nrdtsc":"=a"(lo),"=d"(hi)::"memory");
    return ((uint64_t)hi<<32)|lo;
}
#else
/* Fallback: use clock_gettime (cycles approximated from ns) */
static inline uint64_t RDTSC(void){
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}
#endif

/* 鈹€鈹€ Minimal AES-128 (encrypt only, for CBC baseline) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * Adapted from Tiny-AES-c by kokke 鈥?public domain.                       */
static const uint8_t sbox[256]={
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t rcon[11]={0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t xtime(uint8_t x){ return (x<<1)^((x>>7)*0x1b); }
static uint8_t mul2(uint8_t a,uint8_t b){
    uint8_t r=0; for(int i=0;i<8;i++){if(b&1)r^=a;uint8_t hi=a>>7;a<<=1;a^=hi*0x1b;b>>=1;} return r;
}

typedef struct { uint8_t rk[11][16]; } aes128_ctx;

static void aes128_init(aes128_ctx *ctx, const uint8_t key[16]){
    memcpy(ctx->rk[0],key,16);
    for(int r=1;r<11;r++){
        uint8_t *prev=ctx->rk[r-1], *cur=ctx->rk[r];
        uint8_t tmp[4]={sbox[prev[13]],sbox[prev[14]],sbox[prev[15]],sbox[prev[12]]};
        tmp[0]^=rcon[r];
        for(int j=0;j<4;j++) cur[j]=prev[j]^tmp[j];
        for(int j=4;j<16;j++) cur[j]=prev[j]^cur[j-4];
    }
}

static void aes128_encrypt(const aes128_ctx *ctx, uint8_t b[16]){
    for(int i=0;i<16;i++) b[i]^=ctx->rk[0][i];
    for(int r=1;r<=10;r++){
        /* SubBytes */
        for(int i=0;i<16;i++) b[i]=sbox[b[i]];
        /* ShiftRows */
        uint8_t t;
        t=b[1]; b[1]=b[5]; b[5]=b[9]; b[9]=b[13]; b[13]=t;
        t=b[2]; b[2]=b[10]; b[10]=t; t=b[6]; b[6]=b[14]; b[14]=t;
        t=b[15]; b[15]=b[11]; b[11]=b[7]; b[7]=b[3]; b[3]=t;
        /* MixColumns (skip for round 10) */
        if(r<10){
            for(int c=0;c<4;c++){
                uint8_t *s=b+c*4;
                uint8_t a0=s[0],a1=s[1],a2=s[2],a3=s[3];
                s[0]=mul2(a0,2)^mul2(a1,3)^a2^a3;
                s[1]=a0^mul2(a1,2)^mul2(a2,3)^a3;
                s[2]=a0^a1^mul2(a2,2)^mul2(a3,3);
                s[3]=mul2(a0,3)^a1^a2^mul2(a3,2);
            }
        }
        /* AddRoundKey */
        for(int i=0;i<16;i++) b[i]^=ctx->rk[r][i];
    }
    (void)xtime;
}

/* AES-128-CBC over `len` bytes (must be multiple of 16) */
static void aes128_cbc(const aes128_ctx *ctx, uint8_t *data, size_t len, uint8_t iv[16]){
    for(size_t i=0;i<len;i+=16){
        for(int j=0;j<16;j++) data[i+j]^=iv[j];
        aes128_encrypt(ctx,(uint8_t*)data+i);
        memcpy(iv,data+i,16);
    }
}

/* 鈹€鈹€ Replay window (256-bit sliding bitmap) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
typedef struct { uint32_t base; uint64_t bits[4]; } rwin_t; /* 256 entries */

static void rwin_init(rwin_t *w){ w->base=0; memset(w->bits,0,32); }

/* Returns 1 if seq is acceptable (not seen), 0 if replay/stale. */
static int rwin_check_advance(rwin_t *w, uint32_t seq){
    if(seq<=w->base) return 0;
    uint32_t off=seq-w->base-1;
    if(off>=256){
        uint32_t shift=off-255;
        if(shift>=256){memset(w->bits,0,32);}
        else{
            uint32_t wshift=shift/64, bshift=shift%64;
            for(int i=0;i<4;i++){
                uint32_t src=i+wshift;
                w->bits[i]=(src<4?w->bits[src]:0);
                if(bshift && src+1<4) w->bits[i]|=(w->bits[src+1]<<(64-bshift));
                if(bshift) w->bits[i]>>=bshift;
            }
        }
        w->base+=shift; off=255;
    }
    if((w->bits[off/64]>>(off%64))&1) return 0;
    w->bits[off/64]|=(uint64_t)1<<(off%64);
    return 1;
}

/* 鈹€鈹€ Simulated packet fields 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
/* Representative 24-SID routing context:
 * 40B fixed endpoint/Flow-Label fields + 24 * 16B SIDs. */
#define MODEL_PATH_SIDS 24
#define COVERED (40 + 16 * MODEL_PATH_SIDS)
#define PAYLOAD 512

static uint8_t  domain_key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                   0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
static uint8_t  hmac_key[32]   = {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                                   0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                                   0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                                   0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe};
static uint8_t  aes_key[16]    = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                   0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

/* packet buffer: covered span + payload */
static uint8_t PKT[COVERED+PAYLOAD];

#if defined(_MSC_VER)
#  define NOINLINE __declspec(noinline)
#else
#  define NOINLINE __attribute__((noinline))
#endif

/* 鈹€鈹€ FLAS pipeline 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
/* SRv6-Sec baseline (RFC 8754 profile): per-flow-key HMAC-SHA256 over the routing context, MAC only. */
NOINLINE static void bench_srv6sec(uint8_t out[32]){
    hmac_sha256(hmac_key, 32, PKT, COVERED, out);
}

/* 鈹€鈹€ IPsec-like baseline: HMAC-SHA256 over (40+PAYLOAD)B + AES-CBC 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
static aes128_ctx aes_ctx;

NOINLINE static void bench_ipsec(uint8_t hmac_out[32]){
    /* HMAC over IPv6 header + payload (simplified: no explicit ESP header) */
    hmac_sha256(hmac_key, 32, PKT, 40+PAYLOAD, hmac_out);
    /* AES-128-CBC over PAYLOAD */
    uint8_t iv[16]={0}; uint8_t buf[PAYLOAD];
    memcpy(buf, PKT+COVERED, PAYLOAD);
    aes128_cbc(&aes_ctx, buf, PAYLOAD, iv);
    /* XOR into out to prevent dead-code elimination */
    for(int i=0;i<16;i++) hmac_out[i]^=buf[i];
}

/* 鈹€鈹€ Timing harness 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */
#define WARMUP        10000
#define REPS          11
#define ITERS_PER_REP 100000

typedef uint64_t (*bench_fn)(void);
static uint32_t g_seq = 1;
static uint8_t  g_out[32];
static sha256_ctx g_ictx, g_octx;
static volatile uint64_t g_sink;

/* Verification frame shared by the 6FLAS and SRv6-HMAC-64 cases (Algorithm 1):
 * DA == SID[SL], domain, ingress/egress direction, MAC compare, replay window.
 * Only the MAC differs. Tags are precomputed so that the packet is accepted. */
typedef struct { uint8_t da[16], sid[16]; uint8_t dom, ing, egr; uint64_t tag_sip, tag_hmac; } hdr_t;
static hdr_t HDR;
static uint8_t dir_ok[16];
static rwin_t frame_win[2][16];
#define NODE_DOM 7
static volatile int g_arrival = 1;
static uint64_t g_fail;

NOINLINE static uint64_t verify_frame(int use_sip, rwin_t *wins, uint32_t *seq_ctr){
    const hdr_t *h = &HDR;
    uint64_t t, want;
    if(memcmp(h->da, h->sid, 16)) { g_fail++; return 1; }
    if(h->dom != NODE_DOM)        { g_fail++; return 2; }
    if(h->ing != g_arrival || !dir_ok[h->egr]) { g_fail++; return 3; }
    if(use_sip){ t = siphash24(domain_key, PKT, COVERED); want = h->tag_sip; }
    else {
        uint8_t ih[32], o[32]; sha256_ctx c = g_ictx;
        sha256_update(&c, PKT, COVERED); sha256_final(&c, ih);
        c = g_octx; sha256_update(&c, ih, 32); sha256_final(&c, o);
        memcpy(&t, o, 8); want = h->tag_hmac;
    }
    if(t != want)                 { g_fail++; return 4; }
    if(!rwin_check_advance(&wins[h->egr], (*seq_ctr)++)) { g_fail++; return 5; }
    return t;
}


NOINLINE static uint64_t run_flas(void){ return verify_frame(1, frame_win[0], &g_seq); }
NOINLINE static uint64_t run_srv6sec(void){ bench_srv6sec(g_out); return g_out[0]; }
NOINLINE static uint64_t run_ipsec(void){ bench_ipsec(g_out); return g_out[0]; }

static uint32_t g_seq2 = 1;
NOINLINE static uint64_t run_hmac64(void){ return verify_frame(0, frame_win[1], &g_seq2); }

static int cmp_u64(const void *a, const void *b){
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static void measure(bench_fn f, uint64_t *med, uint64_t *mn, uint64_t *mx){
    uint64_t r[REPS], sink = 0;
    for(int i = 0; i < WARMUP; i++) sink ^= f();
    for(int k = 0; k < REPS; k++){
        uint64_t t0 = RDTSC();
        for(int i = 0; i < ITERS_PER_REP; i++) sink ^= f();
        r[k] = (RDTSC() - t0) / ITERS_PER_REP;
    }
    qsort(r, REPS, sizeof r[0], cmp_u64);
    *med = r[REPS/2]; *mn = r[0]; *mx = r[REPS-1];
    g_sink ^= sink;
}

static void cpu_brand(char *s){
    strcpy(s, "unknown");
#ifdef HAVE_CPUID
    unsigned a, b, c, d;
    for(int i = 0; i < 3; i++){
        if(!__get_cpuid(0x80000002u + i, &a, &b, &c, &d)) return;
        memcpy(s + 16*i, &a, 4); memcpy(s + 16*i + 4, &b, 4);
        memcpy(s + 16*i + 8, &c, 4); memcpy(s + 16*i + 12, &d, 4);
    }
    s[48] = 0;
#endif
}

int main(void){
    for(int i = 0; i < (int)sizeof(PKT); i++) PKT[i] = (uint8_t)(i*7+3);
    PKT[0]=0x60; PKT[1]=0x0a; PKT[2]=0xbc; PKT[3]=0xde;
    aes128_init(&aes_ctx, aes_key);
    {
        uint8_t k[64] = {0}, ik[64], ok[64];
        memcpy(k, hmac_key, 32);
        for(int i = 0; i < 64; i++){ ik[i] = k[i]^0x36; ok[i] = k[i]^0x5c; }
        sha256_init(&g_ictx); sha256_update(&g_ictx, ik, 64);
        sha256_init(&g_octx); sha256_update(&g_octx, ok, 64);
    }
    for(int i = 0; i < 16; i++) HDR.sid[i] = (uint8_t)(0xfc + i * 3);
    memcpy(HDR.da, HDR.sid, 16);
    HDR.dom = NODE_DOM; HDR.ing = 1; HDR.egr = 2;
    for(int d = 0; d < 5; d++) dir_ok[d] = 1;
    HDR.tag_sip = siphash24(domain_key, PKT, COVERED);
    {
        uint8_t o[32]; sha256_ctx c = g_ictx; uint8_t ih[32];
        sha256_update(&c, PKT, COVERED); sha256_final(&c, ih);
        c = g_octx; sha256_update(&c, ih, 32); sha256_final(&c, o);
        memcpy(&HDR.tag_hmac, o, 8);
    }
    for(int a = 0; a < 2; a++) for(int d = 0; d < 16; d++) rwin_init(&frame_win[a][d]);
    char brand[64]; cpu_brand(brand);
    const char *names[4] = {"FLAS", "SRv6-HMAC-64", "SRv6-Sec", "IPsec-like"};
    bench_fn fns[4] = {run_flas, run_hmac64, run_srv6sec, run_ipsec};
    uint64_t med[4], mn[4], mx[4];
    fprintf(stderr, "CPU: %s\nCompiler: %s\n%d reps x %d iterations (warmup %d)\n",
            brand, __VERSION__, REPS, ITERS_PER_REP, WARMUP);
    for(int i = 0; i < 4; i++){
        measure(fns[i], &med[i], &mn[i], &mx[i]);
        fprintf(stderr, "  %-13s: median %6llu  min %6llu  max %6llu cyc (%.2fx vs FLAS)\n",
                names[i], (unsigned long long)med[i], (unsigned long long)mn[i],
                (unsigned long long)mx[i], (double)med[i]/(double)med[0]);
    }
    printf("{\n  \"proto_bench\": {\n");
    printf("    \"cpu\": \"%s\",\n    \"compiler\": \"%s\",\n", brand, __VERSION__);
#ifdef __OPTIMIZE__
    printf("    \"optimized\": true,\n");
#else
    printf("    \"optimized\": false,\n");
#endif
    printf("    \"timer\": \"RDTSC (TSC cycles, not core cycles)\",\n");
    printf("    \"covered_bytes\": %d,\n    \"payload_bytes\": %d,\n", COVERED, PAYLOAD);
    printf("    \"reps\": %d,\n    \"iterations_per_rep\": %d,\n", REPS, ITERS_PER_REP);
    printf("    \"cycles_per_pkt_median_min_max\": {\n");
    for(int i = 0; i < 4; i++)
        printf("      \"%s\": [%llu, %llu, %llu]%s\n", names[i],
               (unsigned long long)med[i], (unsigned long long)mn[i],
               (unsigned long long)mx[i], i < 3 ? "," : "");
    printf("    },\n    \"ratio_vs_flas\": {\n");
    for(int i = 1; i < 4; i++)
        printf("      \"%s\": %.2f%s\n", names[i], (double)med[i]/(double)med[0], i < 3 ? "," : "");
    printf("    }\n  }\n}\n");
    if(g_fail){ fprintf(stderr, "ERROR: %llu frames were rejected\n", (unsigned long long)g_fail); return 1; }
    return 0;
}
