/*
 * bench_flas.c — 6FLAS software prototype benchmark
 *
 * Measures per-packet CPU cycles for:
 *   FLAS      : SipHash-2-4 over 72B routing span + O(1) replay window
 *   SRv6-Sec  : HMAC-SHA256 over same 72B span (RFC 8754 HMAC-TLV baseline)
 *   IPsec-like: HMAC-SHA256 over (40+512)=552B + AES-128-CBC over 512B
 *
 * Outputs a JSON block compatible with ../eval/data.json for direct comparison
 * against the analytical model in ../eval/flas_model.py.
 *
 * Build:  gcc -O2 -o bench_flas bench_flas.c   (Linux/macOS)
 *         gcc -O2 -o bench_flas bench_flas.c    (Windows via MinGW/WSL)
 * Run:    ./bench_flas
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "siphash.h"
#include "sha256.h"

/* ── RDTSC ─────────────────────────────────────────────────────────────── */
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

/* ── Minimal AES-128 (encrypt only, for CBC baseline) ───────────────────
 * Adapted from Tiny-AES-c by kokke — public domain.                       */
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

/* ── Replay window (256-bit sliding bitmap) ─────────────────────────────── */
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

/* ── Simulated packet fields ─────────────────────────────────────────────── */
/* 72-byte covered span: 40B IPv6 base header + 24B SRH-with-one-SID + 8B metadata */
#define COVERED 72
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

#define NOINLINE __attribute__((noinline))

/* ── FLAS pipeline ───────────────────────────────────────────────────────── */
static rwin_t flas_windows[6]; /* one per +Grid direction */

NOINLINE static uint64_t bench_flas(uint32_t *seq_ctr){
    /* Simulate 6 direction windows; hash flow label to select direction */
    uint32_t fl; memcpy(&fl, PKT+6, 3); /* bytes 6-8 of IPv6 hdr = flow label */
    fl &= 0x0fffff;
    rwin_t *w = &flas_windows[fl % 6];

    uint32_t seq = (*seq_ctr)++;

    /* Replay window probe */
    if(!rwin_check_advance(w, seq)) seq = *seq_ctr; /* accept all in bench */

    /* MAC recompute over 72-byte covered span */
    uint64_t tag = siphash24(domain_key, PKT, COVERED);

    /* Direction check (constant-time comparison against 6-element set) */
    uint8_t dir = PKT[COVERED-8]; /* domid byte encodes direction */
    int ok = (dir < 6);
    (void)ok; (void)tag;

    return tag; /* return to prevent dead-code elimination */
}

/* ── SRv6-Sec baseline: HMAC-SHA256 over 72B ────────────────────────────── */
NOINLINE static void bench_srv6sec(uint8_t out[32]){
    hmac_sha256(hmac_key, 32, PKT, COVERED, out);
}

/* ── IPsec-like baseline: HMAC-SHA256 over (40+PAYLOAD)B + AES-CBC ──────── */
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

/* ── Timing harness ─────────────────────────────────────────────────────── */
#define WARMUP   10000
#define ITERS  1000000

static uint64_t measure_flas(void){
    uint32_t seq=1; uint64_t acc=0, sink=0;
    for(int i=0;i<WARMUP;i++) sink^=bench_flas(&seq);
    uint64_t t0=RDTSC();
    for(int i=0;i<ITERS;i++) sink^=bench_flas(&seq);
    acc=RDTSC()-t0;
    (void)sink; return acc/ITERS;
}

static uint64_t measure_srv6sec(void){
    uint8_t out[32]; uint64_t acc=0;
    for(int i=0;i<WARMUP;i++) bench_srv6sec(out);
    uint64_t t0=RDTSC();
    for(int i=0;i<ITERS;i++) bench_srv6sec(out);
    acc=RDTSC()-t0; (void)out; return acc/ITERS;
}

static uint64_t measure_ipsec(void){
    uint8_t out[32]; uint64_t acc=0;
    for(int i=0;i<WARMUP;i++) bench_ipsec(out);
    uint64_t t0=RDTSC();
    for(int i=0;i<ITERS;i++) bench_ipsec(out);
    acc=RDTSC()-t0; (void)out; return acc/ITERS;
}

int main(void){
    /* Fill packet with deterministic data */
    for(int i=0;i<(int)sizeof(PKT);i++) PKT[i]=(uint8_t)(i*7+3);
    /* IPv6 version/TC/FL: flow label = 0xABCDE (bits 12-31 of word 0) */
    PKT[0]=0x60; PKT[1]=0x0a; PKT[2]=0xbc; PKT[3]=0xde;

    aes128_init(&aes_ctx, aes_key);
    for(int d=0;d<6;d++) rwin_init(&flas_windows[d]);

    fprintf(stderr,"Running %d iterations (warmup %d)...\n",ITERS,WARMUP);

    uint64_t cyc_flas    = measure_flas();
    uint64_t cyc_srv6sec = measure_srv6sec();
    uint64_t cyc_ipsec   = measure_ipsec();

    double ratio_srv6 = (double)cyc_srv6sec / (double)cyc_flas;
    double ratio_ipsec= (double)cyc_ipsec   / (double)cyc_flas;

    /* Human-readable summary to stderr */
    fprintf(stderr,"\n--- Results (cycles/packet on host CPU) ---\n");
    fprintf(stderr,"  FLAS         : %6llu cyc\n",(unsigned long long)cyc_flas);
    fprintf(stderr,"  SRv6-Sec     : %6llu cyc  (%.1fx vs FLAS)\n",(unsigned long long)cyc_srv6sec,ratio_srv6);
    fprintf(stderr,"  IPsec-like   : %6llu cyc  (%.1fx vs FLAS)\n",(unsigned long long)cyc_ipsec,ratio_ipsec);
    fprintf(stderr,"\nAnalytical model predicts: SRv6-Sec %.1fx, IPsec %.1fx\n",5.9,47.8);
    fprintf(stderr,"Covered span: %dB  Payload: %dB  Iterations: %d\n",COVERED,PAYLOAD,ITERS);

    /* JSON output to stdout — matches ../eval/data.json schema */
    printf("{\n");
    printf("  \"proto_bench\": {\n");
    printf("    \"note\": \"measured cycles/pkt on host CPU; ratios compare to analytical model\",\n");
    printf("    \"covered_bytes\": %d,\n", COVERED);
    printf("    \"payload_bytes\": %d,\n", PAYLOAD);
    printf("    \"iterations\": %d,\n",    ITERS);
    printf("    \"cycles_per_pkt\": {\n");
    printf("      \"FLAS\":         %llu,\n",(unsigned long long)cyc_flas);
    printf("      \"SRv6-Sec\":     %llu,\n",(unsigned long long)cyc_srv6sec);
    printf("      \"IPsec-like\":   %llu\n", (unsigned long long)cyc_ipsec);
    printf("    },\n");
    printf("    \"speedup_vs_flas\": {\n");
    printf("      \"SRv6-Sec\": %.2f,\n", ratio_srv6);
    printf("      \"IPsec\":    %.2f\n",  ratio_ipsec);
    printf("    },\n");
    printf("    \"analytical_model_speedup\": {\n");
    printf("      \"SRv6-Sec\": 5.9,\n");
    printf("      \"IPsec\":    47.8\n");
    printf("    }\n");
    printf("  }\n}\n");
    return 0;
}
