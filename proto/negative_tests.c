/*
 * negative_tests.c - protocol-level tests of the per-hop verification rule
 * (Algorithm 1) using the real SipHash-2-4 and the packet format of the paper.
 *
 * Build: gcc -O2 -std=c11 -o negative_tests negative_tests.c
 * Run:   ./negative_tests        (exit code 0 iff every expectation holds)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "siphash.h"
#include "sha256.h"

#define NSID 24
#define SL0  12
typedef struct { uint32_t base; uint64_t bits[4]; } rwin_t;
typedef struct {
    uint8_t src[16]; uint32_t fl; uint8_t sid[NSID][16]; /* sid[0] = final dst */
    uint8_t dom; uint32_t seq; uint8_t tag[8];
    uint8_t da[16]; int sl;
} pkt_t;
typedef struct {
    uint8_t dom; int dir_ok[16]; uint8_t key[2][16]; int nkeys; rwin_t win[2][16];
} node_t;
enum { ACCEPT, DROP_POS, DROP_DOM, DROP_DIR, DROP_MAC, DROP_REPLAY, NREASON };
static const char *RN[NREASON] = {"accept","position","domain","direction","mac","replay"};

static int rwin_check_advance(rwin_t *w, uint32_t seq){
    if(seq<=w->base) return 0;
    uint32_t off=seq-w->base-1;
    if(off>=256){
        uint32_t shift=off-255;
        if(shift>=256) memset(w->bits,0,32);
        else{
            uint32_t ws=shift/64, bs=shift%64;
            for(int i=0;i<4;i++){
                uint32_t s=i+ws;
                uint64_t v=(s<4?w->bits[s]:0), n=(s+1<4?w->bits[s+1]:0);
                w->bits[i]= bs ? (v>>bs)|(n<<(64-bs)) : v;
            }
        }
        w->base+=shift; off=255;
    }
    if((w->bits[off/64]>>(off%64))&1) return 0;
    w->bits[off/64]|=(uint64_t)1<<(off%64);
    return 1;
}

static size_t mac_input(const pkt_t *p, uint8_t *b){
    size_t n=0;
    memcpy(b+n,p->src,16); n+=16;
    memcpy(b+n,p->sid[0],16); n+=16;
    b[n++]=(p->fl>>16)&0x0f; b[n++]=(p->fl>>8)&0xff; b[n++]=p->fl&0xff;
    for(int i=0;i<NSID;i++){ memcpy(b+n,p->sid[i],16); n+=16; }
    b[n++]=p->dom;
    for(int i=0;i<4;i++) b[n++]=(uint8_t)(p->seq>>(24-8*i));
    return n;
}
static uint64_t tag_of(const pkt_t *p, const uint8_t key[16]){
    uint8_t b[40+16*NSID]; size_t n=mac_input(p,b);
    return siphash24(key,b,n);
}
static void seal(pkt_t *p, const uint8_t key[16]){
    uint64_t t=tag_of(p,key); memcpy(p->tag,&t,8);
}

static int verify(node_t *v, const pkt_t *p, int arrival){
    const uint8_t *sid=p->sid[p->sl];
    if(memcmp(p->da,sid,16)) return DROP_POS;
    if(p->dom!=v->dom || sid[11]!=p->dom) return DROP_DOM;
    int ing=sid[10]>>4, egr=sid[10]&0x0f;
    if(ing!=arrival || !v->dir_ok[egr]) return DROP_DIR;
    int e=-1; uint64_t t; memcpy(&t,p->tag,8);
    for(int k=0;k<v->nkeys;k++) if(tag_of(p,v->key[k])==t){ e=k; break; }
    if(e<0) return DROP_MAC;
    if(!rwin_check_advance(&v->win[e][egr],p->seq)) return DROP_REPLAY;
    return ACCEPT;
}

static const uint8_t K0[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static const uint8_t K1[16]={9,9,9,9,8,8,8,8,7,7,7,7,6,6,6,6};
static const uint8_t KX[16]={0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,1,2,3,4,5,6,7,8,9,0};
#define DOM 7

static void init_node(node_t *v){
    memset(v,0,sizeof *v); v->dom=DOM; v->nkeys=2;
    memcpy(v->key[0],K0,16); memcpy(v->key[1],K1,16);
    for(int d=0;d<5;d++) v->dir_ok[d]=1;       /* direction 5 unauthorized */
}
static void set_sid(pkt_t *p,int i,int ing,int egr,int dom){
    uint8_t *s=p->sid[i]; memset(s,0,16);
    s[0]=0xfc; s[1]=0x00; s[7]=(uint8_t)i; s[9]=0x01;   /* locator, End.SEC */
    s[10]=(uint8_t)((ing<<4)|egr); s[11]=(uint8_t)dom; s[12]=0xa5;
}
static void build(pkt_t *p,uint32_t seq,int sl){
    memset(p,0,sizeof *p);
    for(int i=0;i<16;i++) p->src[i]=(uint8_t)(0x20+i);
    p->fl=0xABCDE; p->dom=DOM; p->seq=seq;
    for(int i=0;i<NSID;i++) set_sid(p,i,i%4,(i+1)%4,DOM);
    p->sl=sl; memcpy(p->da,p->sid[sl],16); seal(p,K0);
}

static int failures=0;
static void expect(const char *name,int got,int want){
    int ok=(got==want); if(!ok) failures++;
    printf("  %-44s got %-9s want %-9s %s\n",name,RN[got],RN[want],ok?"ok":"FAIL");
}
static int run1(const pkt_t *p,int arrival){
    node_t v; init_node(&v); return verify(&v,p,arrival);
}
static uint64_t rng=0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void){ rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }

static void flip_bit(pkt_t *p,int bit){
    if(bit<128){ p->src[bit/8]^=1<<(bit%8); return; }
    bit-=128;
    if(bit<NSID*128){
        int i=bit/128, b=bit%128; p->sid[i][b/8]^=1<<(b%8);
        if(i==p->sl) p->da[b/8]^=1<<(b%8);          /* keep DA consistent */
        return;
    }
    bit-=NSID*128;
    if(bit<20){ p->fl^=1u<<bit; return; }
    bit-=20;
    if(bit<8){ p->dom^=1<<bit; return; }
    bit-=8;
    if(bit<32){ p->seq^=1u<<bit; return; }
    bit-=32; p->tag[bit/8]^=1<<(bit%8);
}

int main(void){
    pkt_t p; node_t v; build(&p,1000,SL0);
    printf("Single-case tests (node at SL=%d, arrival dir 0):\n",SL0);
    expect("valid packet",run1(&p,0),ACCEPT);
    { init_node(&v); verify(&v,&p,0); expect("duplicate sequence",verify(&v,&p,0),DROP_REPLAY); }
    { init_node(&v); pkt_t a; build(&a,1000,SL0); verify(&v,&a,0);
      pkt_t s; build(&s,500,SL0); expect("stale sequence (below window base)",verify(&v,&s,0),DROP_REPLAY); }
    { pkt_t q=p; q.da[7]^=1; expect("DA differs from SID at SL",run1(&q,0),DROP_POS); }
    { pkt_t q=p; flip_bit(&q,0); expect("changed source",run1(&q,0),DROP_MAC); }
    { pkt_t q=p; flip_bit(&q,128); expect("changed final destination SID[0]",run1(&q,0),DROP_MAC); }
    { pkt_t q=p; q.fl^=1; expect("changed Flow Label",run1(&q,0),DROP_MAC); }
    { pkt_t q=p; q.seq++; expect("changed sequence, old tag",run1(&q,0),DROP_MAC); }
    { pkt_t q=p; q.tag[3]^=0x10; expect("changed tag",run1(&q,0),DROP_MAC); }
    { pkt_t q=p; q.dom=DOM+1; expect("changed domain id",run1(&q,0),DROP_DOM); }
    { int bad=0; for(int i=0;i<NSID;i++){ pkt_t q=p; q.sid[i][0]^=0x01; if(i==q.sl) q.da[0]^=0x01;
        if(run1(&q,0)!=DROP_MAC) bad++; } expect("changed any one of 24 SIDs (all 24 tried)",bad?DROP_POS:DROP_MAC,DROP_MAC); }
    { pkt_t q; build(&q,2000,SL0); seal(&q,KX); expect("tag under unknown key",run1(&q,0),DROP_MAC); }
    { pkt_t q; build(&q,2001,SL0); seal(&q,K1); expect("tag under overlap (previous) epoch key",run1(&q,0),ACCEPT); }
    { pkt_t q; build(&q,2002,SL0); set_sid(&q,SL0,0,5,DOM); memcpy(q.da,q.sid[SL0],16); seal(&q,K0);
      expect("valid MAC, egress direction unauthorized",run1(&q,0),DROP_DIR); }
    expect("arrival direction differs from SID ingress",run1(&p,3),DROP_DIR);
    { pkt_t q; build(&q,2003,SL0); set_sid(&q,SL0,0,1,DOM+1); memcpy(q.da,q.sid[SL0],16); seal(&q,K0);
      expect("valid MAC, SID domain differs from packet",run1(&q,0),DROP_DOM); }
    printf("Documented limit (SL not covered by the tag):\n");
    { pkt_t q=p; q.sl=5; memcpy(q.da,q.sid[5],16);
      expect("SL/DA moved to later SID, matching arrival dir",run1(&q,1),ACCEPT);
      expect("same, but arrival dir does not match SID",run1(&q,0),DROP_DIR); }

    const long N=1000000; long acc=0, byr[NREASON]={0};
    const int nbits=128+NSID*128+20+8+32+64;
    for(long i=0;i<N;i++){
        pkt_t q; build(&q,5000+(uint32_t)(i&0xff),SL0);
        flip_bit(&q,(int)(rnd()%nbits));
        int r=run1(&q,0); byr[r]++; if(r==ACCEPT) acc++;
    }
    printf("Fuzz: %ld single-bit flips of covered fields/tag: accepted=%ld", N, acc);
    for(int r=1;r<NREASON;r++) printf(" %s=%ld",RN[r],byr[r]);
    printf("\n");
    if(acc) failures++;
    printf("%s (%d failures)\n",failures?"FAILED":"ALL EXPECTATIONS HOLD",failures);
    return failures?1:0;
}
