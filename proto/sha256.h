/* Minimal correct SHA-256 + HMAC-SHA256. Public domain (B-Con / adapted). */
#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct { uint32_t s[8]; uint8_t buf[64]; uint64_t bits; uint32_t blen; } sha256_ctx;

static const uint32_t K[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_compress(sha256_ctx *c,const uint8_t d[64]){
    uint32_t w[64],a,b,cc,dd,e,f,g,h,t1,t2;
    for(int i=0;i<16;i++) w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for(int i=16;i<64;i++) w[i]=(ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10))+w[i-7]+(ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3))+w[i-16];
    a=c->s[0];b=c->s[1];cc=c->s[2];dd=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for(int i=0;i<64;i++){
        t1=h+(ROR(e,6)^ROR(e,11)^ROR(e,25))+((e&f)^(~e&g))+K[i]+w[i];
        t2=(ROR(a,2)^ROR(a,13)^ROR(a,22))+((a&b)^(a&cc)^(b&cc));
        h=g;g=f;f=e;e=dd+t1;dd=cc;cc=b;b=a;a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=dd;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
#undef ROR
static void sha256_init(sha256_ctx *c){
    c->blen=0;c->bits=0;
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
}
static void sha256_update(sha256_ctx *c,const void *in,size_t len){
    const uint8_t *p=(const uint8_t*)in;
    while(len--){
        c->buf[c->blen++]=*p++;
        if(c->blen==64){sha256_compress(c,c->buf);c->bits+=512;c->blen=0;}
    }
}
static void sha256_final(sha256_ctx *c,uint8_t out[32]){
    uint64_t total=c->bits+(uint64_t)c->blen*8;
    c->buf[c->blen++]=0x80;
    if(c->blen>56){while(c->blen<64)c->buf[c->blen++]=0;sha256_compress(c,c->buf);c->blen=0;}
    while(c->blen<56)c->buf[c->blen++]=0;
    for(int i=0;i<8;i++) c->buf[56+i]=(uint8_t)(total>>(56-i*8));
    sha256_compress(c,c->buf);
    for(int i=0;i<8;i++){out[i*4]=(c->s[i]>>24);out[i*4+1]=(c->s[i]>>16)&0xff;out[i*4+2]=(c->s[i]>>8)&0xff;out[i*4+3]=c->s[i]&0xff;}
}
static void hmac_sha256(const uint8_t *key,size_t klen,const void *msg,size_t mlen,uint8_t out[32]){
    uint8_t k[64]={0},ik[64],ok[64],ih[32]; sha256_ctx c;
    if(klen>64){sha256_init(&c);sha256_update(&c,key,klen);sha256_final(&c,k);}
    else memcpy(k,key,klen);
    for(int i=0;i<64;i++){ik[i]=k[i]^0x36;ok[i]=k[i]^0x5c;}
    sha256_init(&c);sha256_update(&c,ik,64);sha256_update(&c,msg,mlen);sha256_final(&c,ih);
    sha256_init(&c);sha256_update(&c,ok,64);sha256_update(&c,ih,32);sha256_final(&c,out);
}
#endif
