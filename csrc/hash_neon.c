/* SIMD hash160 for the collider hot loop, aarch64 only.
 *
 * hash160(pubkey) = RIPEMD-160(SHA-256(pubkey)). Both halves are single 64-byte
 * blocks here (33-byte compressed pubkey; 32-byte SHA output), so this file is
 * specialised to those fixed sizes. SHA-256 uses the ARMv8 crypto instructions;
 * RIPEMD-160 (no hardware instruction exists) is done 4 lanes at a time in NEON.
 *
 * The whole file is compiled only on aarch64 (see build.rs); other targets fall
 * back to the `sha2`/`ripemd` crates in Rust. Verified bit-exact against those
 * crates over hundreds of thousands of random inputs.
 */
#if defined(__aarch64__)

#include <arm_neon.h>
#include <stdint.h>
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* SHA-256 of exactly 33 bytes -> out[32], big-endian digest. */
static void sha256_33(const uint8_t *msg, uint8_t out[32]) {
    uint8_t block[64];
    memcpy(block, msg, 33);
    block[33] = 0x80;
    memset(block + 34, 0, 64 - 34);
    /* length = 33*8 = 264 bits = 0x0108, big-endian in the final 8 bytes */
    block[62] = 0x01;
    block[63] = 0x08;

    const uint32_t IV0[4] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a};
    const uint32_t IV1[4] = {0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32x4_t STATE0 = vld1q_u32(IV0);
    uint32x4_t STATE1 = vld1q_u32(IV1);
    uint32x4_t ABEF_SAVE = STATE0, CDGH_SAVE = STATE1;
    uint32x4_t MSG0, MSG1, MSG2, MSG3, TMP0, TMP1, TMP2;

    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x00]));

    /* Rounds 0-3 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x04]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    /* Rounds 4-7 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x08]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    /* Rounds 8-11 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x0c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    /* Rounds 12-15 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x10]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    /* Rounds 16-19 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x14]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    /* Rounds 20-23 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x18]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    /* Rounds 24-27 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x1c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    /* Rounds 28-31 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x20]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    /* Rounds 32-35 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x24]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    /* Rounds 36-39 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x28]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    /* Rounds 40-43 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x2c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    /* Rounds 44-47 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x30]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    /* Rounds 48-51 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x34]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    /* Rounds 52-55 */
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x38]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    /* Rounds 56-59 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x3c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    /* Rounds 60-63 */
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    vst1q_u8(out + 0, vrev32q_u8(vreinterpretq_u8_u32(STATE0)));
    vst1q_u8(out + 16, vrev32q_u8(vreinterpretq_u8_u32(STATE1)));
}

/* ---- 4-way NEON RIPEMD-160 for four fixed 32-byte inputs (one block each) ---- */

static const uint8_t RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
static const uint8_t RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
static const uint8_t SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
static const uint8_t SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
static const uint32_t KL[5] = {0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
static const uint32_t KR[5] = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000};

static inline uint32x4_t rotl(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_u32(x, vdupq_n_s32(n)), vshlq_u32(x, vdupq_n_s32(n - 32)));
}

/* RIPEMD round function, selected by round index 0..4. */
static inline uint32x4_t fr(int round, uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    switch (round) {
        case 0: return veorq_u32(veorq_u32(x, y), z);              /* x^y^z        */
        case 1: return vbslq_u32(x, y, z);                          /* (x&y)|(~x&z) */
        case 2: return veorq_u32(vorrq_u32(x, vmvnq_u32(y)), z);    /* (x|~y)^z     */
        case 3: return vbslq_u32(z, x, y);                          /* (x&z)|(y&~z) */
        default: return veorq_u32(x, vorrq_u32(y, vmvnq_u32(z)));   /* x^(y|~z)     */
    }
}

/* Four independent 32-byte messages laid out contiguously (4*32); 4*20 out. */
static void ripemd160_x4(const uint8_t *in, uint8_t *out) {
    uint32x4_t X[16];
    for (int j = 0; j < 8; j++) {
        uint32_t t[4];
        for (int l = 0; l < 4; l++) memcpy(&t[l], in + l * 32 + j * 4, 4);
        X[j] = vld1q_u32(t);
    }
    X[8] = vdupq_n_u32(0x00000080); /* the 0x80 padding byte at offset 32 */
    for (int j = 9; j < 16; j++) X[j] = vdupq_n_u32(0);
    X[14] = vdupq_n_u32(0x00000100); /* bit length = 256 */

    uint32x4_t h0 = vdupq_n_u32(0x67452301), h1 = vdupq_n_u32(0xEFCDAB89),
               h2 = vdupq_n_u32(0x98BADCFE), h3 = vdupq_n_u32(0x10325476),
               h4 = vdupq_n_u32(0xC3D2E1F0);
    uint32x4_t al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    uint32x4_t ar = h0, br = h1, cr = h2, dr = h3, er = h4;

    for (int j = 0; j < 80; j++) {
        int round = j >> 4;
        uint32x4_t tl = vaddq_u32(vaddq_u32(vaddq_u32(al, fr(round, bl, cl, dl)), X[RL[j]]),
                                  vdupq_n_u32(KL[round]));
        tl = vaddq_u32(rotl(tl, SL[j]), el);
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint32x4_t tr = vaddq_u32(vaddq_u32(vaddq_u32(ar, fr(4 - round, br, cr, dr)), X[RR[j]]),
                                  vdupq_n_u32(KR[round]));
        tr = vaddq_u32(rotl(tr, SR[j]), er);
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    uint32x4_t t = vaddq_u32(vaddq_u32(h1, cl), dr);
    h1 = vaddq_u32(vaddq_u32(h2, dl), er);
    h2 = vaddq_u32(vaddq_u32(h3, el), ar);
    h3 = vaddq_u32(vaddq_u32(h4, al), br);
    h4 = vaddq_u32(vaddq_u32(h0, bl), cr);
    h0 = t;

    uint32_t o0[4], o1[4], o2[4], o3[4], o4[4];
    vst1q_u32(o0, h0); vst1q_u32(o1, h1); vst1q_u32(o2, h2);
    vst1q_u32(o3, h3); vst1q_u32(o4, h4);
    for (int l = 0; l < 4; l++) {
        uint8_t *o = out + l * 20;
        memcpy(o + 0, &o0[l], 4);  memcpy(o + 4, &o1[l], 4);
        memcpy(o + 8, &o2[l], 4);  memcpy(o + 12, &o3[l], 4);
        memcpy(o + 16, &o4[l], 4);
    }
}

/* hash160 for four compressed pubkeys: SHA-256 (HW) then 4-way RIPEMD-160. */
static void hash160_x4(const uint8_t *pub /*4*33*/, uint8_t *out20 /*4*20*/) {
    uint8_t sha[4 * 32];
    for (int l = 0; l < 4; l++) sha256_33(pub + l * 33, sha + l * 32);
    ripemd160_x4(sha, out20);
}

/* hash160 of `n` consecutive 33-byte compressed pubkeys into out (n*20 bytes).
 * Processes 4 lanes at a time; a tail of 1..3 is padded into a final group of 4
 * (duplicating the last key) and only the real outputs are written. */
void hash160_many(const uint8_t *pub, uint8_t *out20, size_t n) {
    size_t full = n & ~(size_t)3;
    for (size_t i = 0; i < full; i += 4) {
        hash160_x4(pub + i * 33, out20 + i * 20);
    }
    size_t rem = n - full;
    if (rem) {
        uint8_t tmp_in[4 * 33];
        uint8_t tmp_out[4 * 20];
        for (int l = 0; l < 4; l++) {
            size_t src = (l < (int)rem) ? full + l : n - 1;
            memcpy(tmp_in + l * 33, pub + src * 33, 33);
        }
        hash160_x4(tmp_in, tmp_out);
        for (size_t l = 0; l < rem; l++) {
            memcpy(out20 + (full + l) * 20, tmp_out + l * 20, 20);
        }
    }
}

#endif /* __aarch64__ */
