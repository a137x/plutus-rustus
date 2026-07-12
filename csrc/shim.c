/* Batched sequential-pubkey walk over the vendored libsecp256k1 internals.
 *
 * The hot loop needs, for a random start key k, the public keys of
 * k, k+1, k+2, ...  Each step is a point addition P += G. Doing that one key at
 * a time (secp256k1_ec_pubkey_combine) costs one *field inversion per key* to get
 * back to affine coordinates for hashing — the dominant cost of the whole program.
 *
 * Instead we accumulate a batch of N points in Jacobian coordinates (gej_add_ge,
 * which needs NO inversion), then convert the whole batch to affine with a single
 * inversion via ge_set_all_gej_var (Montgomery's batch-inversion trick). The
 * per-key inversion cost is amortised to ~zero, and we reuse libsecp256k1's own
 * hand-tuned field arithmetic — measured ~7x faster on the EC step than per-key
 * combine, and correct against it bit-for-bit.
 *
 * We #include the vendored translation unit so the file-local `static` internals
 * are in scope. secp256k1-sys 0.8.2 sed-renames every symbol to
 * rustsecp256k1_v0_8_1_*; the macros below alias the ones we use.
 */
#include "secp256k1.c"

#include <stdlib.h>

#define GE    rustsecp256k1_v0_8_1_ge
#define GEJ   rustsecp256k1_v0_8_1_gej
#define ADD   rustsecp256k1_v0_8_1_gej_add_ge
#define ALL_A rustsecp256k1_v0_8_1_ge_set_all_gej_var
#define SER   rustsecp256k1_v0_8_1_eckey_pubkey_serialize
#define PARSE rustsecp256k1_v0_8_1_eckey_pubkey_parse
#define SETGE rustsecp256k1_v0_8_1_gej_set_ge
#define GEN   rustsecp256k1_v0_8_1_ge_const_g

typedef struct {
    GEJ  p;      /* next point to emit, in Jacobian coordinates */
    GEJ *sgej;   /* scratch: cap Jacobian points */
    GE  *sge;    /* scratch: cap affine points */
    size_t cap;
} ec_walk;

void ec_walk_free(ec_walk *w);

/* Allocate a walker able to emit up to `cap` keys per batch. One per thread. */
ec_walk *ec_walk_new(size_t cap) {
    ec_walk *w = (ec_walk *)malloc(sizeof(ec_walk));
    if (!w) return 0;
    w->sgej = (GEJ *)malloc(cap * sizeof(GEJ));
    w->sge  = (GE  *)malloc(cap * sizeof(GE));
    w->cap  = cap;
    if (!w->sgej || !w->sge) {
        ec_walk_free(w);
        return 0;
    }
    return w;
}

/* Seed the running point from a serialized pubkey (33 or 65 bytes). 1 = ok. */
int ec_walk_set_start(ec_walk *w, const unsigned char *pubkey, size_t len) {
    GE ge;
    if (!PARSE(&ge, pubkey, len)) return 0;
    SETGE(&w->p, &ge);
    return 1;
}

/* Emit n consecutive public keys P, P+G, ..., P+(n-1)G, then advance the running
 * point to P+n*G for the next call. `out_comp` receives n*33 compressed bytes;
 * if `out_uncomp` is non-NULL it also receives n*65 uncompressed bytes. n <= cap.
 * A single field inversion (inside ALL_A) covers the whole batch. */
void ec_walk_batch(ec_walk *w, size_t n, unsigned char *out_comp,
                   unsigned char *out_uncomp) {
    const GE *g = &GEN;

    w->sgej[0] = w->p;
    for (size_t i = 1; i < n; i++) {
        ADD(&w->sgej[i], &w->sgej[i - 1], g);
    }
    ALL_A(w->sge, w->sgej, n); /* <-- one inversion for all n points */
    for (size_t i = 0; i < n; i++) {
        size_t sz = 33;
        SER(&w->sge[i], out_comp + i * 33, &sz, 1);
        if (out_uncomp) {
            size_t szu = 65;
            SER(&w->sge[i], out_uncomp + i * 65, &szu, 0);
        }
    }
    ADD(&w->p, &w->sgej[n - 1], g); /* running point = P + n*G */
}

void ec_walk_free(ec_walk *w) {
    if (!w) return;
    free(w->sgej);
    free(w->sge);
    free(w);
}
