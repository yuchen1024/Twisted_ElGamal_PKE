#include <string.h>
#include <openssl/err.h>

#include "internal/cryptlib.h"
// #include "internal/bn_int.h"
#include "ec_lcl.h"
#include "internal/refcount.h"


// /*
//  * This file implements the wNAF-based interleaving multi-exponentiation method
//  * Formerly at:
//  *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp
//  * You might now find it here:
//  *   http://link.springer.com/chapter/10.1007%2F3-540-45537-X_13
//  *   http://www.bmoeller.de/pdf/TI-01-08.multiexp.pdf
//  * For multiplication with precomputation, we use wNAF splitting, formerly at:
//  *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#fastexp
//  */

// /* structure for precomputed multiples of the generator */
// struct ec_pre_comp_st {
//     const EC_GROUP *group;      /* parent EC_GROUP object */
//     size_t blocksize;           /* block size for wNAF splitting */
//     size_t numblocks;           /* max. number of blocks for which we have
//                                  * precomputation */
//     size_t w;                   /* window size */
//     EC_POINT **points;          /* array with pre-calculated multiples of
//                                  * generator: 'num' pointers to EC_POINT
//                                  * objects followed by a NULL */
//     size_t num;                 /* numblocks * 2^(w-1) */
//     CRYPTO_REF_COUNT references;
//     CRYPTO_RWLOCK *lock;
// };

// static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)
// {
//     EC_PRE_COMP *ret = NULL;

//     if (!group)
//         return NULL;

//     ret = OPENSSL_zalloc(sizeof(*ret));
//     if (ret == NULL) {
//         ECerr(EC_F_EC_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
//         return ret;
//     }

//     ret->group = group;
//     ret->blocksize = 8;         /* default */
//     ret->w = 4;                 /* default */
//     ret->references = 1;

//     ret->lock = CRYPTO_THREAD_lock_new();
//     if (ret->lock == NULL) {
//         ECerr(EC_F_EC_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
//         OPENSSL_free(ret);
//         return NULL;
//     }
//     return ret;
// }

// EC_PRE_COMP *EC_ec_pre_comp_dup(EC_PRE_COMP *pre)
// {
//     int i;
//     if (pre != NULL)
//         CRYPTO_UP_REF(&pre->references, &i, pre->lock);
//     return pre;
// }

// void EC_ec_pre_comp_free(EC_PRE_COMP *pre)
// {
//     int i;

//     if (pre == NULL)
//         return;

//     CRYPTO_DOWN_REF(&pre->references, &i, pre->lock);
//     REF_PRINT_COUNT("EC_ec", pre);
//     if (i > 0)
//         return;
//     REF_ASSERT_ISNT(i < 0);

//     if (pre->points != NULL) {
//         EC_POINT **pts;

//         for (pts = pre->points; *pts != NULL; pts++)
//             EC_POINT_free(*pts);
//         OPENSSL_free(pre->points);
//     }
//     CRYPTO_THREAD_lock_free(pre->lock);
//     OPENSSL_free(pre);
// }

// #define EC_POINT_BN_set_flags(P, flags) do { \
//     BN_set_flags((P)->X, (flags)); \
//     BN_set_flags((P)->Y, (flags)); \
//     BN_set_flags((P)->Z, (flags)); \
// } while(0)



// #undef EC_POINT_BN_set_flags

// /*
//  * TODO: table should be optimised for the wNAF-based implementation,
//  * sometimes smaller windows will give better performance (thus the
//  * boundaries should be increased)
//  */
// #define EC_window_bits_for_scalar_size(b) \
//                 ((size_t) \
//                  ((b) >= 2000 ? 6 : \
//                   (b) >=  800 ? 5 : \
//                   (b) >=  300 ? 4 : \
//                   (b) >=   70 ? 3 : \
//                   (b) >=   20 ? 2 : \
//                   1))

/*-
 * Compute \sum scalars[i]*points[i], also including scalar*generator in the addition if scalar != NULL
 */
int ec_wNAF_fast_mul(const EC_GROUP *group, EC_POINT *result, EC_POINT *fix_point, const BIGNUM *scalar, 
        EC_PRE_COMP *pre_comp, BN_CTX *ctx)
{
    EC_POINT *tmp = NULL;

    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int result_is_inverted = 0;
    int result_is_at_infinity = 1;
    size_t *wsize = NULL;       /* individual window sizes */
    signed char **wNAF = NULL;  /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;

    EC_POINT **val = NULL;      /* precomputation */
    EC_POINT **v;
    EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or 'pre_comp->points' */
    int num_scalar = 0;         /* flag: will be set to 1 if 'scalar' must be
                                 * treated like other scalars, i.e.
                                 * precomputation is not available */
    int success = 0;

    size_t num = 0; 

    /* for wNAF splitting */
    size_t blocksize = pre_comp->blocksize;

    /*
    * determine maximum number of blocks that wNAF splitting may
    * yield (NB: maximum wNAF length is bit length plus one)
    */
    size_t numblocks = (BN_num_bits(scalar) / blocksize) + 1;

    /*
    * we cannot use more blocks than we have precomputation for
    */
    if (numblocks > pre_comp->numblocks) numblocks = pre_comp->numblocks;

    pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

    /* check that pre_comp looks sane */
    if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }


    size_t totalnum = numblocks;

    wsize = OPENSSL_malloc(totalnum * sizeof(wsize[0]));
    wNAF_len = OPENSSL_malloc(totalnum * sizeof(wNAF_len[0]));
    /* include space for pivot */
    wNAF = OPENSSL_malloc((totalnum + 1) * sizeof(wNAF[0]));
    val_sub = OPENSSL_malloc(totalnum * sizeof(val_sub[0]));

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF != NULL)
        wNAF[0] = NULL;         /* preliminary pivot */

    if (wsize == NULL || wNAF_len == NULL || wNAF == NULL || val_sub == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    size_t num_val = 0;



    signed char *tmp_wNAF = NULL;
    size_t tmp_len = 0;

    /*
    * use the window size for which we have precomputation
    */
    wsize[num] = pre_comp->w;
    tmp_wNAF = bn_compute_wNAF(scalar, wsize[num], &tmp_len);
    if (!tmp_wNAF) goto err;

    if (tmp_len <= max_len) {
        /*
        * One of the other wNAFs is at least as long as the wNAF
        * belonging to the generator, so wNAF splitting will not buy us anything.
        */

        numblocks = 1;
        totalnum = num + 1; /* don't use wNAF splitting */
        wNAF[num] = tmp_wNAF;
        wNAF[num + 1] = NULL;
        wNAF_len[num] = tmp_len;
        /*
        * pre_comp->points starts with the points that we need here:
        */
        val_sub[num] = pre_comp->points;
    } 
    else {
        /*
        * don't include tmp_wNAF directly into wNAF array - use wNAF
        * splitting and include the blocks
        */

        signed char *pp;
        EC_POINT **tmp_points;

        if (tmp_len < numblocks * blocksize) {
            /*
            * possibly we can do with fewer blocks than estimated
            */
            numblocks = (tmp_len + blocksize - 1) / blocksize;
            if (numblocks > pre_comp->numblocks) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                OPENSSL_free(tmp_wNAF);
                goto err;
            }
            totalnum = num + numblocks;
        }

        /* split wNAF in 'numblocks' parts */
        pp = tmp_wNAF;
        tmp_points = pre_comp->points;

        for (i = num; i < totalnum; i++) {
            if (i < totalnum - 1) {
                wNAF_len[i] = blocksize;
                if (tmp_len < blocksize) {
                    ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                    OPENSSL_free(tmp_wNAF);
                    goto err;
                }
                tmp_len -= blocksize;
                } else
                /*
                * last block gets whatever is left (this could be
                * more or less than 'blocksize'!)
                */
                wNAF_len[i] = tmp_len;

                wNAF[i + 1] = NULL;
                wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                if (wNAF[i] == NULL) {
                    ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
                    OPENSSL_free(tmp_wNAF);
                    goto err;
                }
                memcpy(wNAF[i], pp, wNAF_len[i]);
                if (wNAF_len[i] > max_len) max_len = wNAF_len[i];

                if (*tmp_points == NULL) {
                    ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                    OPENSSL_free(tmp_wNAF);
                    goto err;
                }
                val_sub[i] = tmp_points;
                tmp_points += pre_points_per_block;
                pp += blocksize;
            }
            OPENSSL_free(tmp_wNAF);
            }
        }


    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc((num_val + 1) * sizeof(val[0]));
    if (val == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    val[num_val] = NULL;        /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = EC_POINT_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((tmp = EC_POINT_new(group)) == NULL)
        goto err;

    if (!EC_POINTs_make_affine(group, num_val, val, ctx))
        goto err;

    result_is_at_infinity = 1;

    for (k = max_len - 1; k >= 0; k--) {
        if (!result_is_at_infinity) {
            if (!EC_POINT_dbl(group, result, result, ctx))
                goto err;
        }

        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;

                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != resukt_is_inverted) {
                        if (!result_is_at_infinity) {
                            if (!EC_POINT_invert(group, result, ctx))
                                goto err;
                        }
                        result_is_inverted = !result_is_inverted;
                    }

                    /* digit > 0 */

                    if (result_is_at_infinity) {
                        if (!EC_POINT_copy(result, val_sub[i][digit >> 1]))
                            goto err;
                        result_is_at_infinity = 0;
                    } else {
                        if (!EC_POINT_add
                            (group, result, result, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }
                }
            }
        }
    }

    if (result_is_at_infinity) {
        if (!EC_POINT_set_to_infinity(group, result))
            goto err;
    } else {
        if (result_is_inverted)
            if (!EC_POINT_invert(group, result, ctx))
                goto err;
    }

    success = 1;

 err:
    EC_POINT_free(tmp);
    OPENSSL_free(wsize);
    OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            EC_POINT_clear_free(*v);

        OPENSSL_free(val);
    }
    OPENSSL_free(val_sub);
    return ret;
}

/*-
 * ec_wNAF_precompute_mult()
 * creates an EC_PRE_COMP object with preprecomputed multiples of the generator
 * for use with wNAF splitting as implemented in ec_wNAF_mul().
 *
 * 'pre_comp->points' is an array of multiples of the generator of the following form:
 * points[0] =     generator;
 * points[1] = 3 * generator;
 * ...
 * points[2^(w-1)-1] =     (2^(w-1)-1) * generator;
 * points[2^(w-1)]   =     2^blocksize * generator;
 * points[2^(w-1)+1] = 3 * 2^blocksize * generator;
 * ...
 * points[2^(w-1)*(numblocks-1)-1] = (2^(w-1)) *  2^(blocksize*(numblocks-2)) * generator
 * points[2^(w-1)*(numblocks-1)]   =              2^(blocksize*(numblocks-1)) * generator
 * ...
 * points[2^(w-1)*numblocks-1]     = (2^(w-1)) *  2^(blocksize*(numblocks-1)) * generator
 * points[2^(w-1)*numblocks]       = NULL
 */
int ec_wNAF_precompute_fast_mult(EC_GROUP *group, EC_POINT *fix_point, EC_PRE_COMP *pre_comp, BN_CTX *ctx)
{
    EC_POINT *tmp_point = NULL, *base = NULL, **var;
    const BIGNUM *order;
    size_t i, bits, w, pre_points_per_block, blocksize, numblocks, num;
    EC_POINT **points = NULL;

    int success = 0;
#ifndef FIPS_MODE
    BN_CTX *new_ctx = NULL;
#endif


#ifndef FIPS_MODE
    if (ctx == NULL)
        ctx = new_ctx = BN_CTX_new();
#endif
    if (ctx == NULL)
        goto err;

    BN_CTX_start(ctx);

    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * The following parameters mean we precompute (approximately) one point per bit. 
     * TBD: The combination 8, 4 is perfect for 160 bits; for other bit lengths, 
     * other parameter combinations might provide better efficiency.
     */
    blocksize = 8;
    w = 4;
    if (EC_window_bits_for_scalar_size(bits) > w) {
        /* let's not make the window too small ... */
        w = EC_window_bits_for_scalar_size(bits);
    }

    numblocks = (bits + blocksize - 1) / blocksize; /* max. number of blocks
                                                     * to use for wNAF
                                                     * splitting */

    pre_points_per_block = (size_t)1 << (w - 1);
    num = pre_points_per_block * numblocks; /* number of points to compute
                                             * and store */

    points = OPENSSL_malloc(sizeof(*points) * (num + 1));
    if (points == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    var = points;
    var[num] = NULL;            /* pivot */
    for (i = 0; i < num; i++) {
        if ((var[i] = EC_POINT_new(group)) == NULL) {
            ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if ((tmp_point = EC_POINT_new(group)) == NULL
        || (base = EC_POINT_new(group)) == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_copy(base, fix_point))
        goto err;

    /* do the precomputation */
    for (i = 0; i < numblocks; i++) {
        size_t j;

        if (!EC_POINT_dbl(group, tmp_point, base, ctx))
            goto err;

        if (!EC_POINT_copy(*var++, base))
            goto err;

        for (j = 1; j < pre_points_per_block; j++, var++) {
            /*
             * calculate odd multiples of the current base point
             */
            if (!EC_POINT_add(group, *var, tmp_point, *(var - 1), ctx))
                goto err;
        }

        if (i < numblocks - 1) {
            /*
             * get the next base (multiply current one by 2^blocksize)
             */
            size_t k;

            if (blocksize <= 2) {
                ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!EC_POINT_dbl(group, base, tmp_point, ctx))
                goto err;
            for (k = 2; k < blocksize; k++) {
                if (!EC_POINT_dbl(group, base, base, ctx))
                    goto err;
            }
        }
    }

    if (!EC_POINTs_make_affine(group, num, points, ctx))
        goto err;

    pre_comp->group = group;
    pre_comp->blocksize = blocksize;
    pre_comp->numblocks = numblocks;
    pre_comp->w = w;
    pre_comp->points = points;
    points = NULL;
    pre_comp->num = num;
    //SETPRECOMP(group, ec, pre_comp);
    success = 1;

 err:
    BN_CTX_end(ctx);
#ifndef FIPS_MODE
    BN_CTX_free(new_ctx);
#endif
    EC_ec_pre_comp_free(pre_comp);
    if (points) {
        EC_POINT **p;

        for (p = points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(points);
    }
    EC_POINT_free(tmp_point);
    EC_POINT_free(base);
    return success;
}

