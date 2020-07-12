/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __ROUTINES__
#define __ROUTINES__

#include "global.hpp"

/* Big Number operations */

/* generate a random big integer mod order */
void BN_random(BIGNUM *&result)
{
    BN_priv_rand_range(result, order);
} 


/* save a 32-bytes big number (<2^256) in binary form */  
void BN_serialize(BIGNUM *&x, ofstream &fout)
{
    unsigned char buffer[BN_LEN];
    BN_bn2binpad(x, buffer, BN_LEN);
    fout.write(reinterpret_cast<char *>(buffer), BN_LEN);   // write to outfile
}

/* recover a ZZn element from binary file */
void BN_deserialize(BIGNUM *&x, ifstream &fin)
{
    char buffer[BN_LEN];
    fin.read(buffer, BN_LEN);
    BN_bin2bn(reinterpret_cast<unsigned char *>(buffer), BN_LEN, x);
}

void BN_mod_negative(BIGNUM *&a)
{ 
    BN_mod_sub(a, BN_0, a, order, bn_ctx); // return a = -a mod order
}

/* EC points operations */

/* generate a random EC points */
void ECP_random(EC_POINT *&result)
{
    BIGNUM *r = BN_new(); 
    BN_random(r);  
    EC_POINT_mul(group, result, r, NULL, NULL, bn_ctx);
    BN_free(r);
} 


/*  save a compressed ECn element in binary form */ 
void ECP_serialize(EC_POINT *&A, ofstream &fout)
{
    unsigned char buffer[POINT_LEN];
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_LEN); 
}

/*  recover an ECn element from binary file */
void ECP_deserialize(EC_POINT *&A, ifstream &fin)
{
    unsigned char buffer[POINT_LEN];
    fin.read(reinterpret_cast<char *>(buffer), POINT_LEN); 
    EC_POINT_oct2point(group, A, buffer, POINT_LEN, bn_ctx);
}


/* single thread substract */
inline int EC_POINT_sub(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b)
{
    EC_POINT *temp_ecp = EC_POINT_new(group);
    EC_POINT_copy(temp_ecp, b);  
    EC_POINT_invert(group, temp_ecp, bn_ctx);
    int result = EC_POINT_add(group, r, a, temp_ecp, bn_ctx);
    EC_POINT_free(temp_ecp); 
    return result;
}

/* multi thread substract */
inline int EC_POINT_sub_without_bnctx(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b)
{
    EC_POINT* temp_ecp = EC_POINT_new(group);
    EC_POINT_copy(temp_ecp, b);  
    EC_POINT_invert(group, temp_ecp, NULL);
    int result = EC_POINT_add(group, r, a, temp_ecp, NULL);
    EC_POINT_free(temp_ecp); 
    return result;
}

inline bool FILE_exist(const string& filename)
{
    bool existing_flag; 
    ifstream fin; 
    fin.open(filename);
    if(!fin)  existing_flag = false;    
    else existing_flag = true;
    return existing_flag; 
}

#endif

