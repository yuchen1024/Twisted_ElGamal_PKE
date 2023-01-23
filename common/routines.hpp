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


/* compute the jth bit of a big integer i (count from little endian to big endian) */
inline uint64_t BN_parse_binary(BIGNUM *BN_i, uint64_t j)
{
    BIGNUM *BN_bit = BN_new(); 
    BN_copy(BN_bit, BN_i); 

    BN_rshift(BN_bit, BN_bit, j);
    BN_mod(BN_bit, BN_bit, BN_2, bn_ctx);

    uint64_t bit; 
    if (BN_is_one(BN_bit)) bit = 1; 
    else bit = 0;
    BN_free(BN_bit); 
    return bit;  
}

inline void BN_parse_vector(BIGNUM *BN_i, vector<uint64_t> &scalar_vec, size_t window_size)
{
    int bn_length  = BN_num_bits(BN_i);

    vector<uint64_t> bitvector(bn_length);
    for(int i = 0; i < bn_length; i++){
        bitvector[i] = BN_parse_binary(BN_i, i); 
    }

    int res_length = bn_length%window_size;  
    if (res_length != 0){
        for(int i; i <= window_size - res_length; i++){
            bitvector.push_back(0);
        }
    } 

    int vec_length = bitvector.size()/window_size; 
    vector<uint64_t> pow_vector(window_size);
    for(int i = 0; i < window_size; i++){
        pow_vector[i] = 1 << i;  
    }

    scalar_vec.resize(vec_length); 
    for(int i = 0; i < vec_length; i++){
        for(int j = 0; j < window_size; j++){
            if(bitvector[i*window_size+j] == 1) scalar_vec[i] += pow_vector[j]; 
        }
    } 
}

/* fast EC point multiplication */
void precompute(vector<EC_POINT*> &precompute_table, EC_POINT* base_point, size_t window_size)
{
    int table_size = (1 << window_size); 
    //cout << "table size = " << table_size << endl; 
    precompute_table.resize(table_size);

    for(int i = 0; i < table_size; i++) precompute_table[i] = EC_POINT_new(group); 

    EC_POINT_set_to_infinity(group, precompute_table[0]);
      
    for(int i = 1; i < table_size; i++){
        EC_POINT_add(group, precompute_table[i], precompute_table[i-1], base_point, bn_ctx);
    }     
} 

void update_precompute_table(vector<EC_POINT*> &precompute_table, size_t window_size)
{
    for(size_t i = 1; i < precompute_table.size(); i++){
        for(size_t j = 0; j < window_size; j++){
            EC_POINT_dbl(group, precompute_table[i], precompute_table[i], bn_ctx);
        }
    }   
}

void EC_POINT_fast_mul(vector<EC_POINT*> &precompute_table, size_t window_size, EC_POINT *result, EC_POINT *base_point, BIGNUM *scalar)
{
    vector<uint64_t> scalar_vec; 
    BN_parse_vector(scalar, scalar_vec, window_size); 

    EC_POINT_set_to_infinity(group, result);
    for(int i = 0; i < scalar_vec.size(); i++){
        //cout << i << "=" << scalar_vec[i] << endl; 
        EC_POINT_add(group, result, result, precompute_table[scalar_vec[i]], bn_ctx); 
        update_precompute_table(precompute_table, window_size); 
    }

    precompute(precompute_table, base_point, window_size); 
} 

  
#endif

