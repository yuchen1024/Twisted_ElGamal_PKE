//#define DEBUG

#include "../src/twisted_elgamal_pke.hpp"

int main()
{  
    global_initialize(NID_X9_62_prime256v1);
 

    EC_POINT *pk = EC_POINT_new(group); 
    BIGNUM *sk = BN_new();    

    EC_POINT_copy(pk, generator); 
    BN_random(sk); // sk \sample Z_p
    // EC_POINT_mul(group, pk, sk, NULL, NULL, bn_ctx); // pk = g^sk

    // uint64_t window_size = 4; 

    // vector<EC_POINT*> pk_precompute_table; 
    // precompute(pk_precompute_table, pk, window_size); 

    size_t TEST_NUM = 10000; 

    BIGNUM *r[TEST_NUM]; 
    for (auto i = 0; i < TEST_NUM; i++){
        r[i] = BN_new(); 
        BN_random(r[i]);
    } 

    EC_POINT *result1[TEST_NUM];
    EC_POINT *result2[TEST_NUM];

    for (auto i = 0; i < TEST_NUM; i++){
        result1[i] = EC_POINT_new(group); 
        result2[i] = EC_POINT_new(group); 
    } 

    EC_PRE_COMP* pk_pre_comp = EC_precompute_new(group);
    int success = EC_fast_mul_precompute(group, pk, pk_pre_comp, bn_ctx); 
    cout << "pre compute success = " << success << endl; 

    // cout << "blocksize =" << pk_pre_comp->blocksize << endl;  
    // cout << "numblocks =" << pk_pre_comp->numblocks << endl;            
    // cout << "window_size =" << pk_pre_comp->w << endl;
    // cout << "num =" << pk_pre_comp->num << endl; 

    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
        EC_POINT_mul(group, result1[i], r[i], NULL, NULL, bn_ctx); // result1 = pk^r
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "normal mul takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;


    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
        EC_fast_mul(group, result2[i], pk, r[i], pk_pre_comp, bn_ctx); 
        //EC_POINT_mul(group, result2[i], NULL, pk, r[i], bn_ctx); // result1 = pk^r
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "faster mul takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;
 
    for(auto i = 0; i < TEST_NUM; i++){
        if(EC_POINT_cmp(group, result1[i], result2[i], bn_ctx) != 0){
            cout << "wrong" << endl; 
            break; 
        } 
    }

    // ECP_print(result1[0], "normal mul"); 
    // ECP_print(result2[0], "faster mul"); 


    BN_free(sk); 
    EC_POINT_free(pk); 
    
    EC_precompute_free(pk_pre_comp); 

    for(auto i = 0; i < TEST_NUM; i++){
        EC_POINT_free(result1[i]);
        EC_POINT_free(result2[i]);
        BN_free(r[i]);          
    }


    global_finalize();
    
    return 0; 
}
