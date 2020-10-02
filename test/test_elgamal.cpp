//#define DEBUG

#include "../src/elgamal_pke.hpp"

void test_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM)
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    ElGamal_PP pp; 
    ElGamal_PP_new(pp); 
    
    ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    ElGamal_Initialize(pp); 

    ElGamal_KP keypair;
    ElGamal_KP_new(keypair); 
    ElGamal_KeyGen(pp, keypair); 

    ElGamal_CT CT; 
    ElGamal_CT_new(CT); 

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    BN_random(m); 
    BN_mod(m, m, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(m, "m"); 
    ElGamal_Enc(pp, keypair.pk, m, CT);
    ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    // boundary test
    SplitLine_print('-'); 
    cout << "begin the left boundary test >>>" << endl; 
    BN_zero(m);
    BN_print(m, "m"); 
    ElGamal_Enc(pp, keypair.pk, m, CT);
    ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    SplitLine_print('-'); 
    cout << "begin the right boundary test >>>" << endl; 
    BN_sub(m, pp.BN_MSG_SIZE, BN_1);  
    BN_print(m, "m");
    ElGamal_Enc(pp, keypair.pk, m, CT);
    ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 
 
    ElGamal_PP_free(pp); 
    ElGamal_KP_free(keypair); 
    ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime); 
}

void benchmark_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, 
                       size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM, size_t TEST_NUM)
{
    SplitLine_print('-'); 
    cout << "begin the benchmark test (single thread), test_num = " << TEST_NUM << endl;

    ElGamal_PP pp; 
    ElGamal_PP_new(pp); 
    ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    ElGamal_Initialize(pp); 

    ElGamal_KP keypair[TEST_NUM];       // keypairs
    BIGNUM *m[TEST_NUM];                        // messages  
    BIGNUM *m_prime[TEST_NUM];                  // decrypted messages
    BIGNUM *k[TEST_NUM];                        // scalars
    ElGamal_CT CT[TEST_NUM];            // CTs    
    ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    BIGNUM *r_new[TEST_NUM];                  // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_KP_new(keypair[i]); 
        m[i] = BN_new(); 
        m_prime[i] = BN_new(); 
        k[i] = BN_new(); 

        BN_random(m[i]); 
        BN_mod(m[i], m[i], pp.BN_MSG_SIZE, bn_ctx);

        BN_random(k[i]); 

        r_new[i] = BN_new(); 
        BN_random(r_new[i]); 

        ElGamal_CT_new(CT[i]); 
        ElGamal_CT_new(CT_new[i]); 
        ElGamal_CT_new(CT_result[i]);
    }

    /* test keygen efficiency */ 
    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_KeyGen(pp, keypair[i]); 
    }
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "average key generation takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test encryption efficiency */ 
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test re-randomization efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_ReRand(pp, keypair[i].pk, keypair[i].sk, CT[i], CT_new[i], r_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average re-randomization takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test decryption efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(BN_cmp(m[i], m_prime[i]) != 0){ 
            cout << "decryption fails in the specified range" << endl;
        } 
    }

    /* test homomorphic add efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_HomoAdd(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average homomorphic add takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test homomorphic subtract efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_HomoSub(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average homomorphic sub takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test scalar efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_ScalarMul(CT_result[i], CT[i], k[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average scalar operation takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    
    for(auto i = 0; i < TEST_NUM; i++)
    {  
        BN_free(m[i]);
        BN_free(m_prime[i]); 
        BN_free(k[i]);  
        ElGamal_KP_free(keypair[i]); 
        ElGamal_CT_free(CT[i]); 
        BN_free(r_new[i]); 
        ElGamal_CT_free(CT_new[i]); 
        ElGamal_CT_free(CT_result[i]); 
    }

    ElGamal_PP_free(pp); 
}


void benchmark_parallel_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, 
                                size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM, size_t TEST_NUM)
{
    SplitLine_print('-'); 
    cout << "begin the benchmark test (2 threads), test_num = " << TEST_NUM << endl;

    ElGamal_PP pp; 
    ElGamal_PP_new(pp); 
    ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    ElGamal_Initialize(pp); 

    ElGamal_KP keypair[TEST_NUM];       // keypairs
    BIGNUM *m[TEST_NUM];                        // messages  
    BIGNUM *m_prime[TEST_NUM];                  // decrypted messages
    BIGNUM *k[TEST_NUM];                        // scalars
    ElGamal_CT CT[TEST_NUM];            // CTs    
    ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    BIGNUM *r_new[TEST_NUM];                    // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_KP_new(keypair[i]); 
        m[i] = BN_new(); 
        m_prime[i] = BN_new(); 
        k[i] = BN_new(); 
        r_new[i] = BN_new(); 

        BN_random(m[i]); 
        BN_mod(m[i], m[i], pp.BN_MSG_SIZE, bn_ctx);

        BN_random(k[i]); 

        ElGamal_CT_new(CT[i]); 
        ElGamal_CT_new(CT_new[i]);
        ElGamal_CT_new(CT_result[i]);
    }

    /* keygen */ 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_KeyGen(pp, keypair[i]); 
    }

    /* test parallel encryption efficiency */ 
    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "average parallel encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test re-randomization efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_ReRand(pp, keypair[i].pk, keypair[i].sk, CT[i], CT_new[i], r_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average re-randomization takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test decryption efficiency */
    cout << "decryption thread = " << pp.DEC_THREAD_NUM << endl; 
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average decryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(BN_cmp(m[i], m_prime[i]) != 0){ 
            cout << "round " << i << ":" << "decryption fails in the specified range" << endl;
        } 
    }

    /* test homomorphic add efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_HomoAdd(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average parallel homomorphic add takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test homomorphic subtract efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_HomoSub(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average parallel homomorphic sub takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;


    /* test parallel scalar efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ElGamal_Parallel_ScalarMul(CT_result[i], CT[i], k[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average parallel scalar multiplication takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;
    
    for(auto i = 0; i < TEST_NUM; i++)
    {  
        BN_free(m[i]);
        BN_free(m_prime[i]); 
        BN_free(r_new[i]); 
        ElGamal_KP_free(keypair[i]); 
        ElGamal_CT_free(CT[i]); 
        ElGamal_CT_free(CT_new[i]);
        ElGamal_CT_free(CT_result[i]); 
    }

    ElGamal_PP_free(pp); 
}

int main()
{  
    global_initialize(NID_X9_62_prime256v1);   
    //global_initialize(NID_X25519);

    SplitLine_print('-'); 
    cout << "ElGamal PKE test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    size_t MSG_LEN = 32; 
    size_t MAP_TUNNING = 7; 
    size_t IO_THREAD_NUM = 4; 
    size_t DEC_THREAD_NUM = 4;  
    size_t TEST_NUM = 30000;  

    test_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    benchmark_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM, TEST_NUM); 
    benchmark_parallel_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM, TEST_NUM); 

    SplitLine_print('-'); 
    cout << "ElGamal PKE test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



