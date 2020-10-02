//#define DEBUG

#include "../src/twisted_elgamal_pke.hpp"

void test_basic_operation(size_t TEST_NUM)
{
    cout << "begin the basic operation >>>" << endl; 
    
    /* random test */ 
    BIGNUM * a[TEST_NUM]; 
    EC_POINT * A[TEST_NUM]; 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        a[i] = BN_new();
        BN_random(a[i]); 
        A[i] = EC_POINT_new(group);
        ECP_random(A[i]);  
    }
    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        EC_POINT_mul(group, A[i], NULL, A[i], a[i], bn_ctx); // A = A^a
    }
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "average point multication takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        BN_free(a[i]);
        EC_POINT_free(A[i]);  
    }
}

void test_twisted_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, 
                          size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM)
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp); 
    
    Twisted_ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    BN_random(m); 
    BN_mod(m, m, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(m, "m"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    // boundary test
    SplitLine_print('-'); 
    cout << "begin the left boundary test >>>" << endl; 
    BN_zero(m);
    BN_print(m, "m"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 

    SplitLine_print('-'); 
    cout << "begin the right boundary test >>>" << endl; 
    BN_sub(m, pp.BN_MSG_SIZE, BN_1);  
    BN_print(m, "m");
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    BN_print(m_prime, "m'"); 
 
    Twisted_ElGamal_PP_free(pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime); 
}

void benchmark_twisted_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, 
                               size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM, 
                               size_t TEST_NUM)
{
    SplitLine_print('-'); 
    cout << "begin the benchmark test (single thread), test_num = " << TEST_NUM << endl;

    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp); 
    Twisted_ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair[TEST_NUM];       // keypairs
    BIGNUM *m[TEST_NUM];                        // messages  
    BIGNUM *m_prime[TEST_NUM];                  // decrypted messages
    BIGNUM *k[TEST_NUM];                        // scalars
    Twisted_ElGamal_CT CT[TEST_NUM];            // CTs    
    Twisted_ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    Twisted_ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    BIGNUM *r_new[TEST_NUM];                  // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KP_new(keypair[i]); 
        m[i] = BN_new(); 
        m_prime[i] = BN_new(); 
        k[i] = BN_new(); 

        BN_random(m[i]); 
        BN_mod(m[i], m[i], pp.BN_MSG_SIZE, bn_ctx);

        BN_random(k[i]); 

        r_new[i] = BN_new(); 
        BN_random(r_new[i]); 

        Twisted_ElGamal_CT_new(CT[i]); 
        Twisted_ElGamal_CT_new(CT_new[i]); 
        Twisted_ElGamal_CT_new(CT_result[i]);
    }

    /* test keygen efficiency */ 
    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KeyGen(pp, keypair[i]); 
    }
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "average key generation takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test encryption efficiency */ 
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test re-randomization efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_ReRand(pp, keypair[i].pk, keypair[i].sk, CT[i], CT_new[i], r_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average re-randomization takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test decryption efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
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
        Twisted_ElGamal_HomoAdd(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average homomorphic add takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test homomorphic subtract efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_HomoSub(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average homomorphic sub takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test scalar efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_ScalarMul(CT_result[i], CT[i], k[i]); 
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
        Twisted_ElGamal_KP_free(keypair[i]); 
        Twisted_ElGamal_CT_free(CT[i]); 
        BN_free(r_new[i]); 
        Twisted_ElGamal_CT_free(CT_new[i]); 
        Twisted_ElGamal_CT_free(CT_result[i]); 
    }

    Twisted_ElGamal_PP_free(pp); 
}


void benchmark_parallel_twisted_elgamal(size_t MSG_LEN, size_t MAP_TUNNING, 
                                        size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM, 
                                        size_t TEST_NUM)
{
    SplitLine_print('-'); 
    cout << "begin the benchmark test: " << " IO_THREAD_NUM = " << IO_THREAD_NUM << 
    " DEC_THREAD_NUM = " << DEC_THREAD_NUM << " TEST_NUM = " << TEST_NUM << endl;

    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp); 
    Twisted_ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair[TEST_NUM];       // keypairs
    BIGNUM *m[TEST_NUM];                        // messages  
    BIGNUM *m_prime[TEST_NUM];                  // decrypted messages
    BIGNUM *k[TEST_NUM];                        // scalars
    Twisted_ElGamal_CT CT[TEST_NUM];            // CTs    
    Twisted_ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    Twisted_ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    BIGNUM *r_new[TEST_NUM];                    // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KP_new(keypair[i]); 
        m[i] = BN_new(); 
        m_prime[i] = BN_new(); 
        k[i] = BN_new(); 
        r_new[i] = BN_new(); 

        BN_random(m[i]); 
        BN_mod(m[i], m[i], pp.BN_MSG_SIZE, bn_ctx);

        BN_random(k[i]); 

        Twisted_ElGamal_CT_new(CT[i]); 
        Twisted_ElGamal_CT_new(CT_new[i]);
        Twisted_ElGamal_CT_new(CT_result[i]);
    }

    /* keygen */ 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KeyGen(pp, keypair[i]); 
    }

    /* test parallel encryption efficiency */ 
    auto start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "average parallel encryption takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test re-randomization efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_ReRand(pp, keypair[i].pk, keypair[i].sk, CT[i], CT_new[i], r_new[i]); 
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
        Twisted_ElGamal_Parallel_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
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
        Twisted_ElGamal_Parallel_HomoAdd(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average parallel homomorphic add takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;

    /* test homomorphic subtract efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_HomoSub(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "average parallel homomorphic sub takes time = " 
    << chrono::duration <double, milli> (running_time).count()/TEST_NUM << " ms" << endl;


    /* test parallel scalar efficiency */
    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_ScalarMul(CT_result[i], CT[i], k[i]); 
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
        Twisted_ElGamal_KP_free(keypair[i]); 
        Twisted_ElGamal_CT_free(CT[i]); 
        Twisted_ElGamal_CT_free(CT_new[i]);
        Twisted_ElGamal_CT_free(CT_result[i]); 
    }

    Twisted_ElGamal_PP_free(pp); 
}

int main()
{  
    global_initialize(NID_X9_62_prime256v1);   

    SplitLine_print('-'); 
    cout << "Twisted ElGamal PKE test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    size_t MSG_LEN = 32; 
    size_t MAP_TUNNING = 7; 
    size_t IO_THREAD_NUM = 4; 
    size_t DEC_THREAD_NUM = 4;  
    size_t TEST_NUM = 30000;  


    test_twisted_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM);
    benchmark_twisted_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM, TEST_NUM); 
    benchmark_parallel_twisted_elgamal(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM, TEST_NUM); 

    SplitLine_print('-'); 
    cout << "Twisted ElGamal PKE test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



