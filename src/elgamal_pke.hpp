/****************************************************************************
this hpp implements standard ElGamal PKE scheme
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

#include "calculate_dlog.hpp"

const string hashmap_file  = "g_point2index.table"; // name of hashmap file

// define the structure of PP
struct ElGamal_PP
{
    size_t MSG_LEN; // the length of message space, also the length of the DLOG interval  
    BIGNUM *BN_MSG_SIZE; // the size of message space
    size_t TUNNING; //increase this parameter in [0, RANGE_LEN/2]: larger table leads to less running time
    size_t IO_THREAD_NUM; // optimized number of threads for faster building hash map 
    size_t DEC_THREAD_NUM; // optimized number of threads for faster decryption: CPU dependent

    EC_POINT *g; 
};

// define the structure of keypair
struct ElGamal_KP
{
    EC_POINT *pk;  // define pk
    BIGNUM *sk;    // define sk
};

// define the structure of ciphertext
struct ElGamal_CT
{
    EC_POINT *X; // X = g^r 
    EC_POINT *Y; // Y = pk^r g^m 
};


/* allocate memory for PP */ 
void ElGamal_PP_new(ElGamal_PP &pp)
{ 
    pp.g = EC_POINT_new(group); 
    pp.BN_MSG_SIZE = BN_new(); 
}

/* free memory of PP */ 
void ElGamal_PP_free(ElGamal_PP &pp)
{ 
    EC_POINT_free(pp.g);
    BN_free(pp.BN_MSG_SIZE); 
}

void ElGamal_KP_new(ElGamal_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void ElGamal_KP_free(ElGamal_KP &keypair)
{
    EC_POINT_free(keypair.pk); 
    BN_free(keypair.sk);
}

void ElGamal_CT_new(ElGamal_CT &CT)
{
    CT.X = EC_POINT_new(group); 
    CT.Y = EC_POINT_new(group);
}

void ElGamal_CT_free(ElGamal_CT &CT)
{
    EC_POINT_free(CT.X); 
    EC_POINT_free(CT.Y);
}


void ElGamal_PP_print(ElGamal_PP &pp)
{
    cout << "the length of message space = " << pp.MSG_LEN << endl; 
    cout << "the tunning parameter for fast decryption = " << pp.TUNNING << endl;
    ECP_print(pp.g, "pp.g"); 
} 

void ElGamal_KP_print(ElGamal_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void ElGamal_CT_print(ElGamal_CT &CT)
{
    ECP_print(CT.X, "CT.X");
    ECP_print(CT.Y, "CT.Y");
} 


void ElGamal_CT_serialize(ElGamal_CT &CT, ofstream &fout)
{
    ECP_serialize(CT.X, fout); 
    ECP_serialize(CT.Y, fout); 
} 

void ElGamal_CT_deserialize(ElGamal_CT &CT, ifstream &fin)
{
    ECP_deserialize(CT.X, fin); 
    ECP_deserialize(CT.Y, fin); 
} 


/* Setup algorithm */ 
void ElGamal_Setup(ElGamal_PP &pp, size_t MSG_LEN, size_t TUNNING, 
                   size_t IO_THREAD_NUM, size_t DEC_THREAD_NUM)
{ 
    pp.MSG_LEN = MSG_LEN; 
    pp.TUNNING = TUNNING; 
    pp.IO_THREAD_NUM = IO_THREAD_NUM; 
    pp.DEC_THREAD_NUM = DEC_THREAD_NUM; 
    /* set the message space to 2^{MSG_LEN} */
    BN_set_word(pp.BN_MSG_SIZE, uint64_t(pow(2, pp.MSG_LEN))); 

    #ifdef DEBUG
    cout << "message space = [0, ";   
    cout << BN_bn2hex(pp.BN_MSG_SIZE) << ')' << endl; 
    #endif
  
    EC_POINT_copy(pp.g, generator); 

    #ifdef DEBUG
    cout << "generate the public parameters for ElGamal >>>" << endl; 
    ElGamal_PP_print(pp); 
    #endif
}

/* initialize the hashmap to accelerate decryption */
void ElGamal_Initialize(ElGamal_PP &pp)
{
    cout << "initialize ElGamal Homomorphic PKE >>>" << endl; 
    /* generate or load the point2index.table */
    if(!FILE_exist(hashmap_file))
    {
        // generate and serialize the point_2_index table
        Parallel_HASHMAP_serialize(pp.g, hashmap_file, pp.MSG_LEN, pp.TUNNING, pp.IO_THREAD_NUM); 
    }
    HASHMAP_deserialize(hashmap_file, pp.MSG_LEN, pp.TUNNING);            // load the table from file 
}

/* KeyGen algorithm */ 
void ElGamal_KeyGen(ElGamal_PP &pp, ElGamal_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

    #ifdef DEBUG
    cout << "key generation finished >>>" << endl;  
    ElGamal_KP_print(keypair); 
    #endif
}

/* Encryption algorithm: compute CT = Enc(pk, m; r) */ 
void ElGamal_Enc(ElGamal_PP &pp, EC_POINT *&pk, BIGNUM *&m, ElGamal_CT &CT)
{ 
    // generate the random coins 
    BIGNUM *r = BN_new(); 
    BN_random(r);

    // begin encryption
    EC_POINT_mul(group, CT.X, r, NULL, NULL, bn_ctx); // X = g^r
    EC_POINT_mul(group, CT.Y, m, pk, r, bn_ctx);  // Y = pk^r g^m
    
    BN_free(r); 

    #ifdef DEBUG
        cout << "ElGamal encryption finishes >>>"<< endl;
        ElGamal_CT_print(CT); 
    #endif
}

/* Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness */ 
void ElGamal_Enc(ElGamal_PP &pp, EC_POINT *&pk, BIGNUM *&m, BIGNUM *&r, ElGamal_CT &CT)
{ 
    // begin encryption
    EC_POINT_mul(group, CT.X, r, NULL, NULL, bn_ctx); // X = g^r
    EC_POINT_mul(group, CT.Y, m, pk, r, bn_ctx);  // Y = pk^r g^m

    #ifdef DEBUG
        cout << "ElGamal encryption finishes >>>"<< endl;
        ElGamal_CT_print(CT); 
    #endif
}

/* Decryption algorithm: compute m = Dec(sk, CT) */ 
void ElGamal_Dec(ElGamal_PP &pp, BIGNUM *&sk, ElGamal_CT &CT, BIGNUM *&m)
{ 
    //begin decryption  

    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk, bn_ctx); // M = X^{sk^} = pk^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -pk^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = g^m

    //Brute_Search(m, pp.h, M); 
    bool success = Shanks_DLOG(m, pp.g, M, pp.MSG_LEN, pp.TUNNING); // use Shanks's algorithm to decrypt
  
    EC_POINT_free(M);
    if(success == false)
    {
        cout << "decyption fails in the specified range"; 
        exit(EXIT_FAILURE); 
    }  
}

/* rerandomize ciphertext CT with given randomness r */ 
void ElGamal_ReRand(ElGamal_PP &pp, EC_POINT *&pk, BIGNUM *&sk, ElGamal_CT &CT, ElGamal_CT &CT_new, BIGNUM *&r)
{ 
    // begin partial decryption  
    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk, bn_ctx); // M = X^{sk} = pk^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -pk^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = g^m

    // begin re-encryption with the given randomness 
    EC_POINT_mul(group, CT_new.X, r, NULL, NULL, bn_ctx); // CT_new.X = g^r 
    EC_POINT_mul(group, CT_new.Y, NULL, pk, r, bn_ctx); // CT_new.Y = pk^r 

    EC_POINT_add(group, CT_new.Y, CT_new.Y, M, bn_ctx);    // M = g^m

    #ifdef DEBUG
        cout << "refresh ciphertext succeeds >>>" << endl;
        ElGamal_CT_print(CT_new); 
    #endif

    EC_POINT_free(M); 
}


/* homomorphic add */
void ElGamal_HomoAdd(ElGamal_CT &CT_result, ElGamal_CT &CT1, ElGamal_CT &CT2)
{ 
    EC_POINT_add(group, CT_result.X, CT1.X, CT2.X, bn_ctx);  
    EC_POINT_add(group, CT_result.Y, CT1.Y, CT2.Y, bn_ctx);  
}

/* homomorphic sub */
void ElGamal_HomoSub(ElGamal_CT &CT_result, ElGamal_CT &CT1, ElGamal_CT &CT2)
{ 
    EC_POINT_sub(CT_result.X, CT1.X, CT2.X);  
    EC_POINT_sub(CT_result.Y, CT1.Y, CT2.Y);  
}

/* scalar operation */
void ElGamal_ScalarMul(ElGamal_CT &CT_result, ElGamal_CT &CT, BIGNUM *&k)
{ 
    EC_POINT_mul(group, CT_result.X, NULL, CT.X, k, bn_ctx);  
    EC_POINT_mul(group, CT_result.Y, NULL, CT.Y, k, bn_ctx);  
}


/* parallel implementation */

// parallel encryption
inline void exp_operation(EC_POINT *&RESULT, EC_POINT *&A, BIGNUM *&r) 
{ 
    EC_POINT_mul(group, RESULT, NULL, A, r, NULL); // RESULT = A^r
} 

inline void builtin_exp_operation(EC_POINT *&RESULT, BIGNUM *&r) 
{ 
    EC_POINT_mul(group, RESULT, r, NULL, NULL, NULL);  // RESULT = g^r 
} 

inline void multiexp_operation(EC_POINT *&RESULT, EC_POINT *&h, BIGNUM *&r, BIGNUM *&m) 
{ 
    EC_POINT_mul(group, RESULT, m, h, r, bn_ctx);  // Y = h^r g^m
} 

/* Parallel Encryption algorithm: compute CT = Enc(pk, m; r) */
void ElGamal_Parallel_Enc(ElGamal_PP &pp, EC_POINT *&pk, BIGNUM *&m, ElGamal_CT &CT)
{ 
    /* generate fresh randomness */ 
    BIGNUM *r = BN_new(); 
    BN_random(r);

    thread enc_thread1(builtin_exp_operation, std::ref(CT.X), std::ref(r));    
    thread enc_thread2(multiexp_operation, std::ref(CT.Y), std::ref(pk), std::ref(r), std::ref(m));

    // synchronize threads
    enc_thread1.join();                // pauses until first finishes
    enc_thread2.join();               // pauses until second finishes

    BN_free(r); 
}


/* Decryption algorithm: compute m = Dec(sk, CT) */
void ElGamal_Parallel_Dec(ElGamal_PP &pp, BIGNUM *&sk, ElGamal_CT &CT, BIGNUM *&m)
{ 
    /* begin to decrypt */  
    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk, bn_ctx); // M = X^{sk} = pk^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -pk^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = g^m

    bool success = Parallel_Shanks_DLOG(m, pp.g, M, pp.MSG_LEN, pp.TUNNING, pp.DEC_THREAD_NUM); // use Shanks's algorithm to decrypt
  
    EC_POINT_free(M);

    if(success == false)
    {
        cout << "decyption fails: cannot find the message in the specified range"; 
        exit(EXIT_FAILURE); 
    }  
}

// parallel re-randomization
void ElGamal_Parallel_ReRand(ElGamal_PP &pp, EC_POINT *&pk, BIGNUM *&sk, ElGamal_CT &CT, ElGamal_CT &CT_new, BIGNUM *&r)
{ 
    /* partial decryption: only recover M = h^m */  

    EC_POINT *M = EC_POINT_new(group); 
    EC_POINT_mul(group, M, NULL, CT.X, sk, bn_ctx); // M = X^{sk} = pk^r 
    EC_POINT_invert(group, M, bn_ctx);          // M = -pk^r
    EC_POINT_add(group, M, CT.Y, M, bn_ctx);    // M = g^m

    /* re-encryption with the given randomness */
    thread rerand_thread1(exp_operation, std::ref(CT.Y), std::ref(pk), std::ref(r));
    thread rerand_thread2(builtin_exp_operation, std::ref(CT.X), std::ref(r));

    rerand_thread1.join(); 
    rerand_thread2.join(); 

    EC_POINT_add(group, CT_new.Y, CT_new.Y, M, bn_ctx);    // Y = pk^r g^m

    EC_POINT_free(M); 
}

/* parallel homomorphic add */
inline void add_operation(EC_POINT *&RESULT, EC_POINT *&X, EC_POINT *&Y) 
{ 
    EC_POINT_add(group, RESULT, X, Y, NULL);  
} 

void ElGamal_Parallel_HomoAdd(ElGamal_CT &CT_result, ElGamal_CT &CT1, ElGamal_CT &CT2)
{ 
    thread add_thread1(add_operation, std::ref(CT_result.X), std::ref(CT1.X), std::ref(CT2.X));
    thread add_thread2(add_operation, std::ref(CT_result.Y), std::ref(CT1.Y), std::ref(CT2.Y));

    add_thread1.join(); 
    add_thread2.join(); 
}

/* parallel homomorphic sub */
inline void sub_operation(EC_POINT *&RESULT, EC_POINT *&X, EC_POINT *&Y) 
{ 
    EC_POINT_sub_without_bnctx(RESULT, X, Y);  
}

void ElGamal_Parallel_HomoSub(ElGamal_CT &CT_result, ElGamal_CT &CT1, ElGamal_CT &CT2)
{ 
    thread sub_thread1(sub_operation, std::ref(CT_result.X), std::ref(CT1.X), std::ref(CT2.X));
    thread sub_thread2(sub_operation, std::ref(CT_result.Y), std::ref(CT1.Y), std::ref(CT2.Y));

    sub_thread1.join(); 
    sub_thread2.join(); 
}

/* parallel scalar operation */
void ElGamal_Parallel_ScalarMul(ElGamal_CT &CT_result, ElGamal_CT &CT, BIGNUM *&k)
{ 
    thread scalar_thread1(exp_operation, std::ref(CT_result.X), std::ref(CT.X), std::ref(k));
    thread scalar_thread2(exp_operation, std::ref(CT_result.Y), std::ref(CT.Y), std::ref(k));
    
    // synchronize threads
    scalar_thread1.join(); 
    scalar_thread2.join(); 
}






