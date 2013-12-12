#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/bn.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>

#define THREADS 4

typedef struct mod_exp_params{
    BIGNUM* base;
    BIGNUM* exponent;
    BIGNUM* mod;
    BIGNUM* result;
} ModParams;

/**
 * Precondition: bits >= 2
 */
BIGNUM* random_prime(int bits);

/**
 * Precondition: m > 0.
 */
void mod_exp(ModParams* p);

int is_prime(BIGNUM* p);

void tester();

void bn_print(const BIGNUM *bn);

int validate_input(char* input);


int main(int args, char* argv[]){
    int bits;
    BIGNUM* result;
    BN_CTX* ctx = BN_CTX_new();
    
    if(args == 1){
        tester();
    }
    else if(args == 2){
        bits = validate_input(argv[1]);        
        result = random_prime(bits);
        assert(BN_is_prime(result, 128, NULL, ctx, NULL));
        bn_print(result);
        BN_clear_free(result);
    }
    else{
        printf("Usage: random_prime [int bits >= 2]\n");
    }
    BN_CTX_free(ctx); 
    return EXIT_SUCCESS;
}


BIGNUM* random_prime(int bits){
    assert(bits >= 2);
    BIGNUM* x = BN_new();
    BIGNUM* p = BN_new();
    BN_one(p); BN_lshift(p, p, bits); 
    for(;;){
        while(!BN_rand_range(x, p));
        if(!BN_is_odd(x)){
            continue;
        }
        if(is_prime(x)){
            break;
        }
    }
    BN_free(p); 
    return x;
}


int is_prime(BIGNUM* p){
    if(BN_is_zero(p)) return 0;
    if(BN_is_one(p)) return 0;
    int i, j, charmichael = 1, not_prime = 0;
    ModParams params[THREADS];
    pthread_t threads[THREADS];
    BIGNUM *neg_one = BN_new(); BN_copy(neg_one, p); 
    BN_sub_word(neg_one, 1); 
    for(i = 0; i < THREADS; i++){
        params[i].exponent = BN_new(); 
        BN_rshift1(params[i].exponent, neg_one); 
        params[i].mod = BN_new(); BN_copy(params[i].mod, p); 
        params[i].result = BN_new(); 
        params[i].base = BN_new();             
    }    
    for(i = 0; i < 128; i += THREADS){
        for(j = 0; j < THREADS; j++){
            BN_one(params[j].result);
            while(!BN_rand_range(params[j].base, neg_one)); 
            BN_add_word(params[j].base, 1); 
            pthread_create(&threads[j], NULL, (void*) mod_exp, 
                            (void*) &params[j]); 
        }
        for(j = 0; j < THREADS; j++){
            pthread_join(threads[j], NULL); 
            if(!BN_is_one(params[j].result) && 
                BN_cmp(params[j].result, neg_one) != 0){
                not_prime = 1;
            }
            if(BN_cmp(params[j].result, neg_one) == 0){
                charmichael = 0;
            }            
        }
        if(not_prime) break;
    }    
    for(i = 0; i < THREADS; i++){
        BN_free(params[i].exponent);
        BN_free(params[i].mod);
        BN_free(params[i].base);
        BN_free(params[i].result);
    }
    BN_free(neg_one);
    return not_prime ? 0: !charmichael;
}



void mod_exp(ModParams* p){
    assert(!BN_is_zero(p->mod) && !BN_is_negative(p->mod));
    
    BIGNUM* base = BN_new(); BN_copy(base, p->base);
    BIGNUM* exponent = BN_new(); BN_copy(exponent, p->exponent);
    BN_CTX* ctx = BN_CTX_new();
    while(!BN_is_zero(exponent)){
        if(BN_is_odd(exponent)){
            BN_mod_mul(p->result, p->result, base, p->mod, ctx);
        }
        BN_mod_sqr(base,base,p->mod,ctx);
        BN_rshift1(exponent,exponent);
    } 
    BN_CTX_free(ctx);
    BN_free(base); BN_free(exponent);
}


void bn_print(const BIGNUM *bn){
    char *s = BN_bn2hex(bn);
    printf("0x%s\n", s);
    OPENSSL_free(s);
}


int validate_input(char* input){
    int i = 0;
    for(; input[i] != 0; i++){
        if(!isdigit(input[i])){
            printf("Invalid input\n");
            exit(EXIT_FAILURE);
        }
    }
    i = atoi(input);
    if(i < 2){
        printf("Invalid input: bits < 2\n");
        exit(EXIT_FAILURE);
    }
    return i;
}


void tester(){
    int i;
    ModParams p;
    srand(0xffff);
    BIGNUM* zero = BN_new(); BN_zero(zero);
    BIGNUM* one = BN_new(); BN_one(one);
    BIGNUM* expected = BN_new();
    BIGNUM* test = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    p.result = BN_new(); p.base = BN_new(); 
    p.exponent = BN_new(); p.mod = BN_new();
    
    
    #define MOD_EXP_TEST
    #ifdef MOD_EXP_TEST
    BN_zero(p.base); BN_zero(p.exponent); 
    BN_one(p.mod); BN_one(p.result);
    mod_exp(&p);
    assert(BN_is_one(p.result));
    BN_one(p.exponent); BN_one(p.result); 
    mod_exp(&p); 
    assert(BN_is_zero(p.result));
    BN_one(p.base); BN_zero(p.exponent); BN_one(p.result);
    mod_exp(&p);
    assert(BN_is_one(p.result)); 
    BN_one(p.exponent = one); BN_one(p.result);
    mod_exp(&p);
    assert(BN_is_zero(p.result)); 
    BN_set_word(p.exponent, 2); BN_one(p.result);
    mod_exp(&p);
    assert(BN_is_zero(p.result));
    BN_set_word(p.mod, 99); BN_one(p.result);
    mod_exp(&p);
    assert(BN_is_one(p.result));  
    
    for(i = 0; i < 1000; i++){
        BN_set_word(p.base, rand() * rand() * rand() * rand());
        BN_set_word(p.exponent, rand() * rand() * rand() * rand());
        BN_set_word(p.mod, rand() * rand() * rand() * rand() + 1);
        mod_exp(&p);
        BN_mod_exp(expected, p.base, p.exponent, p.mod, ctx);
        assert(!BN_cmp(p.result, expected));
        BN_one(p.result);
    } 
    BN_hex2bn(&p.base, 
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BN_copy(p.exponent, p.base); 
    BN_copy(p.mod, p.base); BN_one(p.result);
    BN_mod_exp(expected, p.base, p.exponent, p.mod, ctx);
    mod_exp(&p);
    assert(!BN_cmp(p.result, expected));
    #endif
    
    #define IS_PRIME_TEST
    #ifdef IS_PRIME_TEST
    assert(is_prime(one) == 0); 
    for(i = 0; i < 100; i++){ 
        BN_set_word(test, rand() * rand() * rand() * rand() + 1); 
        assert(is_prime(test) 
                == BN_is_prime(test, 128, NULL, ctx, NULL));
    } 
    BN_hex2bn(&test, 
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert(is_prime(test) == BN_is_prime(test, 128, NULL, ctx, NULL));
    
    int charmichaels[] = {561, 1105, 1729, 2465, 2821, 6601, 8911};
    for(i = 0; i < 7; i++){
        BN_set_word(test, charmichaels[i]);
        assert(is_prime(test) == 0);
    }
    BN_free(test);
    #endif
    
    #define RANDOM_PRIME_TEST
    #ifdef RANDOM_PRIME_TEST
    test = random_prime(2);
    assert(BN_is_prime(test, 128, NULL, ctx, NULL));
    BN_free(test);
    for(i = 0; i < 100; i++){
        test = random_prime(rand() % 62 + 2);
        assert(BN_is_prime(test, 128, NULL, ctx, NULL));
        free(test);
    }
    test = random_prime(512);
    assert(BN_is_prime(test, 128, NULL, ctx, NULL));
    BN_free(test);
    

    #define LEN 10
    int primes_dist[LEN] = {0,0,0,0,0,0,0,0,0,0};
    int primes[LEN] = {3,5,7,11,13,17,19,23,29,31};
    double reps = 40;
    char* s; 
    int j = 0;
    for(i = 0; i < reps; i++){
        test = random_prime(5);
        s = BN_bn2dec(test);
        for(j = 0; j < LEN; j++){
            if(primes[j] == atoi(s)){
                primes_dist[j]++;
                break;
            }
        }
        OPENSSL_free(s);
        BN_free(test);
    }
    printf("Randomness distribution for 5 bit primes:\n");
    for(i = 0; i < LEN; i++){
        printf("%2d: %2.0f%%\n", primes[i], 100*primes_dist[i] / reps);
    }
    #endif
    
    printf("\nAll test cases pass\n");
    BN_CTX_free(ctx); 
    BN_free(one); 
    BN_free(zero); 
    BN_free(expected);
}
