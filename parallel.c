#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <math.h>

#define MAX_PASSWORD_LENGTH 8
#define LEGAL_CHARS "\0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
#define NUM_LEGAL_CHARS 71

#define PWD_NOT_FOUND 0
#define PWD_FOUND 1

#define NUM_THREADS 12

#define PASSWORD_TO_HASH "aaaaa"
unsigned char hashed_password[SHA256_DIGEST_LENGTH];

int brute_force_parallel(unsigned char *hashed_password, unsigned char *output_buffer);
unsigned char get_next_char(unsigned char in);
int increment_pwd(uint *char_tracker, unsigned char *output_buffer, int index, uint inc_amount);
void *thread_work(void *arg);

int main() {
    struct timeval start, end;
    float elapsed;
    unsigned char decoded_pwd[MAX_PASSWORD_LENGTH + 1];
    SHA256(PASSWORD_TO_HASH, strlen(PASSWORD_TO_HASH), hashed_password);
    
    gettimeofday(&start, NULL);
    brute_force_parallel(hashed_password, decoded_pwd);
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1e6f;

    printf("Decoded password: %s\n", decoded_pwd);
    printf("Time taken: %.6f s\n", elapsed);
}


uint status = PWD_NOT_FOUND;
unsigned char _target_hash[SHA256_DIGEST_LENGTH];
unsigned char _result[MAX_PASSWORD_LENGTH];
uint assigned_ids[NUM_THREADS];
pthread_t thread_ids[NUM_THREADS];


int brute_force_parallel(unsigned char *target_hash, unsigned char *output_buffer) {
    strncpy(_target_hash, target_hash, SHA256_DIGEST_LENGTH);

    for(int i = 0; i < NUM_THREADS; i++) {
        assigned_ids[i] = i;
        pthread_create(&thread_ids[i], NULL, thread_work, (void *)&assigned_ids[i]);
    }

    for(int i = 0; i < NUM_THREADS; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    strcpy(output_buffer, _result);

    return 0;
}

void *thread_work(void *arg) {
    uint start_point = *((uint *)arg);
    unsigned char hash_attempt[SHA256_DIGEST_LENGTH];
    unsigned char output_buffer[MAX_PASSWORD_LENGTH + 1];
    uint char_tracker[MAX_PASSWORD_LENGTH];
    memset(output_buffer, 0, MAX_PASSWORD_LENGTH + 1);
    memset(char_tracker, 0, sizeof(uint)*MAX_PASSWORD_LENGTH);

    for(uint j = start_point, i = 0; j > 0; j /= NUM_LEGAL_CHARS, i++) {
        char_tracker[i] = j % NUM_LEGAL_CHARS;
        output_buffer[i] = LEGAL_CHARS[char_tracker[i]];
    }

    for(int i = 0; i < MAX_PASSWORD_LENGTH; i++) {
        do {
            if(status != PWD_NOT_FOUND) {
                return 0;
            }
            SHA256(output_buffer, strlen(output_buffer), hash_attempt);
            if(strcmp(hash_attempt, _target_hash) == 0) {
                strncpy(_result, output_buffer, MAX_PASSWORD_LENGTH);
                status = PWD_FOUND;
                return 0;
            }
        }while(increment_pwd(char_tracker, output_buffer, i, NUM_THREADS));
    }
}

int increment_pwd(uint *char_tracker, unsigned char *output_buffer, int index, uint inc_amount) {
    if(index < 0) {
        return 0;
    }
    

    for(int i = index; i >= 0 && inc_amount > 0; i--) {
        uint c = char_tracker[i] + inc_amount;
        inc_amount = c/NUM_LEGAL_CHARS;
        c %= NUM_LEGAL_CHARS;
        char_tracker[i] = c;
        output_buffer[i] = LEGAL_CHARS[c];
        if(i == 0 && inc_amount > 0){
            return 0;
        }
    }

    return 1;
}