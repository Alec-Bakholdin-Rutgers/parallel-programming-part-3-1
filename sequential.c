#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_PASSWORD_LENGTH 8
#define LEGAL_CHARS "\0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
#define NUM_LEGAL_CHARS 71

#define PASSWORD_TO_HASH "aaaaa"
unsigned char hashed_password[SHA256_DIGEST_LENGTH];

int brute_force_sequential(unsigned char *hashed_password, unsigned char *output_buffer);
unsigned char get_next_char(unsigned char in);
int increment_pwd(uint *char_tracker, unsigned char *output_buffer, int index);

int main() {
    clock_t start, end;
    float elapsed;
    unsigned char decoded_pwd[MAX_PASSWORD_LENGTH + 1];
    SHA256(PASSWORD_TO_HASH, strlen(PASSWORD_TO_HASH), hashed_password);
    
    start = clock();
    brute_force_sequential(hashed_password, decoded_pwd);
    end = clock();
    elapsed = ((float)(end - start))/CLOCKS_PER_SEC;
    printf("Decoded password: %s\n", decoded_pwd);
    printf("Time taken: %.6f s\n", elapsed);
}

int brute_force_sequential(unsigned char *target_hash, unsigned char *output_buffer) {

    
    unsigned char hash_attempt[SHA256_DIGEST_LENGTH];
    uint char_tracker[MAX_PASSWORD_LENGTH];
    uint c;
    memset(output_buffer, 0, MAX_PASSWORD_LENGTH + 1);
    memset(char_tracker, 0, MAX_PASSWORD_LENGTH);

    for(int i = 0; i < MAX_PASSWORD_LENGTH; i++) {
        do{
            SHA256(output_buffer, strlen(output_buffer), hash_attempt);
            if(strcmp(hash_attempt, target_hash) == 0) {
                return 0;
            }
        }while(increment_pwd(char_tracker, output_buffer, i));
    }
    return 0;
}

int increment_pwd(uint *char_tracker, unsigned char *output_buffer, int index) {
    if(index < 0) {
        return 0;
    }
    

    for(int i = index; i >= 0; i--) {
        uint c = char_tracker[i] = (char_tracker[i] + 1) % NUM_LEGAL_CHARS;
        output_buffer[i] = LEGAL_CHARS[c];
        if(c != 0) {
            return 1;
        }
    }

    return 0;
}