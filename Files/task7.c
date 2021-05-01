#include <stdio.h> include <stdlib.h> include <string.h> include 
#<openssl/conf.h> include <openssl/evp.h> include <openssl/err.h>

int encrypt(unsigned char* plaintext, int plaintxt_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
void stringToHex(char *, char *);


int main(){
//First we need to define the initial vector & the  ciphertext
unsigned char iv[] = "*!@)$!sdasASG@#1";
unsigned char cipher[] = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2";



//define plain text 
unsigned char plaintext[] = "This is the top secret";

//The key to be found
unsigned char possible_key[17];
int length;

char candidate[100];
char new_candidate[2*(strlen(candidate))+1];

//Encryption output
char temp_cipher[100];
FILE * dictionary = fopen("./words.txt", "r");
FILE *ciphers = fopen("./ciphers.txt","w");

int plaintxt_len = strlen(plaintext);
int new_cipherlen;
do{
if(feof(dictionary)){
puts("The provided words list doesn't contain the secret-key");
fclose(ciphers);
return 0;
}
fgets(possible_key, 17, dictionary);
length = strlen(possible_key);
if(possible_key[length-1] == '\n'){
possible_key[length - 1] = '\0';
length = strlen(possible_key);
}
//Padding i.e: insert # to the key
for(int i=length; i < 16; i++){
strcat(possible_key, "#");
}
new_cipherlen = encrypt(plaintext, 21, possible_key, iv, candidate);
stringToHex(candidate, new_candidate);
fputs(new_candidate, ciphers);

}while(strcmp(new_candidate, cipher)); //keep doing this until strcmp returns 0

FILE *key_file = fopen("./key.txt", "r");
fwrite(possible_key, 1, strlen(possible_key), key_file);
FILE *file_new_cipher_text = fopen("./newciphertext.txt", "w");
fwrite(candidate, 1, new_cipherlen, file_new_cipher_text);
fclose(dictionary);
fclose(key_file);
return 0;

}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext){
EVP_CIPHER_CTX *ctx;
int len;
int ciphertext_len;

//Create & initialize the context
if(!(ctx = EVP_CIPHER_CTX_new()))
puts("Error");
/*
Here we must make sure that we chose the right IV and key sizes 
for our cipher .
IV size for most modes is the same as the block size.
For AES it's 128 bits.
*/
if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
puts("Error in length");

if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
puts("Error occured in this step");

ciphertext_len = len;
if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
puts("Error in final step");

ciphertext_len += len;

//Clean up
EVP_CIPHER_CTX_free(ctx);
return ciphertext_len;
}

void stringToHex(char *in, char* out){
int loop;
int i;
i = 0;
loop = 0;

while(in[loop] != '\0'){
sprintf((char*) (out+i), "%02X", in[loop]);
loop++;
i+=2;
}
//Insert NULL at the end of the output string
out[i++] = '\0';
}
