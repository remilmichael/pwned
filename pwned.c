/*
 **	Requires openssl-devel/dev package.
 **	Compile : gcc pwned.c -lcrypto -o pwned
 **	Execute : ./pwned <path to the file downloaded from https://haveibeenpwned.com/Passwords>

 *	Program to check if your password has been pwned, instead of typing your password at https://haveibeenpwned.com, like if you are 
	so paranoid about typing it on the website.

 *	This program only works if the contents are hashed(except count and separator) using SHA1 and if it is in the format given below:-
 
	hash1:count
	hash2:count
	.
	.
	.
	hashN:count

 *  If and only if the file has no count given against each hash, execute the program with the option "-nocount". Better not to use
    this option unwanted.
*/



#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#include<termios.h>
#include<stdlib.h>
#include<openssl/evp.h>
#include<string.h>
#include<errno.h>

#define SEPARATOR ':'

#define COLOR_RED "\x1b[0;1;31m"
#define COLOR_GREEN "\x1b[0;1;32m"
#define COLOR_DEFAULT "\x1b[0m"

static int md_len;

char *getPassword(){
	struct termios old, new;
	char *passwd = (char *)malloc(sizeof(char) * 40);

	//Disable ECHOing
	if(tcgetattr(fileno(stdin), &old) == -1){
		return NULL;
	}
	new = old;
	new.c_lflag &= ~ECHO;
	if(tcsetattr(fileno(stdin), TCSAFLUSH, &new) == -1){
		return NULL;
	}

	//Reading passwd
	scanf("%s", passwd);

	//Restore ECHOing
	if(tcsetattr(fileno(stdin), TCSAFLUSH, &old) == -1){
		return NULL;
	}

	return passwd;

}

//function to calculate SHA1 hash of the provided string.
unsigned char *calcSHA1(char *passwd, int len){
	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
	unsigned char *md_value;
	md_value = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE);

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("SHA1");

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, passwd, len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	EVP_cleanup();
	return md_value;
}


int main(int argc, char **argv){
	int fd, err, len, i, j, t;
	char buf[4097], *ptr;
	unsigned char *hash, ch[3], temp;
	unsigned char *passwd;
	char check[41], hashstr[41], found, save, times[41], cnc, nocount;

	fd = open(argv[1], O_RDONLY);
	if(fd == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}

	printf("Password : ");
	passwd = getPassword();
	if(passwd == NULL){
		printf("error\n");
	}
	if(argc > 2){
		if(strcmp(argv[2], "-nocount") == 0){
			nocount = 'y';
		}else{
			fprintf(stderr, "Invalid option specified\npwned path [-nocount]");
			return -1;
		}
	}else{
		nocount = 'n';
	}
	len = strlen(passwd);
	hash = calcSHA1(passwd, len);
	t=j=0;
	for(i=0; i < md_len; ++i){
		sprintf(ch, "%02X", hash[i]);
		hashstr[j++] = ch[0];
		hashstr[j++] = ch[1];
	}
	hashstr[j] = '\0';
	
	//freeing unwanted memory
	free(passwd);
	free(hash);
	passwd = NULL;
	hash = NULL;
	
	printf("\n");
	found = 'n';
	save = 'n';
	cnc = 'n'; //count not complete
	while(1){
		memset(buf, '\0', 4097);
		err = read(fd, buf, 4096);
		if(err == -1){
			fprintf(stderr, "%s\n", strerror(errno));
			break;
		}else if(err == 0){
			if(cnc == 'z'){
				printf(COLOR_RED "Password found in the list %s times\n" COLOR_DEFAULT, times);
			}else{
				fprintf(stderr, COLOR_GREEN "Not found\n" COLOR_DEFAULT);
			}
			break;
		}
		ptr = buf;

		//loop to read fromt the given file until it is completely read in blocks of 4096 bytes.
		while(*ptr != '\0' ){
			if(save == 'n' && cnc != 'z'){
				j=0;
				t=0;
				memset(check, '\0', 41);
				memset(times, '\0', 41);
			}else{
				save = 'n';
			}
			//loop to read line by line both hash and count
			while(*ptr != '\n' && *ptr != '\0' && *ptr != '\r'){
				if((*ptr == SEPARATOR || cnc == 'z')){
					while(*ptr != '\0' && *ptr != '\n' && *ptr != '\r'){
						if(*ptr >= '0' && *ptr <= '9' && nocount == 'n'){
							times[t++]=*ptr;
						}
						++ptr;
					}
					times[t] = '\0';
					if(cnc == 'z' || cnc == 'y'){
						cnc = 'n';
					}
					//If while extracting the count and buffer becomes empty, preserve the hash and count until it is further read from file.
					if(*ptr == '\0'){
						cnc = 'y';
					}

				}
				if(*ptr != '\0' && *ptr != '\n' && *ptr != ' ' && *ptr != '\r'){
					check[j++] = *ptr;
					++ptr;
				}
			}

			//Cases where buffer could be empty just after reading the hash value and before reading the count.
			if(strlen(times) < 1 && *ptr == '\0' && nocount == 'n'){
				cnc = 'y';
			}
			
			if(strlen(check) < 40){
				save = 'y';
			}else if(strcmp(check, hashstr) == 0){
				if(cnc == 'y'){
					cnc = 'z'; //only preserve the count and hash if the hashes matches, else it can be discarded.
				}else{
					if(nocount == 'y'){
						printf(COLOR_RED "Password found in the list\n" COLOR_DEFAULT);
					}else{
						printf(COLOR_RED "Password found in the list %s times\n" COLOR_DEFAULT, times);	
					}
					found = 'y';
					break;
				}
			}
			if(found == 'y'){
				break;
			}

			//Increment only if it doesn't cross its bound.
			if(*ptr != '\0'){
				++ptr;
			}
			
		}
		if(found == 'y'){
			break;
		}
	}
	close(fd);
	return 0;
}
