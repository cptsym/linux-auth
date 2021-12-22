#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "authconf.h"
#include <shadow.h>
#include <crypt.h>
#include <getopt.h>
#include <crypt.h>
#include <termios.h>

#define VERSION 1.0


/* author: 	ddevine
 * email : 	ddevine@live.com
 *
 * auth:	This program demonstrates how system authorization works
 * 			without Linux-PAM. Note that this program needs the correct
 * 			permissions to run properly. It can be run using sudo if the
 * 			file has normal user privileges. It can be run by a regular
 * 			user without sudo if the setuid bit is set, the owner is
 * 			root, and the user has executable permissions; setuid allows
 * 			a user to run the program as root despite not having root
 * 			priviledges.
 *
 * 			Essentially, this program could be modified to run a dictionary
 * 			or rainbow attack against the /etc/shadow file; so it is
 * 			recommended this program be run using sudo.
 */


void enumerate(void);
void verify_creds(char *, char *);
int genctyp(char *, char *);
void getinput(char *, int);

struct option long_options[] = {
	{"show", no_argument, 0, 's'},
	{"verbose", optional_argument, 0, 'v'},
	{0, 0, 0, 0}
};

int option_index = 0;

char username[64];
char password[64];

struct spwd *entry;

int
main(int argn, char **argv){
	
	char c;

	/* show all possible shadow file entries */
	while((c = getopt_long(argn, argv, "s", long_options, &option_index)) != -1){
		switch(c){
			case 's':
					enumerate();
					exit(EXIT_SUCCESS);
					break;
		}
	}	

	printf("Enter username: ");
	getinput(username, sizeof(username));

	printf("Enter password: ");
	getinput(password, sizeof(password));

	printf("The password is: %s\n", password);

	/* lookup shadow entry for user */
	if((entry = getspnam(username)) == NULL){
		printf("Unable to find username %s\n", username);
		exit(EXIT_FAILURE);
	}

	printf("Username discovered: %s\n", entry -> sp_namp);
	printf("Hashed password: %s\n", entry -> sp_pwdp);

	verify_creds(entry -> sp_pwdp, password);

	return 0;
}

void
enumerate(){

	entry = NULL;

	// open database for reading
	setspent();

	// enumerate through entries
	while((entry = getspent()) != NULL){
		
		printf("Name: %s\n", entry -> sp_namp);
	}	

	if(entry == NULL){
		printf("entry EOF reached.\n");
	}

	// close database
	endspent();

	return;
}

void
verify_creds(char *hs, char *password){
	/*  The array "function" is merely a part of a string from the shadow file.
	 *
	 *  Shadow file entries are generally in the following form:
	 *
	 *  	$hash_id$salt$password_hash
	 *
	 * 	A string in this form is returned by the getspnam function. In order
	 * 	to authenticate a password for a user against one of these entries,
	 * 	gnu libcrypt must be used. This can be done using the crypt function:
	 *
	 * 		hash = crypt("password", "$hash_id$salt");
	 *
	 *	The crypt function can use the entry to get the hash type and salt. A
	 *	password is provided by a user, crypt hashes it with the specified
	 *	hash function and salt, and the returned hash can be compared against
	 *	the password_hash of the shadow entry (from which we obtained the the
	 *	hash_type and the salt).
	 */
	char function[40] = "$";
	char enc_type[10] = "";

	char *res;

	char entry_id[5];
	char entry_salt[60];
	char entry_hash[100];

	char res_id[5];
	char res_salt[60];
	char res_hash[100];

	strcpy(entry_id, strtok(hs, "$"));
	strcpy(entry_salt, strtok(NULL,"$"));
	strcpy(entry_hash, strtok(NULL, "$"));

	printf("ID: %s\n", entry_id);
	printf("SALT: %s\n", entry_salt);
	printf("HASH: %s\n", entry_hash);

	genctyp(entry_id, enc_type);
	printf("Encryption type: %s\n", enc_type);
	
	strcat(function, entry_id);
	strcat(function, "$");
	strcat(function, entry_salt);

	/* create password hash */
	res = crypt(password, function);

	strcpy(res_id, strtok(res, "$"));
	strcpy(res_salt, strtok(NULL, "$"));
	strcpy(res_hash, strtok(NULL, "$"));

	printf("MATCH: %s\n", (strcmp(entry_hash, res_hash) == 0)? "TRUE" : "FALSE");
}

int
genctyp(char *tok, char *type){
    if(strcmp(tok, "") == 0)   { strcat(type, "DES");     return 0; }
	if(strcmp(tok, "1") == 0)  { strcat(type, "MD5");     return 1; }
	if(strcmp(tok, "2") == 0)  { strcat(type, "bcrypt");  return 2; }
	if(strcmp(tok, "2a") == 0) { strcat(type, "bcrypt");  return 3; }
	if(strcmp(tok, "2x") == 0) { strcat(type, "bcrypt");  return 4; }
	if(strcmp(tok, "2y") == 0) { strcat(type, "bcrypt");  return 5; }
	if(strcmp(tok, "3") == 0)  { strcat(type, "NTHASH");  return 6; }
	if(strcmp(tok, "5") == 0)  { strcat(type, "SHA-256"); return 7; }
	if(strcmp(tok, "6") == 0)  { strcat(type, "SHA-512"); return 8; }

	return -1;
}

void
getinput(char *input, int len){
	if(fgets(input, len, stdin) == NULL){
		if(ferror(stdin) > 0){
				exit(EXIT_FAILURE);
		}
	}
	
	// remove trailing newline
	input[strcspn(input, "\r\n")] = 0;
}




