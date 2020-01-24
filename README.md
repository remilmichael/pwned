## pwned


Program to check if your password has been pwned, instead of typing your password at https://haveibeenpwned.com, like if you are so paranoid about typing it on the website.

**Compile**
```
gcc pwned.c -lcrypto -o pwned
```

**Run**
```
./pwned FILE [-nocount]
```
***FILE : Download it from https://haveibeenpwned.com/Passwords (SHA-1)***

This program only works if the contents are hashed(except count and separator) using SHA1 and if it is in the format given below:-
 
	hash1:count
	hash2:count
	.
	.
	.
	hashN:count
If and only if the file has no count given against each hash, execute the program with the option "**-nocount**".
