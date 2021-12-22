# linux-auth
This code is to simply demonstrate simple user authentication using the shadow file.

## This code is not:
- perfect/complete
- intended to be the start of a DIY authentication solution. Please do not roll your own authentication solution.
- how Linux authentication works on a modern desktop with Linux-PAM

### This code demonstrates:
- how the shadow file entries can be enumerated using getspent function (./auth -s)
- how specific users can be queried using the getspnam function (use ./auth without flags)
- how using gnu libcrypt can be used to authenticate a particular user

This code/project is built using cmake and can be built by issuing the following commands in the project root folder:

    cmake --configure .

    cmake --build .

This will generate an executable named "auth". In order to run the executable, it should have the following owernship/permissions:

    chown root:root ./auth

    chmod 4751 ./auth

**Note, from a security perspective, this binary executable is NOT safe to leave lying around with these permissions.** 

**This code is intended for educational purposes only**

