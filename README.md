[Simple start]
Make sure to add ./lib in LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib/
./run.sh (will compile and test)

[Notes]
+ Standard make and gcc is used to compile (Linux target)
+ Developed using VisualStudio 2022 IDE
+ Build environment is on Windows 11 22H2, using WSL2 
+ Tested on x64_86 (WSL)
+ Tarball will include binaries
+ Makefile is in src/Makefile
+ Validation done on input, code written to prevent overflows

[Scripts]
Run ./run.sh which will compile and test everything
./test/test.sh will also run tests against the applications

[Build Instructions]
cd src
make
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../lib        // Or whichever path you prefer for the libcryptprov.so library
../bin/testcrypt
../bin/crypt -h

Binary locations:
/bin/testcrypt
/bin/crypt

Shared library is stored in 
/lib/libcryptprov.so

Includes are stored in
/include

Build objects are stored in
/build

Additional testing/dev notes: test/notes.txt