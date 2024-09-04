Standard process injection using syscalls

Explained: 
           Process Injection
Instead of using win32 or ntapi this program skips those and uses syscalls instead, this might be useful for bypassing EDR and AV solutions. As well as this it utilizes AES 256 decryption during runtime so that the shellcode isnt caught in memory as easily. If you are interesed in learning this technique or similar ones heres the sources I read from to get the picture: https://www.crow.rip, https://www.solomonsklash.io/syscalls-for-shellcode-injection.html, https://medium.com/@lsecqt/basic-process-injection-with-c-e6d4d2fa3b4a (Great work!) 

In order to compile, first object files from the syscalls and functions files. 
You can do this with verious compileres, I used MASM for the assembly and CL for the c file. 
Heres an example: 
                      "C:/>ml64 /c syscalls.asm"
                      "C:/>cl /c /Fo functions.obj functions.c"

Then you can compile this into a library that is used with the main.c file,
you can do this using the lib tool included in visual studio build tools:

                      "C:/>lib /out:syscalls.lib main.obj syscalls.obj /MACHINE:X64"

Once you have the library simply use gcc or a compiler of your choice to make an exe/dll or whatever you wish:

                      "C:/>gcc -o main main.c -L. -lsyscalls -lPsapi -lCrypt32"

And there you go you got your exe, this might be obvious to some people but I wanted to include it regardless due to the few that might struggle. Thats all, thanks...
