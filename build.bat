cl.exe encrypt.cpp /Feencrypt.exe
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG loader.c /Feloader.exe
del *.obj
cd ShellcodeTemplate
make
cd ..