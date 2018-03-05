ECHO ON

SET PATH=C:\Program Files\Git\mingw64\bin;%PATH%

IF NOT EXIST stack.exe (
    curl -sS -ostack.zip -L --insecure http://www.stackage.org/stack/windows-i386
    7z x stack.zip stack.exe
)

IF NOT EXIST C:\Users\appveyor\AppData\Local\Programs\stack (
    stack setup > nul
)

