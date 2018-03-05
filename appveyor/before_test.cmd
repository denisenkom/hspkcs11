set PATH=C:\Program Files\Git\mingw64\bin;%PATH%

IF NOT EXIST C:\\Users\\appveyor\\AppData\\Local\\Programs\\stack (
    curl -sS -ostack.zip -L --insecure http://www.stackage.org/stack/windows-i386
    7z x stack.zip stack.exe
    stack setup > nul
)

