CC := x86_64-w64-mingw32-gcc
# CFLAG := -s -Iinclude -Wl,-subsystem,windows
CFLAG := -s -Iinclude

CRES := x86_64-w64-mingw32-windres

default:
	$(CRES) res/resource.rc -o bin/resource.o
	$(CC) $(CFLAG) bin/resource.o  src/*.c  -o bin/beacon.x64.exe -D DEBUG
