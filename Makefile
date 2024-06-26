# Directories
INC       = inc/
SRC       = src/
SRCS      = $(wildcard src/*.c)
OBJ       = obj/
OBJS      = $(addprefix $(OBJ), $(notdir $(SRCS:.c=.o)))

# Compiler options
CC_PREFIX = 
CC        = $(CC_PREFIX)gcc
INCLUDE   = -I$(INC)
CFLAGS    = -Wall

# Private stuff

DEBUG_    = -g -O0 -DDEBUG
NO_OS_    = -DTP_NO_OS
MKDIR     = @mkdir -p $(@D)

# Targets

.PHONY: build build_no_os debug debug_no_os example clean

build: $(OBJS)

build_no_os: CFLAGS += $(NO_OS_)
build_no_os: build

debug: CFLAGS += $(DEBUG_)
debug: build

debug_no_os: CFLAGS += $(DEBUG_) $(NO_OS_)
debug_no_os: build

example: client.elf server.elf

$(OBJ)%.o: $(SRC)%.c $(INC)%.h
	$(MKDIR)
	$(CC) -c $< $(INCLUDE) $(CFLAGS) -o $@

%.elf: %.c
	$(CC) $< $(INCLUDE) $(OBJS) $(CFLAGS) -o $@

clean:
	rm -f *.elf
	rm -f $(OBJ)*