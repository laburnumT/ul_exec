.PHONY: clean debug asan
.DEFAULT_GOAL :=all

CFLAGS := -Wall -Wextra -O2 -std=gnu17
CPPFLAGS := -MMD -MP
DEBUG := 0

EXEC_TARGET := ul_exec
SRC_DIR := src
OBJ_DIR := obj

SRCS := \
	src/helper.c \
	src/main.c \
	src/my_elf.c \

OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

-include $(OBJS:.o=.d)

all: $(EXEC_TARGET)

$(EXEC_TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug: CFLAGS += -g -DDEBUG -O0 -fsanitize=undefined
debug: all

asan: CFLAGS += -fsanitize=address,undefined
asan: all

$(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR)
	rm -f $(EXEC_TARGET)
