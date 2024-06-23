CC = gcc
CFLAGS = -Wall -Wextra -std=gnu17

SOURCES = webserver.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = webserver

.PHONY: clean distclean

make: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean: 
	rm -f $(OBJECTS)

distclean: clean
	rm -f $(EXECUTABLE)
