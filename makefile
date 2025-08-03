LDLIBS=-lpcap

all: send-arp


main.o:  send-arp.h sen-arp.cpp



send-arp: send-arp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
