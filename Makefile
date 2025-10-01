
all: guest.img guest2.img kvm_zadatak3

kvm_zadatak3: kvm_zadatak3.c
	gcc kvm_zadatak3.c -o kvm_zadatak3

guest.img: guest.o
	ld -T guest.ld guest.o -o guest.img

guest.o: guest.c
	$(CC) -m64 -ffreestanding -c -o $@ $^

guest2.img: guest2.o
	ld -T guest2.ld guest2.o -o guest2.img

guest2.o: guest2.c
	$(CC) -m64 -ffreestanding -c -o $@ $^

clean:
	rm -f kvm_zadatak3 guest.o guest.img guest2.o guest2.img
	rm -fr vm_dir_*
dir_clean:
	rm -fr vm_dir_*
