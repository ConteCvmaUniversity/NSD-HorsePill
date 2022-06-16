#!/bin/bash


echo "                     __                                        
  ____  ____   _____/  |_  ____       _______  _______ _____   
_/ ___\/  _ \ /    \   __\/ __ \    _/ ___\  \/ /     \\__  \  
\  \__(  <_> )   |  \  | \  ___/    \  \___\   /  Y Y  \/ __ \_
 \___  >____/|___|  /__|  \___  >____\___  >\_/|__|_|  (____  /
     \/           \/          \/_____/   \/          \/     \/ "

export ENCRYPTION_KEY=$(python -c 'from os import urandom; print(urandom(24).encode("hex"))')
echo $ENCRYPTION_KEY > pass.txt
echo $ENCRYPTION_KEY

