#!/bin/sh

echo "Private key password:\c"
stty -echo
read -r PW_PASSWORD
stty echo
echo
export PW_PASSWORD
