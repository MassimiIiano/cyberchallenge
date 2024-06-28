#!/bin/bash

file=$(find . -maxdepth 1 -type f \( -name "*.zip" -o -name "*.tar.gz" -o -name "*.gz" \) | head -n 1)

case $file in
    *.tar.gz) tar -xzf $file ;;
    *.gz) gunzip $file ;;
    *.zip) unzip -P password $file ;;
    *) echo "Unsupported file format" ;;
esac

rm $file
