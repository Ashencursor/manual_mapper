# Issue:
- [X] for some reason right after i hit an ordinal, and then go onto the next loop and print the name of the import, it crashes my program. Idk why. Everything else should be the same and work, th elogic is correct to my knowledge


- [ ] Not sure why. but whenever i call dllmain inside the shellcode, it calls a specific address that is completely incorrect like `0x51AA0` or something like that. Evyerthintg else up to that point should be correct
- [ ] the iat might be a bit bugged but should be correct to my understanding, however the check_rva function is a dud for me, idk why it works but it does lol


# Goals:
- [ ] make a few more functions to make the code more readable:
  - helper functions for `resolve_imports`(e.g: make info static or something about the remoteloadlibrary)
  - function to write shellcode and params
     
- [ ] offtopic: Since the `remote_load_librarya` works to my understanding(from what ive witnessed in systeminformer and whatnot), I could be lazy and just do   `createremotethread` with `remote_load_librarya` and load dllmain by passing the filepath to my dll or whatever `loadlibrarya` takes
