# Architecture

## Internal Dependencies

- `aes.c` -> `aes.h`
- `beacon.c` -> `aes.h`
- `beacon.c` -> `cJSON.h`
- `cJSON.c` -> `cJSON.h`

## External Imports

- `aes.c` -> string.h
- `aes.h` -> stddef.h, stdint.h
- `beacon.c` -> arpa/inet.h, curl/curl.h, errno.h, fcntl.h, net/if.h, netdb.h, netinet/in.h, openssl/rand.h, pwd.h, stdarg.h, stdint.h, stdio.h, stdlib.h, string.h, sys/ioctl.h, sys/mman.h, sys/socket.h, sys/types.h, sys/utsname.h, sys/wait.h, time.h, unistd.h
- `cJSON.c` -> ctype.h, float.h, limits.h, locale.h, math.h, stdio.h, stdlib.h, string.h
- `cJSON.h` -> stddef.h
