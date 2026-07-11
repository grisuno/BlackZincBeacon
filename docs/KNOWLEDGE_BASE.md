# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 10 | **Total Symbols Extracted:** 227 | **Total Imports:** 38

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
    beacon_c["beacon.c (c)"]
    class beacon_c mod;
    beacon_c_MemoryStruct["MemoryStruct"]
    class beacon_c_MemoryStruct cls;
    beacon_c --> beacon_c_MemoryStruct
    beacon_c_base64_encode["base64_encode"]
    class beacon_c_base64_encode fn;
    beacon_c --> beacon_c_base64_encode
    beacon_c_base64_decode["base64_decode"]
    class beacon_c_base64_decode fn;
    beacon_c --> beacon_c_base64_decode
    beacon_c_aes256_cfb_encrypt["aes256_cfb_encrypt"]
    class beacon_c_aes256_cfb_encrypt fn;
    beacon_c --> beacon_c_aes256_cfb_encrypt
    beacon_c_aes256_cfb_decrypt["aes256_cfb_decrypt"]
    class beacon_c_aes256_cfb_decrypt fn;
    beacon_c --> beacon_c_aes256_cfb_decrypt
    cJSON_c["cJSON.c (c)"]
    class cJSON_c mod;
    cJSON_c_internal_hooks["internal_hooks"]
    class cJSON_c_internal_hooks cls;
    cJSON_c --> cJSON_c_internal_hooks
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    aes_c["aes.c (c)"]
    class aes_c mod;
    aes_c_getSBoxValue["getSBoxValue"]
    class aes_c_getSBoxValue fn;
    aes_c --> aes_c_getSBoxValue
    aes_c_getSBoxInvert["getSBoxInvert"]
    class aes_c_getSBoxInvert fn;
    aes_c --> aes_c_getSBoxInvert
    aes_c_Td0["Td0"]
    class aes_c_Td0 fn;
    aes_c --> aes_c_Td0
    aes_c_Td1["Td1"]
    class aes_c_Td1 fn;
    aes_c --> aes_c_Td1
    aes_c_Td2["Td2"]
    class aes_c_Td2 fn;
    aes_c --> aes_c_Td2
    aes_h["aes.h (h)"]
    class aes_h mod;
    aes_h_AES_ctx["AES_ctx"]
    class aes_h_AES_ctx cls;
    aes_h --> aes_h_AES_ctx
    aes_h_AES_H["AES_H"]
    class aes_h_AES_H fn;
    aes_h --> aes_h_AES_H
    aes_h_CBC["CBC"]
    class aes_h_CBC fn;
    aes_h --> aes_h_CBC
    aes_h_ECB["ECB"]
    class aes_h_ECB fn;
    aes_h --> aes_h_ECB
    aes_h_CTR["CTR"]
    class aes_h_CTR fn;
    aes_h --> aes_h_CTR
    cJSON_h["cJSON.h (h)"]
    class cJSON_h mod;
    cJSON_h_cJSON["cJSON"]
    class cJSON_h_cJSON cls;
    cJSON_h --> cJSON_h_cJSON
    cJSON_h_cJSON_Hooks["cJSON_Hooks"]
    class cJSON_h_cJSON_Hooks cls;
    cJSON_h --> cJSON_h_cJSON_Hooks
    cJSON_h_cJSON__h["cJSON__h"]
    class cJSON_h_cJSON__h fn;
    cJSON_h --> cJSON_h_cJSON__h
    cJSON_h___WINDOWS__["__WINDOWS__"]
    class cJSON_h___WINDOWS__ fn;
    cJSON_h --> cJSON_h___WINDOWS__
    cJSON_h_CJSON_CDECL["CJSON_CDECL"]
    class cJSON_h_CJSON_CDECL fn;
    cJSON_h --> cJSON_h_CJSON_CDECL
    andoid_build_sh["andoid_build.sh (sh)"]
    class andoid_build_sh mod;
    app_py["app.py (py)"]
    class app_py mod;
    armbian_build_sh["armbian_build.sh (sh)"]
    class armbian_build_sh mod;
    build_arm32_sh["build_arm32.sh (sh)"]
    class build_arm32_sh mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    ext_aes_h["aes.h"]
    class ext_aes_h ext;
    aes_c -.->|imports| ext_aes_h
    ext_string_h["string.h"]
    class ext_string_h ext;
    aes_c -.->|imports| ext_string_h
    ext_stdint_h["stdint.h"]
    class ext_stdint_h ext;
    aes_h -.->|imports| ext_stdint_h
    ext_stddef_h["stddef.h"]
    class ext_stddef_h ext;
    aes_h -.->|imports| ext_stddef_h
    ext_stdio_h["stdio.h"]
    class ext_stdio_h ext;
    beacon_c -.->|imports| ext_stdio_h
    ext_stdlib_h["stdlib.h"]
    class ext_stdlib_h ext;
    beacon_c -.->|imports| ext_stdlib_h
    beacon_c -.->|imports| ext_string_h
    ext_unistd_h["unistd.h"]
    class ext_unistd_h ext;
    beacon_c -.->|imports| ext_unistd_h
    ext_time_h["time.h"]
    class ext_time_h ext;
    beacon_c -.->|imports| ext_time_h
    ext_sys_types_h["types.h"]
    class ext_sys_types_h ext;
    beacon_c -.->|imports| ext_sys_types_h
    ext_sys_socket_h["socket.h"]
    class ext_sys_socket_h ext;
    beacon_c -.->|imports| ext_sys_socket_h
    ext_netinet_in_h["in.h"]
    class ext_netinet_in_h ext;
    beacon_c -.->|imports| ext_netinet_in_h
    ext_arpa_inet_h["inet.h"]
    class ext_arpa_inet_h ext;
    beacon_c -.->|imports| ext_arpa_inet_h
    ext_net_if_h["if.h"]
    class ext_net_if_h ext;
    beacon_c -.->|imports| ext_net_if_h
    ext_sys_ioctl_h["ioctl.h"]
    class ext_sys_ioctl_h ext;
    beacon_c -.->|imports| ext_sys_ioctl_h
    ext_pwd_h["pwd.h"]
    class ext_pwd_h ext;
    beacon_c -.->|imports| ext_pwd_h
    ext_errno_h["errno.h"]
    class ext_errno_h ext;
    beacon_c -.->|imports| ext_errno_h
    ext_curl_curl_h["curl.h"]
    class ext_curl_curl_h ext;
    beacon_c -.->|imports| ext_curl_curl_h
    ext_sys_mman_h["mman.h"]
    class ext_sys_mman_h ext;
    beacon_c -.->|imports| ext_sys_mman_h
    ext_fcntl_h["fcntl.h"]
    class ext_fcntl_h ext;
    beacon_c -.->|imports| ext_fcntl_h
    beacon_c -.->|imports| ext_stdint_h
    ext_sys_wait_h["wait.h"]
    class ext_sys_wait_h ext;
    beacon_c -.->|imports| ext_sys_wait_h
    ext_stdarg_h["stdarg.h"]
    class ext_stdarg_h ext;
    beacon_c -.->|imports| ext_stdarg_h
    ext_netdb_h["netdb.h"]
    class ext_netdb_h ext;
    beacon_c -.->|imports| ext_netdb_h
    ext_sys_utsname_h["utsname.h"]
    class ext_sys_utsname_h ext;
    beacon_c -.->|imports| ext_sys_utsname_h
    ext_openssl_rand_h["rand.h"]
    class ext_openssl_rand_h ext;
    beacon_c -.->|imports| ext_openssl_rand_h
    beacon_c -.->|imports| ext_aes_h
    ext_cJSON_h["cJSON.h"]
    class ext_cJSON_h ext;
    beacon_c -.->|imports| ext_cJSON_h
    cJSON_c -.->|imports| ext_string_h
    cJSON_c -.->|imports| ext_stdio_h
    ext_math_h["math.h"]
    class ext_math_h ext;
    cJSON_c -.->|imports| ext_math_h
    cJSON_c -.->|imports| ext_stdlib_h
    ext_limits_h["limits.h"]
    class ext_limits_h ext;
    cJSON_c -.->|imports| ext_limits_h
    ext_ctype_h["ctype.h"]
    class ext_ctype_h ext;
    cJSON_c -.->|imports| ext_ctype_h
    ext_float_h["float.h"]
    class ext_float_h ext;
    cJSON_c -.->|imports| ext_float_h
    ext_locale_h["locale.h"]
    class ext_locale_h ext;
    cJSON_c -.->|imports| ext_locale_h
    cJSON_c -.->|imports| ext_cJSON_h
    cJSON_h -.->|imports| ext_stddef_h
```

---

## Architecture Reference

### C (3 files)

#### `aes.c`
**Path:** `aes.c`

**Functions:**
- `getSBoxValue` (line 12) - *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h> define Nb 4 define KEYLEN_256 32 define RKLENGTH (4 * (...*
- `getSBoxInvert` (line 34)
- `Td0` (line 56)
- `Td1` (line 58)
- `Td2` (line 59)
- `Td3` (line 60)
- `Td4` (line 61)
- `KeyExpansion` (line 166) - *static uint8_t getSBoxValue(uint8_t num) { return sbox[num]; }  define getSBoxValue(num) (sbox[(num)]) This function produces Nb(Nr+1) round keys. ...*
- `AES_init_ctx` (line 238)
- `AES_init_ctx_iv` (line 244) - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249)
- `AddRoundKey` (line 257) - *endif This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row...*
- `xtime` (line 313)
- `MixColumns` (line 320) - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary...*
- `InvMixColumns` (line 370) - *static uint8_t getSBoxInvert(uint8_t num) { return rsbox[num]; }  define getSBoxInvert(num) (rsbox[(num)]) MixColumns function mixes the columns of...*
- `InvSubBytes` (line 391) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402)
- `Cipher` (line 433) - *endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); }  } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB...*
- `AES_ECB_decrypt` (line 495)
- `XorWithIv` (line 510) - *endif // #if defined(ECB) && (ECB == 1) if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520)
- `AES_CBC_decrypt_buffer` (line 535)
- `AES_CTR_xcrypt_buffer` (line 558) - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; }  }  #endif // #if defined(CBC) && (CBC == 1)    #if def...*

**Macros:**
- `Nb` (line 4)
- `KEYLEN_256` (line 6)
- `RKLENGTH` (line 10)
- `BLOCKLEN` (line 11)
- `Nb` (line 67)
- `Nk` (line 70)
- `Nr` (line 71)
- `Nk` (line 73)
- `Nr` (line 74)
- `Nk` (line 76)
- `Nr` (line 77)
- `MULTIPLY_AS_A_FUNCTION` (line 84)
- `getSBoxValue` (line 163)
- `Multiply` (line 349)
- `getSBoxInvert` (line 365)

#### `beacon.c`
**Path:** `beacon.c`

**Functions:**
- `base64_encode` (line 49)
- `base64_decode` (line 75)
- `aes256_cfb_encrypt` (line 118) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 145)
- `WriteMemoryCallback` (line 181)
- `https_request` (line 193)
- `exec_cmd` (line 252) - *=== EXEC CMD ===*
- `get_local_ips` (line 297) - *=== GET LOCAL IPs ===*
- `main` (line 340) - *=== MAIN === === MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2_URL` (line 27)
- `CLIENT_ID` (line 30)
- `MALEABLE` (line 31)
- `USER_AGENTS_COUNT` (line 32)

**Structs:**
- `MemoryStruct` (line 177) - *=== HTTPS REQUEST ===*

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94)
- `CJSON_PUBLIC` (line 99)
- `CJSON_PUBLIC` (line 109)
- `CJSON_PUBLIC` (line 124) - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; }  return item->valuedouble...*
- `case_insensitive_strcmp` (line 134) - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR !=...*
- `internal_malloc` (line 166) - *}  return tolower(*string1) - tolower(*string2); }  typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *...*
- `internal_free` (line 170)
- `internal_realloc` (line 174)
- `cJSON_strdup` (line 188)
- `CJSON_PUBLIC` (line 209)
- `cJSON_New_Item` (line 242) - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; }  /* use realloc only if both free and malloc are used global_hooks.reallo...*
- `get_decimal_point` (line 281) - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->strin...*
- `parse_number` (line 309) - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer;  /*...*
- `ensure` (line 494) - *}  typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool...*
- `update_offset` (line 579) - *p->buffer = NULL;  return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = n...*
- `compare_double` (line 592) - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsi...*
- `print_number` (line 599) - *} buffer_pointer = buffer->buffer + buffer->offset;  buffer->offset += strlen((const char*)buffer_pointer); }  /* securely comparison of floating-p...*
- `parse_hex4` (line 669) - *output_pointer[i] = '.'; continue; }  output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0';  output_buffer->offset += (size_t)length;  ...*
- `utf16_literal_to_utf8` (line 706) - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); }  output_pointer += utf8_length;  return sequence_length;  fail: return 0; }  /* ...*
- `print_string_ptr` (line 957) - *{ input_buffer->hooks.deallocate(output); output = NULL; }  if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buff...*
- `print_string` (line 1079) - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_l...*
- `buffer_skip_whitespace` (line 1093) - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } ...*
- `skip_utf8_bom` (line 1119) - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; }  if (buffer->offset == buffer->length) { buffer...*
- `CJSON_PUBLIC` (line 1133)
- `CJSON_PUBLIC` (line 1235)
- `print` (line 1242) - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315)
- `CJSON_PUBLIC` (line 1320)
- `CJSON_PUBLIC` (line 1351)
- `parse_value` (line 1372) - *return false; }  p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_...*
- `print_value` (line 1427) - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (c...*
- `parse_array` (line 1501) - *return print_string(item, output_buffer);  case cJSON_Array: return print_array(item, output_buffer);  case cJSON_Object: return print_object(item,...*
- `print_array` (line 1599) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an array to text*
- `parse_object` (line 1661) - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buff...*
- `print_object` (line 1780) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an object to text.*
- `get_array_item` (line 1915)
- `CJSON_PUBLIC` (line 1934)
- `get_object_item` (line 1944)
- `CJSON_PUBLIC` (line 1976)
- `CJSON_PUBLIC` (line 1981)
- `CJSON_PUBLIC` (line 1986)
- `suffix_object` (line 1993) - *return get_object_item(object, string, false); }  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...*
- `create_reference` (line 2000) - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; }  /* U...*
- `add_item_to_array` (line 2020)
- `cast_away_const` (line 2066) - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); }  #...*
- `add_item_to_object` (line 2073) - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111)
- `CJSON_PUBLIC` (line 2122)
- `CJSON_PUBLIC` (line 2132)
- `CJSON_PUBLIC` (line 2142)
- `CJSON_PUBLIC` (line 2154)
- `CJSON_PUBLIC` (line 2166)
- `CJSON_PUBLIC` (line 2178)
- `CJSON_PUBLIC` (line 2190)
- `CJSON_PUBLIC` (line 2202)
- `CJSON_PUBLIC` (line 2214)
- `CJSON_PUBLIC` (line 2226)
- `CJSON_PUBLIC` (line 2238)
- `CJSON_PUBLIC` (line 2250)
- `CJSON_PUBLIC` (line 2286)
- `CJSON_PUBLIC` (line 2296)
- `CJSON_PUBLIC` (line 2301)
- `CJSON_PUBLIC` (line 2308)
- `CJSON_PUBLIC` (line 2315)
- `CJSON_PUBLIC` (line 2320)
- `CJSON_PUBLIC` (line 2362)
- `CJSON_PUBLIC` (line 2412)
- `replace_item_in_object` (line 2422)
- `CJSON_PUBLIC` (line 2445)
- `CJSON_PUBLIC` (line 2450)
- `CJSON_PUBLIC` (line 2467)
- `CJSON_PUBLIC` (line 2478)
- `CJSON_PUBLIC` (line 2489)
- `CJSON_PUBLIC` (line 2500)
- `CJSON_PUBLIC` (line 2525)
- `CJSON_PUBLIC` (line 2542)
- `CJSON_PUBLIC` (line 2554)
- `CJSON_PUBLIC` (line 2566)
- `CJSON_PUBLIC` (line 2578)
- `CJSON_PUBLIC` (line 2595)
- `CJSON_PUBLIC` (line 2606)
- `CJSON_PUBLIC` (line 2658)
- `CJSON_PUBLIC` (line 2698)
- `CJSON_PUBLIC` (line 2738)
- `cJSON_Duplicate_rec` (line 2785)
- `skip_oneline_comment` (line 2872)
- `skip_multiline_comment` (line 2885)
- `minify_string` (line 2899)
- `CJSON_PUBLIC` (line 2921)
- `CJSON_PUBLIC` (line 2971)
- `CJSON_PUBLIC` (line 2981)
- `CJSON_PUBLIC` (line 2991)
- `CJSON_PUBLIC` (line 3001)
- `CJSON_PUBLIC` (line 3011)
- `CJSON_PUBLIC` (line 3021)
- `CJSON_PUBLIC` (line 3031)
- `CJSON_PUBLIC` (line 3041)
- `CJSON_PUBLIC` (line 3051)
- `CJSON_PUBLIC` (line 3061)
- `CJSON_PUBLIC` (line 3071)
- `cJSON_ArrayForEach` (line 3157)
- `cJSON_ArrayForEach` (line 3173) - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193)
- `CJSON_PUBLIC` (line 3198)

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28)
- `true` (line 65)
- `false` (line 70)
- `isinf` (line 74)
- `isnan` (line 77)
- `NAN` (line 82)
- `NAN` (line 84)
- `internal_malloc` (line 179)
- `internal_free` (line 180)
- `internal_realloc` (line 181)
- `static_strlen` (line 185)
- `can_read` (line 301)
- `can_access_at_index` (line 303)
- `cannot_access_at_index` (line 304)
- `buffer_at_offset` (line 306)
- `cjson_min` (line 1240)

**Structs:**
- `internal_hooks` (line 157)

### H (2 files)

#### `aes.h`
**Path:** `aes.h`

**Macros:**
- `AES_H` (line 2)
- `CBC` (line 8)
- `ECB` (line 11)
- `CTR` (line 14)
- `AES256` (line 16)
- `AES_BLOCKLEN` (line 18)
- `AES_KEYLEN` (line 21)
- `AES_keyExpSize` (line 22)
- `AES_KEYLEN` (line 24)
- `AES_keyExpSize` (line 25)
- `AES_KEYLEN` (line 27)
- `AES_keyExpSize` (line 28)

**Structs:**
- `AES_ctx` (line 31) - *define AES256 1 define AES_BLOCKLEN 16 if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (...*

#### `cJSON.h`
**Path:** `cJSON.h`

**Macros:**
- `cJSON__h` (line 24)
- `__WINDOWS__` (line 32)
- `CJSON_CDECL` (line 43)
- `CJSON_STDCALL` (line 45)
- `CJSON_EXPORT_SYMBOLS` (line 49)
- `CJSON_PUBLIC` (line 53)
- `CJSON_PUBLIC` (line 55)
- `CJSON_PUBLIC` (line 57)
- `CJSON_CDECL` (line 60)
- `CJSON_STDCALL` (line 61)
- `CJSON_PUBLIC` (line 64)
- `CJSON_PUBLIC` (line 66)
- `CJSON_VERSION_MAJOR` (line 71)
- `CJSON_VERSION_MINOR` (line 72)
- `CJSON_VERSION_PATCH` (line 73)
- `cJSON_Invalid` (line 78)
- `cJSON_False` (line 79)
- `cJSON_True` (line 80)
- `cJSON_NULL` (line 81)
- `cJSON_Number` (line 82)
- `cJSON_String` (line 83)
- `cJSON_Array` (line 84)
- `cJSON_Object` (line 85)
- `cJSON_Raw` (line 86)
- `cJSON_IsReference` (line 87)
- `cJSON_StringIsConst` (line 89)
- `CJSON_NESTING_LIMIT` (line 126)
- `CJSON_CIRCULAR_LIMIT` (line 132)
- `cJSON_SetIntValue` (line 270)
- `cJSON_SetNumberValue` (line 273)
- `cJSON_SetBoolValue` (line 278)
- `cJSON_ArrayForEach` (line 285)

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #...*
- `cJSON_Hooks` (line 114)

### PY (1 files)

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

### SH (4 files)

#### `andoid_build.sh`
**Path:** `andoid_build.sh`

*No symbols extracted*

#### `armbian_build.sh`
**Path:** `armbian_build.sh`

*No symbols extracted*

#### `build_arm32.sh`
**Path:** `build_arm32.sh`

*No symbols extracted*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*
