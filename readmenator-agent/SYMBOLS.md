# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_CBC_decrypt_buffer` | function | `aes.c:536` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:521` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:496` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `aes.c:490` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `aes.c:239` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `aes.c:403` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `aes.c:9` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:5` | `#define Nb` |
| `Nb` | macro | `aes.c:67` | `#define Nb` |
| `Nk` | macro | `aes.c:70` | `#define Nk` |
| `Nk` | macro | `aes.c:73` | `#define Nk` |
| `Nk` | macro | `aes.c:76` | `#define Nk` |
| `Nr` | macro | `aes.c:71` | `#define Nr` |
| `Nr` | macro | `aes.c:74` | `#define Nr` |
| `Nr` | macro | `aes.c:77` | `#define Nr` |
| `RKLENGTH` | macro | `aes.c:10` | `#define RKLENGTH` |
| `ShiftRows` | function | `aes.c:286` | `static void ShiftRows(state_t* state)` |
| `SubBytes` | function | `aes.c:271` | `static void SubBytes(state_t* state)` |
| `Td0` | function | `aes.c:57` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:58` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:59` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:60` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:61` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:512` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `getSBoxInvert` | function | `aes.c:35` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:13` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:163` | `#define getSBoxValue(num)` |
| `xtime` | function | `aes.c:314` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:17` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:18` | `#define AES_BLOCKLEN` |
| `AES_ECB_encrypt` | function | `aes.h:45` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_H` | macro | `aes.h:2` | `#define AES_H` |
| `AES_KEYLEN` | macro | `aes.h:21` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:24` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:27` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `aes.h:31` | `` |
| `AES_ctx_set_iv` | function | `aes.h:41` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);` |
| `AES_init_ctx` | function | `aes.h:38` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
| `AES_init_ctx_iv` | function | `aes.h:40` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` |
| `AES_keyExpSize` | macro | `aes.h:22` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:25` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:28` | `#define AES_keyExpSize` |
| `CBC` | macro | `aes.h:8` | `#define CBC` |
| `CTR` | macro | `aes.h:14` | `#define CTR` |
| `ECB` | macro | `aes.h:11` | `#define ECB` |
| `C2_URL` | macro | `beacon.c:29` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon.c:30` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon.c:31` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon.c:177` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon.c:182` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon.c:1` | `#define _GNU_SOURCE` |
| `aes256_cfb_decrypt` | function | `beacon.c:146` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacon.c:118` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacon.c:76` | `unsigned char* base64_decode(const char* data, size_t* out_len)` |
| `base64_encode` | function | `beacon.c:50` | `char* base64_encode(const unsigned char* data, size_t input_length)` |
| `exec_cmd` | function | `beacon.c:252` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `beacon.c:297` | `char* get_local_ips()` |
| `https_request` | function | `beacon.c:194` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `main` | function | `beacon.c:340` | `int main()` |
| `CJSON_PUBLIC` | function | `cJSON.c:95` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:100` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:110` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:125` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:210` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1134` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1236` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1316` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1321` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1352` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1935` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1977` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1982` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1987` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2112` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2123` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2133` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2143` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2155` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2167` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2179` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2191` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2203` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2215` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2227` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2239` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2287` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2297` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2302` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2309` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2316` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2321` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2363` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2413` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2446` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2468` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2479` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2490` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2501` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2526` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2555` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2567` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2579` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2596` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2607` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2659` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2699` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2739` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2922` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2972` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2982` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2992` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3002` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3012` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3022` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3032` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3042` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3052` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3062` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3072` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3194` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3199` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2021` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `cJSON.c:2075` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2786` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_strdup` | function | `cJSON.c:189` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `cJSON.c:1241` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `cJSON.c:88` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `get_array_item` | function | `cJSON.c:1916` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1945` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:157` | `` |
| `internal_malloc` | function | `cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:77` | `#define isnan(d)` |
| `minify_string` | function | `cJSON.c:2900` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:291` | `` |
| `parse_hex4` | function | `cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `cJSON.c:1243` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:482` | `` |
| `replace_item_in_object` | function | `cJSON.c:2423` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `cJSON.c:2886` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2873` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `static_strlen` | macro | `cJSON.c:185` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `CJSON_CDECL` | macro | `cJSON.h:44` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `cJSON.h:60` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `cJSON.h:132` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `cJSON.h:49` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `cJSON.h:126` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `cJSON.h:53` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:55` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:57` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:64` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:66` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `cJSON.h:45` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `cJSON.h:61` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `cJSON.h:71` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `cJSON.h:72` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `cJSON.h:73` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `cJSON.h:32` | `#define __WINDOWS__` |
| `cJSON` | struct | `cJSON.h:92` | `` |
| `cJSON_Array` | macro | `cJSON.h:84` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `cJSON.h:285` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `cJSON.h:79` | `#define cJSON_False` |
| `cJSON_Hooks` | struct | `cJSON.h:114` | `` |
| `cJSON_Invalid` | macro | `cJSON.h:78` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `cJSON.h:88` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `cJSON.h:81` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `cJSON.h:82` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `cJSON.h:85` | `#define cJSON_Object` |
| `cJSON_Raw` | macro | `cJSON.h:86` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `cJSON.h:278` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `cJSON.h:270` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `cJSON.h:273` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `cJSON.h:83` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `cJSON.h:89` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `cJSON.h:80` | `#define cJSON_True` |
| `cJSON__h` | macro | `cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `cJSON.h:120` | `typedef int cJSON_bool;` |
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\| defined` |
| `sensitive` | function | `cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_` |
