# root

*Community 0 | 5 files | cohesion 1.00*

## Definition

This community groups 5 file(s) rooted at `root` with dominant language c (cohesion 1.00). Central symbols: `AES256`, `AES_BLOCKLEN`, `AES_CBC_decrypt_buffer`, `AES_CBC_encrypt_buffer`, `AES_CTR_xcrypt_buffer`, `AES_ECB_decrypt`, `AES_ECB_encrypt`, `AES_H`. Core file: `cJSON.c` (125 symbols). Documented purpose: tiny-AES-c (https://github.com/kokke/tiny-AES-c).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `aes.c` | c | utility | 43 | yes |
| `aes.h` | h | utility | 17 | no |
| `beacon.c` | c | utility | 15 | no |
| `cJSON.c` | c | utility | 125 | no |
| `cJSON.h` | h | utility | 37 | no |

## Key Symbols

- `Nb` (macro, `aes.c:5`) `#define Nb`
- `KEYLEN_256` (macro, `aes.c:9`) `#define KEYLEN_256`
- `RKLENGTH` (macro, `aes.c:10`) `#define RKLENGTH`
- `BLOCKLEN` (macro, `aes.c:11`) `#define BLOCKLEN`
- `getSBoxValue` (function, `aes.c:13`) `static uint8_t getSBoxValue(uint8_t num)`
- `getSBoxInvert` (function, `aes.c:35`) `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (function, `aes.c:57`) `static uint8_t Td0(int x)`
- `Td1` (function, `aes.c:58`) `static uint8_t Td1(int x)`
- `Td2` (function, `aes.c:59`) `static uint8_t Td2(int x)`
- `Td3` (function, `aes.c:60`) `static uint8_t Td3(int x)`
- `Td4` (function, `aes.c:61`) `static uint8_t Td4(int x)`
- `Nb` (macro, `aes.c:67`) `#define Nb`
- `Nk` (macro, `aes.c:70`) `#define Nk`
- `Nr` (macro, `aes.c:71`) `#define Nr`
- `Nk` (macro, `aes.c:73`) `#define Nk`
- `Nr` (macro, `aes.c:74`) `#define Nr`
- `Nk` (macro, `aes.c:76`) `#define Nk`
- `Nr` (macro, `aes.c:77`) `#define Nr`
- `MULTIPLY_AS_A_FUNCTION` (macro, `aes.c:84`) `#define MULTIPLY_AS_A_FUNCTION`
- `getSBoxValue` (macro, `aes.c:163`) `#define getSBoxValue(num)`
- `KeyExpansion` (function, `aes.c:166`) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the sta
- `AES_init_ctx` (function, `aes.c:239`) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (function, `aes.c:244`) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - if (defined(CBC) && (CBC == 1)) \|\| (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function, `aes.c:249`) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (function, `aes.c:257`) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - This function adds the round key to state. The round key is added to the state by an XOR function.
- `SubBytes` (function, `aes.c:271`) `static void SubBytes(state_t* state)` - The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function, `aes.c:286`) `static void ShiftRows(state_t* state)` - The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with differen
- `xtime` (function, `aes.c:314`) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function, `aes.c:320`) `static void MixColumns(state_t* state)` - MixColumns function mixes the columns of the state matrix
- `Multiply` (function, `aes.c:340`) `static uint8_t Multiply(uint8_t x, uint8_t y)` - Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 4
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 1 (strength 0.5): Inferred shared context (layer utility) with no import path between community 0 (root) and community 1 (orphans).

## Risks

- [dataflow UNCHECKED_ALLOC] `beacon.c:122` `aes256_cfb_encrypt` `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacon.c:150` `aes256_cfb_decrypt` `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacon.c:456` `main` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow DEAD_STORE] `cJSON.c:1654` `print_array` `output_pointer`: `output_pointer` assigned at line 1654 but never read afterwards.
- [dataflow DEAD_STORE] `cJSON.c:1887` `print_object` `output_pointer`: `output_pointer` assigned at line 1887 but never read afterwards.

## Open Questions

- Why do 4 file(s) lack file-level docs (e.g. `aes.h`)? What purpose do they serve?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `aes.c`
- `aes.h`
- `beacon.c`
- `cJSON.c`
- `cJSON.h`
