#include <iostream>
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include <vector>
#include <string>
#include <iomanip>

using namespace std;

// RC4 解密函数
void rc4(const vector<unsigned char>& data, const vector<unsigned char>& key, vector<unsigned char>& output) {
    // 初始化 S-盒
    vector<unsigned char> S(256);
    for (int i = 0; i < 256; i++) {
        S[i] = static_cast<unsigned char>(i);
    }

    // 密钥调度算法 (KSA)
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        swap(S[i], S[j]);
    }

    // 伪随机生成器 (PRGA)
    int i = 0, k = 0;
    for (size_t x = 0; x < data.size(); x++) {
        i = (i + 1) % 256;
        k = (k + S[i]) % 256;
        swap(S[i], S[k]);
        unsigned char keystream_byte = S[(S[i] + S[k]) % 256];
        output.push_back(data[x] ^ keystream_byte);
    }
}

// 去除 PKCS7 填充
vector<unsigned char> unpad(const vector<unsigned char>& data) {
    if (data.empty()) return {};
    unsigned char padding_len = data.back();
    if (padding_len > data.size()) return {};
    return vector<unsigned char>(data.begin(), data.end() - padding_len);
}

// AES 解密函数
vector<unsigned char> aes_decrypt(const vector<unsigned char>& data, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[!] Error initializing EVP_CIPHER_CTX." << endl;
        return {};
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
        cerr << "[!] Error initializing AES decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int len;
    vector<unsigned char> decrypted(data.size() + 16);

    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), data.size()) != 1) {
        cerr << "[!] Error during AES decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        cerr << "[!] Error finalizing AES decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    decrypted.resize(plaintext_len);

    return unpad(decrypted);  // 去填充
}

// 打印十六进制 ShellCode
void printShellcode(const vector<unsigned char>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        cout << "\\x" << hex << setw(2) << setfill('0') << (int)data[i];
    }
    cout << endl;
}

int main() {

    vector<unsigned char> encrypted_shellcode = { /* 填入加密的 shellcode */
        
    };

    // RC4 Key
    vector<unsigned char> rc4_key = { 'w','o','z','h','e','n','d','e','a','i','n','i'};

    // 16 字节的 AES Key
    vector<unsigned char> aes_key = { 'n','i','s','h','i','b','u','s','h','i','b','u','a','i','l','e'};

    // 16 字节的 AES IV
    vector<unsigned char> aes_iv = { 'w','o','c','h','a','o','j','i','x','i','h','u','a','n','n','i'};

    // 1. AES-CBC 解密
    cout << "[+] 正在使用 AES-CBC 解密 shellcode..." << endl;
    vector<unsigned char> aes_decrypted_shellcode = aes_decrypt(encrypted_shellcode, aes_key, aes_iv);

    // 2. RC4 解密
    cout << "[+] 正在使用 RC4 解密 shellcode..." << endl;
    vector<unsigned char> final_decrypted_shellcode;
    rc4(aes_decrypted_shellcode, rc4_key, final_decrypted_shellcode);

    //动态分配数组
    unsigned char* buf = new unsigned char[final_decrypted_shellcode.size() + 1]; 
    for (size_t i = 0; i < final_decrypted_shellcode.size(); ++i) {
        buf[i] = final_decrypted_shellcode[i];
    }
    buf[final_decrypted_shellcode.size()] = '\0';

    // 输出解密后的 shellcode
    cout << "[+] 解密后的 shellcode:" << endl;
    printShellcode(final_decrypted_shellcode);

    //释放动态分配的内存
    delete[] buf;

    return 0;
}
