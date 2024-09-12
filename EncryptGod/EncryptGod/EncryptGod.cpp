#include <iostream>
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

using namespace std;

// shellcode 形式转换
vector<unsigned char> hexStringToBytes(const string& hex_str) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex_str.length(); i += 4) {
        string byteString = hex_str.substr(i + 2, 2); // 跳过 '\x'
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// RC4 加密/解密函数
void rc4(const vector<unsigned char>& data, const vector<unsigned char>& key, vector<unsigned char>& output) {
    vector<unsigned char> S(256);
    for (int i = 0; i < 256; i++) {
        S[i] = static_cast<unsigned char>(i);
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        swap(S[i], S[j]);
    }

    int i = 0, k = 0;
    for (size_t x = 0; x < data.size(); x++) {
        i = (i + 1) % 256;
        k = (k + S[i]) % 256;
        swap(S[i], S[k]);
        unsigned char keystream_byte = S[(S[i] + S[k]) % 256];
        output.push_back(data[x] ^ keystream_byte);
    }
}

// 手动填充，使用 PKCS7 填充
vector<unsigned char> pad(const vector<unsigned char>& data, size_t block_size) {
    size_t padding_len = block_size - data.size() % block_size;
    vector<unsigned char> padded_data = data;
    padded_data.insert(padded_data.end(), padding_len, static_cast<unsigned char>(padding_len));
    return padded_data;
}

// AES-CBC 加密函数
vector<unsigned char> aes_encrypt(const vector<unsigned char>& data, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[!] Error initializing EVP_CIPHER_CTX." << endl;
        return {};
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
        cerr << "[!] Error initializing AES encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    vector<unsigned char> padded_data = pad(data, 16);
    int len;
    vector<unsigned char> encrypted(padded_data.size() + 16);

    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, padded_data.data(), padded_data.size()) != 1) {
        cerr << "[!] Error during AES encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        cerr << "[!] Error finalizing AES encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    encrypted.resize(ciphertext_len);
    return encrypted;

}

// 输出 shellcode
void printShellcode(const vector<unsigned char>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        if (i != 0) cout << ", ";
        cout << "0x" << hex << setw(2) << setfill('0') << (int)data[i];
    }
    cout << endl;
}

int main() {
    // 输入 shellcode 字符串
    string input_shellcode;
    cout << "请输入 shellcode (形如 \\xfc\\x48\\x83\\xe4\\xf0): ";
    getline(cin, input_shellcode);
    vector<unsigned char> shellcode = hexStringToBytes(input_shellcode);

    // 输入 RC4 密钥
    string rc4_key_str;
    cout << "请输入 RC4 密钥: ";
    getline(cin, rc4_key_str);
    vector<unsigned char> rc4_key(rc4_key_str.begin(), rc4_key_str.end());

    // 输入 AES 密钥 (16 字节)
    string aes_key_str;
    cout << "请输入 16 字节的 AES 密钥: ";
    getline(cin, aes_key_str);
    vector<unsigned char> aes_key(aes_key_str.begin(), aes_key_str.end());
    if (aes_key.size() != 16) {
        cerr << "[!] AES 密钥必须是 16 字节" << endl;
        return 1;
    }

    // 输入 AES IV (16 字节)
    string aes_iv_str;
    cout << "请输入 16 字节的 IV (初始化向量): ";
    getline(cin, aes_iv_str);
    vector<unsigned char> aes_iv(aes_iv_str.begin(), aes_iv_str.end());
    if (aes_iv.size() != 16) {
        cerr << "[!] IV 必须是 16 字节" << endl;
        return 1;
    }

    // 1. RC4 加密
    vector<unsigned char> rc4_encrypted_shellcode;
    rc4(shellcode, rc4_key, rc4_encrypted_shellcode);

    // 2. AES-CBC 加密
    vector<unsigned char> aes_encrypted_shellcode = aes_encrypt(rc4_encrypted_shellcode, aes_key, aes_iv);

    // 输出加密后的 shellcode
    cout << "[+] 加密后的 shellcode:" << endl;
    printShellcode(aes_encrypted_shellcode);

    return 0;
}
