#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <random>
#include <iomanip>
#include <functional>

// Add extern "C" block for the C functions
extern "C" {
#include "../trezor-crypto/sha2.h"
#include "../trezor-crypto/ecdsa.h"
#include "../trezor-crypto/rand.h"
#include "../trezor-crypto/secp256k1.h"
#include "../trezor-crypto/memzero.h"
#include "../trezor-crypto/hasher.h"
// Include nanopb headers
#include "../nanopb/pb_encode.h"
#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_common.h"
}

// Include generated protocol buffer files
#include "../proto/secure_communication.pb.h"

// Simple class for cryptographic operations
class CryptoUtils {
public:
    // ECDSA keypair generation
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateEcdsaKeypair() {
        // Use Trezor crypto for ECDSA keypair generation
        std::vector<uint8_t> privateKey(32);
        std::vector<uint8_t> publicKey(65);  // 65 bytes for uncompressed secp256k1 key (0x04 + 32 bytes X + 32 bytes Y)
        
        // Generate random private key
        random_buffer(privateKey.data(), privateKey.size());
        
        // Generate corresponding public key
        ecdsa_get_public_key65(&secp256k1, privateKey.data(), publicKey.data());
        
        return {privateKey, publicKey};
    }
    
    // ECDSA signature operations
    static std::vector<uint8_t> signEcdsa(const std::vector<uint8_t>& privateKey, 
                                        const std::vector<uint8_t>& message) {
        // Use Trezor crypto for ECDSA signing
        std::vector<uint8_t> signature(64);  // 64 bytes for R and S values
        uint8_t by = 0;  // Recovery byte
        
        // Hash the message with SHA-256 if not already hashed
        std::vector<uint8_t> hash = message.size() == 32 ? message : sha256(message);
        
        std::cout << "Signing message - Hash size: " << hash.size() << std::endl;
        std::cout << "Hash bytes: ";
        for (size_t i = 0; i < std::min(hash.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)hash[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        // Sign the hash with the appropriate hasher type
        int result = ecdsa_sign(&secp256k1, HASHER_SHA2, privateKey.data(), hash.data(), 
                            hash.size(), signature.data(), &by, nullptr);
                            
        if (result != 0) {
            std::cerr << "ECDSA signing failed with error code: " << result << std::endl;
        }
        
        // Debug signature
        std::cout << "Generated signature (" << signature.size() << " bytes): ";
        for (size_t i = 0; i < std::min(signature.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)signature[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        return signature;
    }
    
    static bool verifyEcdsa(const std::vector<uint8_t>& publicKey, 
                          const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature) {
        // Use Trezor crypto for ECDSA verification
        if (publicKey.size() != 65 || signature.size() != 64) {
            std::cerr << "Invalid key or signature size: publicKey=" << publicKey.size() 
                      << ", signature=" << signature.size() << std::endl;
            return false;
        }
        
        // Hash the message with SHA-256 if not already hashed
        std::vector<uint8_t> hash = message.size() == 32 ? message : sha256(message);
        
        // Debug information
        std::cout << "Verifying signature - Hash size: " << hash.size() << std::endl;
        std::cout << "Hash bytes: ";
        for (int i = 0; i < std::min(hash.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)hash[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        // Verify the signature with the appropriate hasher type
        int result = ecdsa_verify(&secp256k1, HASHER_SHA2, 
                                publicKey.data(), signature.data(), 
                                hash.data(), hash.size());
        
        std::cout << "ECDSA verification result: " << result << " (0 means success)" << std::endl;
        return result == 0;  // 0 means success in Trezor crypto
    }
    
    // Hashing functions
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        // Use Trezor crypto for SHA-256 hashing
        std::vector<uint8_t> hash(32);
        
        SHA256_CTX ctx;
        sha256_Init(&ctx);
        sha256_Update(&ctx, data.data(), data.size());
        sha256_Final(&ctx, hash.data());
        
        return hash;
    }
    
    // Random number generation
    static std::vector<uint8_t> generateRandomBytes(size_t length) {
        // Use Trezor crypto for random bytes generation
        std::vector<uint8_t> bytes(length);
        random_buffer(bytes.data(), bytes.size());
        return bytes;
    }
    
    // Utility functions
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto& byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
};

// Protocol buffer utilities
class ProtocolUtils {
public:
    // Create authentication request message using nanopb
    static std::vector<uint8_t> createAuthRequest(
        const std::vector<uint8_t>& serialId,
        const std::vector<uint8_t>& signature) {
        
        // Create nanopb buffer
        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_AUTH_REQUEST;
        
        // Set AuthRequest fields
        message.has_auth_request = true;
        memcpy(message.auth_request.serial_id.bytes, serialId.data(), serialId.size());
        message.auth_request.serial_id.size = serialId.size();
        memcpy(message.auth_request.signature.bytes, signature.data(), signature.size());
        message.auth_request.signature.size = signature.size();
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse authentication request message using nanopb
    static bool parseAuthRequest(
        const std::vector<uint8_t>& message,
        std::vector<uint8_t>& serialId,
        std::vector<uint8_t>& signature) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_AUTH_REQUEST || !secureMessage.has_auth_request) {
            return false;
        }
        
        // Extract data
        serialId.assign(
            secureMessage.auth_request.serial_id.bytes,
            secureMessage.auth_request.serial_id.bytes + secureMessage.auth_request.serial_id.size
        );
        
        signature.assign(
            secureMessage.auth_request.signature.bytes,
            secureMessage.auth_request.signature.bytes + secureMessage.auth_request.signature.size
        );
        
        return true;
    }
    
    // Create server challenge message using nanopb
    static std::vector<uint8_t> createServerChallenge(
        const std::vector<uint8_t>& challenge,
        const std::vector<uint8_t>& signature) {
        
        // Create nanopb buffer
        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_SERVER_CHALLENGE;
        
        // Set ServerChallenge fields
        message.has_server_challenge = true;
        memcpy(message.server_challenge.random_number.bytes, challenge.data(), challenge.size());
        message.server_challenge.random_number.size = challenge.size();
        memcpy(message.server_challenge.signature.bytes, signature.data(), signature.size());
        message.server_challenge.signature.size = signature.size();
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse server challenge message using nanopb
    static bool parseServerChallenge(
        const std::vector<uint8_t>& message,
        std::vector<uint8_t>& challenge,
        std::vector<uint8_t>& signature) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_SERVER_CHALLENGE || !secureMessage.has_server_challenge) {
            return false;
        }
        
        // Extract data
        challenge.assign(
            secureMessage.server_challenge.random_number.bytes,
            secureMessage.server_challenge.random_number.bytes + secureMessage.server_challenge.random_number.size
        );
        
        signature.assign(
            secureMessage.server_challenge.signature.bytes,
            secureMessage.server_challenge.signature.bytes + secureMessage.server_challenge.signature.size
        );
        
        return true;
    }
    
    // Create client challenge response message using nanopb
    static std::vector<uint8_t> createClientChallengeResponse(
        const std::vector<uint8_t>& challenge,
        const std::vector<uint8_t>& signature) {
        
        // Create nanopb buffer
        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_CLIENT_CHALLENGE_RESPONSE;
        
        // Set ClientChallengeResponse fields
        message.has_client_challenge_response = true;
        memcpy(message.client_challenge_response.random_number.bytes, challenge.data(), challenge.size());
        message.client_challenge_response.random_number.size = challenge.size();
        memcpy(message.client_challenge_response.signature.bytes, signature.data(), signature.size());
        message.client_challenge_response.signature.size = signature.size();
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse client challenge response message using nanopb
    static bool parseClientChallengeResponse(
        const std::vector<uint8_t>& message,
        std::vector<uint8_t>& challenge,
        std::vector<uint8_t>& signature) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_CLIENT_CHALLENGE_RESPONSE || !secureMessage.has_client_challenge_response) {
            return false;
        }
        
        // Extract data
        challenge.assign(
            secureMessage.client_challenge_response.random_number.bytes,
            secureMessage.client_challenge_response.random_number.bytes + secureMessage.client_challenge_response.random_number.size
        );
        
        signature.assign(
            secureMessage.client_challenge_response.signature.bytes,
            secureMessage.client_challenge_response.signature.bytes + secureMessage.client_challenge_response.signature.size
        );
        
        return true;
    }
    
    // Create COT init message (multiplicative share) using nanopb
    static std::vector<uint8_t> createCotInitMessage(uint64_t multiplicativeShare) {
        // Create nanopb buffer
        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_COT_INIT;
        
        // Set CotInitMessage fields
        message.has_cot_init = true;
        
        // Convert uint64_t to bytes
        uint8_t shareBytes[8];
        for (int i = 0; i < 8; ++i) {
            shareBytes[i] = static_cast<uint8_t>((multiplicativeShare >> (i * 8)) & 0xFF);
        }
        
        memcpy(message.cot_init.multiplicative_share.bytes, shareBytes, 8);
        message.cot_init.multiplicative_share.size = 8;
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse COT init message using nanopb
    static bool parseCotInitMessage(
        const std::vector<uint8_t>& message,
        uint64_t& multiplicativeShare) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_COT_INIT || !secureMessage.has_cot_init) {
            return false;
        }
        
        // Convert bytes to uint64_t
        multiplicativeShare = 0;
        for (size_t i = 0; i < secureMessage.cot_init.multiplicative_share.size && i < 8; ++i) {
            multiplicativeShare |= static_cast<uint64_t>(secureMessage.cot_init.multiplicative_share.bytes[i]) << (i * 8);
        }
        
        return true;
    }
    
    // Create COT response message (additive share) using nanopb
    static std::vector<uint8_t> createCotResponseMessage(uint64_t additiveShare) {
        // Create nanopb buffer
        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_COT_RESPONSE;
        
        // Set CotResponseMessage fields
        message.has_cot_response = true;
        
        // Convert uint64_t to bytes
        uint8_t shareBytes[8];
        for (int i = 0; i < 8; ++i) {
            shareBytes[i] = static_cast<uint8_t>((additiveShare >> (i * 8)) & 0xFF);
        }
        
        memcpy(message.cot_response.additive_share.bytes, shareBytes, 8);
        message.cot_response.additive_share.size = 8;
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse COT response message using nanopb
    static bool parseCotResponseMessage(
        const std::vector<uint8_t>& message,
        uint64_t& additiveShare) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_COT_RESPONSE || !secureMessage.has_cot_response) {
            return false;
        }
        
        // Convert bytes to uint64_t
        additiveShare = 0;
        for (size_t i = 0; i < secureMessage.cot_response.additive_share.size && i < 8; ++i) {
            additiveShare |= static_cast<uint64_t>(secureMessage.cot_response.additive_share.bytes[i]) << (i * 8);
        }
        
        return true;
    }

    // Create custom text message using nanopb
    static std::vector<uint8_t> createCustomTextMessage(const std::string& text) {
        // Create nanopb buffer
        uint8_t buffer[512]; // Larger buffer for text messages
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        // Initialize message
        SecureMessage message = SecureMessage_init_zero;
        message.message_type = SecureMessage_MessageType_CUSTOM_TEXT;
        
        // Set CustomTextMessage fields
        message.has_custom_text = true;
        
        // Copy the text string
        strncpy(message.custom_text.text, text.c_str(), sizeof(message.custom_text.text) - 1);
        message.custom_text.text[sizeof(message.custom_text.text) - 1] = '\0'; // Ensure null termination
        
        // Encode the message
        bool status = pb_encode(&stream, SecureMessage_fields, &message);
        if (!status) {
            std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return {};
        }
        
        // Convert to vector
        return std::vector<uint8_t>(buffer, buffer + stream.bytes_written);
    }
    
    // Parse custom text message using nanopb
    static bool parseCustomTextMessage(
        const std::vector<uint8_t>& message,
        std::string& text) {
        
        // Create nanopb stream
        pb_istream_t stream = pb_istream_from_buffer(message.data(), message.size());
        
        // Initialize message
        SecureMessage secureMessage = SecureMessage_init_zero;
        
        // Decode the message
        bool status = pb_decode(&stream, SecureMessage_fields, &secureMessage);
        if (!status) {
            std::cerr << "Decoding failed: " << PB_GET_ERROR(&stream) << std::endl;
            return false;
        }
        
        // Check message type
        if (secureMessage.message_type != SecureMessage_MessageType_CUSTOM_TEXT || !secureMessage.has_custom_text) {
            return false;
        }
        
        // Extract text
        text = secureMessage.custom_text.text;
        
        return true;
    }
};

// Correlated Oblivious Transfer implementation
class CorrelatedOT {
public:
    // Initialize with a random value for multiplicative share
    explicit CorrelatedOT(uint64_t multiplicativeShare) 
        : m_multiplicativeShare(multiplicativeShare), m_additiveShare(0) {}
    
    // Generate client's additive share using Trezor crypto functions for security
    uint64_t generateClientAdditiveShare(uint64_t serverMultiplicativeShare) {
        // Create a secure hash of both shares to derive the additive share
        std::vector<uint8_t> clientShareBytes(8);
        std::vector<uint8_t> serverShareBytes(8);
        
        // Convert shares to bytes
        for (int i = 0; i < 8; ++i) {
            clientShareBytes[i] = static_cast<uint8_t>((m_multiplicativeShare >> (i * 8)) & 0xFF);
            serverShareBytes[i] = static_cast<uint8_t>((serverMultiplicativeShare >> (i * 8)) & 0xFF);
        }
        
        // Combine the shares
        std::vector<uint8_t> combinedShares;
        combinedShares.insert(combinedShares.end(), clientShareBytes.begin(), clientShareBytes.end());
        combinedShares.insert(combinedShares.end(), serverShareBytes.begin(), serverShareBytes.end());
        
        // Hash the combined shares using Trezor's SHA-256
        SHA256_CTX ctx;
        std::vector<uint8_t> hash(32);
        sha256_Init(&ctx);
        sha256_Update(&ctx, combinedShares.data(), combinedShares.size());
        sha256_Final(&ctx, hash.data());
        
        // Generate additive share from the hash
        m_additiveShare = 0;
        for (int i = 0; i < 8; ++i) {
            m_additiveShare |= static_cast<uint64_t>(hash[i]) << (i * 8);
        }
        
        return m_additiveShare;
    }
    
    // Generate server's additive share using Trezor crypto functions for security
    uint64_t generateServerAdditiveShare(uint64_t clientMultiplicativeShare) {
        // Create a secure hash of both shares to derive the additive share
        std::vector<uint8_t> serverShareBytes(8);
        std::vector<uint8_t> clientShareBytes(8);
        
        // Convert shares to bytes
        for (int i = 0; i < 8; ++i) {
            serverShareBytes[i] = static_cast<uint8_t>((m_multiplicativeShare >> (i * 8)) & 0xFF);
            clientShareBytes[i] = static_cast<uint8_t>((clientMultiplicativeShare >> (i * 8)) & 0xFF);
        }
        
        // Combine the shares
        std::vector<uint8_t> combinedShares;
        combinedShares.insert(combinedShares.end(), clientShareBytes.begin(), clientShareBytes.end());
        combinedShares.insert(combinedShares.end(), serverShareBytes.begin(), serverShareBytes.end());
        
        // Hash the combined shares using Trezor's SHA-256
        SHA256_CTX ctx;
        std::vector<uint8_t> hash(32);
        sha256_Init(&ctx);
        sha256_Update(&ctx, combinedShares.data(), combinedShares.size());
        sha256_Final(&ctx, hash.data());
        
        // Generate additive share from the hash
        m_additiveShare = 0;
        for (int i = 0; i < 8; ++i) {
            m_additiveShare |= static_cast<uint64_t>(hash[i]) << (i * 8);
        }
        
        return m_additiveShare;
    }
    
    // Getters
    uint64_t getMultiplicativeShare() const {
        return m_multiplicativeShare;
    }
    
    uint64_t getAdditiveShare() const {
        return m_additiveShare;
    }
    
private:
    uint64_t m_multiplicativeShare;
    uint64_t m_additiveShare;
}; 