#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <cstdint>
#include <random>

// Include Trezor crypto headers directly for testing with extern "C"
extern "C" {
#include "../trezor-crypto/sha2.h"
#include "../trezor-crypto/ecdsa.h"
#include "../trezor-crypto/rand.h"
#include "../trezor-crypto/secp256k1.h"
#include "../trezor-crypto/hasher.h"
}

// Include common utilities
#include "common.cpp"

// Function to demonstrate direct Trezor crypto usage
void demonstrateTrezorCrypto() {
    std::cout << "===== DIRECT TREZOR CRYPTO DEMONSTRATION =====\n\n";
    
    // 1. SHA-256 hashing with Trezor crypto
    std::cout << "1. SHA-256 Hashing\n";
    std::cout << "----------------\n";
    
    const char* message = "Testing Trezor crypto SHA-256";
    uint8_t hash[32];
    
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, (const uint8_t*)message, strlen(message));
    sha256_Final(&ctx, hash);
    
    std::cout << "Message: " << message << std::endl;
    std::cout << "SHA-256 Hash: ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << std::endl << std::endl;
    
    // 2. Generate ECDSA key pair with Trezor crypto
    std::cout << "2. ECDSA Key Generation\n";
    std::cout << "---------------------\n";
    
    uint8_t privateKey[32];
    uint8_t publicKey[65];
    
    random_buffer(privateKey, sizeof(privateKey));
    ecdsa_get_public_key65(&secp256k1, privateKey, publicKey);
    
    std::cout << "Private key: ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)privateKey[i];
    }
    std::cout << std::dec << std::endl;
    
    std::cout << "Public key (first 16 bytes): ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)publicKey[i];
    }
    std::cout << "..." << std::dec << std::endl << std::endl;
    
    // 3. Sign and verify with Trezor crypto
    std::cout << "3. ECDSA Sign and Verify\n";
    std::cout << "----------------------\n";
    
    uint8_t signature[64];
    uint8_t by = 0; // Recovery byte
    
    // Sign using the corrected API
    ecdsa_sign(&secp256k1, HASHER_SHA2, privateKey, hash, 32, signature, &by, nullptr);
    
    std::cout << "Signature (first 16 bytes): ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)signature[i];
    }
    std::cout << "..." << std::dec << std::endl;
    
    // Verify using the corrected API
    int result = ecdsa_verify(&secp256k1, HASHER_SHA2, publicKey, signature, hash, 32);
    std::cout << "Signature verification: " << (result == 0 ? "VALID" : "INVALID") << std::endl << std::endl;
    
    // 4. Random number generation
    std::cout << "4. Secure Random Generation\n";
    std::cout << "-------------------------\n";
    
    uint8_t random_bytes[16];
    random_buffer(random_bytes, sizeof(random_bytes));
    
    std::cout << "Random bytes: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)random_bytes[i];
    }
    std::cout << std::dec << std::endl << std::endl;
}

// Function to simulate network delay
void simulateNetworkDelay() {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

// Simulate the authentication and CoT conversation
void simulateConversation() {
    std::cout << "========= SECURE COMMUNICATION SIMULATION =========\n\n";
    
    // Step 1: Generate key pairs for client and server
    std::cout << "1. GENERATING KEYPAIRS WITH TREZOR CRYPTO\n";
    std::cout << "---------------------------------------\n";
    
    auto clientKeypair = CryptoUtils::generateEcdsaKeypair();
    auto serverKeypair = CryptoUtils::generateEcdsaKeypair();
    
    std::vector<uint8_t> clientPrivateKey = clientKeypair.first;
    std::vector<uint8_t> clientPublicKey = clientKeypair.second;
    std::vector<uint8_t> serverPrivateKey = serverKeypair.first;
    std::vector<uint8_t> serverPublicKey = serverKeypair.second;
    
    std::cout << "Client private key: " << CryptoUtils::bytesToHex(clientPrivateKey).substr(0, 16) << "...\n";
    std::cout << "Client public key: " << CryptoUtils::bytesToHex(clientPublicKey).substr(0, 16) << "...\n";
    std::cout << "Server private key: " << CryptoUtils::bytesToHex(serverPrivateKey).substr(0, 16) << "...\n";
    std::cout << "Server public key: " << CryptoUtils::bytesToHex(serverPublicKey).substr(0, 16) << "...\n";
    
    // Step 2: Client authentication request
    std::cout << "\n2. CLIENT AUTHENTICATION REQUEST\n";
    std::cout << "-------------------------------\n";
    
    // Create client serial ID using Trezor's random generation
    std::vector<uint8_t> clientSerialId = CryptoUtils::generateRandomBytes(8);
    std::cout << "Client Serial ID: " << CryptoUtils::bytesToHex(clientSerialId) << std::endl;
    
    // Hash the serial ID using Trezor's SHA-256
    auto serialIdHash = CryptoUtils::sha256(clientSerialId);
    std::cout << "Hashed Serial ID (SHA-256): " << CryptoUtils::bytesToHex(serialIdHash).substr(0, 16) << "...\n";
    
    // Sign the hashed serial ID using Trezor's ECDSA
    auto authSignature = CryptoUtils::signEcdsa(clientPrivateKey, serialIdHash);
    std::cout << "ECDSA Signature: " << CryptoUtils::bytesToHex(authSignature).substr(0, 16) << "...\n";
    
    // Create auth request message
    auto authRequest = ProtocolUtils::createAuthRequest(clientSerialId, authSignature);
    std::cout << "Auth Request Message Size: " << authRequest.size() << " bytes\n";
    std::cout << "AUTH REQUEST -> SERVER\n";
    
    // Simulate network delay
    simulateNetworkDelay();
    
    // Step 3: Server processes authentication request
    std::cout << "\n3. SERVER PROCESSES AUTH REQUEST\n";
    std::cout << "-------------------------------\n";
    
    // Server parses the auth request
    std::vector<uint8_t> receivedSerialId, receivedSignature;
    bool authParsed = ProtocolUtils::parseAuthRequest(authRequest, receivedSerialId, receivedSignature);
    
    std::cout << "Auth Request Parsed: " << (authParsed ? "Success" : "Failed") << std::endl;
    if (!authParsed) {
        std::cerr << "Error: Failed to parse auth request!" << std::endl;
        return;
    }
    
    std::cout << "Received Serial ID: " << CryptoUtils::bytesToHex(receivedSerialId) << std::endl;
    std::cout << "Received Signature: " << CryptoUtils::bytesToHex(receivedSignature).substr(0, 16) << "...\n";
    
    // Server verifies the client's signature using Trezor's ECDSA verification
    auto receivedSerialIdHash = CryptoUtils::sha256(receivedSerialId);
    bool signatureValid = CryptoUtils::verifyEcdsa(clientPublicKey, receivedSerialIdHash, receivedSignature);
    
    std::cout << "ECDSA Signature Verification: " << (signatureValid ? "Valid" : "Invalid") << std::endl;
    
    if (!signatureValid) {
        std::cout << "Authentication failed. Aborting.\n";
        return;
    }
    
    // Step 4: Server sends challenge
    std::cout << "\n4. SERVER CHALLENGE\n";
    std::cout << "-------------------\n";
    
    // Generate random challenge
    auto serverChallenge = CryptoUtils::generateRandomBytes(32);
    std::cout << "Server Challenge: " << CryptoUtils::bytesToHex(serverChallenge).substr(0, 16) << "...\n";
    
    // Sign the challenge
    auto challengeSignature = CryptoUtils::signEcdsa(serverPrivateKey, serverChallenge);
    std::cout << "Challenge Signature: " << CryptoUtils::bytesToHex(challengeSignature).substr(0, 16) << "...\n";
    
    // Create server challenge message
    auto serverChallengeMsg = ProtocolUtils::createServerChallenge(serverChallenge, challengeSignature);
    std::cout << "Server Challenge Message Size: " << serverChallengeMsg.size() << " bytes\n";
    std::cout << "SERVER CHALLENGE -> CLIENT\n";
    
    // Simulate network delay
    simulateNetworkDelay();
    
    // Step 5: Client processes server challenge
    std::cout << "\n5. CLIENT PROCESSES SERVER CHALLENGE\n";
    std::cout << "-----------------------------------\n";
    
    // Client parses the server challenge
    std::vector<uint8_t> receivedChallenge, receivedChallengeSignature;
    bool challengeParsed = ProtocolUtils::parseServerChallenge(serverChallengeMsg, receivedChallenge, receivedChallengeSignature);
    
    std::cout << "Server Challenge Parsed: " << (challengeParsed ? "Success" : "Failed") << std::endl;
    if (!challengeParsed) {
        std::cerr << "Error: Failed to parse server challenge!" << std::endl;
        return;
    }
    
    std::cout << "Received Challenge: " << CryptoUtils::bytesToHex(receivedChallenge).substr(0, 16) << "...\n";
    std::cout << "Received Challenge Signature: " << CryptoUtils::bytesToHex(receivedChallengeSignature).substr(0, 16) << "...\n";
    
    // Client verifies the server's signature
    bool serverSignatureValid = CryptoUtils::verifyEcdsa(serverPublicKey, receivedChallenge, receivedChallengeSignature);
    
    std::cout << "Server Signature Verification: " << (serverSignatureValid ? "Valid" : "Invalid") << std::endl;
    
    if (!serverSignatureValid) {
        std::cout << "Server authentication failed. Aborting.\n";
        return;
    }
    
    // Client signs the challenge
    auto clientChallengeSignature = CryptoUtils::signEcdsa(clientPrivateKey, receivedChallenge);
    std::cout << "Client's Signature of Challenge: " << CryptoUtils::bytesToHex(clientChallengeSignature).substr(0, 16) << "...\n";
    
    // Create challenge response
    auto challengeResponse = ProtocolUtils::createClientChallengeResponse(receivedChallenge, clientChallengeSignature);
    std::cout << "Challenge Response Size: " << challengeResponse.size() << " bytes\n";
    std::cout << "CHALLENGE RESPONSE -> SERVER\n";
    
    // Simulate network delay
    simulateNetworkDelay();
    
    // Step 6: Server verifies client's challenge response
    std::cout << "\n6. SERVER VERIFIES CHALLENGE RESPONSE\n";
    std::cout << "------------------------------------\n";
    
    // Server parses the challenge response
    std::vector<uint8_t> receivedChallengeResponse, receivedResponseSignature;
    bool responseParsed = ProtocolUtils::parseClientChallengeResponse(challengeResponse, receivedChallengeResponse, receivedResponseSignature);
    
    std::cout << "Challenge Response Parsed: " << (responseParsed ? "Success" : "Failed") << std::endl;
    if (!responseParsed) {
        std::cerr << "Error: Failed to parse challenge response!" << std::endl;
        return;
    }
    
    // Verify the challenge matches
    bool challengeMatches = (receivedChallengeResponse == serverChallenge);
    std::cout << "Challenge Match: " << (challengeMatches ? "Matched" : "Mismatched") << std::endl;
    
    // Verify client's signature on the challenge
    bool responseSignatureValid = CryptoUtils::verifyEcdsa(clientPublicKey, receivedChallengeResponse, receivedResponseSignature);
    
    std::cout << "Client Challenge Signature Verification: " << (responseSignatureValid ? "Valid" : "Invalid") << std::endl;
    
    if (!responseSignatureValid || !challengeMatches) {
        std::cout << "Challenge verification failed. Aborting.\n";
        return;
    }
    
    std::cout << "Client fully authenticated!\n";
    
    // Step 7: Correlated OT protocol (with improved Trezor crypto)
    std::cout << "\n7. CORRELATED OBLIVIOUS TRANSFER WITH TREZOR CRYPTO\n";
    std::cout << "------------------------------------------------\n";
    
    // Generate random multiplicative shares using Trezor's random generator
    uint8_t randomBytes[16];
    random_buffer(randomBytes, sizeof(randomBytes));
    
    uint64_t clientMultiplicativeShare = 0;
    uint64_t serverMultiplicativeShare = 0;
    
    // Convert random bytes to usable shares
    for (int i = 0; i < 8; i++) {
        clientMultiplicativeShare |= (uint64_t)randomBytes[i] << (i * 8);
        serverMultiplicativeShare |= (uint64_t)randomBytes[i + 8] << (i * 8);
    }
    
    // Ensure non-zero values
    clientMultiplicativeShare = (clientMultiplicativeShare % 100) + 1;
    serverMultiplicativeShare = (serverMultiplicativeShare % 100) + 1;
    
    std::cout << "Client multiplicative share: " << clientMultiplicativeShare << std::endl;
    std::cout << "Server multiplicative share: " << serverMultiplicativeShare << std::endl;
    
    // Initialize CoT for client and server with Trezor crypto-enhanced implementation
    CorrelatedOT clientCoT(clientMultiplicativeShare);
    CorrelatedOT serverCoT(serverMultiplicativeShare);
    
    // Perform CoT protocol (now with Trezor SHA-256 inside)
    uint64_t clientAdditiveShare = clientCoT.generateClientAdditiveShare(serverMultiplicativeShare);
    uint64_t serverAdditiveShare = serverCoT.generateServerAdditiveShare(clientMultiplicativeShare);
    
    std::cout << "Client additive share (via Trezor SHA-256): " << clientAdditiveShare << std::endl;
    std::cout << "Server additive share (via Trezor SHA-256): " << serverAdditiveShare << std::endl;
    
    std::cout << "\nSecure Communication with Trezor Crypto Completed Successfully!\n";
}

int main() {
    try {
        // First demonstrate direct Trezor crypto usage
        demonstrateTrezorCrypto();
        
        // Then demonstrate secure communication using Trezor crypto
        simulateConversation();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 