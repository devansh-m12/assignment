#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <memory>
#include <map>
#include <vector>
#include <cstdint>
#include <random>

// Include Trezor crypto headers directly for any additional functionality
extern "C" {
#include "../trezor-crypto/sha2.h"
#include "../trezor-crypto/ecdsa.h"
#include "../trezor-crypto/rand.h"
#include "../trezor-crypto/secp256k1.h"
#include "../nanopb/pb_encode.h"
#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_common.h"
}

// Include generated protocol buffer files
#include "../proto/secure_communication.pb.h"

// Include shared keys
#include "shared_keys.h"

using boost::asio::ip::tcp;

// Include common utilities
#include "common.cpp"

// Helper template for make_unique functionality in C++11
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// Server state definitions
enum ServerState { 
    WAIT_AUTH, 
    WAIT_CHALLENGE_RESPONSE, 
    AUTHENTICATED, 
    COT_COMPLETED,
    READY_FOR_MESSAGES
};

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, 
           const std::vector<uint8_t>& serverPrivateKey, 
           const std::map<std::vector<uint8_t>, std::vector<uint8_t>>& clientPublicKeys)
        : m_socket(std::move(socket)),
          m_state(WAIT_AUTH),
          m_serverPrivateKey(serverPrivateKey),
          m_clientPublicKeys(clientPublicKeys) {
        
        // Generate server public key from private key
        m_serverPublicKey.resize(65);
        ecdsa_get_public_key65(&secp256k1, m_serverPrivateKey.data(), m_serverPublicKey.data());
    }
    
    void start() {
        std::cout << "Server: New client session started\n";
        
        // Start reading messages from client
        read_message();
    }
    
private:
    void read_message() {
        std::cout << "Server: Waiting for client message\n";
        
        // Use asynchronous read operation with boost::asio
        // First, resize the buffer to make room for incoming data
        m_buffer.resize(1024);
        
        // Use async_read_some to read data (more appropriate for this simplified example)
        auto self(shared_from_this());
        m_socket.async_read_some(
            boost::asio::buffer(m_buffer, m_buffer.size()),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    std::cout << "Server: Received message of size " << length << " bytes\n";
                    
                    // Resize the buffer to actual message size
                    m_buffer.resize(length);
                    
                    // First check if it's a text message - handle these in any state
                    std::string text;
                    if (ProtocolUtils::parseCustomTextMessage(m_buffer, text)) {
                        handle_text_message(text);
                    }
                    // Otherwise process based on current state
                    else if (m_state == WAIT_AUTH) {
                        handle_auth_request(m_buffer);
                    } else if (m_state == WAIT_CHALLENGE_RESPONSE) {
                        handle_client_challenge_response(m_buffer);
                    } else if (m_state == AUTHENTICATED || m_state == READY_FOR_MESSAGES) {
                        handle_cot_share_request(m_buffer);
                    }
                    
                    // Continue reading for next message
                    read_message();
                } else if (ec == boost::asio::error::eof) {
                    std::cout << "Server: Client disconnected\n";
                } else {
                    std::cerr << "Server: Read error: " << ec.message() << std::endl;
                }
            });
    }
    
    void handle_auth_request(const std::vector<uint8_t>& message) {
        std::cout << "Server: Handling authentication request\n";
        
        // Parse auth request
        std::vector<uint8_t> serialId, signature;
        bool success = ProtocolUtils::parseAuthRequest(message, serialId, signature);
        
        if (!success) {
            std::cerr << "Server: Failed to parse auth request\n";
            return;
        }
        
        // Store client ID
        m_clientId = serialId;
        
        std::cout << "Server: Client Serial ID size: " << serialId.size() << " bytes\n";
        std::cout << "Server: Client Serial ID: ";
        for (size_t i = 0; i < std::min(serialId.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)serialId[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        // Hash the serial ID
        auto serialIdHash = CryptoUtils::sha256(serialId);
        
        std::cout << "Server: Serial ID hash size: " << serialIdHash.size() << " bytes\n";
        std::cout << "Server: Serial ID hash: ";
        for (size_t i = 0; i < std::min(serialIdHash.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)serialIdHash[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        std::cout << "Server: Signature size: " << signature.size() << " bytes\n";
        std::cout << "Server: Signature: ";
        for (size_t i = 0; i < std::min(signature.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)signature[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        // Verify if this is the expected client ID from shared_keys
        if (serialId == SharedKeys::clientSerialId) {
            std::cout << "Server: Recognized client from shared keys\n";
            // Use the pre-shared client public key directly
            m_clientPublicKey = SharedKeys::clientPublicKey;
            
            std::cout << "Server: Client public key size: " << m_clientPublicKey.size() << " bytes\n";
            std::cout << "Server: Client public key: ";
            for (size_t i = 0; i < std::min(m_clientPublicKey.size(), size_t(10)); i++) {
                std::cout << std::hex << (int)m_clientPublicKey[i] << " ";
            }
            std::cout << "...\n" << std::dec;
        } else {
            std::cerr << "Server: Unknown client, client ID doesn't match expected\n";
            return;
        }
        
        // Verify client's signature
        bool valid = CryptoUtils::verifyEcdsa(m_clientPublicKey, serialIdHash, signature);
        
        if (!valid) {
            std::cerr << "Server: Client signature verification failed\n";
            return;
        }
        
        std::cout << "Server: Client signature verified successfully\n";
        
        // Generate a random challenge
        m_challenge = CryptoUtils::generateRandomBytes(32);
        
        // Sign the challenge with server's private key
        auto serverSignature = CryptoUtils::signEcdsa(m_serverPrivateKey, m_challenge);
        
        std::cout << "Server: Challenge size: " << m_challenge.size() << " bytes\n";
        std::cout << "Server: Server signature size: " << serverSignature.size() << " bytes\n";
        
        // Create server challenge message
        auto serverChallenge = ProtocolUtils::createServerChallenge(m_challenge, serverSignature);
        
        // Send the challenge to client
        write_message(serverChallenge);
        m_state = WAIT_CHALLENGE_RESPONSE;
    }
    
    void handle_client_challenge_response(const std::vector<uint8_t>& message) {
        std::cout << "Server: Handling client challenge response\n";
        
        // Parse client challenge response
        std::vector<uint8_t> challenge, signature;
        bool success = ProtocolUtils::parseClientChallengeResponse(message, challenge, signature);
        
        if (!success) {
            std::cerr << "Server: Failed to parse challenge response\n";
            return;
        }
        
        std::cout << "Server: Received challenge size: " << challenge.size() << " bytes\n";
        std::cout << "Server: Received signature size: " << signature.size() << " bytes\n";
        
        // Verify challenge matches what we sent
        if (challenge != m_challenge) {
            std::cerr << "Server: Challenge mismatch\n";
            return;
        }
        
        // Verify client's signature on the challenge
        bool valid = CryptoUtils::verifyEcdsa(m_clientPublicKey, challenge, signature);
        
        if (!valid) {
            std::cerr << "Server: Client signature on challenge verification failed\n";
            return;
        }
        
        std::cout << "Server: Client successfully authenticated\n";
        m_state = AUTHENTICATED;
        m_state = READY_FOR_MESSAGES;
        
        // Send a welcome message
        std::string welcomeMsg = "Welcome! You are now authenticated and can send messages.";
        auto textMessage = ProtocolUtils::createCustomTextMessage(welcomeMsg);
        write_message(textMessage);
    }
    
    void handle_cot_share_request(const std::vector<uint8_t>& message) {
        std::cout << "Server: Handling CoT share request\n";
        
        // Parse CoT share request
        uint64_t clientMultiplicativeShare;
        bool success = ProtocolUtils::parseCotInitMessage(message, clientMultiplicativeShare);
        
        if (!success) {
            std::cerr << "Server: Failed to parse CoT share request\n";
            return;
        }
        
        std::cout << "Server: Received client's multiplicative share: " << clientMultiplicativeShare << std::endl;
        
        // Generate a random multiplicative share for the server
        std::vector<uint8_t> randomBytes = CryptoUtils::generateRandomBytes(8);
        m_multiplicativeShare = 0;
        for (int i = 0; i < 8; i++) {
            m_multiplicativeShare |= (uint64_t)randomBytes[i] << (i * 8);
        }
        
        // Ensure non-zero value
        m_multiplicativeShare = (m_multiplicativeShare % 100) + 1;
        
        // Initialize CoT with the server's multiplicative share
        m_cot = make_unique<CorrelatedOT>(m_multiplicativeShare);
        
        // Calculate the server's additive share
        m_additiveShare = m_cot->generateServerAdditiveShare(clientMultiplicativeShare);
        
        std::cout << "Server: Generated multiplicative share: " << m_multiplicativeShare << std::endl;
        std::cout << "Server: Generated additive share: " << m_additiveShare << std::endl;
        
        // Create CoT share response
        auto cotShareResponse = ProtocolUtils::createCotResponseMessage(m_additiveShare);
        
        // Send CoT share response to client
        write_message(cotShareResponse);
        m_state = COT_COMPLETED;
        m_state = READY_FOR_MESSAGES;
    }
    
    void handle_text_message(const std::string& text) {
        std::cout << "Server: Received text message from client: " << text << std::endl;
        
        // Echo back the message with a prefix
        std::string response = "Server received: " + text;
        auto textMessage = ProtocolUtils::createCustomTextMessage(response);
        write_message(textMessage);
    }
    
    void write_message(const std::vector<uint8_t>& message) {
        std::cout << "Server: Sending message of size " << message.size() << " bytes\n";
        
        // Use asynchronous write operation with boost::asio
        auto self(shared_from_this());
        boost::asio::async_write(m_socket,
            boost::asio::buffer(message),
            [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    std::cerr << "Server: Write error: " << ec.message() << std::endl;
                }
            });
    }
    
    tcp::socket m_socket;
    ServerState m_state;
    std::vector<uint8_t> m_clientId;
    std::vector<uint8_t> m_challenge;
    
    // For CoT protocol
    std::unique_ptr<CorrelatedOT> m_cot;
    uint64_t m_multiplicativeShare;
    uint64_t m_additiveShare;
    
    // Buffer for incoming messages
    std::vector<uint8_t> m_buffer;
    
    // Client public key (would be stored securely in a real implementation)
    std::vector<uint8_t> m_clientPublicKey;
    
    // Server credentials
    std::vector<uint8_t> m_serverPrivateKey;
    std::vector<uint8_t> m_serverPublicKey;
    
    // Database of client public keys, indexed by serial IDs
    const std::map<std::vector<uint8_t>, std::vector<uint8_t>>& m_clientPublicKeys;
};

class Server {
public:
    Server(boost::asio::io_context& io_context, short port)
        : m_acceptor(io_context, tcp::endpoint(tcp::v4(), port)) {
        
        // Use shared keys instead of generating random ones
        m_privateKey = SharedKeys::serverPrivateKey;
        m_publicKey = SharedKeys::serverPublicKey;
        
        // Initialize the client keys database from shared keys
        m_clientKeys = SharedKeys::createClientDatabase();
        
        // Start accepting connections
        do_accept();
    }

private:
    void do_accept() {
        m_acceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout << "Server: Accepted new connection\n";
                    // Start a new session
                    std::make_shared<Session>(std::move(socket), m_privateKey, m_clientKeys)->start();
                } else {
                    std::cerr << "Server: Accept error: " << ec.message() << std::endl;
                }
                
                // Continue accepting connections
                do_accept();
            });
    }

    tcp::acceptor m_acceptor;
    
    // Server credentials
    std::vector<uint8_t> m_privateKey;
    std::vector<uint8_t> m_publicKey;
    
    // Database of client public keys
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> m_clientKeys;
};

int server_main(int argc, char* argv[]) {
    try {
        // Default port is 9999, but can be overridden by command-line argument
        short port = 9999;
        if (argc > 1) {
            port = static_cast<short>(std::stoi(argv[1]));
        }
        
        boost::asio::io_context io_context;
        Server server(io_context, port);
        std::cout << "Server: Started on port " << port << std::endl;
        io_context.run();
    } catch (const std::exception& e) {
        std::cerr << "Server Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    return server_main(argc, argv);
} 