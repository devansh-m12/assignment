#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <random>
#include <thread>

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

// Client state
enum ClientState { 
    CONNECTING, 
    AUTHENTICATING, 
    AUTHENTICATED, 
    COT_EXCHANGING, 
    COT_COMPLETED,
    READY_FOR_MESSAGES
};

class Client : public std::enable_shared_from_this<Client> {
public:
    Client(boost::asio::io_context& io_context, 
           const std::string& host, 
           const std::string& port,
           const std::vector<uint8_t>& serialId,
           const std::vector<uint8_t>& privateKey,
           const std::vector<uint8_t>& serverPublicKey)
        : m_io_context(io_context),
          m_resolver(io_context),
          m_socket(io_context),
          m_state(CONNECTING),
          m_serialId(serialId),
          m_privateKey(privateKey),
          m_serverPublicKey(serverPublicKey) {
        
        // Use the pre-shared public key directly instead of generating it
        m_publicKey = SharedKeys::clientPublicKey;
        
        connect(host, port);
    }
    
    // Create a client with pre-provisioned keys
    static std::shared_ptr<Client> createClient(boost::asio::io_context& io_context, 
                                              const std::string& host, 
                                              const std::string& port) {
        // Use shared keys instead of generating random ones
        std::vector<uint8_t> serialId = SharedKeys::clientSerialId;
        std::vector<uint8_t> privateKey = SharedKeys::clientPrivateKey;
        std::vector<uint8_t> serverPublicKey = SharedKeys::serverPublicKey;
        
        // Create client with pre-shared keys
        return std::make_shared<Client>(io_context, host, port, serialId, privateKey, serverPublicKey);
    }
    
    // Start the authentication process
    void authenticate() {
        std::cout << "Client: Starting authentication process\n";
        
        // Hash the serial ID
        auto serialIdHash = CryptoUtils::sha256(m_serialId);
        
        std::cout << "Client: Serial ID: ";
        for (size_t i = 0; i < std::min(m_serialId.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)m_serialId[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        std::cout << "Client: Serial ID hash: ";
        for (size_t i = 0; i < std::min(serialIdHash.size(), size_t(8)); i++) {
            std::cout << std::hex << (int)serialIdHash[i] << " ";
        }
        std::cout << "..." << std::dec << std::endl;
        
        // Sign the hashed serial ID with the private key
        auto signature = CryptoUtils::signEcdsa(m_privateKey, serialIdHash);
        
        std::cout << "Client: Serial ID size: " << m_serialId.size() << " bytes\n";
        std::cout << "Client: Serial ID hash size: " << serialIdHash.size() << " bytes\n";
        std::cout << "Client: Signature size: " << signature.size() << " bytes\n";
        std::cout << "Client: Private key size: " << m_privateKey.size() << " bytes\n";
        std::cout << "Client: Public key size: " << m_publicKey.size() << " bytes\n";
        
        // Verify our own signature first as a sanity check
        bool selfVerify = CryptoUtils::verifyEcdsa(m_publicKey, serialIdHash, signature);
        std::cout << "Client: Self-verification of signature: " << (selfVerify ? "SUCCESS" : "FAILED") << std::endl;
        
        // Create authentication request
        auto authRequest = ProtocolUtils::createAuthRequest(m_serialId, signature);
        
        // Send authentication request
        write_message(authRequest);
        m_state = AUTHENTICATING;
        
        // Wait for the server response
        read_message();
    }
    
    // Perform Correlated OT protocol
    void performCoT() {
        std::cout << "Client: Starting CoT protocol\n";
        
        // Generate a random multiplicative share using Trezor's secure random
        std::vector<uint8_t> randomBytes = CryptoUtils::generateRandomBytes(8);
        m_multiplicativeShare = 0;
        for (int i = 0; i < 8; i++) {
            m_multiplicativeShare |= (uint64_t)randomBytes[i] << (i * 8);
        }
        
        // Ensure non-zero value
        m_multiplicativeShare = (m_multiplicativeShare % 100) + 1;
        
        // Initialize CoT with the multiplicative share
        m_cot = make_unique<CorrelatedOT>(m_multiplicativeShare);
        
        std::cout << "Client: Generated multiplicative share: " << m_multiplicativeShare << std::endl;
        
        // Create CoT share request
        auto cotShareRequest = ProtocolUtils::createCotInitMessage(m_multiplicativeShare);
        
        // Send CoT share request to server
        write_message(cotShareRequest);
        m_state = COT_EXCHANGING;
    }
    
    // Send a custom text message to the server
    void sendTextMessage(const std::string& text) {
        // Skip authentication check to simplify example
        std::cout << "Client: Sending text message: " << text << std::endl;
        
        // Create custom text message
        auto textMessage = ProtocolUtils::createCustomTextMessage(text);
        
        // Send to server
        write_message(textMessage);
        m_state = READY_FOR_MESSAGES;
    }
    
private:
    // Network functions
    void connect(const std::string& host, const std::string& port) {
        std::cout << "Client: Connecting to server " << host << ":" << port << std::endl;
        
        auto endpoints = m_resolver.resolve(host, port);
        boost::asio::connect(m_socket, endpoints);
        
        std::cout << "Client: Connected to server\n";
    }
    
    void read_message() {
        // Use asynchronous read operation with boost::asio
        // First, resize the buffer to make room for incoming data
        m_buffer.resize(1024);
        
        // Use async_read_some to read data (more appropriate for this simplified example)
        auto self(shared_from_this());
        m_socket.async_read_some(
            boost::asio::buffer(m_buffer, m_buffer.size()),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    std::cout << "Client: Received message of size " << length << " bytes\n";
                    
                    // Resize the buffer to actual message size
                    m_buffer.resize(length);
                    
                    // Process the received message based on current state
                    if (m_state == AUTHENTICATING) {
                        handle_server_challenge(m_buffer);
                    } else if (m_state == COT_EXCHANGING) {
                        handle_cot_share_response(m_buffer);
                    } else if (m_state == READY_FOR_MESSAGES) {
                        handle_text_message(m_buffer);
                    }
                    
                    // Continue reading messages
                    read_message();
                } else if (ec == boost::asio::error::eof) {
                    std::cout << "Client: Server disconnected\n";
                } else {
                    std::cerr << "Client: Read error: " << ec.message() << std::endl;
                }
            });
    }
    
    void write_message(const std::vector<uint8_t>& message) {
        std::cout << "Client: Sending message of size " << message.size() << " bytes\n";
        
        // Use asynchronous write operation with boost::asio
        auto self(shared_from_this());
        boost::asio::async_write(m_socket,
            boost::asio::buffer(message),
            [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    std::cerr << "Client: Write error: " << ec.message() << std::endl;
                }
            });
    }
    
    // Message handlers
    void handle_server_challenge(const std::vector<uint8_t>& message) {
        std::cout << "Client: Handling server challenge\n";
        
        // Parse server challenge
        std::vector<uint8_t> challenge, signature;
        bool success = ProtocolUtils::parseServerChallenge(message, challenge, signature);
        
        if (!success) {
            std::cerr << "Client: Failed to parse server challenge\n";
            return;
        }
        
        // Verify server's signature on the challenge
        bool valid = CryptoUtils::verifyEcdsa(m_serverPublicKey, challenge, signature);
        
        if (!valid) {
            std::cerr << "Client: Server signature verification failed\n";
            return;
        }
        
        std::cout << "Client: Server signature verified successfully\n";
        
        // Sign the challenge with client's private key
        auto clientSignature = CryptoUtils::signEcdsa(m_privateKey, challenge);
        
        std::cout << "Client: Challenge size: " << challenge.size() << " bytes\n";
        std::cout << "Client: Client signature size: " << clientSignature.size() << " bytes\n";
        
        // Create client challenge response
        auto clientResponse = ProtocolUtils::createClientChallengeResponse(challenge, clientSignature);
        
        // Send the response to server
        write_message(clientResponse);
        m_state = AUTHENTICATED;
        
        // Instead of immediately starting CoT, we'll set client to READY_FOR_MESSAGES
        m_state = READY_FOR_MESSAGES;
        std::cout << "Client: Authentication complete, ready for messages\n";
    }
    
    void handle_cot_share_response(const std::vector<uint8_t>& message) {
        std::cout << "Client: Handling CoT share response\n";
        
        // Parse CoT share response
        uint64_t serverMultiplicativeShare;
        bool success = ProtocolUtils::parseCotResponseMessage(message, serverMultiplicativeShare);
        
        if (!success) {
            std::cerr << "Client: Failed to parse CoT share response\n";
            return;
        }
        
        std::cout << "Client: Received server's multiplicative share: " << serverMultiplicativeShare << std::endl;
        
        // Convert multiplicative shares to additive shares
        m_additiveShare = m_cot->generateClientAdditiveShare(serverMultiplicativeShare);
        
        std::cout << "Client: Generated additive share: " << m_additiveShare << std::endl;
        std::cout << "Client: Multiplicative share: " << m_multiplicativeShare << std::endl;
        
        m_state = COT_COMPLETED;
        // After CoT completes, we're ready for messages
        m_state = READY_FOR_MESSAGES;
        std::cout << "Client: CoT protocol completed successfully\n";
    }
    
    void handle_text_message(const std::vector<uint8_t>& message) {
        std::string text;
        bool success = ProtocolUtils::parseCustomTextMessage(message, text);
        
        if (success) {
            std::cout << "Client: Received text message from server: " << text << std::endl;
        } else {
            // Try to parse as another message type
            // For now, we'll just log that we couldn't parse it as text
            std::cout << "Client: Received non-text message\n";
        }
    }
    
    // Client state
    ClientState m_state;
    
    // Network members
    boost::asio::io_context& m_io_context;
    tcp::resolver m_resolver;
    tcp::socket m_socket;
    std::vector<uint8_t> m_buffer;
    
    // Client credentials
    std::vector<uint8_t> m_serialId;
    std::vector<uint8_t> m_privateKey;
    std::vector<uint8_t> m_publicKey;
    std::vector<uint8_t> m_serverPublicKey;
    
    // For CoT protocol
    std::unique_ptr<CorrelatedOT> m_cot;
    uint64_t m_multiplicativeShare;
    uint64_t m_additiveShare;
};

// Main function that actually runs the client
int client_main(int argc, char* argv[]) {
    try {
        // Default host and port
        std::string host = "localhost";
        std::string port = "9999";  // Make sure this matches the server port
        
        // Override with command-line arguments if provided
        if (argc > 1) {
            host = argv[1];
        }
        if (argc > 2) {
            port = argv[2];
        }
        
        boost::asio::io_context io_context;
        auto client = Client::createClient(io_context, host, port);
        client->authenticate();
        
        // Add prompt for sending messages after authentication
        std::thread t([&io_context, client]() {
            std::this_thread::sleep_for(std::chrono::seconds(2)); // Give time for authentication
            
            std::string line;
            std::cout << "Enter messages to send (or 'exit' to quit):\n";
            
            while (true) {
                std::getline(std::cin, line);
                if (line == "exit") {
                    io_context.stop();
                    break;
                }
                
                if (!line.empty()) {
                    client->sendTextMessage(line);
                }
            }
        });
        
        // Detach thread so it can run independently
        t.detach();
        
        io_context.run();
    } catch (const std::exception& e) {
        std::cerr << "Client Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    return client_main(argc, argv);
} 