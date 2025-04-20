# Secure Client-Server Communication System

This project implements a secure client-server communication system using TCP/IP networking, cryptographic operations, data serialization, and multi-party computation as specified in the assignment requirements.

## Features

- **TCP/IP Communication**: Built with Boost Asio for reliable network communication
- **Strong Cryptography**: Uses Trezor Crypto library for all cryptographic operations
- **Structured Messages**: Implements Protocol Buffers (nanopb) for efficient message serialization
- **Secure Authentication**: Multi-step challenge-response mechanism with ECDSA signatures
- **Multi-Party Computation**: Implements Correlated Oblivious Transfer (CoT) protocol
- **MTA Protocol**: Converts multiplicative shares to additive shares securely

## Technical Implementation

### Core Components
- **Boost Asio**: Handles all TCP/IP networking operations
- **Trezor Crypto**: Provides cryptographic primitives (ECDSA, SHA256)
- **nanopb**: Lightweight Protocol Buffer implementation for message serialization
- **secp256k1**: Elliptic curve used for all cryptographic operations

### Authentication Flow
1. Client sends its serial ID with an ECDSA signature
2. Server verifies the signature using client's public key
3. Server generates a 32-byte random challenge, signs it, and sends to client
4. Client verifies server's signature and sends signed challenge response
5. Server verifies client's signature on challenge response

### MTA Protocol Implementation
The system implements the Multiplicative-to-Additive (MTA) protocol:
1. Both parties generate random numbers as multiplicative shares
2. Using Correlated Oblivious Transfer (CoT), these are converted to additive shares
3. The system displays both multiplicative and additive shares for verification

## Project Structure

- `src/`: Source code for client, server and common functionality
- `proto/`: Protocol Buffer definitions and generated code
- `trezor-crypto/`: Cryptographic library (submodule)
- `nanopb/`: Protocol Buffer library (submodule)
- `build.sh`: Script to build the project
- `run_server.sh`: Script to run the server
- `run_client.sh`: Script to run the client

## Getting Started

### Prerequisites
- C++ compiler with C++11 support
- CMake (3.10 or higher)
- Boost libraries (system component)

### Installation

1. Clone the repository with submodules:
   ```
   git clone --recursive https://github.com/yourusername/secure-communication.git
   cd secure-communication
   ```

2. If you've already cloned without submodules:
   ```
   git submodule update --init --recursive
   ```

3. Build the project:
   ```
   ./build.sh
   ```
   
   Alternatively, build manually:
   ```
   mkdir -p build
   cd build
   cmake ..
   cmake --build .
   ```

### Running the Application

1. Start the server:
   ```
   ./run_server.sh
   ```
   
2. In a separate terminal, start the client:
   ```
   ./run_client.sh
   ```

3. Running tests:
   ```
   ./build/secure_communication_test
   ```

## Security Considerations

- All message sizes are strictly limited to prevent buffer overflow attacks
- Digital signatures ensure message authenticity
- Random challenges prevent replay attacks
- Cryptographic operations follow industry best practices
- The implementation follows the CoT protocol from the assignment specification

## Development Notes

- The project uses CMake for cross-platform building
- All cryptographic operations are handled by the Trezor Crypto library
- Protocol Buffers with size restrictions enhance security
- Error handling is implemented for all network and cryptographic operations

## License

This project is provided as per assignment requirements. Copyright and license information will be determined by the assignment guidelines. 