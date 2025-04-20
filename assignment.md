Secure Client-Server Communication System

## Project Overview
This project requires building a secure client-server system implementing:
1. TCP/IP network communication using Boost Asio
2. Cryptographic operations using Trezor Crypto
3. Data serialization using nanopb (Protocol Buffers)
4. Multi-party computation using Correlated Oblivious Transfer (CoT)

## Core Requirements

### Setup
- Implement a TCP/IP based client and server using Boost Asio
- Integrate Trezor Crypto library on both client and server
- Configure nanopb (Protocol Buffer) on both client and server

### Authentication Mechanism
1. Client is pre-provisioned with:
   - 32-byte ECDSA private key
   - Serial ID
   - Server's public key
2. Server stores client's public key
3. Authentication flow:
   - Client generates signature on hash of serial ID and sends to server
   - Server verifies signature using client's public key
   - Server generates 32-byte random number, signs it, and sends to client
   - Client verifies server signature and sends signed random number back
   - Server verifies client signature on random number

### Service Mechanism
1. After authentication, implement MTA (Multiplicative to Additive shares) protocol:
   - Generate random numbers as multiplicative shares on both client and server
   - Convert multiplicative shares to additive shares using CoT protocol
   - Display both multiplicative and additive shares

### Technical Requirements
- Use Trezor Crypto for all cryptographic operations
- Use Boost Asio for all network operations
- Implement ECDSA for all signatures
- Use secp256k1 curve for all cryptographic operations
- Use SHA256 for all hash functions
- Follow OOP principles and design patterns with good coding practices

### Good to Have
- CMake build system
- Protection against well-known attacks
- Write code manually (no AI tools)

## Submission Guidelines
- Provide complete source code
- Include a README with implementation details and build instructions
- Email submission to designated Cypherock email addresses with resume

## Implementation References
- Boost Asio: 
  - https://www.codingwiththomas.com/blog/boost-asio-server-client-example
  - https://github.com/alejandrofsevilla/boost-tcp-server-client
- Trezor Crypto:
  - https://github.com/trezor/trezor-crypto
- Protocol Buffer:
  - https://github.com/nanopb/nanopb
  - https://jpa.kapsi.fi/nanopb/docs/
- ECDSA Concepts:
  - Supplied YouTube videos
- CoT Implementation:
  - Use algorithm in Appendix A.3.1, A.3.2, and A.3.3 of CoT.pdf

## Code Style and Organization
- Use clear file and class naming conventions
- Separate client and server implementations
- Create modular components for:
  - Network communication
  - Cryptographic operations
  - Protocol buffer encoding/decoding
  - CoT implementation
- Include proper error handling and logging
- Comment code clearly, especially for complex cryptographic operations
