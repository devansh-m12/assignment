# Secure Communication Protocol

This repository contains implementation of a secure communication protocol designed for authenticated and encrypted data exchange. The protocol uses modern cryptographic techniques to ensure confidentiality, integrity, and authentication.

## Features

- **Secure Authentication**: Uses challenge-response mechanism with digital signatures
- **Correlated Oblivious Transfer (COT)**: Implements privacy-preserving data exchange
- **Message Size Limits**: Enforces strict limits on message sizes to prevent buffer overflow attacks
- **Structured Protocol Buffers**: Clearly defined message formats using Protocol Buffers

## Protocol Structure

The protocol implements several message types:

### Authentication Messages
- `AuthenticationRequest`: Initial authentication request with serial ID and signature
- `ServerChallenge`: Challenge issued by the server with a random number
- `ClientChallengeResponse`: Client's response to the server challenge

### Correlated Oblivious Transfer
- `CotInitMessage`: Initializes COT with multiplicative share
- `CotResponseMessage`: Response containing additive share

### Application Messages
- `CustomTextMessage`: Secure text messages with size limitations

## Development

This project uses Protocol Buffers for message serialization with specific size restrictions defined in `.options` files to enhance security.

## Security Considerations

- All message sizes are strictly limited to prevent buffer overflow attacks
- Digital signatures are used for authentication
- Random numbers are used in challenges to prevent replay attacks

## Getting Started

[Instructions for setting up and using the library will go here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[License information will go here] 