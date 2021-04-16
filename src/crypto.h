//
// Created by keplerc on 4/15/21.
//

#ifndef PARANOID_SGX_CRYPTO_H
#define PARANOID_SGX_CRYPTO_H

namespace asylo{
    // Dummy 128-bit AES key.
    constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15};
    //std::unique_ptr <SigningKey> signing_key;

    //// Helper function that adapts absl::BytesToHexString, allowing it to be used
    //// with ByteContainerView.
    //std::string BytesToHexString(ByteContainerView bytes) {
    //    return absl::BytesToHexString(absl::string_view(
    //            reinterpret_cast<const char *>(bytes.data()), bytes.size()));
    //}

    //        // signs the message with ecdsa signing key
    //        const std::vector <uint8_t> SignMessage(const std::string &message) {
    //            signing_key = EcdsaP256Sha256SigningKey::Create().ValueOrDie();
    //            std::vector <uint8_t> signature;
    //            ASYLO_CHECK_OK(signing_key->Sign(message, &signature));
    //            return signature;
    //        }
    //
    //        // verify the message with ecdsa verfying key
    //        const Status VerifyMessage(const std::string &message, std::vector <uint8_t> signature) {
    //            std::unique_ptr <VerifyingKey> verifying_key;
    //            ASYLO_ASSIGN_OR_RETURN(verifying_key,
    //                                   signing_key->GetVerifyingKey());
    //            return verifying_key->Verify(message, signature);
    //        }

    //a dummy version of signing
    //TODO: actually signing it
    std::string SignMessage(const std::string &message){
        return message;
    }
    bool VerifyMessage(const std::string &message, const std::string& signature){
        return message == signature;
    }
    //
    //// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
    //// by authenticated ciphertext, encoded as a hex string.
    //const StatusOr <std::string> EncryptMessage(const std::string &message) {
    //    std::unique_ptr <AeadCryptor> cryptor;
    //    ASYLO_ASSIGN_OR_RETURN(cryptor,
    //                           AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));
    //
    //    std::vector <uint8_t> additional_authenticated_data;
    //    std::vector <uint8_t> nonce(cryptor->NonceSize());
    //    std::vector <uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
    //    size_t ciphertext_size;
    //
    //    ASYLO_RETURN_IF_ERROR(cryptor->Seal(
    //            message, additional_authenticated_data, absl::MakeSpan(nonce),
    //            absl::MakeSpan(ciphertext), &ciphertext_size));
    //
    //    return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
    //}
    //
    //const StatusOr <CleansingString> DecryptMessage(
    //        const std::string &nonce_and_ciphertext) {
    //    std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);
    //
    //    std::unique_ptr <AeadCryptor> cryptor;
    //    ASYLO_ASSIGN_OR_RETURN(cryptor,
    //                           AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));
    //
    //    if (input_bytes.size() < cryptor->NonceSize()) {
    //        return Status(
    //                error::GoogleError::INVALID_ARGUMENT,
    //                absl::StrCat("Input too short: expected at least ",
    //                             cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
    //    }
    //
    //    std::vector <uint8_t> additional_authenticated_data;
    //    std::vector <uint8_t> nonce = {input_bytes.begin(),
    //                                   input_bytes.begin() + cryptor->NonceSize()};
    //    std::vector <uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
    //                                        input_bytes.end()};
    //
    //    // The plaintext is always smaller than the ciphertext, so use
    //    // `ciphertext.size()` as an upper bound on the plaintext buffer size.
    //    CleansingVector <uint8_t> plaintext(ciphertext.size());
    //    size_t plaintext_size;
    //
    //    ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
    //                                        nonce, absl::MakeSpan(plaintext),
    //                                        &plaintext_size));
    //
    //    return CleansingString(plaintext.begin(), plaintext.end());
    //}
}
#endif //PARANOID_SGX_CRYPTO_H
