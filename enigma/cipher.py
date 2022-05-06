def _xor_encrypt_decrypt(message: str, key_string: str):
    output = []
    key = list(key_string)

    for i in range(len(message)):
        char_code = ord(message[i]) ^ ord(key[i % len(key)][0])
        output.append(chr(char_code))

    return "".join(output)


def encrypt(message: str, key: str):
    return _xor_encrypt_decrypt(message, key)


def decrypt(encrypted_message: str, key: str):
    return _xor_encrypt_decrypt(encrypted_message, key)
