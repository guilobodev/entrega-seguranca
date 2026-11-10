import os
import json
import base64
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


@dataclass
class MensagemCifrada:
    chave_aes_encapsulada_b64: str
    nonce_b64: str
    ciphertext_b64: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, ensure_ascii=False)


def gerar_par_chaves_rsa() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica


def exportar_chave_publica_pem(chave_publica: rsa.RSAPublicKey) -> str:
    return chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8").strip()


def cifrar_mensagem_hibrida(
    mensagem_clara: bytes,
    chave_publica_destinatario: rsa.RSAPublicKey,
) -> MensagemCifrada:
    chave_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    aesgcm = AESGCM(chave_aes)
    ciphertext = aesgcm.encrypt(nonce, mensagem_clara, associated_data=None)

    chave_aes_encapsulada = chave_publica_destinatario.encrypt(
        chave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return MensagemCifrada(
        chave_aes_encapsulada_b64=base64.b64encode(chave_aes_encapsulada).decode("utf-8"),
        nonce_b64=base64.b64encode(nonce).decode("utf-8"),
        ciphertext_b64=base64.b64encode(ciphertext).decode("utf-8"),
    )


def decifrar_mensagem_hibrida(
    pacote: MensagemCifrada,
    chave_privada_destinatario: rsa.RSAPrivateKey,
) -> bytes:
    chave_aes_encapsulada = base64.b64decode(pacote.chave_aes_encapsulada_b64)
    nonce = base64.b64decode(pacote.nonce_b64)
    ciphertext = base64.b64decode(pacote.ciphertext_b64)

    chave_aes = chave_privada_destinatario.decrypt(
        chave_aes_encapsulada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(chave_aes)
    mensagem_clara = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return mensagem_clara


def executar_demonstracao():
    chave_privada, chave_publica = gerar_par_chaves_rsa()
    print("Chave publica RSA gerada:")
    print(exportar_chave_publica_pem(chave_publica))

    mensagem_original = "Transferencia: Conta 1042 para Conta 8891 - Valor R$ 2500,00".encode("utf-8")
    pacote = cifrar_mensagem_hibrida(mensagem_original, chave_publica)

    print("\nPacote cifrado:")
    print(pacote.to_json())

    mensagem_decifrada = decifrar_mensagem_hibrida(pacote, chave_privada)
    print("\nTeste de sucesso (mensagem integra):")
    print("Mensagem decifrada:", mensagem_decifrada.decode("utf-8"))

    print("\nTeste de falha (apos adulteracao no ciphertext):")
    bytes_adulterados = bytearray(base64.b64decode(pacote.ciphertext_b64))
    bytes_adulterados[0] ^= 0x01

    pacote_adulterado = MensagemCifrada(
        chave_aes_encapsulada_b64=pacote.chave_aes_encapsulada_b64,
        nonce_b64=pacote.nonce_b64,
        ciphertext_b64=base64.b64encode(bytes(bytes_adulterados)).decode("utf-8"),
    )

    try:
        decifrar_mensagem_hibrida(pacote_adulterado, chave_privada)
        print("Erro: mensagem adulterada foi aceita.")
    except InvalidTag:
        print("Falha detectada (InvalidTag): mensagem adulterada rejeitada pelo AES-GCM.")


if __name__ == "__main__":
    executar_demonstracao()
