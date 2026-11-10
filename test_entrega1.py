import unittest
import base64
from cryptography.exceptions import InvalidTag
try:
    from entrega1_criptografia.criptografia_hibrida import (
        gerar_par_chaves_rsa,
        cifrar_mensagem_hibrida,
        decifrar_mensagem_hibrida,
        MensagemCifrada,
    )
except ModuleNotFoundError:
    from criptografia_hibrida import (
        gerar_par_chaves_rsa,
        cifrar_mensagem_hibrida,
        decifrar_mensagem_hibrida,
        MensagemCifrada,
    )


class TestEntrega1CifragemHibrida(unittest.TestCase):
    def setUp(self):
        self.chave_privada, self.chave_publica = gerar_par_chaves_rsa()
        self.mensagem = b"Transferencia: Conta 1042 para Conta 8891 - Valor R$ 2500,00"

    def test_sucesso_cifrar_e_decifrar(self):
        pacote = cifrar_mensagem_hibrida(self.mensagem, self.chave_publica)
        decifrada = decifrar_mensagem_hibrida(pacote, self.chave_privada)
        self.assertEqual(decifrada, self.mensagem)

    def test_falha_apos_adulteracao_conteudo_cifrado(self):
        pacote = cifrar_mensagem_hibrida(self.mensagem, self.chave_publica)
        bytes_adulterados = bytearray(base64.b64decode(pacote.ciphertext_b64))
        bytes_adulterados[0] ^= 0x01

        pacote_adulterado = MensagemCifrada(
            chave_aes_encapsulada_b64=pacote.chave_aes_encapsulada_b64,
            nonce_b64=pacote.nonce_b64,
            ciphertext_b64=base64.b64encode(bytes(bytes_adulterados)).decode("utf-8"),
        )
        with self.assertRaises(InvalidTag):
            decifrar_mensagem_hibrida(pacote_adulterado, self.chave_privada)

    def test_falha_apos_adulteracao_tag_gcm(self):
        pacote = cifrar_mensagem_hibrida(self.mensagem, self.chave_publica)
        bytes_adulterados = bytearray(base64.b64decode(pacote.ciphertext_b64))
        bytes_adulterados[-1] ^= 0xFF

        pacote_adulterado = MensagemCifrada(
            chave_aes_encapsulada_b64=pacote.chave_aes_encapsulada_b64,
            nonce_b64=pacote.nonce_b64,
            ciphertext_b64=base64.b64encode(bytes(bytes_adulterados)).decode("utf-8"),
        )
        with self.assertRaises(InvalidTag):
            decifrar_mensagem_hibrida(pacote_adulterado, self.chave_privada)


if __name__ == "__main__":
    unittest.main()
