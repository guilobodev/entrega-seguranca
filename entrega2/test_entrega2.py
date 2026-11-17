import hashlib
import sqlite3
import unittest

from argon2 import PasswordHasher, Type

from autenticacao import (
    PARAMETROS_ARGON2,
    ErroCadastro,
    autenticar,
    cadastrar_usuario,
    conectar,
)

SENHA = "SenhaForte#2026-A"


class TestEntrega2Autenticacao(unittest.TestCase):
    def setUp(self):
        self.conexao = conectar(":memory:")

    def tearDown(self):
        self.conexao.close()

    def _hash_de(self, usuario):
        return self.conexao.execute(
            "SELECT senha_hash FROM usuarios WHERE nome_usuario = ?", (usuario,)
        ).fetchone()[0]

    # --- Requisito: login correto e incorreto ---
    def test_login_com_senha_correta(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        self.assertTrue(autenticar(self.conexao, "alice", SENHA).sucesso)

    def test_login_com_senha_incorreta(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        self.assertFalse(autenticar(self.conexao, "alice", "SenhaErrada#999999").sucesso)

    def test_login_com_usuario_inexistente(self):
        self.assertFalse(autenticar(self.conexao, "fantasma", SENHA).sucesso)

    def test_mensagem_igual_para_usuario_inexistente_e_senha_errada(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        a = autenticar(self.conexao, "alice", "SenhaErrada#999999")
        b = autenticar(self.conexao, "fantasma", SENHA)
        self.assertEqual(a.motivo, b.motivo)

    # --- Requisito: nao armazenar senha em texto puro; hash + salt ---
    def test_senha_nao_fica_em_texto_puro(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        conteudo = " ".join(
            str(c) for linha in self.conexao.execute("SELECT * FROM usuarios") for c in linha
        )
        self.assertNotIn(SENHA, conteudo)

    def test_hash_usa_argon2id_com_parametros_configurados(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        h = self._hash_de("alice")
        self.assertTrue(h.startswith("$argon2id$v=19$"))
        self.assertIn(
            f"m={PARAMETROS_ARGON2['memory_cost']},t={PARAMETROS_ARGON2['time_cost']},"
            f"p={PARAMETROS_ARGON2['parallelism']}",
            h,
        )

    def test_salt_unico_por_usuario(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        cadastrar_usuario(self.conexao, "bob", SENHA)  # mesma senha
        h1, h2 = self._hash_de("alice"), self._hash_de("bob")
        self.assertNotEqual(h1, h2)
        self.assertNotEqual(h1.split("$")[-2], h2.split("$")[-2])  # campo do salt

    # --- Requisito: comparacao segura pela biblioteca ---
    def test_verificacao_e_feita_pela_biblioteca(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        h = self._hash_de("alice")
        hasher = PasswordHasher(**PARAMETROS_ARGON2)
        self.assertTrue(hasher.verify(h, SENHA))

    def test_hash_adulterado_no_banco_rejeita_login(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        h = self._hash_de("alice")
        adulterado = h[:-3] + ("AAA" if not h.endswith("AAA") else "BBB")
        self.conexao.execute("UPDATE usuarios SET senha_hash = ?", (adulterado,))
        self.assertFalse(autenticar(self.conexao, "alice", SENHA).sucesso)

    def test_hash_corrompido_nao_gera_excecao(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        self.conexao.execute("UPDATE usuarios SET senha_hash = 'lixo'")
        self.assertFalse(autenticar(self.conexao, "alice", SENHA).sucesso)

    # --- Requisito: SHA-256 isolado nao e adequado ---
    def test_sha256_isolado_e_deterministico_e_sem_salt(self):
        # Mesma senha -> mesmo hash: permite rainbow tables e revela senhas repetidas.
        self.assertEqual(
            hashlib.sha256(SENHA.encode()).hexdigest(),
            hashlib.sha256(SENHA.encode()).hexdigest(),
        )
        # Argon2id: mesma senha -> hashes diferentes por causa do salt.
        hasher = PasswordHasher(**PARAMETROS_ARGON2)
        self.assertNotEqual(hasher.hash(SENHA), hasher.hash(SENHA))

    # --- Validacao de entrada e seguranca da consulta ---
    def test_usuario_duplicado_e_recusado(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        with self.assertRaises(ErroCadastro):
            cadastrar_usuario(self.conexao, "alice", "OutraSenha#2026-B")

    def test_senha_curta_e_recusada(self):
        with self.assertRaises(ErroCadastro):
            cadastrar_usuario(self.conexao, "alice", "curta")

    def test_senha_muito_longa_e_recusada(self):
        with self.assertRaises(ErroCadastro):
            cadastrar_usuario(self.conexao, "alice", "a" * 129)

    def test_nome_usuario_invalido_e_recusado(self):
        with self.assertRaises(ErroCadastro):
            cadastrar_usuario(self.conexao, "al ice; DROP TABLE usuarios", SENHA)

    def test_sql_injection_no_login_nao_autentica(self):
        cadastrar_usuario(self.conexao, "alice", SENHA)
        r = autenticar(self.conexao, "' OR '1'='1", "qualquer")
        self.assertFalse(r.sucesso)
        r = autenticar(self.conexao, "alice' --", SENHA)
        self.assertFalse(r.sucesso)

    def test_rehash_quando_parametros_antigos(self):
        antigo = PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1, type=Type.ID)
        self.conexao.execute(
            "INSERT INTO usuarios (nome_usuario, senha_hash) VALUES (?, ?)",
            ("alice", antigo.hash(SENHA)),
        )
        self.assertTrue(autenticar(self.conexao, "alice", SENHA).sucesso)
        self.assertIn("m=65536,t=3,p=4", self._hash_de("alice"))


if __name__ == "__main__":
    unittest.main()
