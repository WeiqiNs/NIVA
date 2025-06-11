from src.ipfe.helper import expo_f, discrete_log_f
from src.ipfe.ipfe import param_gen, encrypt, keygen, decrypt


class TestIPFE:
    def test_param_gen(self):
        # Get the parameters.
        _, mpk = param_gen(lambda_bits=40, mu_bits=36, length=1)
        # Compute f^m.
        exp_f = expo_f(mpk.p, mpk.delta_q, 97)
        # Find discrete log.
        m_tag = discrete_log_f(mpk.p, mpk.delta_q, exp_f)
        # The discrete log should be correct.
        assert m_tag == 97

    def test_ipfe(self):
        # Get the parameters.
        msk, mpk = param_gen(lambda_bits=40, mu_bits=36, length=5)

        # Decryption.
        ct = encrypt(mpk=mpk, y_vec=[1, 2, 3, 4, 5])
        sk = keygen(msk=msk, x_vec=[5, 4, 3, 2, 1])

        # Decrypt the inner product.
        r = decrypt(mpk=mpk, sk=sk, ct=ct, x_vec=[5, 4, 3, 2, 1])

        assert r == 35
