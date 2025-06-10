from src.ipfe.helper import expo_f, discrete_log_f
from src.ipfe.ipfe import param_gen, encrypt, keygen, decrypt


class TestIPFE:
    def test_param_gen(self):
        # Get the parameters.
        _, mpk = param_gen(lambda_bits=12, mu_bits=8, length=1)
        # Compute f^m.
        exp_f = expo_f(mpk.p, mpk.delta_q, 97)
        # Find discrete log.
        m_tag = discrete_log_f(mpk.p, mpk.delta_q, exp_f)
        # The discrete log should be correct.
        assert m_tag == 97

    def test_scheme(self):
        # Get the parameters.
        msk, mpk = param_gen(lambda_bits=12, mu_bits=8, length=1)

        # Encrypt and keygen.
        ct = encrypt(mpk=mpk, y_vec=[3])
        sk = keygen(msk=msk, x_vec=[5])

        r = decrypt(mpk=mpk, sk=sk, ct=ct, x_vec=[5])
        print(r)
        if r >= mpk.p // 2:
            r = r - mpk.p
        print(mpk.p)
        print(r)