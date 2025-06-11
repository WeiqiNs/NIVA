import random
from dataclasses import dataclass
from math import ceil, floor
from typing import List, Tuple

from sage.arith.misc import random_prime, kronecker, next_prime
from sage.misc.functional import log, sqrt
from sage.quadratic_forms.binary_qf import BinaryQF

from src.ipfe.helper import prime_form, phi_q_inverse, binary_qf_pow, expo_f, binary_qf_inverse, discrete_log_f


@dataclass
class PK:
    """Public key structure for the IPFE scheme."""
    p: int
    delta_q: int
    s_tilde: int
    lambda_bits: int
    gp: BinaryQF
    vec_h: List[BinaryQF]


def param_gen(mu_bits: int, lambda_bits: int, length: int) -> Tuple[List[int], PK]:
    """
    Generate parameters for the inner product functional encryption scheme.

    :param mu_bits: Bit-length of the small prime p.
    :param lambda_bits: Bit-length for the security parameter.
    :param length: Dimension of the input/output vectors.
    :return: A tuple containing the secret key vector and the public key.
    """
    # Check for desired condition.
    assert lambda_bits >= mu_bits + 2

    # Generate the primes.
    while True:
        p = random_prime(2 ** mu_bits - 1, lbound=2 ** (mu_bits - 1))
        q = random_prime(2 ** (2 * lambda_bits - mu_bits) - 1, lbound=2 ** (2 * lambda_bits - mu_bits - 1))
        # Check for desired condition on p and q.
        if (p * q) % 4 == -1 % 4 and kronecker(p, q) == -1:
            break

    # Check again for the desired condition.
    assert 4 * p < q

    # Compute the discriminants.
    delta_k = -p * q
    delta_q = delta_k * p ** 2

    # Compute the bound for s.
    s_tilde = ceil(log(-delta_k, 2) * sqrt(-delta_k))

    # Set r to be a small prime and keep finding the next prime until a condition is reached.
    r = 3
    while kronecker(delta_k, r) != 1:
        r = next_prime(r)

    # Compute the ideal r_goth.
    r_goth = prime_form(delta_k, r)

    # Compute the reduced r_goth squared.
    r_goth_sq = (r_goth * r_goth).reduced_form()

    # Compute the gq generator.
    gp_tmp = phi_q_inverse(r_goth_sq, p).reduced_form()
    gp = binary_qf_pow(gp_tmp, p)

    # Set the bound to sample the randomness.
    bound = floor(s_tilde * sqrt(2 * lambda_bits) * p ** 1.5)

    # Sample the random values.
    vec_s = [random.randint(0, bound) for _ in range(length)]

    # Compute the h vector.
    vec_h = [binary_qf_pow(gp, s) for s in vec_s]

    # Return the secret key and the public key.
    return vec_s, PK(p=p, delta_q=delta_q, s_tilde=s_tilde, lambda_bits=lambda_bits, gp=gp, vec_h=vec_h)


def encrypt(mpk: PK, y_vec: List[int]):
    """
    Encrypt a vector y under the public key.

    :param mpk: The public key.
    :param y_vec: The plaintext input vector to encrypt.
    :return: A ciphertext consisting of [c_0, c_1, ..., c_n], each as a BinaryQF.
    """
    # First sample a random r.
    bound = floor(mpk.s_tilde * sqrt(mpk.lambda_bits))
    r = random.randint(0, bound)

    # Compute c_0.
    c_0 = binary_qf_pow(mpk.gp, r)

    # Compute C vector.
    c_vec = [expo_f(mpk.p, mpk.delta_q, y) * binary_qf_pow(mpk.vec_h[i], r) for i, y in enumerate(y_vec)]

    return [c_0] + c_vec


def keygen(msk: List[int], x_vec: List[int]):
    """
    Generate a secret key corresponding to vector x and master secret key.

    :param msk: Master secret key vector.
    :param x_vec: Function vector for which the key is derived.
    :return: Inner product of msk and x_vec as the secret key.
    """
    # Return the inner product between the two inputs.
    r = 0

    for (a, b) in zip(msk, x_vec):
        r += a * b
    return r


def decrypt(mpk: PK, sk: int, ct: List[BinaryQF], x_vec: List[int]):
    """
    Decrypt a ciphertext using the secret key and the function vector x.

    :param mpk: Public key parameters used in the scheme.
    :param sk: The functional secret key (inner product of msk and x).
    :param ct: Ciphertext as a list of BinaryQF elements [c_0, c_1, ..., c_n].
    :param x_vec: Function vector x corresponding to the key.
    :return: Decrypted inner product y·x as an integer.
    """
    c_x = binary_qf_inverse(binary_qf_pow(ct[0], sk))

    for i, c in enumerate(ct[1:]):
        # Reduce c_x after each multiplication.
        c_x = (c_x * binary_qf_pow(c, x_vec[i])).reduced_form()

    return discrete_log_f(mpk.p, mpk.delta_q, c_x)
