import random
from dataclasses import dataclass
from math import ceil, floor
from typing import List, Tuple

from sage.arith.misc import random_prime, kronecker, next_prime
from sage.misc.functional import log, sqrt
from sage.modules.free_module_element import vector
from sage.quadratic_forms.binary_qf import BinaryQF

from src.ipfe.helper import prime_form, phi_q_inverse, binary_qf_pow, expo_f, binary_qf_inverse, discrete_log_f


@dataclass
class PK:
    p: int
    delta_q: int
    s_tilde: int
    lambda_bits: int
    gq: BinaryQF
    vec_h: List[BinaryQF]


def param_gen(mu_bits: int, lambda_bits: int, length: int) -> Tuple[List[int], PK]:
    """

    :param length:
    :param mu_bits:
    :param lambda_bits:
    :return:
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
    gq_tmp = phi_q_inverse(r_goth_sq, p).reduced_form()
    gq = binary_qf_pow(gq_tmp, p)

    # Set the bound to sample the randomness.
    bound = floor(s_tilde * sqrt(2 * lambda_bits) * p ** 1.5)

    # Sample the random values.
    vec_s = [random.randint(0, bound) for _ in range(length)]

    # Compute the h vector.
    vec_h = [binary_qf_pow(gq, s) for s in vec_s]

    # Return the secret key and the public key.
    return vec_s, PK(p=p, delta_q=delta_q, s_tilde=s_tilde, lambda_bits=lambda_bits, gq=gq, vec_h=vec_h)


def encrypt(mpk: PK, y_vec: List[int]):
    """

    :param mpk:
    :param y_vec:
    :return:
    """
    # First sample a random r.
    bound = floor(mpk.s_tilde * sqrt(mpk.lambda_bits))
    r = random.randint(0, bound)

    # Compute c_0.
    c_0 = binary_qf_pow(mpk.gq, r)

    # Compute C vector.
    c_vec = [expo_f(mpk.p, mpk.delta_q, y) * binary_qf_pow(mpk.vec_h[i], r) for i, y in enumerate(y_vec)]

    return [c_0] + c_vec


def keygen(msk: List[int], x_vec: List[int]):
    """

    :param msk:
    :param x_vec:
    :return:
    """
    # Return the inner product between the two inputs.
    return vector(msk) * vector(x_vec)


def decrypt(mpk: PK, sk: int, ct: List[BinaryQF], x_vec: List[int]):
    """

    :param mpk:
    :param sk:
    :param ct:
    :param x_vec:
    :return:
    """
    c_x = binary_qf_inverse(binary_qf_pow(ct[0], sk))

    for i, c in enumerate(ct[1:]):
        c_x = c_x * binary_qf_pow(c, x_vec[i])

    return discrete_log_f(mpk.p, mpk.delta_q, c_x)
