import random
from abc import ABC, abstractmethod
from typing import List, Tuple

from sage.modules.free_module_element import vector
from sage.rings.all import Integers, Polynomial
from sage.rings.finite_rings.all import GF
from sage.rings.polynomial.polynomial_number_field import PolynomialRing

# Declare some useful types.
Message = List[int]
Proof = vector
Query = Tuple[List[vector], vector, vector]


class FLPCP(ABC):
    """
    The base class for FLPCP.

    This abstract class provides utility functions and defines the interface for any FLPCP construction, including
    proof generation, query generation, and verification. All operations are performed over a finite field GF(p),
    where `p = field_size`.
    """

    def __init__(self, field_size: int):
        """
        Initialize the FLPCP base class with a finite field of given size.

        :param field_size: The prime field size to use for all computations. Must be a prime number.
        """
        # Define a universal symbol to use.
        self._arg = "x"
        # Define the prime field.
        self._field = GF(field_size)
        # Declare other useful parameters.
        self._total_size = 0

    @property
    def total_size(self) -> int:
        """Return the total size of the FLPCP message and proof combined."""
        return self._total_size

    def _random_larger_than(self, x: int) -> Integers:
        """
        Sample a random element from the finite field that is strictly greater than `x`.

        :param x: An integer threshold.
        :return: A uniformly random field element y such that y > x.
        """
        return self._field(random.randint(x + 1, self._field.order() - 1))

    def _polynomial_interpolation(self, evaluations: List[Tuple[int, int]]) -> Polynomial:
        """
        Perform Lagrange interpolation over the field using the given evaluation points.

        :param evaluations: A list of (x, y) tuples where the polynomial should pass through.
        :return: A polynomial f such that f(x_i) = y_i for all (x_i, y_i) in evaluations.
        """
        ring = PolynomialRing(self._field, self._arg)
        return ring.lagrange_polynomial(evaluations)

    def _query_lagrange_basis_gen(self, r: Integers, input_size: int) -> List[Integers]:
        """
        Evaluate all Lagrange basis polynomials L_j(r) for j in [0, ..., input_size].

        This assumes a canonical interpolation domain of integers [0, ..., input_size].
        :param r: A field element at which to evaluate the basis.
        :param input_size: The number of input positions (basis size = input_size + 1).
        :return: A list of field elements [L_0(r), ..., L_input_size(r)].
        """

        def _lagrange_basis(j):
            """Compute the j-th Lagrange basis polynomial evaluated at r."""
            base = self._field(1)
            for m in range(input_size + 1):
                if m != j:
                    base *= (r - m) / (j - m)
            return base

        # Compute the Lagrange basis values.
        return [_lagrange_basis(j) for j in range(input_size + 1)]

    @abstractmethod
    def proof_gen(self, message: Message) -> Proof:
        """
        Generate a proof for a given message vector.

        The proof is in the format message || constants || polynomial_coefficients.
        :param message: A list of integers representing the input message.
        :return: A `Proof` object encoding the prover's response.
        """
        raise NotImplementedError

    @abstractmethod
    def query_gen(self) -> Query:
        """
        Generate a verifier query consisting of evaluation points and masking values.

        :return: A `Query` tuple used for verification, which includes:
            - a list of vectors (query coefficients) to compute f_i at r,
            - a vector to evaluate the polynomial contained in the proof at r,
            - a vector to compute the final output of the validated circuit.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, proof: Proof, query: Query) -> bool:
        """
        Verify whether the given proof satisfies the verification conditions under the query.

        :param proof: The proof vector submitted by the prover.
        :param query: The verifier’s query tuple.
        :return: True if the proof is accepted; False otherwise.
        """
        raise NotImplementedError
