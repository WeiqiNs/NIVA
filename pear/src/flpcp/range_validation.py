from src.flpcp.base import FLPCP, Message, Proof, Query, vector


class RangeValidation(FLPCP):
    """The FLPCP for validating if some range bounds each input."""

    def __init__(self, field_size: int, input_size: int, lower: int, upper: int):
        """
        Initialize the FLPCP class for validating if some range bounds each input.

        :param field_size: The prime field size to use for all computations. Must be a prime number.
        :param input_size: The length of the input to validate.
        :param lower: The lower bound of the range to validate.
        :param upper: The upper bound of the range to validate.
        """
        # Initialize the parent FLPCP class.
        super().__init__(field_size)

        # Store the desired range for the proof.
        self._lower = lower
        self._upper = upper

        # Set the degree of this circuit. The gate is (x - lower) * (x - lower - 1) * ... * (x - upper).
        self._degree = upper - lower + 1
        # Store the number of g-gates.
        self._num_gate = input_size
        # Store the proof size.
        self._proof_size = self._num_gate * self._degree + 1
        # Store the total size.
        self._total_size = input_size + self._degree + self._proof_size

    def proof_gen(self, message: Message) -> Proof:
        """
        Generate a proof for a given message vector.

        :param message: A list of integers representing the input message.
        :return: A `Proof` object encoding the prover's response.
        """
        # For the degree sample desired number of random values.
        constants = [self._field.random_element() for _ in range(self._degree)]

        # Get input lists.
        input_list = [(index + 1, x) for index, x in enumerate(message)]

        # Assume the first input is x, and the second is x - 1.
        polynomials = [self._polynomial_interpolation([(0, c)] + input_list) for c in constants]

        # Compute the proof polynomial.
        p = 1
        for i, polynomial in enumerate(polynomials):
            p = p * (polynomial - i - self._lower)

        # Get the coefficients of the polynomial and pad it to the desired length.
        p_coeff = (self._proof_size - len(p.list())) * [0] + p.list()

        # Return message, random points, and coefficients, in order c0, c1, ..., cd.
        return vector(self._field, message + constants + p_coeff)

    def query_gen(self) -> Query:
        """
        Generate a verifier query consisting of evaluation points and masking values.

        :return: A `Query` tuple used for verification, which includes:
            - a list of vectors (query coefficients) to compute f_i at r,
            - a vector to evaluate the polynomial contained in the proof at r,
            - a vector to compute the final output of the validated circuit.
        """
        # Sample a random point that's larger than the number of g-gates.
        r = self._random_larger_than(x=self._num_gate)

        # Generate the lagrange basis.
        lagrange_basis = self._query_lagrange_basis_gen(r, self._num_gate)

        # Holder for the f polynomials.
        f_poly = []

        # Generate the A matrix, note that row of A has length equals to x || proof.
        for i in range(self._degree):
            # Generate the A matrix.
            a_mat = [[0 for _ in range(self.total_size)] for _ in range(self._num_gate + 1)]
            # Multiply with the constant.
            a_mat[0][self._num_gate + i] = 1
            # Multiply with the input message.
            for j in range(self._num_gate):
                a_mat[j + 1][j] = 1

            # Multiply with the lagrange basis and sum up the vectors.
            f_vec = [[basis * value for value in a_vec] for basis, a_vec in zip(lagrange_basis, a_mat)]

            # Find the correct summarized vector.
            f_vec_sum = [sum(col) for col in list(zip(*f_vec))]

            # Append to the polynomial list.
            f_poly.append(vector(self._field, f_vec_sum))

        # Generate the vector to evaluate polynomial p at random r.
        p_poly = vector(
            self._field, [0] * (self._total_size - self._proof_size) + [r ** i for i in range(self._proof_size)]
        )

        # Generate the vector to compute the final output of the circuit.
        queries = []
        # Apply the optimization, to get a random combination of all g-gates output that matter.
        for i in range(1, self._num_gate + 1):
            # Sample a random point.
            temp_r = self._random_larger_than(x=0)
            queries.append([temp_r * i ** j for j in range(self._proof_size)])

        # Summarize the query.
        c_poly = vector(
            self._field, [0] * (self._total_size - self._proof_size) + [sum(col) for col in list(zip(*queries))]
        )

        return f_poly, p_poly, c_poly

    def verify(self, proof: Proof, query: Query) -> bool:
        """
        Verify whether the given proof satisfies the verification conditions under the query.

        :param proof: The proof vector submitted by the prover.
        :param query: The verifier’s query tuple.
        :return: True if the proof is accepted; False otherwise.
        """
        # First unpack the query.
        f_list, p, c = query

        # Compute the a_i values.
        a_list = [f * proof for f in f_list]

        # Compute the G-gate over the a_i values.
        p_value = 1
        for i, a in enumerate(a_list):
            p_value *= (a - self._lower - i)

        # Evaluate the polynomial p.
        p_prime_value = p * proof

        # Evaluate the output of the entire circuit.
        c_value = c * proof

        # Return the final decision.
        return p_value == p_prime_value and c_value == 0
