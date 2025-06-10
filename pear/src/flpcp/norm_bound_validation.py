from src.flpcp.base import FLPCP, Message, Proof, Query, vector


class NormBoundValidation(FLPCP):
    def __init__(self, field_size: int, input_size: int, norm_bound: int, input_bound: int):
        """
        Initialize the FLPCP class for validating if some range bounds each input.

        :param field_size: The prime field size to use for all computations. Must be a prime number.
        :param input_size: The length of the input to validate.
        """
        # Initialize the parent FLPCP class.
        super().__init__(field_size)

        # Store the bound for the integers.
        self._norm_bound = norm_bound + 1
        self._input_bound = input_bound

        # Set the degree of this circuit, which is fixed to be 2. The gate is x * (x - 1).
        self._degree = 2

        # Each input and all binaries goes through a G-gate.
        self._num_gate = input_size * (input_bound + 1) + self._norm_bound
        # Store the input size.
        self._input_size = input_size
        # Store the proof size.
        self._proof_size = self._num_gate * self._degree + 1
        # Store the total size.
        self._total_size = self._num_gate + self._degree + self._proof_size

    @staticmethod
    def to_fixed_binary(x: int, length: int) -> Message:
        # Convert integer to binary and remove '0b' prefix.
        bin_str = bin(x)[2:]

        # Truncate the binary or fill with zeros to the desired length.
        bin_str = bin_str.zfill(length) if len(bin_str) < length else bin_str[-length:]

        # Convert the string to a list of integers.
        return [int(bit) for bit in bin_str[::-1]]

    def _prepare_message(self, message: Message) -> Message:
        # Let the result contain the real message first.
        result = [x for x in message]

        # Append the binary representation of each input to the result.
        for x in message:
            result += self.to_fixed_binary(x=x, length=self._input_bound)

        # Compute the bound on the message.
        result += self.to_fixed_binary(x=sum([x ** 2 for x in message]), length=self._norm_bound)

        # Return the final result.
        return result

    def proof_gen(self, message: Message) -> Proof:
        """
        Generate a proof for a given message vector.

        :param message: A list of integers representing the input message.
        :return: A `Proof` object encoding the prover's response.
        """
        # Prepare the input message to the desired format.
        message = self._prepare_message(message=message)

        # For the degree sample desired number of random values.
        constants = [self._field.random_element() for _ in range(self._degree)]

        # Get input lists.
        input_list = [(index + 1, x) for index, x in enumerate(message)]

        # Assume the first input is x, and the second is x - 1.
        polynomials = [self._polynomial_interpolation([(0, c)] + input_list) for c in constants]

        # Compute the proof polynomial.
        p = polynomials[0] * (polynomials[1] - 1)

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

        # These are the query to verify each input corresponds to its binary representation.
        for i in range(self._input_size):
            # Sample a random point.
            temp_r = self._random_larger_than(x=0)
            # Get a temp query of all zeros.
            temp_query = [0] * self._total_size

            # Compute message - binary representation.
            temp_query[i] = temp_r
            for j in range(self._input_bound):
                temp_query[self._input_size + i * self._input_bound + j] = -temp_r * 2 ** j

            # Add the query to queries.
            queries.append(temp_query)

        # This is the query to verify the norm bound binary representation is correct.
        temp_query = [1] * self._input_size + [0] * (self._total_size - self._input_size)

        # Evaluate the polynomial from p(1) to p(input_size).
        for i in range(1, self._input_size + 1):
            for j in range(self._proof_size):
                temp_query[self._total_size - self._proof_size + j] += i ** j

        # Minus the binary representation.
        for i in range(self._norm_bound):
            temp_query[self._input_size * (self._input_bound + 1) + i] = -2 ** i

        # Sample a random point.
        temp_r = self._random_larger_than(x=0)

        # Add the query to queries.
        queries.append([temp_r * x for x in temp_query])

        # These are the query to verify G-gates should output zero.
        for i in range(self._input_size + 1, self._num_gate + 1):
            # Sample a random point.
            temp_r = self._random_larger_than(x=0)
            queries.append(
                [0] * (self._total_size - self._proof_size) + [temp_r * i ** j for j in range(self._proof_size)]
            )

        # Summarize the query.
        c_poly = vector(self._field, [sum(col) for col in list(zip(*queries))])

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
        p_value = a_list[0] * (a_list[1] - 1)

        # Evaluate the polynomial p.
        p_prime_value = p * proof

        # Evaluate the output of the entire circuit.
        c_value = c * proof

        # Return the final decision.
        return p_value == p_prime_value and c_value == 0
