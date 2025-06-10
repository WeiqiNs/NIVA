from sage.arith.misc import random_prime

from src.flpcp import NormBoundValidation


class TestNormBoundValidation:
    def test_integer_conversion(self):
        assert NormBoundValidation.to_fixed_binary(x=5, length=5) == [1, 0, 1, 0, 0]
        assert NormBoundValidation.to_fixed_binary(x=64, length=5) == [0, 0, 0, 0, 0]

    def test_norm_bound_validation_correct(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        norm_bound, input_bound = 10, 5

        # Initialize the prover.
        prover = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate a proof.
        proof = prover.proof_gen(message=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

        # Initialize the verifier.
        verifier = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof, query=query) is True

    def test_norm_bound_validation_incorrect(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        norm_bound, input_bound = 10, 5

        # Initialize the prover.
        prover = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate a proof.
        proof = prover.proof_gen(message=[100, 2, 3, 4, 5, 6, 7, 8, 9, 10])

        # Initialize the verifier.
        verifier = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should fail.
        assert verifier.verify(proof=proof, query=query) is False

    def test_norm_bound_validation_mixed(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        norm_bound, input_bound = 11, 5

        # Initialize the prover.
        prover = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate a proof; this should pass.
        proof_1 = prover.proof_gen(message=[1, 2, 3, 4, 5, 1, 2, 3, 4, 5])
        # Generate a proof; this should fail.
        proof_2 = prover.proof_gen(message=[1, 1, 1, 1, 1, 1, 1, 1, 1, 33])
        # Generate a proof; this should fail.
        proof_3 = prover.proof_gen(message=[30, 30, 30, 30, 30, 30, 30, 30, 30, 30])

        # Initialize the verifier.
        verifier = NormBoundValidation(
            input_size=input_size, field_size=field_size, norm_bound=norm_bound, input_bound=input_bound
        )
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof_1, query=query) is True
        # The verification on this proof should fail.
        assert verifier.verify(proof=proof_2, query=query) is False
        # The verification on this proof should fail.
        assert verifier.verify(proof=proof_3, query=query) is False
