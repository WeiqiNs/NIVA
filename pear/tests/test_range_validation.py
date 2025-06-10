from sage.arith.misc import random_prime

from src.flpcp import RangeValidation


class TestRangeValidation:
    def test_range_validation_correct(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        lower, upper = 10, 20

        # Initialize the prover.
        prover = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate a proof.
        proof = prover.proof_gen(message=[10, 11, 12, 13, 14, 15, 16, 17, 18, 19])

        # Initialize the verifier.
        verifier = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof, query=query) is True

    def test_range_validation_incorrect(self):
        # Sample a field size for this test.
        input_size = 11
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        lower, upper = 10, 20

        # Initialize the prover.
        prover = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate a proof.
        proof = prover.proof_gen(message=[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 100])

        # Initialize the verifier.
        verifier = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should fail.
        assert verifier.verify(proof=proof, query=query) is False

    def test_range_validation_mixed(self):
        # Sample a field size for this test.
        input_size = 15
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Set the bounds.
        lower, upper = 10, 100

        # Initialize the prover.
        prover = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate proofs.
        proof_1 = prover.proof_gen(message=[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
        proof_2 = prover.proof_gen(message=[200, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])

        # Initialize the verifier.
        verifier = RangeValidation(input_size=input_size, field_size=field_size, lower=lower, upper=upper)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof_1, query=query) is True
        # The verification on this proof should fail.
        assert verifier.verify(proof=proof_2, query=query) is False
