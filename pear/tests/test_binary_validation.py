from sage.arith.misc import random_prime

from src.flpcp import BinaryValidation


class TestBinaryValidation:
    def test_binary_validation_correct(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Initialize the prover.
        prover = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate a proof.
        proof = prover.proof_gen(message=[1, 0, 1, 0, 1, 0, 1, 0, 1, 0])

        # Initialize the verifier.
        verifier = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof, query=query) is True

    def test_binary_validation_incorrect(self):
        # Sample a field size for this test.
        input_size = 11
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Initialize the prover.
        prover = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate a proof.
        proof = prover.proof_gen(message=[1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 11])

        # Initialize the verifier.
        verifier = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should fail.
        assert verifier.verify(proof=proof, query=query) is False

    def test_binary_validation_mixed(self):
        # Sample a field size for this test.
        input_size = 10
        field_size = random_prime(2 ** 128 - 1, lbound=2 ** 127)

        # Initialize the prover.
        prover = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate proofs.
        proof_1 = prover.proof_gen(message=[1, 0, 1, 0, 1, 0, 1, 0, 1, 0])
        proof_2 = prover.proof_gen(message=[11, 0, 1, 0, 1, 0, 1, 0, 1, 0])

        # Initialize the verifier.
        verifier = BinaryValidation(input_size=input_size, field_size=field_size)
        # Generate the query for verification.
        query = verifier.query_gen()

        # The verification on this proof should pass.
        assert verifier.verify(proof=proof_1, query=query) is True
        # The verification on this proof should fail.
        assert verifier.verify(proof=proof_2, query=query) is False
