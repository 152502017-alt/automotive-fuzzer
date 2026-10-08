import random
from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    data: bytes
    strategy: str


class BaseFuzzer:
    name = "base"

    def mutate(self, seed: bytes) -> bytes:
        raise NotImplementedError

    def fuzz(self, seed: bytes, count: int = 1000):
        return [
            FuzzResult(self.mutate(seed), self.name)
            for _ in range(count)
        ]


# 1. Random mutation
class RandomFuzzer(BaseFuzzer):
    name = "random"

    def mutate(self, seed):
        data = bytearray(seed)

        if not data:
            return bytes(data)

        index = random.randrange(len(data))
        data[index] = random.randrange(256)

        return bytes(data)


# 2. Boundary-value mutation
class BoundaryFuzzer(BaseFuzzer):
    name = "boundary"

    VALUES = [0, 1, 2, 127, 128, 254, 255]

    def mutate(self, seed):
        data = bytearray(seed)

        if not data:
            return bytes(data)

        index = random.randrange(len(data))
        data[index] = random.choice(self.VALUES)

        return bytes(data)


# 3. Structure-aware mutation
class StructureFuzzer(BaseFuzzer):
    name = "structure"

    def mutate(self, seed):
        data = bytearray(seed)

        if len(data) < 2:
            return bytes(data)

        # Mutate a complete 16-bit field.
        index = random.randrange(0, len(data) - 1)
        value = random.choice([
            0,
            1,
            0x7FFF,
            0xFFFF,
        ])

        data[index:index + 2] = value.to_bytes(2, "big")

        return bytes(data)


# 4. Stateful mutation
class StatefulFuzzer(BaseFuzzer):
    name = "stateful"

    def __init__(self, sequences):
        self.sequences = sequences

    def mutate(self, seed):
        if not self.sequences:
            return seed

        sequence = random.choice(self.sequences)

        if not sequence:
            return seed

        message = random.choice(sequence)
        return bytes(message)


# 5. Coverage-guided mutation
class CoverageFuzzer(BaseFuzzer):
    name = "coverage"

    def __init__(self):
        self.coverage = set()

    def mutate(self, seed):
        candidate = bytearray(seed)

        if not candidate:
            return bytes(candidate)

        index = random.randrange(len(candidate))
        candidate[index] = random.randrange(256)

        return bytes(candidate)

    def accept(self, coverage):
        new_coverage = set(coverage) - self.coverage

        if new_coverage:
            self.coverage.update(new_coverage)
            return True

        return False


# 6. Genetic algorithm
class GeneticFuzzer(BaseFuzzer):
    name = "genetic"

    def mutate(self, seed):
        data = bytearray(seed)

        if not data:
            return bytes(data)

        for _ in range(random.randint(1, 3)):
            index = random.randrange(len(data))
            data[index] = random.randrange(256)

        return bytes(data)

    def crossover(self, parent1, parent2):
        if not parent1 or not parent2:
            return parent1 or parent2

        point = random.randrange(min(len(parent1), len(parent2)))

        return parent1[:point] + parent2[point:]


# 7. ML-guided mutation
class MLGUIDEDFuzzer(BaseFuzzer):
    name = "ml_guided"

    def __init__(self):
        self.history = []

    def record(self, mutation_type, reward):
        self.history.append((mutation_type, reward))

    def choose_mutation(self):
        if not self.history:
            return random.choice([
                "byte",
                "boundary",
                "field",
            ])

        scores = {}

        for mutation, reward in self.history:
            scores.setdefault(mutation, []).append(reward)

        return max(
            scores,
            key=lambda x: sum(scores[x]) / len(scores[x])
        )

    def mutate(self, seed):
        mutation = self.choose_mutation()
        data = bytearray(seed)

        if not data:
            return bytes(data)

        index = random.randrange(len(data))

        if mutation == "boundary":
            data[index] = random.choice([0, 1, 127, 128, 255])

        elif mutation == "field" and len(data) >= 2:
            data[index:index + 2] = random.choice(
                [0, 1, 0xFFFF]
            ).to_bytes(2, "big")

        else:
            data[index] = random.randrange(256)

        return bytes(data)