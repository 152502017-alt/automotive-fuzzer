
def generate_candidates(seeds, iterations):
    results = []
    for i in range(iterations):
        seed = seeds[i % len(seeds)]
        data = bytearray(seed)
        if data:
            data[i % len(data)] ^= (i % 255) + 1
        results.append(bytes(data))
    return results
