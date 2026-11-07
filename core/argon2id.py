"""Native Python Argon2id v1.3 and unkeyed BLAKE2b, for the local experiment.

Specifications: RFC 9106 sections 3 and 5; RFC 7693 sections 2 and 3.
No crypto library is used. Lanes are processed sequentially in slice order.
CPython arithmetic/memory handling is not constant-time and does not guarantee
erasure of secret copies. This module is an inspectable experimental implementation.
"""

from array import array
from struct import pack, unpack


MASK = (1 << 64) - 1
LOW_MASK = (1 << 32) - 1
IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)
SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)
BLOCK_ROWS = tuple(tuple(range(start, start + 16)) for start in range(0, 128, 16))
BLOCK_COLUMNS = tuple(tuple(row * 16 + col * 2 + offset for row in range(8) for offset in range(2)) for col in range(8))


def blake2b(data: bytes, length: int = 64) -> bytes:
    """Unkeyed sequential BLAKE2b; output length is part of its parameter block."""
    if not isinstance(data, bytes):
        raise TypeError('BLAKE2b input must be bytes')
    if type(length) is not int or not 1 <= length <= 64:
        raise ValueError('BLAKE2b output length must be 1..64 bytes')
    state = list(IV)
    state[0] ^= 0x01010000 ^ length
    for offset in range(0, max(1, len(data)), 128):
        block = data[offset:offset + 128]
        words = unpack('<16Q', block.ljust(128, b'\0'))
        work = state + list(IV)
        count = offset + len(block)
        work[12] ^= count & MASK
        work[13] ^= count >> 64
        if count == len(data):
            work[14] ^= MASK
        for round_index in range(12):
            order = SIGMA[round_index % 10]
            _blake_mix(work, 0, 4, 8, 12, words[order[0]], words[order[1]])
            _blake_mix(work, 1, 5, 9, 13, words[order[2]], words[order[3]])
            _blake_mix(work, 2, 6, 10, 14, words[order[4]], words[order[5]])
            _blake_mix(work, 3, 7, 11, 15, words[order[6]], words[order[7]])
            _blake_mix(work, 0, 5, 10, 15, words[order[8]], words[order[9]])
            _blake_mix(work, 1, 6, 11, 12, words[order[10]], words[order[11]])
            _blake_mix(work, 2, 7, 8, 13, words[order[12]], words[order[13]])
            _blake_mix(work, 3, 4, 9, 14, words[order[14]], words[order[15]])
        state = [state[i] ^ work[i] ^ work[i + 8] for i in range(8)]
    return pack('<8Q', *state)[:length]


def derive(password: bytes, salt: bytes, memory_kib: int = 65536, iterations: int = 3, lanes: int = 4,
           length: int = 32, secret: bytes = b'', associated_data: bytes = b'') -> bytes:
    """Derive a key; allocating and filling memory happens only on this call.

    Small parameters are supported for specification tests, not recommended for
    stored passwords. Keep the original requested memory value in H0 even when
    the allocated number of blocks is rounded down to a multiple of 4 * lanes.
    """
    for name, value in (('password', password), ('salt', salt), ('secret', secret), ('associated_data', associated_data)):
        if not isinstance(value, bytes):
            raise TypeError(f'{name} must be bytes')
        if len(value) > LOW_MASK:
            raise ValueError(f'{name} exceeds the Argon2 length field')
    if type(lanes) is not int or not 1 <= lanes < (1 << 24):
        raise ValueError('lanes must be an integer in 1..2**24-1')
    if type(memory_kib) is not int or not 8 * lanes <= memory_kib <= LOW_MASK:
        raise ValueError('memory_kib must be an integer in 8*lanes..2**32-1')
    if type(iterations) is not int or not 1 <= iterations <= LOW_MASK:
        raise ValueError('iterations must be an integer in 1..2**32-1')
    if type(length) is not int or not 4 <= length <= LOW_MASK:
        raise ValueError('output length must be an integer in 4..2**32-1')

    # H0 includes parameters and explicit byte lengths; there is no ambiguous string concatenation.
    initial = pack('<6I', lanes, length, memory_kib, iterations, 0x13, 2)
    initial += b''.join(pack('<I', len(value)) + value for value in (password, salt, secret, associated_data))
    initial = blake2b(initial)
    block_count = memory_kib // (4 * lanes) * (4 * lanes)
    lane_length = block_count // lanes
    segment_length = lane_length // 4
    memory = array('Q', [0]) * (block_count * 128)
    if memory.itemsize != 8:
        raise RuntimeError('This implementation requires an 8-byte unsigned Q array item')
    for lane in range(lanes):
        for column in range(2):
            start = (lane * lane_length + column) * 128
            memory[start:start + 128] = array('Q', unpack('<128Q', _long_hash(initial + pack('<2I', column, lane), 1024)))

    # Only the first two slices of pass 0 use data-independent addressing.
    zero = [0] * 128
    for pass_index in range(iterations):
        for slice_index in range(4):
            for lane in range(lanes):
                independent = pass_index == 0 and slice_index < 2
                first = 2 if pass_index == 0 and slice_index == 0 else 0
                if independent:
                    address_input = [pass_index, lane, slice_index, block_count, iterations, 2, 0] + [0] * 121
                    if first:
                        address_input[6] += 1
                        addresses = _compress(zero, _compress(zero, address_input))
                for index in range(first, segment_length):
                    column = slice_index * segment_length + index
                    previous = lane * lane_length + (column - 1) % lane_length
                    if independent:
                        if index % 128 == 0:
                            address_input[6] += 1
                            addresses = _compress(zero, _compress(zero, address_input))
                        random_value = addresses[index % 128]
                    else:
                        random_value = memory[previous * 128]
                    reference_lane = (random_value >> 32) % lanes
                    if pass_index == 0 and slice_index == 0:
                        reference_lane = lane
                    same_lane = reference_lane == lane
                    if pass_index == 0:
                        area = slice_index * segment_length
                    else:
                        area = lane_length - segment_length
                    area += index - 1 if same_lane else (-1 if index == 0 else 0)
                    relative = (random_value & LOW_MASK) ** 2 >> 32
                    relative = area - 1 - (area * relative >> 32)
                    start_column = 0 if pass_index == 0 else ((slice_index + 1) * segment_length) % lane_length
                    reference = reference_lane * lane_length + (start_column + relative) % lane_length
                    block = _compress(memory[previous * 128:(previous + 1) * 128], memory[reference * 128:(reference + 1) * 128])
                    start = (lane * lane_length + column) * 128
                    if pass_index:
                        block = [word ^ memory[start + i] for i, word in enumerate(block)]
                    memory[start:start + 128] = array('Q', block)

    # Array storage is native-endian internally, but all encoded inputs/outputs are explicitly little-endian.
    final = [0] * 128
    for lane in range(lanes):
        start = ((lane + 1) * lane_length - 1) * 128
        final = [word ^ memory[start + i] for i, word in enumerate(final)]
    return _long_hash(pack('<128Q', *final), length)


def _long_hash(data, length):
    value = pack('<I', length) + data
    if length <= 64:
        return blake2b(value, length)
    rounds = (length + 31) // 32 - 2
    value = blake2b(value)
    result = bytearray(value[:32])
    for _ in range(1, rounds):
        value = blake2b(value)
        result.extend(value[:32])
    result.extend(blake2b(value, length - 32 * rounds))
    return bytes(result)


def _blake_mix(state, a, b, c, d, x, y):
    va, vb, vc, vd = state[a], state[b], state[c], state[d]
    va = (va + vb + x) & MASK
    vd ^= va
    vd = ((vd >> 32) | (vd << 32)) & MASK
    vc = (vc + vd) & MASK
    vb ^= vc
    vb = ((vb >> 24) | (vb << 40)) & MASK
    va = (va + vb + y) & MASK
    vd ^= va
    vd = ((vd >> 16) | (vd << 48)) & MASK
    vc = (vc + vd) & MASK
    vb ^= vc
    vb = ((vb >> 63) | (vb << 1)) & MASK
    state[a], state[b], state[c], state[d] = va, vb, vc, vd


def _blamka_mix(state, a, b, c, d):
    va, vb, vc, vd = state[a], state[b], state[c], state[d]
    va = (va + vb + 2 * (va & LOW_MASK) * (vb & LOW_MASK)) & MASK
    vd ^= va
    vd = ((vd >> 32) | (vd << 32)) & MASK
    vc = (vc + vd + 2 * (vc & LOW_MASK) * (vd & LOW_MASK)) & MASK
    vb ^= vc
    vb = ((vb >> 24) | (vb << 40)) & MASK
    va = (va + vb + 2 * (va & LOW_MASK) * (vb & LOW_MASK)) & MASK
    vd ^= va
    vd = ((vd >> 16) | (vd << 48)) & MASK
    vc = (vc + vd + 2 * (vc & LOW_MASK) * (vd & LOW_MASK)) & MASK
    vb ^= vc
    vb = ((vb >> 63) | (vb << 1)) & MASK
    state[a], state[b], state[c], state[d] = va, vb, vc, vd


def _compress(previous, reference):
    combined = [a ^ b for a, b in zip(previous, reference)]
    work = combined.copy()
    for positions in BLOCK_ROWS + BLOCK_COLUMNS:
        _blamka_mix(work, positions[0], positions[4], positions[8], positions[12])
        _blamka_mix(work, positions[1], positions[5], positions[9], positions[13])
        _blamka_mix(work, positions[2], positions[6], positions[10], positions[14])
        _blamka_mix(work, positions[3], positions[7], positions[11], positions[15])
        _blamka_mix(work, positions[0], positions[5], positions[10], positions[15])
        _blamka_mix(work, positions[1], positions[6], positions[11], positions[12])
        _blamka_mix(work, positions[2], positions[7], positions[8], positions[13])
        _blamka_mix(work, positions[3], positions[4], positions[9], positions[14])
    return [a ^ b for a, b in zip(combined, work)]
