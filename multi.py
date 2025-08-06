''' MIT License

    Copyright (c) Microsoft Corporation. All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.'''



import nacl.public
import nacl.signing
import nacl.encoding
import hashlib, hmac, os, sys, time, tracemalloc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from frodokem import FrodoKEM
import time
import tracemalloc
import statistics
import csv
import os

# == UTILITY FUNCTIONS ==
def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, prev, i = b'', b'', 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        okm += prev
        i += 1
    return okm[:length]

def print_key(title, key_bytes):
    print(f"{title}: {key_bytes.hex()} ({len(key_bytes)} bytes)")

def print_keypair(title, priv, pub):
    priv_bytes = priv.encode(nacl.encoding.RawEncoder())
    pub_bytes = pub.encode(nacl.encoding.RawEncoder()) if hasattr(pub, 'encode') else bytes(pub)
    print(f"{title} Private Key: {priv_bytes.hex()} ({len(priv_bytes)} bytes)")
    print(f"{title} Public  Key: {pub_bytes.hex()} ({len(pub_bytes)} bytes)\n")

def print_pq_key(title, priv, pub):
    print(f"{title} FrodoKEM Private Key: {priv.hex()[:64]}... ({len(priv)} bytes)")
    print(f"{title} FrodoKEM Public  Key: {pub.hex()[:64]}... ({len(pub)} bytes)\n")

# == PREKEY BUNDLE ==
def generate_prekey_bundle(name):
    print(f"== {name} Prekey Bundle ==")
    ik_sk = nacl.signing.SigningKey.generate()
    ik_vk = ik_sk.verify_key
    print_keypair(f"{name} Identity", ik_sk, ik_vk)
    spk_sk = nacl.signing.SigningKey.generate()
    spk_vk = spk_sk.verify_key
    print_keypair(f"{name} Signed Prekey", spk_sk, spk_vk)
    opk_sk = nacl.public.PrivateKey.generate()
    opk_vk = opk_sk.public_key
    print_keypair(f"{name} One-Time Prekey", opk_sk, opk_vk)
    pqkem = FrodoKEM('FrodoKEM-640-AES')
    pq_pub, pq_priv = pqkem.kem_keygen()
    print_pq_key(f"{name} Initial", pq_priv, pq_pub)
    spk_pub_bytes = spk_vk.encode(nacl.encoding.RawEncoder())
    spk_signature = ik_sk.sign(spk_pub_bytes).signature
    print(f"{name} SPK signature by IK: {spk_signature.hex()} ({len(spk_signature)} bytes)\n")
    return dict(
        IK_sk=ik_sk, IK_vk=ik_vk, SPK_sk=spk_sk, SPK_vk=spk_vk,
        OPK_sk=opk_sk, OPK_vk=opk_vk, SPK_sig=spk_signature,
        FrodoKEM=pqkem, PQKEM_pub=pq_pub, PQKEM_priv=pq_priv
    )

# == (Hybrid) X3DH/PQXDH SESSION SETUP ==
def session_setup(alice_b, bob_b):
    try:
        bob_b['IK_vk'].verify(bob_b['SPK_vk'].encode(nacl.encoding.RawEncoder()), bob_b['SPK_sig'])
        print("Bob's signed prekey is VALID.\n")
    except Exception as e:
        print("Bob's signed prekey is INVALID!\n", e)
        sys.exit(1)
    # Ephemeral key for Alice
    eka_sk = nacl.public.PrivateKey.generate()
    eka_vk = eka_sk.public_key
    print_keypair("Alice Ephemeral", eka_sk, eka_vk)
    IK_A_curve = alice_b['IK_sk'].to_curve25519_private_key()
    IK_B_curve = bob_b['IK_vk'].to_curve25519_public_key()
    SPK_B_curve = bob_b['SPK_vk'].to_curve25519_public_key()
    dh1 = nacl.public.Box(IK_A_curve, SPK_B_curve)._shared_key
    dh2 = nacl.public.Box(eka_sk, IK_B_curve)._shared_key
    dh3 = nacl.public.Box(eka_sk, SPK_B_curve)._shared_key

    pqkem = alice_b['FrodoKEM']
    ct, pq_shared = pqkem.kem_encaps(bob_b['PQKEM_pub'])
    print_key("FrodoKEM Ciphertext", ct)
    print(f"\nFrodoKEM Ciphertext size: {len(ct)} bytes\n")
    print_key("FrodoKEM Shared Secret", pq_shared)
    print("\n")
    premaster_secret = dh1 + dh2 + dh3 + pq_shared
    salt = bytes(32)
    info = b"PQXDH-frodokem"
    ms = hkdf(salt, premaster_secret, info, 64)
    root_key_a = ms[:32]
    send_chain_a = ms[32:]
    print_key("\nAlice Root Key", root_key_a)
    print_key("Alice Send Chain Key", send_chain_a)
    print("\n")

    # Bob side
    pqkem = bob_b['FrodoKEM']
    pq_shared_b = pqkem.kem_decaps(bob_b['PQKEM_priv'], ct)
    IK_B_curve_sk = bob_b['IK_sk'].to_curve25519_private_key()
    SPK_B_curve_sk = bob_b['SPK_sk'].to_curve25519_private_key()
    EK_A_vk = eka_vk
    IK_A_curve_vk = alice_b['IK_vk'].to_curve25519_public_key()
    dh1_b = nacl.public.Box(SPK_B_curve_sk, IK_A_curve_vk)._shared_key
    dh2_b = nacl.public.Box(IK_B_curve_sk, EK_A_vk)._shared_key
    dh3_b = nacl.public.Box(SPK_B_curve_sk, EK_A_vk)._shared_key
    premaster_secret_b = dh1_b + dh2_b + dh3_b + pq_shared_b
    ms_b = hkdf(salt, premaster_secret_b, info, 64)
    root_key_b = ms_b[:32]
    recv_chain_b = ms_b[32:]
    print_key("\nBob Root Key", root_key_b)
    print_key("Bob Receive Chain Key", recv_chain_b)
    print("\n")

    AD = alice_b['IK_vk'].encode(nacl.encoding.RawEncoder()) + bob_b['IK_vk'].encode(nacl.encoding.RawEncoder())
    return {
        "eka_sk": eka_sk, "eka_vk": eka_vk,
        "root_key_a": root_key_a, "send_chain_a": send_chain_a,
        "root_key_b": root_key_b, "recv_chain_b": recv_chain_b,
        "AD": AD
    }

# == HYBRID DOUBLE RATCHET ==
class HybridDoubleRatchet:
    def __init__(self, root_key, DHs_priv, DHr_pub, PQs_priv_pub, PQr_pub, send_chain=None, recv_chain=None):
        self.root_key = root_key
        self.DHs = DHs_priv
        self.DHs_pub = DHs_priv.public_key
        self.DHr_pub = DHr_pub
        self.PQs_priv, self.PQs_pub = PQs_priv_pub # tuple (priv, pub)
        self.PQr_pub = PQr_pub
        self.send_chain = send_chain
        self.recv_chain = recv_chain
        self.pqkem = FrodoKEM('FrodoKEM-640-AES')

    def ratchet_send(self, their_dh_pub, their_pq_pub):
        # -- DH Phase --
        self.DHs = nacl.public.PrivateKey.generate()
        self.DHs_pub = self.DHs.public_key
        # -- PQ Phase --
        PQs_pub, PQs_priv = self.pqkem.kem_keygen()
        self.PQs_pub = PQs_pub
        self.PQs_priv = PQs_priv
        ct, pq_shared = self.pqkem.kem_encaps(their_pq_pub)
        print_keypair("New DH Ratchet ", self.DHs, self.DHs_pub)
        print_pq_key("New FrodoKEM Ratchet", PQs_priv, PQs_pub)
        print_key("FrodoKEM Ciphertext", ct)
        print_key("FrodoKEM Shared Secret", pq_shared)
        print(f"FrodoKEM pub/priv size: {len(PQs_pub)}/{len(PQs_priv)}\n")
        dh_shared = nacl.public.Box(self.DHs, their_dh_pub)._shared_key
        print_key("DH Shared Secret", dh_shared)
        hybrid_shared = dh_shared + pq_shared
        kdfmat = hkdf(self.root_key, hybrid_shared, b'HybridRatchetStep', 64)
        self.root_key = kdfmat[:32]
        self.send_chain = kdfmat[32:]
        print_key("Updated Root Key", self.root_key)
        print_key("Updated Send Chain Key", self.send_chain)
        return {
            'dh_pub': self.DHs_pub.encode(nacl.encoding.RawEncoder()),
            'pq_pub': PQs_pub,
            'pq_ct': ct
        }

    def ratchet_recv(self, their_dh_pub, their_pq_pub, pq_ct):
        self.DHr_pub = nacl.public.PublicKey(their_dh_pub)
        self.PQr_pub = their_pq_pub
        pq_shared = self.pqkem.kem_decaps(self.PQs_priv, pq_ct)
        print_pq_key("FrodoKEM Recv (Our priv, Their pub)", self.PQs_priv, their_pq_pub)
        print_key("FrodoKEM Received Ciphertext", pq_ct)
        print_key("FrodoKEM Decapsulated", pq_shared)
        dh_shared = nacl.public.Box(self.DHs, self.DHr_pub)._shared_key
        print_key("DH Shared Recv", dh_shared)
        hybrid_shared = dh_shared + pq_shared
        kdfmat = hkdf(self.root_key, hybrid_shared, b'HybridRatchetStep', 64)
        self.root_key = kdfmat[:32]
        self.recv_chain = kdfmat[32:]
        print_key("Updated Root Key", self.root_key)
        print_key("Updated Recv Chain Key", self.recv_chain)
        # Update FrodoKEM ratchet keypair for next receive step
        PQs_pub, PQs_priv = self.pqkem.kem_keygen()
        self.PQs_pub = PQs_pub
        self.PQs_priv = PQs_priv
        print_pq_key("Next FrodoKEM Ratchet", PQs_priv, PQs_pub)
        print(f"FrodoKEM pub/priv size: {len(PQs_pub)}/{len(PQs_priv)}\n")

    def encrypt(self, plaintext, AD):
        print("\n=== ENCRYPT (SENDING a Ratchet Step) ===")
        header = self.ratchet_send(self.DHr_pub, self.PQr_pub)
        mk = hkdf(self.send_chain, b"MessageKey", b"SignalMessageMK", 32)
        print_key("Message Key (MK/Encrypt)", mk)
        self.send_chain = hkdf(self.send_chain, b"ChainKey", b"SignalChainK", 32)
        nonce = os.urandom(12)
        ct = AESGCM(mk).encrypt(nonce, plaintext, AD)
        print(f"Encrypting message: {plaintext} with Message Key: {mk.hex()}")
        print(f"Ciphertext (hex): {ct.hex()}\n")
        return {
            'dh_pub': header['dh_pub'],
            'pq_pub': header['pq_pub'],
            'pq_ct': header['pq_ct'],
            'nonce': nonce,
            'ct': ct
        }

    def decrypt(self, msg, AD):
        print("\n=== DECRYPT (RECEIVING a Ratchet Step) ===")
        their_pub = nacl.public.PublicKey(msg['dh_pub'])
        if their_pub != self.DHr_pub:
            self.ratchet_recv(
                msg['dh_pub'], msg['pq_pub'], msg['pq_ct']
            )
        mk = hkdf(self.recv_chain, b"MessageKey", b"SignalMessageMK", 32)
        print_key("Message Key (MK/Decrypt)", mk)
        self.recv_chain = hkdf(self.recv_chain, b"ChainKey", b"SignalChainK", 32)
        pt = AESGCM(mk).decrypt(msg['nonce'], msg['ct'], AD)
        print(f"Decrypting ciphertext: {msg['ct'].hex()} with Message Key: {mk.hex()}")
        print(f"Decrypted message: {pt}\n")
        return pt
def test_hkdf():
    """Test that hkdf produces consistent output for known input."""
    salt = b"salt"
    ikm = b"input keying material"
    info = b"info"
    length = 32
    # The correct expected output for the HKDF function
    expected_output = bytes.fromhex('55e906cde65145a29218620e9e34b7fcdae07a38258f17cc9f16cbe6b2ed5ba6')
    result = hkdf(salt, ikm, info, length)
    assert result == expected_output, f"HKDF output is incorrect. Got {result.hex()}, expected {expected_output.hex()}"
    print("Functional Test: HKDF passed.")

def test_generate_prekey_bundle():
    """Test that prekey bundles are generated correctly."""
    alice_b = generate_prekey_bundle("Alice")
    assert 'IK_sk' in alice_b and 'IK_vk' in alice_b, "Identity key pair missing"
    assert 'SPK_sk' in alice_b and 'SPK_vk' in alice_b, "Signed prekey pair missing"
    assert 'PQKEM_pub' in alice_b and 'PQKEM_priv' in alice_b, "PQ key pair missing"
    assert 'SPK_sig' in alice_b, "SPK signature missing"
    try:
        spk_pub_bytes = alice_b['SPK_vk'].encode(nacl.encoding.RawEncoder())
        alice_b['IK_vk'].verify(spk_pub_bytes, alice_b['SPK_sig'])
        print("Functional Test: Prekey bundle generation passed (signature valid).")
    except Exception as e:
        assert False, f"Signature verification failed: {e}"

def test_session_setup():
    """Test that the session setup results in identical root keys for both parties."""
    alice_b = generate_prekey_bundle("Alice")
    bob_b = generate_prekey_bundle("Bob")
    sess_out = session_setup(alice_b, bob_b)
    assert sess_out['root_key_a'] == sess_out['root_key_b'], "Root keys do not match after session setup"
    print("Functional Test: Session setup passed (root keys match).")

def test_double_ratchet_flow():
    """Test a full double ratchet message exchange."""
    # Setup
    alice_b = generate_prekey_bundle("Alice")
    bob_b = generate_prekey_bundle("Bob")
    sess_out = session_setup(alice_b, bob_b)

    alice_initial_dh = nacl.public.PrivateKey.generate()
    bob_initial_dh = nacl.public.PrivateKey.generate()
    pqkem = alice_b['FrodoKEM']
    alice_pq_pub, alice_pq_priv = pqkem.kem_keygen()
    bob_pq_pub, bob_pq_priv = pqkem.kem_keygen()

    alice = HybridDoubleRatchet(
        sess_out['root_key_a'],
        alice_initial_dh, bob_initial_dh.public_key,
        (alice_pq_priv, alice_pq_pub), bob_pq_pub,
        send_chain=sess_out['send_chain_a']
    )
    bob = HybridDoubleRatchet(
        sess_out['root_key_b'],
        bob_initial_dh, alice_initial_dh.public_key,
        (bob_pq_priv, bob_pq_pub), alice_pq_pub,
        recv_chain=sess_out['recv_chain_b']
    )

    # Test Message 1 (Alice -> Bob)
    msg1_plaintext = b"Hello Bob!"
    msg1_ciphertext = alice.encrypt(msg1_plaintext, sess_out['AD'])
    decrypted_msg1 = bob.decrypt(msg1_ciphertext, sess_out['AD'])
    assert decrypted_msg1 == msg1_plaintext, "Message 1 failed to decrypt correctly"
    
    # Test Message 2 (Bob -> Alice)
    msg2_plaintext = b"Hi Alice, how are you?"
    msg2_ciphertext = bob.encrypt(msg2_plaintext, sess_out['AD'])
    decrypted_msg2 = alice.decrypt(msg2_ciphertext, sess_out['AD'])
    assert decrypted_msg2 == msg2_plaintext, "Message 2 failed to decrypt correctly"

    # Test Message 3 (Alice -> Bob)
    msg3_plaintext = b"I'm great, thanks!"
    msg3_ciphertext = alice.encrypt(msg3_plaintext, sess_out['AD'])
    decrypted_msg3 = bob.decrypt(msg3_ciphertext, sess_out['AD'])
    assert decrypted_msg3 == msg3_plaintext, "Message 3 failed to decrypt correctly"

    print("Functional Test: Double Ratchet flow passed (all messages decrypted correctly).")


def run_tests():
    """Orchestrates all functional tests."""
    print("--- Running Functional Tests ---")
    try:
        test_hkdf()
        test_generate_prekey_bundle()
        test_session_setup()
        test_double_ratchet_flow()
        print("\n--- All functional tests passed successfully! ---\n")
    except AssertionError as e:
        print(f"\n--- A functional test FAILED: {e} ---")
        sys.exit(1)


# == MAIN DEMO WITH BENCHMARKING ==
def benchmark(iterations):
    keygen_times = []
    keygen_memories = []
    session_times = []
    session_memories = []
    encdec_times = []
    encdec_memories = []
    
    messages = [
        b"Alice: Hi Bob",
        b"Bob: Hi Alice",
        b"Alice: How are you? Hope you are doing well!",
        b"Bob: Yeah I am fine! What about you",
        b"Alice: Yeah I am doing good",
        b"Bob: Nice Nice"
    ]


    for i in range(iterations):
        print(f"Iteration {i+1}/{iterations}")
        # Key Generation
        tracemalloc.start()
        t0 = time.perf_counter()
        alice_b = generate_prekey_bundle("Alice")
        bob_b = generate_prekey_bundle("Bob")
        t1 = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        keygen_times.append(t1 - t0)
        keygen_memories.append(peak)

        # Session Setup
        tracemalloc.start()
        t2 = time.perf_counter()
        sess_out = session_setup(alice_b, bob_b)
        t3 = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        session_times.append(t3 - t2)
        session_memories.append(peak)

        # Setup ratchets for Alice and Bob like in your main
        alice_initial_dh = nacl.public.PrivateKey.generate()
        bob_initial_dh = nacl.public.PrivateKey.generate()
        pqkem = alice_b['FrodoKEM']
        alice_pq_pub, alice_pq_priv = pqkem.kem_keygen()
        bob_pq_pub, bob_pq_priv = pqkem.kem_keygen()

        alice = HybridDoubleRatchet(
            sess_out['root_key_a'],
            alice_initial_dh, bob_initial_dh.public_key,
            (alice_pq_priv, alice_pq_pub), bob_pq_pub,
            send_chain=sess_out['send_chain_a']
        )
        bob = HybridDoubleRatchet(
            sess_out['root_key_b'],
            bob_initial_dh, alice_initial_dh.public_key,
            (bob_pq_priv, bob_pq_pub), alice_pq_pub,
            recv_chain=sess_out['recv_chain_b']
        )


        # Encryption+Decryption timed together for all messages in the sequence
        tracemalloc.start()
        t_encdec_start = time.perf_counter()

        for i_msg in range(0, len(messages), 2):
            m1 = alice.encrypt(messages[i_msg], sess_out['AD'])
            plaintext1 = bob.decrypt(m1, sess_out['AD'])

            m2 = bob.encrypt(messages[i_msg+1], sess_out['AD'])
            plaintext2 = alice.decrypt(m2, sess_out['AD'])

        t_encdec_end = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        encdec_times.append(t_encdec_end - t_encdec_start)
        encdec_memories.append(peak)

    # Calculate statistics for all phases
    def stats(data):
        return {
            'mean': statistics.mean(data),
            'max': max(data),
            'min': min(data),
            'stddev': statistics.stdev(data) if len(data) > 1 else 0.0
        }

    keygen_stats = stats(keygen_times)
    keygen_mem_stats = stats(keygen_memories)
    session_stats = stats(session_times)
    session_mem_stats = stats(session_memories)
    encdec_stats = stats(encdec_times)
    encdec_mem_stats = stats(encdec_memories)

    # Prepare CSV output data
    rows = [
        ["Phase", "Time Mean (s)", "Time Max (s)", "Time Min (s)", "Time Stddev (s)", "Memory Mean (bytes)", "Memory Max (bytes)", "Memory Min (bytes)", "Memory Stddev (bytes)"],
        ["Key Generation",
         f"{keygen_stats['mean']:.6f}", f"{keygen_stats['max']:.6f}", f"{keygen_stats['min']:.6f}", f"{keygen_stats['stddev']:.6f}",
         f"{keygen_mem_stats['mean']}", f"{keygen_mem_stats['max']}", f"{keygen_mem_stats['min']}", f"{keygen_mem_stats['stddev']:.2f}"],
        ["Session Setup",
         f"{session_stats['mean']:.6f}", f"{session_stats['max']:.6f}", f"{session_stats['min']:.6f}", f"{session_stats['stddev']:.6f}",
         f"{session_mem_stats['mean']}", f"{session_mem_stats['max']}", f"{session_mem_stats['min']}", f"{session_mem_stats['stddev']:.2f}"],
        ["Encryption+Decryption",
         f"{encdec_stats['mean']:.6f}", f"{encdec_stats['max']:.6f}", f"{encdec_stats['min']:.6f}", f"{encdec_stats['stddev']:.6f}",
         f"{encdec_mem_stats['mean']}", f"{encdec_mem_stats['max']}", f"{encdec_mem_stats['min']}", f"{encdec_mem_stats['stddev']:.2f}"],
    ]

    # Save CSV to same directory as this file
    filename = "pq_x3dh_benchmark_results.csv"
    with open(filename, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"\nBenchmarking results saved to {filename}")

if __name__ == "__main__":
    import nacl.public # needed for DH key generation in runner
    run_tests()
    benchmark(2)
