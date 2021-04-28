/*******************************************************************************

    The class that defines the BOASodium.

    Copyright:
        Copyright (c) 2020-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        ISC License. See LICENSE for details.

*******************************************************************************/

import { IBOASodium } from "boa-sodium-base-ts";

/**
 * @ignore
 */
import _sodium_module = require('libsodium-wrappers-sumo');

export class BOASodium implements IBOASodium
{
    public crypto_core_ed25519_BYTES: number = 0;
    public crypto_core_ed25519_UNIFORMBYTES: number = 0;
    public crypto_core_ed25519_SCALARBYTES: number = 0;
    public crypto_core_ed25519_NONREDUCEDSCALARBYTES: number = 0;
    public crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number = 0;
    public crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number = 0;

    /**
     * @ignore
     */
    private static _sodium: any = null;

    public init (): Promise<void>
    {
        return new Promise<void>((resolve, reject) =>
        {
            if (BOASodium._sodium !== null)
            {
                this.initVariable();
                return resolve();
            }

            _sodium_module.ready
                .then(() =>
                {
                    BOASodium._sodium = _sodium_module;
                    this.initVariable();
                    return resolve();
                })
                .catch((err: any) =>
                {
                    return reject(err);
                });
        });
    }

    private initVariable ()
    {
        this.crypto_core_ed25519_BYTES = BOASodium._sodium.crypto_core_ed25519_BYTES;
        this.crypto_core_ed25519_UNIFORMBYTES = BOASodium._sodium.crypto_core_ed25519_UNIFORMBYTES;
        this.crypto_core_ed25519_SCALARBYTES = BOASodium._sodium.crypto_core_ed25519_SCALARBYTES;
        this.crypto_core_ed25519_NONREDUCEDSCALARBYTES = BOASodium._sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES;
        this.crypto_aead_xchacha20poly1305_ietf_KEYBYTES = BOASodium._sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        this.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = BOASodium._sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    }

    public crypto_core_ed25519_random (): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_random();
    }

    public crypto_core_ed25519_from_uniform (r: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_from_uniform(r);
    }
    public crypto_core_ed25519_add (p: Uint8Array, q: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_add(p, q);
    }

    public crypto_core_ed25519_sub (p: Uint8Array, q: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_sub(p, q);
    }

    public crypto_core_ed25519_is_valid_point (p: Uint8Array): boolean
    {
        return BOASodium._sodium.crypto_core_ed25519_is_valid_point(p);
    }

    public crypto_core_ed25519_scalar_random (): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_random();
    }

    public crypto_core_ed25519_scalar_add (x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_add(x, y);
    }

    public crypto_core_ed25519_scalar_sub (x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_sub(x, y);
    }

    public crypto_core_ed25519_scalar_negate (s: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_negate(s);
    }

    public crypto_core_ed25519_scalar_complement (s: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_complement(s);
    }

    public crypto_core_ed25519_scalar_mul (x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_mul(x, y);
    }

    public crypto_core_ed25519_scalar_invert (s: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_invert(s);
    }

    public crypto_core_ed25519_scalar_reduce (s: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_core_ed25519_scalar_reduce(s);
    }

    public crypto_scalarmult_ed25519 (n: Uint8Array, p: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_scalarmult_ed25519(n, p);
    }

    public crypto_scalarmult_ed25519_base (n: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_scalarmult_ed25519_base(n);
    }

    public crypto_scalarmult_ed25519_base_noclamp (n: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_scalarmult_ed25519_base_noclamp(n);
    }

    public crypto_scalarmult_ed25519_noclamp (n: Uint8Array, p: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_scalarmult_ed25519_noclamp(n, p);
    }

    public randombytes_buf (n: number): Uint8Array
    {
        return BOASodium._sodium.randombytes_buf(n);
    }

    public crypto_generichash (hash_length: number, message: Uint8Array, key?: Uint8Array): Uint8Array
    {
        return BOASodium._sodium.crypto_generichash(hash_length, message, key);
    }

    public crypto_aead_chacha20poly1305_ietf_keygen (): Uint8Array
    {
        return BOASodium._sodium.crypto_aead_chacha20poly1305_ietf_keygen();
    }

    public crypto_aead_xchacha20poly1305_ietf_encrypt (
        message: Uint8Array,
        additional_data: Uint8Array | null,
        secret_nonce: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array
    {
        return BOASodium._sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, additional_data, secret_nonce, public_nonce, key);
    }

    public crypto_aead_xchacha20poly1305_ietf_decrypt (
        secret_nonce: Uint8Array | null,
        ciphertext: Uint8Array,
        additional_data: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array
    {
        return BOASodium._sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(secret_nonce, ciphertext, additional_data, public_nonce, key);
    }
}
