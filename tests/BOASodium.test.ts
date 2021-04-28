/*******************************************************************************

    Test for libsodium ported to TypeScript

    Copyright:
        Copyright (c) 2020 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import { BOASodium } from '../lib';

import * as assert from 'assert';
import * as fs from 'fs';

describe ('Test crypto_core', () =>
{
    let sodium: BOASodium;
    before('Wait for the package libsodium to finish loading', () =>
    {
        sodium = new BOASodium();
        return sodium.init();
    });

    let sample_crypto_core_ed25519_random:Array<any>
        = JSON.parse(fs.readFileSync('tests/data/Sample.crypto_core_ed25519_random.json', 'utf-8'));
    let sample_crypto_core_ed25519_add_sub:Array<any>
        = JSON.parse(fs.readFileSync('tests/data/Sample.crypto_core_ed25519_add_sub.json', 'utf-8'));
    let sample_crypto_core_ed25519_scalar_reduce:Array<any>
        = JSON.parse(fs.readFileSync('tests/data/Sample.crypto_core_ed25519_scalar_reduce.json', 'utf-8'));
    let sample_crypto_core_ed25519_scalar_xxxxx:Array<any>
        = JSON.parse(fs.readFileSync('tests/data/Sample.crypto_core_ed25519_scalar_xxxxx.json', 'utf-8'));

    it ('Test variable', () =>
    {
        assert.strictEqual(sodium.crypto_core_ed25519_BYTES, 32);
        assert.strictEqual(sodium.crypto_core_ed25519_UNIFORMBYTES, 32);
        assert.strictEqual(sodium.crypto_core_ed25519_SCALARBYTES, 32);
        assert.strictEqual(sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES, 64);
        assert.strictEqual(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 32);
        assert.strictEqual(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 24);
    });

    it ('Test crypto_core_ed25519_random', () =>
    {
        for (let i = 0; i < 20; i++)
        {
            let p = sodium.crypto_core_ed25519_random();
            assert.ok(sodium.crypto_core_ed25519_is_valid_point(p));
        }
    });

    it ('Test crypto_core_ed25519_from_uniform', () =>
    {
        sample_crypto_core_ed25519_random.forEach((m) =>
        {
            let random = Buffer.from(m.random, "hex");
            let res = Buffer.from(sodium.crypto_core_ed25519_from_uniform(random));
            assert.deepStrictEqual(res.toString("hex"), m.crypto_core_ed25519_from_uniform);
        });
    });

    it ('Test crypto_core_ed25519_add', () =>
    {
        sample_crypto_core_ed25519_add_sub.forEach((m) =>
        {
            let p = Buffer.from(m.p, "hex");
            let q = Buffer.from(m.q, "hex");
            let add = Buffer.from(sodium.crypto_core_ed25519_add(p, q));
            assert.deepStrictEqual(add.toString("hex"), m.add);
        });
    });

    it ('Test crypto_core_ed25519_sub', () =>
    {
        sample_crypto_core_ed25519_add_sub.forEach((m) =>
        {
            let p = Buffer.from(m.p, "hex");
            let q = Buffer.from(m.q, "hex");
            let sub = Buffer.from(sodium.crypto_core_ed25519_sub(p, q));
            assert.deepStrictEqual(sub.toString("hex"), m.sub);
        });
    });

    it ('Test crypto_core_ed25519_is_valid_point', () =>
    {
        let valid = Buffer.from("ab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511b", "hex").reverse();
        assert.ok(sodium.crypto_core_ed25519_is_valid_point(valid));

        let invalid = Buffer.from("ab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c", "hex").reverse();
        assert.ok(!sodium.crypto_core_ed25519_is_valid_point(invalid));

        let invalid2 = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex").reverse();
        assert.ok(!sodium.crypto_core_ed25519_is_valid_point(invalid2));
    });

    it ('Test crypto_core_ed25519_scalar_reduce', () =>
    {
        sample_crypto_core_ed25519_scalar_reduce.forEach((elem) =>
        {
            let hash = Buffer.from(elem.hash, "hex");
            let result = Buffer.from(sodium.crypto_core_ed25519_scalar_reduce(hash));
            assert.deepStrictEqual(result.toString("hex"), elem.result);
        });
    });

    it ('Test crypto_core_ed25519_scalar_add', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            let y = Buffer.from(elem.y, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_add(x, y)).toString("hex"), elem.add);
        });
    });

    it ('Test crypto_core_ed25519_scalar_sub', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            let y = Buffer.from(elem.y, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_sub(x, y)).toString("hex"), elem.sub);
        });
    });

    it ('Test crypto_core_ed25519_scalar_mul', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            let y = Buffer.from(elem.y, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_mul(x, y)).toString("hex"), elem.mul);
        });
    });

    it ('Test crypto_core_ed25519_scalar_negate', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_negate(x)).toString("hex"), elem.negate_x);
        });
    });

    it ('Test crypto_core_ed25519_scalar_invert', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_invert(x)).toString("hex"), elem.invert_x);
        });
    });

    it ('Test crypto_core_ed25519_scalar_complement', () =>
    {
        sample_crypto_core_ed25519_scalar_xxxxx.forEach((elem) =>
        {
            let x = Buffer.from(elem.x, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_core_ed25519_scalar_complement(x)).toString("hex"), elem.complement_x);
        });
    });
});

describe ('Test crypto_scalarmult', () =>
{
    let sodium: BOASodium;
    before('Wait for the package libsodium to finish loading', () =>
    {
        sodium = new BOASodium();
        return sodium.init();
    });

    let sample_crypto_scalarmult_ed25519_xxxxx:Array<any>
        = JSON.parse(fs.readFileSync('tests/data/Sample.crypto_scalarmult_ed25519_xxxxx.json', 'utf-8'));

    it ('Test crypto_scalarmult_ed25519_base', () =>
    {
        sample_crypto_scalarmult_ed25519_xxxxx.forEach((elem) =>
        {
            let s = Buffer.from(elem.s, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_scalarmult_ed25519_base(s)).toString("hex"), elem.scalarmult_ed25519_base);
        });
    });

    it ('Test crypto_scalarmult_ed25519_base_noclamp', () =>
    {
        sample_crypto_scalarmult_ed25519_xxxxx.forEach((elem) =>
        {
            let s = Buffer.from(elem.s, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_scalarmult_ed25519_base_noclamp(s)).toString("hex"), elem.scalarmult_ed25519_base_noclamp);
        });
    });

    it ('Test crypto_scalarmult_ed25519', () =>
    {
        sample_crypto_scalarmult_ed25519_xxxxx.forEach((elem) =>
        {
            let s = Buffer.from(elem.s, "hex");
            let p = Buffer.from(elem.p, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_scalarmult_ed25519(s, p)).toString("hex"), elem.scalarmult_ed25519);
        });
    });

    it ('Test crypto_scalarmult_ed25519_noclamp', () =>
    {
        sample_crypto_scalarmult_ed25519_xxxxx.forEach((elem) =>
        {
            let s = Buffer.from(elem.s, "hex");
            let p = Buffer.from(elem.p, "hex");
            assert.deepStrictEqual(Buffer.from(sodium.crypto_scalarmult_ed25519_noclamp(s, p)).toString("hex"), elem.scalarmult_ed25519_noclamp);
        });
    });
});
