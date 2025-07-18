// xonlypubkey.move
// Copyright (C) 2025  ZHANG, HENGMING
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
/// Module: nip_01_addr
/// Name: xonlypubkey
/// Description: X only public key module on Aptos blockchain
*/
module nip_01_addr::xonlypubkey {
    use std::vector;
    use std::hash;
    use aptos_std::from_bcs;

    // signature scheme id for aptos_std::single_key
    const SIGNATURE_SCHEME_ID: u8 = 2;

    // error codes
    const ErrorWrongAptosAuthKey: u64 = 1000;
    const ErrorWrongAptosAddress: u64 = 1001;

    // derive an aptos authentication key from an x only public key
    fun x_only_public_key_to_authentication_key(x_only_public_key: vector<u8>): vector<u8> {
        // add custom signature scheme id, for lacking implementation of schnorr signature on aptos blockchain
        vector::push_back(&mut x_only_public_key, SIGNATURE_SCHEME_ID);
        // authentication key (computed via a sha3 hash of `(public key bytes | scheme as u8)`).
        hash::sha3_256(x_only_public_key)
    }

    /// derive an aptos address from an aptos authentication key from an x-only public key
    public fun derive_aptos_address_from_x_only_pubkey(x_only_public_key: vector<u8>): address {
        let auth_key = x_only_public_key_to_authentication_key(x_only_public_key);
        let aptos_address = from_bcs::to_address(auth_key);
        aptos_address
    }

    #[test]
    fun test_x_only_public_key_to_authentication_key_success() {
        let x_only_public_key = x"cddcc4a1d4a94d627e7808f904d0477cf16ae9d4fafa1eb883ab7a498bdda777";
        let expected_auth_key = x"71287783b142f146a1268fecf8e11fb805531ad957a4e2c30f284784f8ccf9de";
        let auth_key = x_only_public_key_to_authentication_key(x_only_public_key);
        assert!(auth_key == expected_auth_key, ErrorWrongAptosAuthKey);
    }

    #[test]
    fun test_derive_aptos_address_from_x_only_pubkey_success() {
        let x_only_public_key = x"cddcc4a1d4a94d627e7808f904d0477cf16ae9d4fafa1eb883ab7a498bdda777";
        let expected_address = @0x71287783b142f146a1268fecf8e11fb805531ad957a4e2c30f284784f8ccf9de;
        let aptos_address = derive_aptos_address_from_x_only_pubkey(x_only_public_key);
        assert!(aptos_address == expected_address, ErrorWrongAptosAddress);
    }
}
