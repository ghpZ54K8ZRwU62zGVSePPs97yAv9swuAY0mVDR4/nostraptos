// xonlypubkey_test.move
// Copyright (C) 2025  ZHANG, HENGMING
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
/// Module: nip_01_addr
/// Name: xonlypubkey_test
/// Description: Tests x only public key module on Aptos blockchain
*/
#[test_only]
module nip_01_addr::xonlypubkey_test {
    use nip_01_addr::xonlypubkey;

    // error codes
    const ErrorWrongAptosAuthKey: u64 = 1000;
    const ErrorWrongAptosAddress: u64 = 1001;

    #[test]
    fun test_x_only_public_key_to_authentication_key_success() {
        let x_only_public_key = x"cddcc4a1d4a94d627e7808f904d0477cf16ae9d4fafa1eb883ab7a498bdda777";
        let expected_auth_key = x"71287783b142f146a1268fecf8e11fb805531ad957a4e2c30f284784f8ccf9de";
        let auth_key = xonlypubkey::x_only_public_key_to_authentication_key(x_only_public_key);
        assert!(auth_key == expected_auth_key, ErrorWrongAptosAuthKey);
    }

    #[test]
    fun test_derive_aptos_address_from_x_only_pubkey_success() {
        let x_only_public_key = x"cddcc4a1d4a94d627e7808f904d0477cf16ae9d4fafa1eb883ab7a498bdda777";
        let expected_address = @0x71287783b142f146a1268fecf8e11fb805531ad957a4e2c30f284784f8ccf9de;
        let aptos_address = xonlypubkey::derive_aptos_address_from_x_only_pubkey(x_only_public_key);
        assert!(aptos_address == expected_address, ErrorWrongAptosAddress);
    }

}
