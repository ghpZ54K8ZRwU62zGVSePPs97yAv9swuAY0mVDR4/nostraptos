// event_test.move.
// Copyright (C) 2025  ZHANG, HENGMING
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
/// Module: nip_01_addr
/// Name: event_test
/// Description: tests NIP-01 event units
*/
#[test_only]
module nip_01_addr::event_test {
    use std::string;
    use aptos_std::ordered_map;
    use nip_01_addr::event;

    // Error codes starting from 1000
    const ErrorKeyNotFoundUserMetadataName: u64 = 1000;
    const ErrorKeyNotFoundUserMetadataAbout: u64 = 1001;
    const ErrorKeyNotFoundUserMetadataPicture: u64 = 1002;

    #[test]
    fun test_create_ordered_map_from_content_success() {
        let content = string::utf8(b"{\"name\":\"ZHANG, HENGMING\",\"about\":\"\",\"picture\":\"\",\"website\":\"\",}");
        let map = event::create_ordered_map_from_content(content);
        assert!(ordered_map::contains(&map, &event::name_key_user_metadata_string()), ErrorKeyNotFoundUserMetadataName);
        assert!(ordered_map::contains(&map, &event::about_key_user_metadata_string()), ErrorKeyNotFoundUserMetadataAbout);
        assert!(ordered_map::contains(&map, &event::picture_key_user_metadata_string()), ErrorKeyNotFoundUserMetadataPicture);
    }

}
