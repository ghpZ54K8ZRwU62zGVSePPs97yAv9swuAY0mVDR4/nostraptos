// event.move, based on RoochNetwork's Move base smart contract at https://github.com/rooch-network/rooch/blob/main/examples/nostr/sources/event.move.
// Copyright (C) 2025  ZHANG, HENGMING
// SPDX-License-Identifier: AGPL-3.0-or-later

// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

/*
/// Module: nip_01_addr
/// Name: event
/// Description: implements NIP-01 event structure
*/
module nip_01_addr::event {
    use std::vector;
    use std::string::{Self, String};
    use std::option::{Self, Option};
    use std::signer;
    use std::hash;
    use aptos_framework::object::{Self, Object};
    use nip_01_addr::hex;
    use aptos_framework::timestamp;
    use aptos_framework::event;
    use nip_01_addr::json;
    use aptos_std::string_utils;
    use nip_01_addr::ecdsa_k1;
    use nip_01_addr::inner;

    // Kind of the event
    const EVENT_KIND_USER_METADATA: u16 = 0;

    // Error codes starting from 1000
    const ErrorMalformedId: u64 = 1000;
    const ErrorSignatureValidationFailure: u64 = 1001;
    const ErrorMalformedPublicKey: u64 = 1002;
    const ErrorUtf8Encoding: u64 = 1003;
    const ErrorMalformedSignature: u64 = 1004;
    const ErrorEventStoreNotExist: u64 = 1005;
    const ErrorSigAlreadyExists: u64 = 1006;
    const ErrorInvalidUserMetadata: u64 = 1007;

    /// EventStore
    struct EventStore has key, copy, drop {
        events: vector<Event>
    }

    /// Event
    struct Event has key, store, copy, drop {
        id: vector<u8>, // 32-bytes lowercase hex-encoded sha256 of the serialized event data
        pubkey: vector<u8>, // 32-bytes lowercase hex-encoded public key of the event creator
        created_at: u64, // unix timestamp in seconds
        kind: u16, // integer between 0 and 65535
        tags: vector<vector<String>>, // arbitrary string
        content: String, // arbitrary string
        sig: Option<vector<u8>> // 64-bytes lowercase hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field
    }

    #[event]
    /// Event create notification for Move events
    struct NostrEventCreatedEvent has copy, store, drop {
        object_address: address
    }

    #[event]
    /// Event update notification for Move events
    struct NostrEventUpdatedEvent has copy, store, drop {
        object_address: address
    }

    #[event]
    /// Event save notification for Move events
    struct NostrEventSavedEvent has copy, store, drop {
        object_address: address
    }

    /// UserMetadata field as stringified JSON object, when the Event kind is equal to 0
    struct UserMetadata has copy, drop {
        name: String,
        about: String,
        picture: String
    }

    /// Serialize to byte arrays, which could be sha256 hashed and hex-encoded with lowercase to 32 byte arrays
    fun serialize(pubkey: String, created_at: u64, kind: u16, tags: vector<vector<String>>, content: String): vector<u8> {
        let serialized = string::utf8(b"");
        let left_sb = string::utf8(b"[");
        let right_sb = string::utf8(b"]");
        let double_qm = string::utf8(b"\"");
        let coma = string::utf8(b",");

        // version 0, as described in NIP-01
        let version = 0u8;
        let version_str = string_utils::to_string(&version);
        string::append(&mut serialized, left_sb);
        string::append(&mut serialized, version_str);
        string::append(&mut serialized, coma);

        // pubkey
        assert!(string::length(&pubkey) == 64, ErrorMalformedPublicKey);
        string::append(&mut serialized, double_qm);
        string::append(&mut serialized, pubkey);
        string::append(&mut serialized, double_qm);
        string::append(&mut serialized, coma);

        // created_at
        let created_at_str = string_utils::to_string(&created_at);
        string::append(&mut serialized, created_at_str);
        string::append(&mut serialized, coma);

        // kind
        let kind_str = string_utils::to_string(&kind);
        string::append(&mut serialized, kind_str);
        string::append(&mut serialized, coma);

        // tags
        let tags_str = string::utf8(json::to_json(&tags));
        string::append(&mut serialized, tags_str);
        string::append(&mut serialized, coma);

        // content
        string::append(&mut serialized, double_qm);
        string::append(&mut serialized, content);
        string::append(&mut serialized, double_qm);
        string::append(&mut serialized, right_sb);

        // get the serialized string bytes
        let serialized_bytes = string::bytes(&serialized);

        // check UTF-8 encoding
        assert!(string::internal_check_utf8(serialized_bytes), ErrorUtf8Encoding);

        *serialized_bytes
    }

    /// Check signature with public key, id and signature for schnorr
    fun check_signature(id: vector<u8>, x_only_public_key: vector<u8>, signature: vector<u8>) {
        assert!(ecdsa_k1::verify(
            &signature,
            &x_only_public_key,
            &id,
            ecdsa_k1::sha256()
        ), ErrorSignatureValidationFailure);
    }

    /// Check the referenced user metadata from content with UserMetadata struct
    fun check_user_metadata(content: String) {
        // check the content integrity
        let content_json = json::to_json<String>(&content);
        // some bits are stripped for verification
        let dq = inner::doublequote();
        vector::remove_value(&mut content_json, &dq);
        vector::reverse(&mut content_json);
        vector::remove_value(&mut content_json, &dq);
        vector::reverse(&mut content_json);
        let bs = inner::backslash();
        while (vector::contains(&content_json, &bs)) {
            vector::remove_value(&mut content_json, &bs);
        };
        let user_metadata_option = json::from_json_option<UserMetadata>(content_json);
        assert!(option::is_some(&user_metadata_option), ErrorInvalidUserMetadata);
    }

    // Clean the old user metadata when there is a new one from event store object address
    fun clean_user_metadata(event_store_object_address: address) acquires EventStore {
        // borrow event store from the event store object address
        let event_store = borrow_global<EventStore>(event_store_object_address);
        // borrow inner events
        let events = borrow_events(event_store);
        // find the index of the user metadata event
        let (user_metatada_exists, index) = vector::find<Event>(events, |event_ref| {
            let event: &Event = event_ref;
            event.kind == EVENT_KIND_USER_METADATA
        });
        // remove the first occurrence of the user metadata if there's an old user metadata
        if (user_metatada_exists) {
            // borrow mutable event store from the event store object address
            let event_store_mut = borrow_global_mut<EventStore>(event_store_object_address);
            // borrow inner mutable events
            let events_mut = borrow_mut_events(event_store_mut);
            // use remove since the ordering isn't priority
            let removed_event = vector::remove<Event>(events_mut, index);
            // drop the removed event
            drop_event(removed_event);
        };
    }

    /// Create an Event id
    fun create_event_id(pubkey: String, created_at: u64, kind: u16, tags: vector<vector<String>>, content: String): vector<u8> {
        // serialize input to bytes for an Event id
        let serialized = serialize(pubkey, created_at, kind, tags, content);

        // hash with sha256
        let id = hash::sha2_256(serialized);

        // verify the length of the hex bytes to 32 bytes (64 characters)
        assert!(vector::length(&hex::encode(id)) == 64, ErrorMalformedId);

        id
    }

    /// Create an Event for signing
    public fun create_event(x_only_public_key: String, kind: u16, tags: vector<vector<String>>, content: String) acquires EventStore {
        // get now timestamp by seconds
        let created_at = timestamp::now_seconds();

        // create event id
        let id = create_event_id(x_only_public_key, created_at, kind, tags, content);

        // get the hex decoded public key bytes
        let pubkey = hex::decode(*string::bytes(&x_only_public_key));

        // derive a aptos address
        let aptos_address = inner::derive_aptos_address(pubkey);

        // init an empty signature
        let sig = option::none<vector<u8>>();

        // get event store object address
        let event_store_constructor_ref = object::create_object(aptos_address);
        let event_store_object_address = object::address_from_constructor_ref(&event_store_constructor_ref);

        // handle a range of different kinds of an Event
        if (kind == EVENT_KIND_USER_METADATA) {
            check_user_metadata(content);
            // clear past user metadata events from the user with the same aptos address from the public key
            if (object::object_exists<EventStore>(event_store_object_address)) {
                clean_user_metadata(event_store_object_address);
            };
        };

        // save the event for signing to the aptos address mapped to the public key
        let event = Event {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        };
        // init event store if not already
        if (!object::object_exists<EventStore>(event_store_object_address)) {
            init_event_store(aptos_address);
        };
        // borrow mutable event store
        let event_store_mut = borrow_global_mut<EventStore>(event_store_object_address);
        // borrow inner mutable events
        let events_mut = borrow_mut_events(event_store_mut);
        // get the event for signing pushed to the event store's events
        vector::push_back<Event>(events_mut, event);

        // emit a move event nofitication
        let move_event = NostrEventCreatedEvent {
            object_address: event_store_object_address
        };
        event::emit(move_event);
    }

    /// Entry function to create an Event for signing
    public entry fun create_event_entry(x_only_public_key: String, kind: u16, tags: vector<vector<String>>, content: String) acquires EventStore {
        create_event(x_only_public_key, kind, tags, content);
    }

    /// Update a signature under the sig field of an Event
    public fun update_event_signature(caller: &signer, signature: String) acquires EventStore {
        // get the caller's address
        let caller_address = signer::address_of(caller);

        // get event store object address
        let event_store_constructor_ref = object::create_object(caller_address);
        let event_store_object_address = object::address_from_constructor_ref(&event_store_constructor_ref);

        // check the event store object id if it exists
        assert!(object::object_exists<EventStore>(event_store_object_address), ErrorEventStoreNotExist);

        // borrow mutable event store from the event store object address
        let event_store_mut = borrow_global_mut<EventStore>(event_store_object_address);

        // borrow inner mutable events
        let events_mut = borrow_mut_events(event_store_mut);

        // get the last element of event
        let last_event_index = vector::length(events_mut) - 1;

        // get the signature of the last event updated
        let event_mut = vector::borrow_mut(events_mut, last_event_index);

        // flatten the elements
        let (id, pubkey, _created_at, _kind, _tags, _content, sig) = unpack_event(*event_mut);

        // avoid overide signature
        assert!(option::is_none(&sig), ErrorSigAlreadyExists);

        // decode signature with hex
        let update_sig = hex::decode(*string::bytes(&signature));

        // check the signature
        check_signature(id, pubkey, update_sig);

        // update the signature of the sig field of the event
        option::fill<vector<u8>>(&mut event_mut.sig, update_sig);

        // emit a move event nofitication
        let move_event = NostrEventUpdatedEvent {
            object_address: event_store_object_address
        };
        event::emit(move_event);
    }

    /// Entry function to update a signature under sig field of an Event
    public entry fun update_event_signature_entry(signer: &signer, signature: String) acquires EventStore {
        update_event_signature(signer, signature);
    }

    /// Save an Event
    public fun save_event(x_only_public_key: String, created_at: u64, kind: u16, tags: vector<vector<String>>, content: String, signature: String) acquires EventStore {
        // check signature length
        assert!(string::length(&signature) == 128, ErrorMalformedSignature);

        // check public key length
        assert!(string::length(&x_only_public_key) == 64, ErrorMalformedPublicKey);

        // create event id
        let id = create_event_id(x_only_public_key, created_at, kind, tags, content);

        // get the hex decoded public key bytes
        let pubkey = hex::decode(*string::bytes(&x_only_public_key));

        // get the hex decoded signature bytes
        let check_sig = hex::decode(*string::bytes(&signature));

        // check the signature
        check_signature(id, pubkey, check_sig);

        // derive a aptos address
        let aptos_address = inner::derive_aptos_address(pubkey);

        // pass check sig as option to form sig option
        let sig = option::some<vector<u8>>(check_sig);

        // get event store object address
        let event_store_constructor_ref = object::create_object(aptos_address);
        let event_store_object_address = object::address_from_constructor_ref(&event_store_constructor_ref);

        // handle a range of different kinds of an Event
        if (kind == EVENT_KIND_USER_METADATA) {
            check_user_metadata(content);
            // clear past user metadata events from the user with the same aptos address from the public key
            if (object::object_exists<EventStore>(event_store_object_address)) {
                clean_user_metadata(event_store_object_address);
            };
        };

        // save the event to the aptos address mapped to the public key
        let event = Event {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig
        };
        // init event store if not already
        if (!object::object_exists<EventStore>(event_store_object_address)) {
            init_event_store(aptos_address);
        };
        // borrow mutable event store
        let event_store_mut = borrow_global_mut<EventStore>(event_store_object_address);
        // borrow inner mutable events
        let events_mut = borrow_mut_events(event_store_mut);
        // get the event pushed to the event store's events
        vector::push_back<Event>(events_mut, event);

        // emit a move event nofitication
        let move_event = NostrEventSavedEvent {
            object_address: event_store_object_address
        };
        event::emit(move_event);
    }

    /// Entry function to save an Event
    public entry fun save_event_entry(x_only_public_key: String, created_at: u64, kind: u16, tags: vector<vector<String>>, content: String, signature: String) acquires EventStore {
        save_event(x_only_public_key, created_at, kind, tags, content, signature);
    }

    /// drop an event
    fun drop_event(event: Event) {
        let Event {id: _, pubkey: _, created_at: _, kind: _, tags: _, content: _, sig: _} = event;
    }

    public fun unpack_event(event: Event): (vector<u8>, vector<u8>, u64, u16, vector<vector<String>>, String, Option<vector<u8>>) {
        let Event { id, pubkey, created_at, kind, tags, content, sig } = event;
        (id, pubkey, created_at, kind, tags, content, sig)
    }

    fun event_store_object_address(object: Object<EventStore>): address {
        let object_address = object::object_address(&object);
        object_address
    }

    fun init_event_store(caller_address: address) {
        // create an event store object and transfer to the object address
        let empty_event_store = empty_event_store();
        let event_store_constructor_ref = object::create_object(caller_address);
        let event_store_object_signer = object::generate_signer(&event_store_constructor_ref);
        move_to(&event_store_object_signer, empty_event_store);
    }

    fun empty_event_store(): EventStore {
        let event_store = EventStore {
            events: vector::empty<Event>()
        };

        event_store
    }

    fun borrow_events(event_store: &EventStore): &vector<Event> {
        &event_store.events
    }

    fun borrow_mut_events(event_store_mut: &mut EventStore): &mut vector<Event> {
        &mut event_store_mut.events
    }

    /// getter functions for event

    public fun id(event: &Event): vector<u8> {
        event.id
    }

    public fun pubkey(event: &Event): vector<u8> {
        event.pubkey
    }

    public fun created_at(event: &Event): u64 {
        event.created_at
    }

    public fun kind(event: &Event): u16 {
        event.kind
    }

    public fun tags(event: &Event): vector<vector<String>> {
        event.tags
    }

    public fun content(event: &Event): String {
        event.content
    }

    public fun sig(event: &Event): Option<vector<u8>> {
        event.sig
    }

    /// getter functions for event store

    public fun events(event_store: &EventStore): vector<Event> {
        event_store.events
    }
}
