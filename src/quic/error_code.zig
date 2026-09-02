//! RFC 9000 section 20: transport error codes, and RFC 9114 section 8.1's
//! HTTP/3 codes that travel in the same fields.
//!
//! Two registries, one wire field. A CONNECTION_CLOSE frame of type 0x1c
//! carries a *transport* error code and 0x1d carries an *application* one, and
//! the numbers overlap — `0x0103` is `H3_STREAM_CREATION_ERROR` in the
//! application registry and nothing at all in the transport one. Keeping them
//! in two enums is what stops a `switch` from answering the wrong registry's
//! name, which is the kind of bug that only shows up in someone else's log.

const std = @import("std");

const assert = @import("../assert.zig").assert;

/// Section 20.1. Non-exhaustive: section 20's registry is extensible, and
/// section 22.5 reserves a whole family of GREASE values (`0x1f * N + 0x1b`)
/// that a conforming endpoint must accept without knowing them.
pub const Transport = enum(u62) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    _,

    /// Section 20.1: codes `0x0100` to `0x01ff` carry a TLS alert in their low
    /// octet. Not a member of the enum, because there are 256 of them and they
    /// mean "the handshake failed, here is why" rather than anything this
    /// package decides.
    pub const crypto_error_base: u62 = 0x0100;

    pub fn fromAlert(tls_alert: u8) Transport {
        return @enumFromInt(crypto_error_base + tls_alert);
    }

    /// The TLS alert inside a crypto error, or null for anything else.
    pub fn alert(code: Transport) ?u8 {
        const value = @intFromEnum(code);
        if (value < crypto_error_base or value > crypto_error_base + 0xff) return null;
        return @intCast(value - crypto_error_base);
    }
};

/// RFC 9114 section 8.1. Travels in a CONNECTION_CLOSE frame of type 0x1d, and
/// in RESET_STREAM and STOP_SENDING.
pub const Application = enum(u62) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
    /// RFC 9204 section 6: QPACK's three, which share the registry.
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
    _,
};

/// RFC 9000 section 22.5 and RFC 9114 section 7.2.8: the reserved pattern both
/// registries use, so that an endpoint's handling of unknown values is
/// exercised rather than assumed.
pub fn isReserved(value: u62) bool {
    // `0x1f * N + 0x1b` for non-negative N. Written as the modulus rather than
    // as a loop, which is the same claim without the unbounded search.
    if (value < 0x1b) return false;
    return (value - 0x1b) % 0x1f == 0;
}

comptime {
    assert(@intFromEnum(Transport.protocol_violation) == 0x0a);
    assert(@intFromEnum(Application.no_error) == 0x0100);
    // The overlap the module comment warns about, made a proof rather than a
    // claim: the same number names different things in the two registries.
    assert(@intFromEnum(Application.stream_creation_error) != @intFromEnum(Transport.internal_error));
    assert(isReserved(0x1b));
    assert(isReserved(0x1b + 0x1f));
    assert(!isReserved(0x1c));
}

test "a crypto error carries the alert it was built from" {
    const code = Transport.fromAlert(48); // unknown_ca
    try std.testing.expectEqual(@as(u62, 0x0130), @intFromEnum(code));
    try std.testing.expectEqual(@as(?u8, 48), code.alert());
    try std.testing.expectEqual(@as(?u8, null), Transport.protocol_violation.alert());
    try std.testing.expectEqual(@as(?u8, null), @as(Transport, @enumFromInt(0x0200)).alert());
}

test "an unknown code keeps its value rather than becoming an error" {
    // Section 20 requires an unknown code to be treated as `INTERNAL_ERROR` by
    // the receiver, which is the *consumer's* decision; the enum's job is to
    // carry the number without losing it.
    const unknown: Transport = @enumFromInt(0x4242);
    try std.testing.expectEqual(@as(u62, 0x4242), @intFromEnum(unknown));
}

test "the reserved pattern matches what section 22.5 describes" {
    var n: u62 = 0;
    while (n < 16) : (n += 1) {
        try std.testing.expect(isReserved(0x1f * n + 0x1b));
    }
    try std.testing.expect(!isReserved(0));
    try std.testing.expect(!isReserved(0x0a));
}
