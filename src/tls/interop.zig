const std = @import("std");
const handshake_mod = @import("handshake.zig");
const tls_context_mod = @import("tls_context.zig");
const transport_params_mod = @import("../core/transport_params.zig");

pub const CaseOutcome = enum {
    success,
    handshake_failed,
    alpn_mismatch,
    unsupported_cipher_suite,
    invalid_state,
    out_of_memory,
};

pub const ClientServerHelloCase = struct {
    server_name: []const u8 = "example.com",
    offered_alpn: []const []const u8 = &[_][]const u8{"h3"},
    server_hello_data: []const u8,
};

pub fn run_client_server_hello_case(
    allocator: std.mem.Allocator,
    case: ClientServerHelloCase,
) !CaseOutcome {
    var client = tls_context_mod.TlsContext.init(allocator, true);
    defer client.deinit();

    var client_tp = transport_params_mod.TransportParams.defaultClient();
    const client_tp_encoded = try client_tp.encode(allocator);
    defer allocator.free(client_tp_encoded);

    const ch = try client.startClientHandshakeWithParams(case.server_name, case.offered_alpn, client_tp_encoded);
    defer allocator.free(ch);

    client.processServerHello(case.server_hello_data) catch |err| {
        return map_tls_error(err);
    };
    return .success;
}

pub fn map_tls_error(err: anyerror) CaseOutcome {
    return switch (err) {
        error.HandshakeFailed => .handshake_failed,
        error.AlpnMismatch => .alpn_mismatch,
        error.UnsupportedCipherSuite => .unsupported_cipher_suite,
        error.InvalidState => .invalid_state,
        error.OutOfMemory => .out_of_memory,
        else => .handshake_failed,
    };
}

test "interop hook reports success for valid server hello" {
    const allocator = std.testing.allocator;

    var server_tp = transport_params_mod.TransportParams.defaultServer();
    const server_tp_encoded = try server_tp.encode(allocator);
    defer allocator.free(server_tp_encoded);

    const ext = [_]handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &[_]u8{ 0x00, 0x03, 0x02, 'h', '3' },
        },
        .{
            .extension_type = @intFromEnum(handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = server_tp_encoded,
        },
    };
    const sh = handshake_mod.ServerHello{
        .random = [_]u8{0x61} ** 32,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const sh_bytes = try sh.encode(allocator);
    defer allocator.free(sh_bytes);

    const outcome = try run_client_server_hello_case(allocator, .{ .server_hello_data = sh_bytes });
    try std.testing.expectEqual(CaseOutcome.success, outcome);
}

test "interop hook reports alpn mismatch" {
    const allocator = std.testing.allocator;

    var server_tp = transport_params_mod.TransportParams.defaultServer();
    const server_tp_encoded = try server_tp.encode(allocator);
    defer allocator.free(server_tp_encoded);

    const ext = [_]handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &[_]u8{ 0x00, 0x03, 0x02, 'h', '2' },
        },
        .{
            .extension_type = @intFromEnum(handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = server_tp_encoded,
        },
    };
    const sh = handshake_mod.ServerHello{
        .random = [_]u8{0x62} ** 32,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const sh_bytes = try sh.encode(allocator);
    defer allocator.free(sh_bytes);

    const outcome = try run_client_server_hello_case(allocator, .{ .server_hello_data = sh_bytes });
    try std.testing.expectEqual(CaseOutcome.alpn_mismatch, outcome);
}

test "interop hook reports unsupported cipher and malformed payload" {
    const allocator = std.testing.allocator;

    const bad_cipher_sh = handshake_mod.ServerHello{
        .random = [_]u8{0x63} ** 32,
        .cipher_suite = 0xDEAD,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const bad_cipher_bytes = try bad_cipher_sh.encode(allocator);
    defer allocator.free(bad_cipher_bytes);

    const bad_cipher_outcome = try run_client_server_hello_case(allocator, .{ .server_hello_data = bad_cipher_bytes });
    try std.testing.expectEqual(CaseOutcome.unsupported_cipher_suite, bad_cipher_outcome);

    const malformed = [_]u8{ 0x02, 0x00, 0x01, 0x00 };
    const malformed_outcome = try run_client_server_hello_case(allocator, .{ .server_hello_data = &malformed });
    try std.testing.expectEqual(CaseOutcome.handshake_failed, malformed_outcome);
}
