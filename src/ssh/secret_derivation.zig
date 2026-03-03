const std = @import("std");
const crypto = std.crypto;
const kex_methods = @import("kex_methods.zig");

pub const DerivationError = error{
    InvalidHashAlgorithm,
    DerivationFailed,
    OutOfMemory,
};

pub const QuicSecrets = struct {
    client_initial_secret: [32]u8,
    server_initial_secret: [32]u8,
    hash_algorithm: kex_methods.HashAlgorithm,

    pub fn zeroize(self: *QuicSecrets) void {
        @memset(&self.client_initial_secret, 0);
        @memset(&self.server_initial_secret, 0);
    }
};

pub fn deriveQuicSecrets(
    shared_secret: []const u8,
    exchange_hash: []const u8,
    hash_algorithm: kex_methods.HashAlgorithm,
) DerivationError!QuicSecrets {
    var secrets = QuicSecrets{
        .client_initial_secret = undefined,
        .server_initial_secret = undefined,
        .hash_algorithm = hash_algorithm,
    };

    const client_label = "client";
    switch (hash_algorithm) {
        .sha256 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha256.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            client_hmac.final(&secrets.client_initial_secret);
        },
        .sha384 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha384.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            var client_digest: [48]u8 = undefined;
            defer @memset(&client_digest, 0);
            client_hmac.final(&client_digest);
            @memcpy(&secrets.client_initial_secret, client_digest[0..32]);
        },
        .sha512 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha512.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            var client_digest: [64]u8 = undefined;
            defer @memset(&client_digest, 0);
            client_hmac.final(&client_digest);
            @memcpy(&secrets.client_initial_secret, client_digest[0..32]);
        },
    }

    const server_label = "server";
    switch (hash_algorithm) {
        .sha256 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha256.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            server_hmac.final(&secrets.server_initial_secret);
        },
        .sha384 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha384.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            var server_digest: [48]u8 = undefined;
            defer @memset(&server_digest, 0);
            server_hmac.final(&server_digest);
            @memcpy(&secrets.server_initial_secret, server_digest[0..32]);
        },
        .sha512 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha512.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            var server_digest: [64]u8 = undefined;
            defer @memset(&server_digest, 0);
            server_hmac.final(&server_digest);
            @memcpy(&secrets.server_initial_secret, server_digest[0..32]);
        },
    }

    return secrets;
}

pub fn expandLabel(
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: usize,
    hash_algorithm: kex_methods.HashAlgorithm,
    output: []u8,
) DerivationError!void {
    if (output.len < length) return error.DerivationFailed;
    if (length > 0xFFFF) return error.DerivationFailed;

    const length_be = [2]u8{ @intCast((length >> 8) & 0xFF), @intCast(length & 0xFF) };
    const prefix = "tls13 ";
    if (prefix.len + label.len > 255) return error.DerivationFailed;
    if (context.len > 255) return error.DerivationFailed;

    const full_label_len: u8 = @intCast(prefix.len + label.len);
    const context_len: u8 = @intCast(context.len);
    const counter = [_]u8{0x01};

    switch (hash_algorithm) {
        .sha256 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha256.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter);
            var digest: [32]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 32)], digest[0..@min(length, 32)]);
        },
        .sha384 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha384.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter);
            var digest: [48]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 48)], digest[0..@min(length, 48)]);
        },
        .sha512 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha512.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter);
            var digest: [64]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 64)], digest[0..@min(length, 64)]);
        },
    }
}

test "derive QUIC secrets from SSH key exchange" {
    const shared_secret = "test-shared-secret-from-curve25519-key-exchange";
    const exchange_hash = "test-exchange-hash-from-sha256";

    var secrets = try deriveQuicSecrets(shared_secret, exchange_hash, .sha256);
    defer secrets.zeroize();
    try std.testing.expect(!std.mem.eql(u8, &secrets.client_initial_secret, &secrets.server_initial_secret));
}
