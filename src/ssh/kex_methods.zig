const std = @import("std");
const crypto = std.crypto;

pub const KexError = error{
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    UnsupportedMethod,
    KeyExchangeFailed,
    OutOfMemory,
};

pub const KexMethod = enum {
    curve25519_sha256,
    diffie_hellman_group14_sha256,

    pub fn fromName(method_name: []const u8) ?KexMethod {
        if (std.mem.eql(u8, method_name, "curve25519-sha256")) {
            return .curve25519_sha256;
        } else if (std.mem.eql(u8, method_name, "diffie-hellman-group14-sha256")) {
            return .diffie_hellman_group14_sha256;
        }
        return null;
    }

    pub fn name(self: KexMethod) []const u8 {
        return switch (self) {
            .curve25519_sha256 => "curve25519-sha256",
            .diffie_hellman_group14_sha256 => "diffie-hellman-group14-sha256",
        };
    }

    pub fn hashAlgorithm(self: KexMethod) HashAlgorithm {
        return switch (self) {
            .curve25519_sha256 => .sha256,
            .diffie_hellman_group14_sha256 => .sha256,
        };
    }
};

pub const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,

    pub fn digestLength(self: HashAlgorithm) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

pub const KexResult = struct {
    shared_secret: []const u8,
    exchange_hash: []const u8,
    hash_algorithm: HashAlgorithm,

    pub fn deinit(self: *KexResult, allocator: std.mem.Allocator) void {
        allocator.free(self.shared_secret);
        allocator.free(self.exchange_hash);
    }
};

pub const KexState = struct {
    method: KexMethod,
    is_client: bool,
    curve25519_private: ?[32]u8 = null,
    curve25519_public: ?[32]u8 = null,
    peer_public_key: ?[]const u8 = null,
    client_id_string: []const u8,
    server_id_string: []const u8,
    client_init_packet: []const u8,
    server_reply_packet: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        method: KexMethod,
        is_client: bool,
        client_id: []const u8,
        server_id: []const u8,
        client_init: []const u8,
        server_reply: []const u8,
    ) KexState {
        return .{
            .method = method,
            .is_client = is_client,
            .allocator = allocator,
            .client_id_string = client_id,
            .server_id_string = server_id,
            .client_init_packet = client_init,
            .server_reply_packet = server_reply,
        };
    }

    pub fn generateKeyPair(self: *KexState) KexError![]const u8 {
        switch (self.method) {
            .curve25519_sha256 => {
                var private: [32]u8 = undefined;
                crypto.random.bytes(&private);
                const public = crypto.dh.X25519.recoverPublicKey(private) catch return error.KeyExchangeFailed;
                self.curve25519_private = private;
                self.curve25519_public = public;
                return self.allocator.dupe(u8, &public);
            },
            .diffie_hellman_group14_sha256 => return error.UnsupportedMethod,
        }
    }

    pub fn setPeerPublicKey(self: *KexState, peer_key: []const u8) KexError!void {
        if (peer_key.len != 32 and self.method == .curve25519_sha256) return error.InvalidPublicKey;
        self.peer_public_key = try self.allocator.dupe(u8, peer_key);
    }

    pub fn computeSharedSecret(self: *KexState) KexError![]const u8 {
        switch (self.method) {
            .curve25519_sha256 => {
                if (self.curve25519_private == null) return error.InvalidPrivateKey;
                if (self.peer_public_key == null or self.peer_public_key.?.len != 32) return error.InvalidPublicKey;

                const peer_key: [32]u8 = self.peer_public_key.?[0..32].*;
                const shared_secret = crypto.dh.X25519.scalarmult(self.curve25519_private.?, peer_key) catch return error.KeyExchangeFailed;
                return self.allocator.dupe(u8, &shared_secret);
            },
            .diffie_hellman_group14_sha256 => return error.UnsupportedMethod,
        }
    }

    pub fn computeExchangeHash(self: *KexState, host_key: []const u8) KexError![]const u8 {
        const hash_alg = self.method.hashAlgorithm();
        var hash_input: std.ArrayList(u8) = .{};
        defer hash_input.deinit(self.allocator);

        try hash_input.appendSlice(self.allocator, self.client_id_string);
        try hash_input.appendSlice(self.allocator, self.server_id_string);
        try hash_input.appendSlice(self.allocator, self.client_init_packet);
        try hash_input.appendSlice(self.allocator, self.server_reply_packet);
        try hash_input.appendSlice(self.allocator, host_key);

        if (self.is_client) {
            if (self.curve25519_public) |pub_key| try hash_input.appendSlice(self.allocator, &pub_key);
            if (self.peer_public_key) |peer_key| try hash_input.appendSlice(self.allocator, peer_key);
        } else {
            if (self.peer_public_key) |peer_key| try hash_input.appendSlice(self.allocator, peer_key);
            if (self.curve25519_public) |pub_key| try hash_input.appendSlice(self.allocator, &pub_key);
        }

        const digest_len = hash_alg.digestLength();
        const digest = try self.allocator.alloc(u8, digest_len);

        switch (hash_alg) {
            .sha256 => crypto.hash.sha2.Sha256.hash(hash_input.items, digest[0..32], .{}),
            .sha384 => crypto.hash.sha2.Sha384.hash(hash_input.items, digest[0..48], .{}),
            .sha512 => crypto.hash.sha2.Sha512.hash(hash_input.items, digest[0..64], .{}),
        }

        return digest;
    }

    pub fn performKeyExchange(self: *KexState, host_key: []const u8) KexError!KexResult {
        const shared_secret = try self.computeSharedSecret();
        errdefer self.allocator.free(shared_secret);

        const exchange_hash = try self.computeExchangeHash(host_key);
        errdefer self.allocator.free(exchange_hash);

        return .{
            .shared_secret = shared_secret,
            .exchange_hash = exchange_hash,
            .hash_algorithm = self.method.hashAlgorithm(),
        };
    }

    pub fn deinit(self: *KexState) void {
        if (self.peer_public_key) |key| self.allocator.free(key);
        if (self.curve25519_private) |*priv| @memset(priv, 0);
    }
};

test "Curve25519 shared secret computation" {
    const allocator = std.testing.allocator;

    var client_state = KexState.init(allocator, .curve25519_sha256, true, "client-id", "server-id", "init", "reply");
    defer client_state.deinit();
    const client_public = try client_state.generateKeyPair();
    defer allocator.free(client_public);

    var server_state = KexState.init(allocator, .curve25519_sha256, false, "client-id", "server-id", "init", "reply");
    defer server_state.deinit();
    const server_public = try server_state.generateKeyPair();
    defer allocator.free(server_public);

    try client_state.setPeerPublicKey(server_public);
    try server_state.setPeerPublicKey(client_public);

    const client_secret = try client_state.computeSharedSecret();
    defer allocator.free(client_secret);
    const server_secret = try server_state.computeSharedSecret();
    defer allocator.free(server_secret);

    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}
