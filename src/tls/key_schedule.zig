const std = @import("std");
const crypto = std.crypto;
const keys_mod = @import("../crypto/keys.zig");

pub const KeyScheduleError = error{
    InvalidSecret,
    InvalidSecretLength,
    DerivationFailed,
    OutOfMemory,
};

pub const HashAlgorithm = keys_mod.HashAlgorithm;

pub const KeySchedule = struct {
    hash_alg: HashAlgorithm,
    transcript_hash: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, hash_alg: HashAlgorithm) !KeySchedule {
        const hash_len = hash_alg.digestLength();
        const transcript = try allocator.alloc(u8, hash_len);
        @memset(transcript, 0);

        return .{
            .hash_alg = hash_alg,
            .transcript_hash = transcript,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *KeySchedule) void {
        @memset(self.transcript_hash, 0);
        self.allocator.free(self.transcript_hash);
    }

    pub fn updateTranscript(self: *KeySchedule, message: []const u8) void {
        switch (self.hash_alg) {
            .sha256 => {
                var hasher = crypto.hash.sha2.Sha256.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..32]);
            },
            .sha384 => {
                var hasher = crypto.hash.sha2.Sha384.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..48]);
            },
            .sha512 => {
                var hasher = crypto.hash.sha2.Sha512.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..64]);
            },
        }
    }

    pub fn deriveEarlySecret(self: *KeySchedule, psk: ?[]const u8) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const salt = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(salt);
        @memset(salt, 0);

        const ikm = if (psk) |p| p else blk: {
            const zeros = try self.allocator.alloc(u8, hash_len);
            @memset(zeros, 0);
            break :blk zeros;
        };
        defer if (psk == null) self.allocator.free(ikm);

        return try self.hkdfExtract(salt, ikm);
    }

    pub fn deriveHandshakeSecret(self: *KeySchedule, early_secret: []const u8, ecdhe: []const u8) KeyScheduleError![]u8 {
        const derived = try self.deriveSecret(early_secret, "derived", &[_]u8{});
        defer self.allocator.free(derived);
        return try self.hkdfExtract(derived, ecdhe);
    }

    pub fn deriveMasterSecret(self: *KeySchedule, handshake_secret: []const u8) KeyScheduleError![]u8 {
        const derived = try self.deriveSecret(handshake_secret, "derived", &[_]u8{});
        defer self.allocator.free(derived);

        const hash_len = self.hash_alg.digestLength();
        const zeros = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(zeros);
        @memset(zeros, 0);
        return try self.hkdfExtract(derived, zeros);
    }

    pub fn deriveHandshakeTrafficSecrets(self: *KeySchedule, handshake_secret: []const u8) KeyScheduleError!struct { client: []u8, server: []u8 } {
        const client = try self.deriveSecret(handshake_secret, "c hs traffic", self.transcript_hash);
        errdefer self.allocator.free(client);
        const server = try self.deriveSecret(handshake_secret, "s hs traffic", self.transcript_hash);
        return .{ .client = client, .server = server };
    }

    pub fn deriveApplicationTrafficSecrets(self: *KeySchedule, master_secret: []const u8) KeyScheduleError!struct { client: []u8, server: []u8 } {
        const client = try self.deriveSecret(master_secret, "c ap traffic", self.transcript_hash);
        errdefer self.allocator.free(client);
        const server = try self.deriveSecret(master_secret, "s ap traffic", self.transcript_hash);
        return .{ .client = client, .server = server };
    }

    fn deriveSecret(self: *KeySchedule, secret: []const u8, label: []const u8, context: []const u8) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const output = try self.allocator.alloc(u8, hash_len);
        errdefer self.allocator.free(output);
        try keys_mod.hkdfExpandLabel(secret, label, context, hash_len, self.hash_alg, output);
        return output;
    }

    fn hkdfExtract(self: *KeySchedule, salt: []const u8, ikm: []const u8) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const prk = try self.allocator.alloc(u8, hash_len);

        switch (self.hash_alg) {
            .sha256 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha256.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..32]);
            },
            .sha384 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha384.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..48]);
            },
            .sha512 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha512.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..64]);
            },
        }

        return prk;
    }
};

test "key schedule basic derivation" {
    const allocator = std.testing.allocator;
    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early = try ks.deriveEarlySecret(null);
    defer allocator.free(early);
    const hs = try ks.deriveHandshakeSecret(early, "shared");
    defer allocator.free(hs);
    const ms = try ks.deriveMasterSecret(hs);
    defer allocator.free(ms);

    try std.testing.expectEqual(@as(usize, 32), ms.len);
}
