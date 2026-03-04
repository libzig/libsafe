const std = @import("std");
const ssh_secrets = @import("secret_derivation.zig");

pub const RekeyError = error{
    DerivationFailed,
    OutOfMemory,
};

pub const RekeyThresholdPolicy = struct {
    max_bytes: u64,
    max_seconds: u64,

    pub fn should_rekey(self: RekeyThresholdPolicy, bytes_since_last_rekey: u64, seconds_since_last_rekey: u64) bool {
        return bytes_since_last_rekey >= self.max_bytes or seconds_since_last_rekey >= self.max_seconds;
    }
};

pub const RekeyContextLabel = enum {
    handshake,
    application,
    update,

    pub fn as_string(self: RekeyContextLabel) []const u8 {
        return switch (self) {
            .handshake => "handshake",
            .application => "application",
            .update => "update",
        };
    }
};

pub const RekeyTrafficSecrets = struct {
    client_to_server: [32]u8,
    server_to_client: [32]u8,

    pub fn zeroize(self: *RekeyTrafficSecrets) void {
        @memset(&self.client_to_server, 0);
        @memset(&self.server_to_client, 0);
    }
};

pub const OwnedSecretBuffer = struct {
    allocator: std.mem.Allocator,
    buf: []u8,

    pub fn init_copy(allocator: std.mem.Allocator, data: []const u8) RekeyError!OwnedSecretBuffer {
        const copied = try allocator.dupe(u8, data);
        return .{
            .allocator = allocator,
            .buf = copied,
        };
    }

    pub fn as_slice(self: *const OwnedSecretBuffer) []const u8 {
        return self.buf;
    }

    pub fn deinit(self: *OwnedSecretBuffer) void {
        @memset(self.buf, 0);
        self.allocator.free(self.buf);
        self.buf = &[_]u8{};
    }
};

pub fn derive_next_generation_traffic_secrets(
    allocator: std.mem.Allocator,
    shared_secret_k: []const u8,
    exchange_hash_h: []const u8,
    context_label: RekeyContextLabel,
    generation: u32,
) RekeyError!RekeyTrafficSecrets {
    var generation_context: [4]u8 = undefined;
    std.mem.writeInt(u32, &generation_context, generation, .big);

    const client_label = try std.fmt.allocPrint(allocator, "rekey/client/{s}", .{context_label.as_string()});
    defer allocator.free(client_label);
    const server_label = try std.fmt.allocPrint(allocator, "rekey/server/{s}", .{context_label.as_string()});
    defer allocator.free(server_label);

    const client_secret = ssh_secrets.deriveSshQuicExporterSecret(
        allocator,
        shared_secret_k,
        exchange_hash_h,
        client_label,
        &generation_context,
    ) catch {
        return error.DerivationFailed;
    };

    const server_secret = ssh_secrets.deriveSshQuicExporterSecret(
        allocator,
        shared_secret_k,
        exchange_hash_h,
        server_label,
        &generation_context,
    ) catch {
        return error.DerivationFailed;
    };

    return .{
        .client_to_server = client_secret,
        .server_to_client = server_secret,
    };
}

test "rekey threshold policy checks bytes and time" {
    const policy = RekeyThresholdPolicy{ .max_bytes = 1024, .max_seconds = 60 };
    try std.testing.expect(!policy.should_rekey(512, 10));
    try std.testing.expect(policy.should_rekey(1024, 10));
    try std.testing.expect(policy.should_rekey(1, 60));
}

test "derive next generation traffic secrets varies by generation" {
    const allocator = std.testing.allocator;
    const shared_secret = "test_shared_secret_32_bytes_value!";
    const exchange_hash = "test_exchange_hash_value_32_bytes!";

    var g1 = try derive_next_generation_traffic_secrets(
        allocator,
        shared_secret,
        exchange_hash,
        .application,
        1,
    );
    defer g1.zeroize();

    var g2 = try derive_next_generation_traffic_secrets(
        allocator,
        shared_secret,
        exchange_hash,
        .application,
        2,
    );
    defer g2.zeroize();

    try std.testing.expect(!std.mem.eql(u8, &g1.client_to_server, &g2.client_to_server));
    try std.testing.expect(!std.mem.eql(u8, &g1.server_to_client, &g2.server_to_client));
}

test "owned secret buffer stores independent copy" {
    const allocator = std.testing.allocator;
    var source = [_]u8{ 1, 2, 3, 4 };
    var owned = try OwnedSecretBuffer.init_copy(allocator, &source);
    defer owned.deinit();

    source[0] = 9;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, owned.as_slice());
}
