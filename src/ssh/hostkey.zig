const std = @import("std");

pub const HostKeyError = error{
    InvalidSignatureBlob,
    InvalidHostKeyBlob,
    InvalidSignatureLength,
    InvalidPublicKeyLength,
    UnsupportedAlgorithm,
};

pub fn encode_ed25519_signature_blob(
    allocator: std.mem.Allocator,
    signature: *const [64]u8,
) ![]u8 {
    const algorithm = "ssh-ed25519";
    const blob_size = 4 + algorithm.len + 4 + signature.len;
    const signature_blob = try allocator.alloc(u8, blob_size);
    errdefer allocator.free(signature_blob);

    var offset: usize = 0;
    std.mem.writeInt(u32, signature_blob[offset..][0..4], @intCast(algorithm.len), .big);
    offset += 4;
    @memcpy(signature_blob[offset .. offset + algorithm.len], algorithm);
    offset += algorithm.len;

    std.mem.writeInt(u32, signature_blob[offset..][0..4], @intCast(signature.len), .big);
    offset += 4;
    @memcpy(signature_blob[offset .. offset + signature.len], signature);

    return signature_blob;
}

pub fn decode_ed25519_signature_blob(blob: []const u8) HostKeyError![64]u8 {
    var offset: usize = 0;

    if (blob.len < 4) return error.InvalidSignatureBlob;
    const alg_len = std.mem.readInt(u32, blob[offset..][0..4], .big);
    offset += 4;

    if (offset + alg_len > blob.len) return error.InvalidSignatureBlob;
    const algorithm = blob[offset .. offset + alg_len];
    offset += alg_len;

    if (!std.mem.eql(u8, algorithm, "ssh-ed25519")) return error.UnsupportedAlgorithm;

    if (offset + 4 > blob.len) return error.InvalidSignatureBlob;
    const sig_len = std.mem.readInt(u32, blob[offset..][0..4], .big);
    offset += 4;

    if (sig_len != 64) return error.InvalidSignatureLength;
    if (offset + sig_len > blob.len) return error.InvalidSignatureBlob;

    var signature: [64]u8 = undefined;
    @memcpy(&signature, blob[offset .. offset + 64]);
    return signature;
}

pub fn encode_ed25519_host_key_blob(
    allocator: std.mem.Allocator,
    public_key: *const [32]u8,
) ![]u8 {
    const algorithm = "ssh-ed25519";
    const blob_size = 4 + algorithm.len + 4 + public_key.len;
    const host_key_blob = try allocator.alloc(u8, blob_size);
    errdefer allocator.free(host_key_blob);

    var offset: usize = 0;
    std.mem.writeInt(u32, host_key_blob[offset..][0..4], @intCast(algorithm.len), .big);
    offset += 4;
    @memcpy(host_key_blob[offset .. offset + algorithm.len], algorithm);
    offset += algorithm.len;

    std.mem.writeInt(u32, host_key_blob[offset..][0..4], @intCast(public_key.len), .big);
    offset += 4;
    @memcpy(host_key_blob[offset .. offset + public_key.len], public_key);

    return host_key_blob;
}

pub fn decode_ed25519_host_key_blob(blob: []const u8) HostKeyError![32]u8 {
    var offset: usize = 0;

    if (blob.len < 4) return error.InvalidHostKeyBlob;
    const alg_len = std.mem.readInt(u32, blob[offset..][0..4], .big);
    offset += 4;

    if (offset + alg_len > blob.len) return error.InvalidHostKeyBlob;
    const algorithm = blob[offset .. offset + alg_len];
    offset += alg_len;

    if (!std.mem.eql(u8, algorithm, "ssh-ed25519")) return error.UnsupportedAlgorithm;

    if (offset + 4 > blob.len) return error.InvalidHostKeyBlob;
    const key_len = std.mem.readInt(u32, blob[offset..][0..4], .big);
    offset += 4;

    if (key_len != 32) return error.InvalidPublicKeyLength;
    if (offset + key_len > blob.len) return error.InvalidHostKeyBlob;

    var public_key: [32]u8 = undefined;
    @memcpy(&public_key, blob[offset .. offset + 32]);
    return public_key;
}

pub fn fingerprint_sha256(allocator: std.mem.Allocator, host_key_blob: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(host_key_blob, &digest, .{});

    const b64_len = std.base64.standard.Encoder.calcSize(digest.len);
    const b64 = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, &digest);

    return std.fmt.allocPrint(allocator, "SHA256:{s}", .{b64});
}

test "host key blob roundtrip" {
    const allocator = std.testing.allocator;
    const public_key: [32]u8 = [_]u8{0x11} ** 32;

    const blob = try encode_ed25519_host_key_blob(allocator, &public_key);
    defer allocator.free(blob);

    const decoded = try decode_ed25519_host_key_blob(blob);
    try std.testing.expectEqualSlices(u8, &public_key, &decoded);
}
