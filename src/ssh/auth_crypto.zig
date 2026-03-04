const std = @import("std");
const ssh_hostkey = @import("hostkey.zig");
const ssh_signature = @import("signature.zig");

pub const AuthCryptoError = error{
    SignatureBlobMalformed,
    SignatureAlgorithmMismatch,
    SignatureLengthInvalid,
    PublicKeyLengthInvalid,
    VerificationFailed,
    OutOfMemory,
};

pub fn create_ed25519_auth_signature_blob(
    allocator: std.mem.Allocator,
    payload: []const u8,
    private_key: *const [64]u8,
) AuthCryptoError![]u8 {
    const raw_signature = ssh_signature.sign(payload, private_key) catch {
        return error.SignatureBlobMalformed;
    };

    return ssh_hostkey.encode_ed25519_signature_blob(allocator, &raw_signature) catch {
        return error.OutOfMemory;
    };
}

pub fn verify_ed25519_auth_signature_blob(
    payload: []const u8,
    signature_blob: []const u8,
    public_key: []const u8,
) AuthCryptoError!void {
    if (public_key.len != 32) return error.PublicKeyLengthInvalid;

    const decoded_signature = ssh_hostkey.decode_ed25519_signature_blob_strict(signature_blob) catch |err| {
        return switch (err) {
            error.UnsupportedAlgorithm => error.SignatureAlgorithmMismatch,
            error.InvalidSignatureLength => error.SignatureLengthInvalid,
            error.InvalidSignatureBlob, error.BlobTooLarge, error.TrailingData => error.SignatureBlobMalformed,
            else => error.SignatureBlobMalformed,
        };
    };

    var public_key_fixed: [32]u8 = undefined;
    @memcpy(&public_key_fixed, public_key);

    if (!ssh_signature.verify_ed25519(payload, &decoded_signature, &public_key_fixed)) {
        return error.VerificationFailed;
    }
}

pub fn timing_safe_equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |av, bv| {
        diff |= av ^ bv;
    }
    return diff == 0;
}

test "auth signature blob create and verify" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1234);
    const kp = ssh_signature.KeyPair.generate(prng.random());
    const payload = "ssh-userauth-request";

    const blob = try create_ed25519_auth_signature_blob(allocator, payload, &kp.private_key);
    defer allocator.free(blob);

    try verify_ed25519_auth_signature_blob(payload, blob, &kp.public_key);
}

test "auth signature verify rejects unsupported algorithm" {
    const allocator = std.testing.allocator;
    const bad_blob = try allocator.alloc(u8, 4 + 7 + 4 + 64);
    defer allocator.free(bad_blob);

    var offset: usize = 0;
    std.mem.writeInt(u32, bad_blob[offset..][0..4], 7, .big);
    offset += 4;
    @memcpy(bad_blob[offset .. offset + 7], "ssh-rsa");
    offset += 7;
    std.mem.writeInt(u32, bad_blob[offset..][0..4], 64, .big);
    offset += 4;
    @memset(bad_blob[offset .. offset + 64], 0xAA);

    const pk: [32]u8 = [_]u8{0x11} ** 32;
    try std.testing.expectError(
        error.SignatureAlgorithmMismatch,
        verify_ed25519_auth_signature_blob("payload", bad_blob, &pk),
    );
}

test "auth signature verify rejects malformed trailing bytes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(77);
    const kp = ssh_signature.KeyPair.generate(prng.random());
    const payload = "auth-payload";

    const blob = try create_ed25519_auth_signature_blob(allocator, payload, &kp.private_key);
    defer allocator.free(blob);

    const padded = try allocator.alloc(u8, blob.len + 1);
    defer allocator.free(padded);
    @memcpy(padded[0..blob.len], blob);
    padded[padded.len - 1] = 0xEE;

    try std.testing.expectError(
        error.SignatureBlobMalformed,
        verify_ed25519_auth_signature_blob(payload, padded, &kp.public_key),
    );
}

test "auth signature verify maps invalid signature length" {
    const allocator = std.testing.allocator;
    const bad_blob = try allocator.alloc(u8, 4 + 11 + 4 + 63);
    defer allocator.free(bad_blob);

    var offset: usize = 0;
    std.mem.writeInt(u32, bad_blob[offset..][0..4], 11, .big);
    offset += 4;
    @memcpy(bad_blob[offset .. offset + 11], "ssh-ed25519");
    offset += 11;
    std.mem.writeInt(u32, bad_blob[offset..][0..4], 63, .big);
    offset += 4;
    @memset(bad_blob[offset .. offset + 63], 0xBB);

    const pk: [32]u8 = [_]u8{0x33} ** 32;
    try std.testing.expectError(
        error.SignatureLengthInvalid,
        verify_ed25519_auth_signature_blob("payload", bad_blob, &pk),
    );
}

test "auth signature verify rejects wrong payload and public key size" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(91);
    const kp = ssh_signature.KeyPair.generate(prng.random());

    const blob = try create_ed25519_auth_signature_blob(allocator, "right", &kp.private_key);
    defer allocator.free(blob);

    try std.testing.expectError(
        error.VerificationFailed,
        verify_ed25519_auth_signature_blob("wrong", blob, &kp.public_key),
    );

    try std.testing.expectError(
        error.PublicKeyLengthInvalid,
        verify_ed25519_auth_signature_blob("right", blob, "short"),
    );
}

test "timing safe equal utility" {
    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 1, 2, 3, 4 };
    const c = [_]u8{ 1, 2, 3, 5 };

    try std.testing.expect(timing_safe_equal(&a, &b));
    try std.testing.expect(!timing_safe_equal(&a, &c));
    try std.testing.expect(!timing_safe_equal("x", "xy"));
}
