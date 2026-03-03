const std = @import("std");
const engine = @import("../engine.zig");

pub const LibfastTlsContextAdapter = struct {
    allocator: std.mem.Allocator,
    role: engine.Role,
    handshake_state: engine.HandshakeState,
    selected_alpn: ?[]u8,
    peer_transport_params: ?[]u8,

    pub fn init(allocator: std.mem.Allocator, role: engine.Role) LibfastTlsContextAdapter {
        return .{
            .allocator = allocator,
            .role = role,
            .handshake_state = .idle,
            .selected_alpn = null,
            .peer_transport_params = null,
        };
    }

    pub fn deinit(self: *LibfastTlsContextAdapter) void {
        if (self.selected_alpn) |alpn| {
            self.allocator.free(alpn);
            self.selected_alpn = null;
        }
        if (self.peer_transport_params) |tp| {
            self.allocator.free(tp);
            self.peer_transport_params = null;
        }
    }

    pub fn asEngine(self: *LibfastTlsContextAdapter) engine.Engine {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn cast(ctx: *anyopaque) *LibfastTlsContextAdapter {
        return @ptrCast(@alignCast(ctx));
    }

    fn castConst(ctx: *const anyopaque) *const LibfastTlsContextAdapter {
        return @ptrCast(@alignCast(ctx));
    }

    fn deinitErased(ctx: *anyopaque) void {
        const self = cast(ctx);
        self.deinit();
    }

    fn beginClientHandshakeErased(
        ctx: *anyopaque,
        server_name: []const u8,
        alpn_protocols: []const []const u8,
        local_transport_params: []const u8,
    ) engine.EngineError![]u8 {
        const self = cast(ctx);
        _ = server_name;

        if (self.role != .client or self.handshake_state != .idle) {
            return error.InvalidState;
        }

        if (self.selected_alpn) |old| {
            self.allocator.free(old);
            self.selected_alpn = null;
        }
        if (alpn_protocols.len > 0) {
            self.selected_alpn = self.allocator.dupe(u8, alpn_protocols[0]) catch {
                return error.OutOfMemory;
            };
        }

        if (self.peer_transport_params) |old_tp| {
            self.allocator.free(old_tp);
            self.peer_transport_params = null;
        }
        self.peer_transport_params = self.allocator.dupe(u8, local_transport_params) catch {
            return error.OutOfMemory;
        };

        self.handshake_state = .client_hello_sent;
        return self.allocator.dupe(u8, "libsafe-client-hello-v0") catch {
            return error.OutOfMemory;
        };
    }

    fn buildServerHelloErased(
        ctx: *anyopaque,
        client_hello_data: []const u8,
        server_supported_alpn: []const []const u8,
        local_transport_params: []const u8,
    ) engine.EngineError![]u8 {
        const self = cast(ctx);
        _ = client_hello_data;

        if (self.role != .server or self.handshake_state != .idle) {
            return error.InvalidState;
        }

        if (server_supported_alpn.len == 0) {
            return error.AlpnMismatch;
        }

        if (self.selected_alpn) |old| {
            self.allocator.free(old);
            self.selected_alpn = null;
        }
        self.selected_alpn = self.allocator.dupe(u8, server_supported_alpn[0]) catch {
            return error.OutOfMemory;
        };

        if (self.peer_transport_params) |old_tp| {
            self.allocator.free(old_tp);
            self.peer_transport_params = null;
        }
        self.peer_transport_params = self.allocator.dupe(u8, local_transport_params) catch {
            return error.OutOfMemory;
        };

        self.handshake_state = .server_hello_received;
        return self.allocator.dupe(u8, "libsafe-server-hello-v0") catch {
            return error.OutOfMemory;
        };
    }

    fn processServerHelloErased(ctx: *anyopaque, server_hello_data: []const u8) engine.EngineError!void {
        const self = cast(ctx);
        _ = server_hello_data;
        if (self.role != .client or self.handshake_state != .client_hello_sent) {
            return error.InvalidState;
        }
        self.handshake_state = .server_hello_received;
    }

    fn completeHandshakeErased(ctx: *anyopaque, shared_secret: []const u8) engine.EngineError!void {
        const self = cast(ctx);
        if (shared_secret.len == 0) {
            return error.HandshakeFailed;
        }
        if (self.handshake_state != .server_hello_received) {
            return error.InvalidState;
        }
        self.handshake_state = .handshake_complete;
    }

    fn getSelectedAlpnErased(ctx: *const anyopaque) ?[]const u8 {
        const self = castConst(ctx);
        return self.selected_alpn;
    }

    fn getPeerTransportParamsErased(ctx: *const anyopaque) ?[]const u8 {
        const self = castConst(ctx);
        return self.peer_transport_params;
    }

    fn stateErased(ctx: *const anyopaque) engine.HandshakeState {
        const self = castConst(ctx);
        return self.handshake_state;
    }

    fn freeBufferErased(ctx: *anyopaque, bytes: []u8) void {
        const self = cast(ctx);
        self.allocator.free(bytes);
    }

    const vtable: engine.EngineVTable = .{
        .deinit = deinitErased,
        .begin_client_handshake = beginClientHandshakeErased,
        .build_server_hello = buildServerHelloErased,
        .process_server_hello = processServerHelloErased,
        .complete_handshake = completeHandshakeErased,
        .get_selected_alpn = getSelectedAlpnErased,
        .get_peer_transport_params = getPeerTransportParamsErased,
        .state = stateErased,
        .free_buffer = freeBufferErased,
    };
};

test "adapter begins client handshake" {
    const allocator = std.testing.allocator;

    var adapter = LibfastTlsContextAdapter.init(allocator, .client);
    defer adapter.deinit();

    var tls_engine = adapter.asEngine();

    const offered = [_][]const u8{"h3"};
    const client_hello = try tls_engine.beginClientHandshake(
        "example.com",
        &offered,
        "tp",
    );
    defer tls_engine.freeBuffer(client_hello);

    try std.testing.expect(client_hello.len > 0);
    try std.testing.expectEqual(engine.HandshakeState.client_hello_sent, tls_engine.state());
}
