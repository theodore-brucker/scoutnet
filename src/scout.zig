const std = @import("std");

const HoneypotReport = struct {
    protocol: []const u8,
    source_ip: []const u8,
    timestamp: i64,
};

const C2Config = struct {
    ip: []const u8,
    port: u16,
};

fn logToFile(allocator: std.mem.Allocator, report: HoneypotReport) !void {
    const log_path = "scout_reports.log";

    const file = try std.fs.cwd().createFile(log_path, .{ .read = false, .truncate = false });
    defer file.close();

    try file.seekFromEnd(0);

    var json_string = std.ArrayList(u8).init(allocator);
    defer json_string.deinit();

    try std.json.stringify(.{
        .timestamp = report.timestamp,
        .protocol = report.protocol,
        .source_ip = report.source_ip,
        .status = "sent",
    }, .{}, json_string.writer());

    try json_string.append('\n');

    try file.writeAll(json_string.items);
}

fn getC2Config() C2Config {
    return .{
        .ip = "public_ip",
        .port = 8080,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const c2_config = getC2Config();

    // Attempt registration with central server
    if (try registerWithServer(allocator, c2_config)) {
        std.log.info("Successfully registered with central server at {s}:{}", .{ c2_config.ip, c2_config.port });
        // Start monitoring ports
        try monitorPorts(allocator, c2_config);
    } else {
        std.log.err("Failed to register with central server - exiting", .{});
        return error.RegistrationFailed;
    }
}

fn monitorPorts(allocator: std.mem.Allocator, c2_config: C2Config) !void {
    const ports = [_]u16{ 22, 23, 3389 };
    const protocols = [_][]const u8{ "SSH", "TELNET", "RDP" };

    // Track successfully bound ports
    var active_ports = std.ArrayList(struct {
        server: *std.net.Server, // Changed: Store pointer to allow mutation
        port: u16,
        protocol: []const u8,
    }).init(allocator);
    defer {
        // Cleanup servers on exit
        for (active_ports.items) |item| {
            item.server.deinit();
            allocator.destroy(item.server); // Add cleanup for allocated server
        }
        active_ports.deinit();
    }

    // Try to bind each port
    for (ports, protocols) |port, protocol| {
        const address = try std.net.Address.parseIp("0.0.0.0", port);

        // Allocate server on heap
        const server = try allocator.create(std.net.Server);
        errdefer allocator.destroy(server);

        // Initialize server
        server.* = address.listen(.{}) catch |err| {
            allocator.destroy(server);
            switch (err) {
                error.AccessDenied => {
                    std.log.err("Access denied while binding {s} port {d} - requires elevated privileges", .{ protocol, port });
                    continue;
                },
                error.AddressInUse => {
                    std.log.err("Port {d} ({s}) is already in use", .{ port, protocol });
                    continue;
                },
                else => {
                    std.log.err("Failed to bind {s} port {d}: {}", .{ protocol, port, err });
                    continue;
                },
            }
        };

        // Successfully bound the port
        try active_ports.append(.{
            .server = server,
            .port = port,
            .protocol = protocol,
        });
        std.log.info("Successfully monitoring {s} on port {d}", .{ protocol, port });
    }

    if (active_ports.items.len == 0) {
        std.log.err("No ports could be bound - agent will exit", .{});
        return error.NoPortsBound;
    }

    // Monitor all active ports
    while (true) {
        for (active_ports.items) |item| {
            var connection = item.server.accept() catch |err| {
                std.log.err("Error accepting connection on port {d} ({s}): {}", .{ item.port, item.protocol, err });
                continue;
            };
            defer connection.stream.close();

            const source_addr = connection.address;

            // Send report to central server
            sendReport(allocator, c2_config, .{
                .protocol = item.protocol,
                .source_ip = try std.fmt.allocPrint(allocator, "{}", .{source_addr}),
                .timestamp = std.time.timestamp(),
            }) catch |err| {
                std.log.err("Failed to send report for {s} connection: {}", .{ item.protocol, err });
            };
        }
    }
}

fn registerWithServer(allocator: std.mem.Allocator, c2_config: C2Config) !bool {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();

    const writer = payload.writer();
    try std.json.stringify(HoneypotReport{
        .protocol = "REGISTRATION",
        .source_ip = "public_ip",
        .timestamp = std.time.timestamp(),
    }, .{}, writer);

    const formatted_uri = try std.fmt.allocPrint(allocator, "http://{s}:{d}/report", .{ c2_config.ip, c2_config.port });
    defer allocator.free(formatted_uri);
    const uri = try std.Uri.parse(formatted_uri);

    var header_buffer: [4092]u8 = undefined;
    var req = try client.open(.PUT, uri, .{
        .server_header_buffer = &header_buffer,
        .headers = .{
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = payload.items.len };

    std.log.info("Sending registration with content-length: {d}", .{payload.items.len});
    std.log.info("Payload: {s}", .{payload.items});

    try req.send();
    try req.writer().writeAll(payload.items);
    try req.finish();
    try req.wait();

    const status = req.response.status;

    // Add debug logging for response
    std.log.info("Server response status: {}", .{status});

    if (req.response.content_length) |len| {
        if (len > 0) {
            var response_body = try allocator.alloc(u8, @intCast(len));
            defer allocator.free(response_body);
            const bytes_read = try req.reader().readAll(response_body);
            std.log.info("Response body: {s}", .{response_body[0..bytes_read]});
        }
    }

    if (status != .ok) {
        std.log.err("Server returned non-OK status: {}", .{status});
        return false;
    }

    return true;
}

fn sendReport(allocator: std.mem.Allocator, c2_config: C2Config, report: HoneypotReport) !void {
    try logToFile(allocator, report);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();

    try std.json.stringify(report, .{}, payload.writer());

    const formatted_uri = try std.fmt.allocPrint(allocator, "http://{s}:{any}/report", .{ c2_config.ip, c2_config.port });
    defer allocator.free(formatted_uri);
    const uri = try std.Uri.parse(formatted_uri);

    var header_buffer: [4092]u8 = undefined;
    var req = try client.open(.PUT, uri, .{
        .server_header_buffer = &header_buffer,
        .headers = .{
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = payload.items.len };

    try req.send();
    try req.writer().writeAll(payload.items);
    try req.finish();
    try req.wait();

    switch (req.response.status) {
        .ok => std.log.info("Report sent successfully", .{}),
        else => std.log.err("Failed to send report: {}", .{req.response.status}),
    }
}
