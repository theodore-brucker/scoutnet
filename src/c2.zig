const std = @import("std");

const HoneypotReport = struct {
    protocol: []const u8,
    source_ip: []const u8,
    timestamp: i64,
};

const LogEntry = struct {
    timestamp: i64,
    event_type: []const u8,
    source_ip: []const u8,
    protocol: []const u8,
};

fn logToFile(allocator: std.mem.Allocator, entry: LogEntry) !void {
    const log_path = "c2_reports.log";

    // Open log file with correct flags
    const file = try std.fs.cwd().createFile(log_path, .{ .read = false, .truncate = false });
    defer file.close();

    // Seek to end of file for appending
    try file.seekFromEnd(0);

    // Format the log entry as JSON
    var json_string = std.ArrayList(u8).init(allocator);
    defer json_string.deinit();

    try std.json.stringify(.{
        .timestamp = entry.timestamp,
        .event_type = entry.event_type,
        .source_ip = entry.source_ip,
        .protocol = entry.protocol,
    }, .{}, json_string.writer());

    try json_string.append('\n');

    // Write to file
    try file.writeAll(json_string.items);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create server address
    const address = try std.net.Address.parseIp("0.0.0.0", 8080);

    // Create server
    var server = try address.listen(.{});
    defer server.deinit();

    std.log.info("Honeypot collector listening on {}", .{address});

    while (true) {
        var connection = try server.accept();
        defer connection.stream.close();

        try handleConnection(allocator, &connection);
    }
}

fn handleConnection(allocator: std.mem.Allocator, connection: *std.net.Server.Connection) !void {
    std.log.info("Connection from {}", .{connection.address});

    var header_buffer: [4092]u8 = undefined;
    var total_read: usize = 0;

    // Read until we find \r\n\r\n
    var header_end: ?usize = null;
    var content_length: ?usize = null;

    // Read the initial data which should contain headers
    while (total_read < header_buffer.len) {
        const bytes_read = try connection.stream.read(header_buffer[total_read..]);
        if (bytes_read == 0) break;
        total_read += bytes_read;

        if (std.mem.indexOf(u8, header_buffer[0..total_read], "\r\n\r\n")) |end_pos| {
            header_end = end_pos;
            break;
        }
    }

    if (header_end == null) {
        std.log.err("Could not find end of headers", .{});
        return;
    }

    // Parse headers
    const headers = header_buffer[0..header_end.?];

    // Find Content-Length
    if (std.mem.indexOf(u8, headers, "content-length:")) |cl_start| {
        const cl_line_end = std.mem.indexOfPos(u8, headers, cl_start, "\r\n") orelse headers.len;
        const cl_str = std.mem.trim(u8, headers[cl_start + 15 .. cl_line_end], " \t\r\n");
        content_length = try std.fmt.parseInt(usize, cl_str, 10);
    }

    if (content_length == null) {
        std.log.err("No content length found", .{});
        return;
    }

    // Calculate how much of the body we already have
    const body_start = header_end.? + 4; // Skip \r\n\r\n
    const body_bytes_in_buffer = total_read - body_start;

    // Allocate buffer for the full body
    var body = try allocator.alloc(u8, content_length.?);
    defer allocator.free(body);

    // Copy any body bytes we already have
    if (body_bytes_in_buffer > 0) {
        @memcpy(body[0..body_bytes_in_buffer], header_buffer[body_start..total_read]);
    }

    // Read any remaining body bytes
    var body_read = body_bytes_in_buffer;
    while (body_read < content_length.?) {
        const bytes_read = try connection.stream.read(body[body_read..]);
        if (bytes_read == 0) break;
        body_read += bytes_read;
    }

    // Parse JSON
    var json_parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        body[0..body_read],
        .{},
    ) catch |err| {
        std.log.err("Failed to parse JSON: {}", .{err});
        std.log.err("Invalid JSON content: {s}", .{body[0..body_read]});
        try sendErrorResponse(connection, "Invalid JSON payload");
        return;
    };
    defer json_parsed.deinit();

    const root = json_parsed.value;

    // Validate the request
    const protocol = root.object.get("protocol") orelse {
        try sendErrorResponse(connection, "Missing protocol field");
        return;
    };

    const timestamp = root.object.get("timestamp").?.integer;
    const source_ip = root.object.get("source_ip").?.string;
    const protocol_str = protocol.string;

    try logToFile(allocator, .{
        .timestamp = timestamp,
        .event_type = if (std.mem.eql(u8, protocol_str, "REGISTRATION")) "registration" else "connection",
        .source_ip = source_ip,
        .protocol = protocol_str,
    });

    // Different handling for REGISTRATION vs report protocols
    if (std.mem.eql(u8, protocol.string, "REGISTRATION")) {
        std.log.info("Registration received - Protocol: {s}, Source IP: {s}, Timestamp: {d}", .{
            protocol.string,
            root.object.get("source_ip").?.string,
            root.object.get("timestamp").?.integer,
        });
    } else if (std.mem.eql(u8, protocol.string, "SSH") or
        std.mem.eql(u8, protocol.string, "TELNET") or
        std.mem.eql(u8, protocol.string, "RDP"))
    {
        std.log.info("Report received - Protocol: {s}, Source IP: {s}, Timestamp: {d}", .{
            protocol.string,
            root.object.get("source_ip").?.string,
            root.object.get("timestamp").?.integer,
        });
    } else {
        try sendErrorResponse(connection, "Invalid protocol type");
        return;
    }

    // Send success response
    try sendSuccessResponse(connection);
}

fn sendErrorResponse(connection: *std.net.Server.Connection, message: []const u8) !void {
    const response = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{{\"error\": \"{s}\"}}",
        .{ message.len + 11, message },
    );
    defer std.heap.page_allocator.free(response);

    try connection.stream.writeAll(response);
}
fn sendSuccessResponse(connection: *std.net.Server.Connection) !void {
    // Note: Each header line must end with \r\n, and headers must be followed by \r\n
    try connection.stream.writeAll("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 2\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n" ++
        "{}");
}
