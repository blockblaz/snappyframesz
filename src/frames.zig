const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("snappyz");

pub fn decode(allocator: Allocator, writer: anytype, data: []const u8) !void {
    var i: usize = 0;
    // 1 byte chunktype 3 bytes chunk len
    while (i + 4 <= data.len) {
        const chunk_type = try ChunkType.getChunkType(data[i]);
        const chunk_size = getChunkSize(data, i + 1);
        if (i + 4 + chunk_size > data.len) {
            break;
        }

        switch (chunk_type) {
            .IDENTIFIER => {
                if (!std.mem.eql(u8, data[i .. i + 4 + chunk_size], &IDENTIFIER_FRAME)) {
                    return SnappyFrameError.InvalidIdentifierFrame;
                }
            },
            .UNCOMPRESSED => {
                // drop 4 bytes of crc as well
                try writer.writeAll(data[i + 4 + 4 .. i + 4 + chunk_size]);
            },
            .COMPRESSED => {
                // drop 4 bytes of crc as well
                const decoded = snappy.decode(allocator, data[i + 4 + 4 .. i + 4 + chunk_size]) catch {
                    return SnappyFrameError.InvalidSnappyBlockDecode;
                };
                defer allocator.free(decoded);

                try writer.writeAll(decoded);
            },
            .PADDING => {
                // noop
            },
        }

        i = i + 4 + chunk_size;
    }
}

pub fn encode(allocator: Allocator, writer: anytype, data: []u8) !void {
    // push identifier frame
    try writer.writeAll(&IDENTIFIER_FRAME);
    var i: usize = 0;
    while (i < data.len) {
        const chunk = data[i..@min(i + UNCOMPRESSED_CHUNK_SIZE, data.len)];
        const compressed = try snappy.encode(allocator, chunk);
        defer allocator.free(compressed);

        if (compressed.len < chunk.len) {
            const size = compressed.len + 4;
            const frame_header = [_]u8{ @as(u8, @intFromEnum(ChunkType.COMPRESSED)), @as(u8, @truncate(size)), @as(u8, @truncate(size >> 8)), @as(u8, @truncate(size >> 16)) };

            const crc_hash = snappy.crc(chunk);
            const crc_bytes = try allocator.alloc(u8, 4);
            defer allocator.free(crc_bytes);
            std.mem.writePackedInt(u32, crc_bytes, 0, crc_hash, .little);

            try writer.writeAll(frame_header ++ crc_bytes[0..4]);
            try writer.writeAll(compressed);
        } else {
            const size = chunk.len + 4;
            const frame_header = [_]u8{ @as(u8, @intFromEnum(ChunkType.UNCOMPRESSED)), @as(u8, @truncate(size)), @as(u8, @truncate(size >> 8)), @as(u8, @truncate(size >> 16)) };

            const crc_hash = snappy.crc(chunk);
            const crc_bytes = try allocator.alloc(u8, 4);
            defer allocator.free(crc_bytes);
            std.mem.writePackedInt(u32, crc_bytes, 0, crc_hash, .little);

            try writer.writeAll(frame_header ++ crc_bytes[0..4]);
            try writer.writeAll(chunk);
        }
        i = i + UNCOMPRESSED_CHUNK_SIZE;
    }
}

const ChunkType = enum(u8) {
    IDENTIFIER = 0xff,
    COMPRESSED = 0x00,
    UNCOMPRESSED = 0x01,
    PADDING = 0xfe,

    pub fn getChunkType(value: u8) !ChunkType {
        switch (value) {
            @intFromEnum(ChunkType.IDENTIFIER) => {
                return ChunkType.IDENTIFIER;
            },
            @intFromEnum(ChunkType.COMPRESSED) => {
                return ChunkType.COMPRESSED;
            },
            @intFromEnum(ChunkType.UNCOMPRESSED) => {
                return ChunkType.UNCOMPRESSED;
            },
            @intFromEnum(ChunkType.PADDING) => {
                return ChunkType.PADDING;
            },
            else => {
                return SnappyFrameError.InvalidChunkType;
            },
        }
    }
};

const SnappyFrameError = error{
    InvalidChunkType,
    InvalidIdentifierFrame,
    NotImplemented,
    InvalidSnappyBlockDecode,
};

fn getChunkSize(data: []const u8, offset: usize) usize {
    return (@as(u32, data[offset + 2]) << 16) + (@as(u32, data[offset + 1]) << 9) + data[offset];
}

const IDENTIFIER_STRING = [_]u8{ 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59 };
const IDENTIFIER_FRAME = [_]u8{ 0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59 };
const UNCOMPRESSED_CHUNK_SIZE = 65536;

test "decode" {
    const ck = [_]u8{
        // frame
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
        //compressed
        0x00, 0x0a, 0x00, 0x00, 0x38, 0x93, 0x3e, 0xdb, 0x04, 0x0c,
        't',  'h',  'i',  's',
        // uncompressed
         0x01, 0x0a, 0x00, 0x00, 0xc0, 0x80,
        0x04, 0xaa, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
        // padding
        0xfe, 0x06,
        0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
    };

    var arraylistdata = std.ArrayList(u8).init(std.testing.allocator);
    defer arraylistdata.deinit();
    const fbswriter = arraylistdata.writer();

    try decode(std.testing.allocator, fbswriter, &ck);
    const dumped = arraylistdata.items;

    const expected = "thissNaPpY";
    try std.testing.expectEqualSlices(std.meta.Child([]const u8), dumped, expected);
}

test "encode" {
    // this should lead to an uncompressed chunk
    const data = "thissNaPpY";
    const data_slice = try std.testing.allocator.alloc(u8, data.len);
    defer std.testing.allocator.free(data_slice);

    std.mem.copyForwards(u8, data_slice, data);

    var arraylistdata = std.ArrayList(u8).init(std.testing.allocator);
    defer arraylistdata.deinit();
    const fbswriter = arraylistdata.writer();

    try encode(std.testing.allocator, fbswriter, data_slice);
    const dumped = arraylistdata.items;
    const expected = IDENTIFIER_FRAME ++ [_]u8{ 0x01, 0x0e, 0x00, 0x00, 0x58, 0x09, 0xd7, 0x88 } ++ "thissNaPpY";

    try std.testing.expectEqualSlices(std.meta.Child([]const u8), dumped, expected);
}

test "encode<>decode" {
    // this should lead to a compressed chunk
    const data = "thissNaPpYYYYYYYYYYYYYYYYYYYY";
    const data_slice = try std.testing.allocator.alloc(u8, data.len);
    defer std.testing.allocator.free(data_slice);

    std.mem.copyForwards(u8, data_slice, data);
    var arraylistdata = std.ArrayList(u8).init(std.testing.allocator);
    defer arraylistdata.deinit();
    const fbswriter = arraylistdata.writer();

    try encode(std.testing.allocator, fbswriter, data_slice);
    const encoded = arraylistdata.items;

    var arraylistdata1 = std.ArrayList(u8).init(std.testing.allocator);
    defer arraylistdata1.deinit();
    const fbswriter1 = arraylistdata1.writer();
    try decode(std.testing.allocator, fbswriter1, encoded);
    const decoded = arraylistdata1.items;

    try std.testing.expectEqualSlices(std.meta.Child([]const u8), data, decoded);
}
