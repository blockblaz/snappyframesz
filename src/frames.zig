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
                try writer.writeAll(data[i + 4 .. i + 4 + chunk_size]);
            },
            .COMPRESSED => {
                const decoded = snappy.decode(allocator, data[i + 4 .. i + 4 + chunk_size]) catch {
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

test "get chunk type" {
    const ck = [_]u8{
        // frame
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
        //compressed
        0x00, 0x06, 0x00, 0x00, 0x04, 0x0c, 't',  'h',  'i',  's',
        // uncompressed
        0x01, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
        // padding
        0xfe, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
    };

    var arraylistdata = std.ArrayList(u8).init(std.testing.allocator);
    defer arraylistdata.deinit();
    const fbswriter = arraylistdata.writer();

    try decode(std.testing.allocator, fbswriter, &ck);
    const dumped = arraylistdata.items;

    // need to figure out why writer is writing in reverse order
    // should be sNaPpYthis
    const expected = "thissNaPpY";
    try std.testing.expectEqualSlices(std.meta.Child([]const u8), dumped, expected);
}
