pub const ReadElfOptions = struct {
    file_path: []const u8,
};

pub fn readelf(options: ReadElfOptions) void {
    _ = options;
}
