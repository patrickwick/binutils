const objcopy = @import("Build/Step/ObjCopy.zig");

/// Zig build.zig compatible build step wrapper.
pub const Build = struct {
    pub const Step = struct {
        pub const ObjCopy = objcopy.ObjCopy;
    };
};
