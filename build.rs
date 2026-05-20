fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut resource = winresource::WindowsResource::new();
    resource
        .set("CompanyName", "Devolutions")
        .set(
            "FileDescription",
            "psign-tool Authenticode signing and verification tool",
        )
        .set("InternalName", "psign-tool")
        .set("OriginalFilename", "psign-tool.exe")
        .set("ProductName", "psign")
        .set("LegalCopyright", "Copyright (c) Devolutions")
        .set("Comments", "https://github.com/Devolutions/psign");

    resource
        .compile()
        .expect("compile Windows version resource");
}
