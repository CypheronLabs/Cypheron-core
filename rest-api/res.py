import os

# Define folder and file structure
structure = {
    "src": [
        "main.rs",
        "lib.rs",
        "config.rs",
        "error.rs",
        "api/mod.rs",
        "api/kem.rs",
        "api/sig.rs",
        "api/hybrid.rs",
        "handlers/mod.rs",
        "handlers/kem_handler.rs",
        "handlers/sig_handler.rs",
        "handlers/hybrid_handler.rs",
        "services/mod.rs",
        "services/kem_service.rs",
        "services/sig_service.rs",
        "services/hybrid_service.rs",
        "models/mod.rs",
        "models/kem.rs",
        "models/sig.rs",
        "models/hybrid.rs",
        "utils/mod.rs",
        "utils/encoding.rs",
    ]
}

def create_structure(base_path, structure):
    for folder, files in structure.items():
        for file_path in files:
            full_path = os.path.join(base_path, folder, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w") as f:
                f.write("// " + os.path.basename(full_path) + "\n")

if __name__ == "__main__":
    root_dir = os.getcwd()
    print(f"Generating structure at: {root_dir}")
    create_structure(root_dir, structure)
    print("✅ REST API structure generated.")

