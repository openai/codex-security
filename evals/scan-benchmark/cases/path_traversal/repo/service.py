from pathlib import Path


def unsafe_read(root, user_path):
    return (Path(root) / user_path).read_text()


def safe_read(root, user_path):
    root = Path(root).resolve()
    target = (root / user_path).resolve()
    if not target.is_relative_to(root):
        raise ValueError("outside root")
    return target.read_text()
