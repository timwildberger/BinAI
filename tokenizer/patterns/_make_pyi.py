import inspect
import typing
from typing import Any

def format_type(typ):
    if hasattr(typ, '__module__') and typ.__module__ == 'typing':
        return str(typ).replace('typing.', '')
    if isinstance(typ, type):
        return typ.__name__
    return str(typ)

def generate_stub(module, output_path):
    type_aliases = []
    classes = []
    variables = []

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj):
            class_lines = [f"class {name}:"]
            hints = typing.get_type_hints(obj)
            for attr_name, attr_value in obj.__dict__.items():
                if inspect.isfunction(attr_value) or inspect.ismethod(attr_value):
                    sig = inspect.signature(attr_value)
                    class_lines.append(f"    def {attr_name}{sig}: ...")
                elif not attr_name.startswith("_"):
                    typ = hints.get(attr_name, Any)
                    class_lines.append(f"    {attr_name}: {format_type(typ)}")
            class_lines.append("")
            classes.append('\n'.join(class_lines))
        elif not name.startswith("_"):
            # Type alias detection: variable is a type
            if isinstance(obj, type) or str(obj).startswith("typing."):
                type_aliases.append(f"{name}: {format_type(obj)}")
            elif inspect.isfunction(obj):
                sig = inspect.signature(obj)
                variables.append(f"def {name}{sig}: ...")
            else:
                typ = getattr(module, "__annotations__", {}).get(name, Any)
                variables.append(f"{name}: {format_type(typ)}")

    with open(output_path, "w") as f:
        for line in type_aliases:
            f.write(line + "\n")
        f.write("\n")
        for class_def in classes:
            f.write(class_def + "\n")
        for line in variables:
            f.write(line + "\n")