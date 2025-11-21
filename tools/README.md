# Tools Module

This directory hosts the individual reconnaissance tool modules.

## Structure

Each tool is a class that inherits from `BaseTool` and implements `run()`.

## BaseTool class

All tools inherit from `BaseTool` in `base.py`:

```python
from .base import BaseTool

class MyTool(BaseTool):
    def run(self, *args, **kwargs):
        # Implementation here
        pass
```

### BaseTool provides

- `self.output_dir` — output directory
- `self.base_name` — base name for output files
- `self.logger` — logger instance
- `self.run_command()` — helper to execute shell commands
- `self.check_input_file()` — helper to validate input files

## Adding a new tool

### Step 1: Create the module

Create `tools/mytool.py`:

```python
"""
MyTool - Description of your tool
"""

from .base import BaseTool
import os


class MyTool(BaseTool):
    """MyTool description"""
    
    def run(self, input_file):
        """Run MyTool"""
        if not self.check_input_file(input_file):
            self.logger.warning("[MyTool] Skipping - no input file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[MyTool] Starting...")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"mytool_{self.base_name}.txt"
        
        cmd = ["mytool", "-input", input_file, "-output", str(output_file)]
        
        success = self.run_command(cmd, output_file)
        
        if success:
            self.logger.info(f"[MyTool] ✓ Results saved to: {output_file}")
            return str(output_file)
        else:
            self.logger.warning("[MyTool] Error occurred")
            return str(output_file) if os.path.exists(output_file) else None
```

### Step 2: Import in `recon_tool.py`

Add:

```python
from tools.mytool import MyTool
```

### Step 3: Initialize inside `ReconOrchestrator`

Inside `__init__`:

```python
self.mytool = MyTool(self.output_dir, self.base_name, self.logger)
```

### Step 4: Call it in `run()`

```python
# Step X: My Tool
self.logger.info("\n[STEP X/Y] My Tool Description")
self.mytool.run(input_file)
```

## Best practices

1. **Always validate the input file** before running
2. **Use `self.logger`** for every log message
3. **Return the file path** on success, `None` on failure
4. **Handle errors gracefully**
5. **Write outputs to `self.output_dir`**
6. **Use `self.base_name`** for consistent naming

## Examples

See `subfinder.py`, `httpx.py`, and other modules for reference implementations.

