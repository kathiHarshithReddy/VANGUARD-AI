```markdown
# VANGUARD-AI Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill documents the development patterns and conventions used in the VANGUARD-AI Python codebase. It covers file naming, import/export styles, commit message habits, and testing patterns, providing clear examples and suggested commands for common workflows. This guide is intended to help contributors write consistent, maintainable code in VANGUARD-AI.

## Coding Conventions

### File Naming
- Use **snake_case** for all file and module names.
  - **Example:**  
    `data_processor.py`  
    `model_utils.py`

### Import Style
- Use **relative imports** within the package.
  - **Example:**
    ```python
    from .utils import preprocess_data
    from ..models import ModelClass
    ```

### Export Style
- Use **default exports** (i.e., no explicit `__all__` unless necessary).
  - **Example:**
    ```python
    # data_processor.py
    def process():
        pass
    ```

### Commit Messages
- Freeform style, no strict prefix required.
- Average length: ~41 characters.
  - **Example:**  
    `Fix bug in data normalization step`  
    `Add support for new input format`

## Workflows

### Adding a New Module
**Trigger:** When implementing a new feature or logical component  
**Command:** `/add-module`

1. Create a new Python file using snake_case (e.g., `feature_extractor.py`).
2. Implement your logic, using relative imports for dependencies.
3. Export functions/classes as needed (no need for explicit `__all__`).
4. Add or update tests if applicable.
5. Commit changes with a clear, concise message.

### Refactoring Code
**Trigger:** When improving or restructuring existing code  
**Command:** `/refactor`

1. Identify the code to refactor.
2. Rename files/modules using snake_case if needed.
3. Update relative imports in affected files.
4. Ensure all functionality remains intact.
5. Run tests to verify no regressions.
6. Commit with a message describing the refactor.

### Writing and Running Tests
**Trigger:** When adding or updating tests  
**Command:** `/test`

1. Write test files (pattern: `*.test.ts`).  
   *Note: The test framework is currently unknown; check project documentation or existing tests for details.*
2. Place tests in the appropriate directory.
3. Run the test suite using the project's preferred method.
4. Fix any failing tests before committing.

## Testing Patterns

- Test files follow the pattern: `*.test.ts`
- The testing framework is currently **unknown**; refer to existing test files for style and structure.
- Ensure all new features and bug fixes are covered by corresponding tests.

## Commands
| Command      | Purpose                                      |
|--------------|----------------------------------------------|
| /add-module  | Scaffold and add a new module                |
| /refactor    | Refactor existing code following conventions |
| /test        | Write and run tests                          |
```
