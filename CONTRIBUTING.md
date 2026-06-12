# Contributing to PhantomShell

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test with `php -l` for syntax
5. Commit: `git commit -m "Add: description"`
6. Push: `git push origin feature/my-feature`
7. Open a Pull Request

## Guidelines

- Maintain PHP 5.6+ compatibility
- Zero external dependencies
- All execution must go through the `x()` bypass engine
- Test on restricted environments (disable_functions enabled)
- Keep functions self-contained
- Follow existing code style

## Adding Commands

1. Add the function: `function cmd_yourcommand($sock, $args) { ... }`
2. Register in `dispatch()` switch statement
3. Add to `cmd_help()` output
4. Add to tab completion list in `tab_complete()`

## Adding Modules

Create a standalone PHP file in `modules/` that can be loaded via MINIMAL mode's `fetch` command.

## Reporting Issues

Use GitHub Issues with the provided templates for bug reports and feature requests.
