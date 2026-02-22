# Flash Drive UnCorruptor (FDU)

First aid toolkit for flash drives — detect, diagnose, and recover corrupted USB storage.

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `fdu-core` | Core recovery engine: filesystem analysis, repair strategies, health scoring |
| `fdu-cli` | Command-line interface |
| `fdu-web` | Web API server (Axum) |
| `fdu-device-enum` | USB device enumeration and platform abstraction |

## Building

```sh
cargo build --workspace
```

## Testing

```sh
cargo test --workspace
```

## License

MIT
