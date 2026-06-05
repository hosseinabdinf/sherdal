# Sherdal: A Hybrid Homomorphic Encryption Framework in Golang

<p align="center">
	<img src="logo.png" height="400" width="400"/>
</p>

This framework is based on the [Lattigo](https://github.com/tuneinsight/lattigo) library.

## Running Benchmarks

You can run benchmarks using Go to measure execution performance and memory metrics.

### Basic Benchmarking
To run all benchmarks across the project:
```bash
go test -bench=. -run=^$ ./...
```

### Memory Allocation Stats
To include detailed memory allocation statistics (like `B/op` and `allocs/op`):
```bash
go test -bench=. -run=^$ -benchmem ./...
```

### Profiling CPU and Memory
To collect profiling data for further analysis using `go tool pprof`:
```bash
# CPU Profiling
go test -bench=. -run=^$ -cpuprofile=cpu.pprof ./...

# Memory Profiling
go test -bench=. -run=^$ -memprofile=mem.pprof ./...
```

To profile a specific package (e.g., `ske/pasta2`):
```bash
go test -bench=. -run=^$ -benchmem -cpuprofile=cpu.pprof -memprofile=mem.pprof ./ske/pasta2
```

## License

Sherdal is licensed under the Apache 2.0 License.


