# Sherdal: A Hybrid Homomorphic Encryption Framework in Golang

<p align="center">
	<img src="logo.png" height="400" width="400"/>
</p>

This framework is based on the [Lattigo](https://github.com/tuneinsight/lattigo) library.

## Getting Started

### 1. Prerequisites (Setup Go)
Ensure that you have Go installed on your system.
* **Go version**: `1.21` or newer is recommended.
* Download and installation instructions can be found at the official Go website: [go.dev/doc/install](https://go.dev/doc/install).
* Verify your installation:
  ```bash
  go version
  ```

### 2. Clone the Repository
Clone the repository to your local machine:
```bash
git clone https://github.com/hosseinabdinf/sherdal.git
cd sherdal
```

### 3. Install Dependencies
Download and tidy all the required Go modules and libraries:
```bash
go mod tidy
```

---

## Command Line Examples

### Run All Project Tests
```bash
go test -v ./...
```

### Run Project Tests (Short Mode)
```bash
go test -v -short ./...
```

### Run Project Benchmarks with Memory Stats
```bash
go test -v -bench=. -run=^$ -benchmem ./...
```

### Generate Performance Profiles (CPU & Memory)
```bash
# CPU Profiling
go test -v -bench=. -run=^$ -cpuprofile=cpu.pprof ./...

# Memory Profiling
go test -v -bench=. -run=^$ -memprofile=mem.pprof ./...
```

---

## Project Structure & Supported Ciphers

Sherdal is organized into layers, each implementing a phase of symmetric or homomorphic hybrid encryption (HHE):

| Layer | Package Path | Description | Supported Ciphers |
| :--- | :--- | :--- | :--- |
| **SKE** | [`ske/`](file:///C:/Users/Nisec/Documents/Implementations/My_repos/sherdal/ske) | Cleartext reference implementations of symmetric ciphers. | `aes`, `hera`, `pasta`, `pasta2`, `rubato` |
| **HE Evaluation** | [`pkg/`](file:///C:/Users/Nisec/Documents/Implementations/My_repos/sherdal/pkg) | Homomorphic evaluations over BGV / RLWE. | `aes_bootstrapping`, `fv_hera`, `fv_pasta`, `fv_pasta2`, `fv_rubato` |
| **HHE** | [`hhe/`](file:///C:/Users/Nisec/Documents/Implementations/My_repos/sherdal/hhe) | High-level hybrid homomorphic encryption pipelines. | `aes`, `hera`, `pasta`, `pasta2`, `rubato` |
| **Applications** | [`applications/`](file:///C:/Users/Nisec/Documents/Implementations/My_repos/sherdal/applications) | Simple end-to-end HHE use cases (like image encryption). | `aes_ctr`, `hera`, `pasta`, `pasta2`, `rubato` |

---

## Detailed Testing & Benchmarking Guide

Below is a quick reference table showing how to test and benchmark each package layer:

| Layer | Package Target | Test Command | Benchmark Command | Example command |
| :--- | :--- | :--- | :--- | :--- |
| **SKE** | `ske/<cipher>` | `go test -v ./ske/...` | `go test -v -bench=. -run=^$ ./ske/...` | `go test -v -bench=BenchmarkPasta2_4 -run=^$ ./ske/pasta2` |
| **HE Evaluation** | `pkg/` | `go test -v -short ./pkg` | `go test -v -bench=. -run=^$ ./pkg` | `go test -v -bench=BenchmarkFVPasta -run=^$ ./pkg` |
| **HHE** | `hhe/<cipher>` | `go test -v ./hhe/...` | `go test -v -bench=. -run=^$ ./hhe/...` | `go test -v ./hhe/pasta2` |
| **Applications** | `applications/hhe/03_hhe_simple/<cipher>` | `go test -v ./applications/hhe/03_hhe_simple/...` | `go test -v -bench=. -run=^$ ./applications/hhe/03_hhe_simple/...` | `go test -v ./applications/hhe/03_hhe_simple/pasta2` |

> [!NOTE]
> Testing command flags:
> * `-v`: Enables verbose output so you can see individual test logs/run progress.
> * `-short`: Skips heavy/long-running BGV bootstrapping and homomorphic evaluation tests.
> * `-bench=.`: Runs all benchmark functions.
> * `-run=^$`: Skips standard unit tests during benchmark execution.
> * `-benchmem`: Includes memory allocations statistics (B/op and allocs/op).
> * `-cpuprofile=cpu.pprof` / `-memprofile=mem.pprof`: Generates pprof files for offline visualization.

---


## License

Sherdal is licensed under the Apache 2.0 License.


