# Benchmarking Pure HE Schemes


# Test instruction
Execute the following commands:

```bash
go test -run TestCNAME
```
# Benchmark instruction
Execute the following commands:

### List of CNAME
1. BenchmarkBFV
2. BenchmarkBGV
3. BenchmarkCKKS

```bash
go test -bench=^BenchmarkCNAME$ -benchmem
```