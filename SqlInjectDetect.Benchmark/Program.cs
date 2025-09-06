using BenchmarkDotNet.Running;
using SqlInjectDetect.Benchmark;

public class Program
{
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<SqlInjectionDetectorBenchmark>();
    }
}