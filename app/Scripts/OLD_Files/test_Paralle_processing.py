import concurrent.futures
import time

def task_function(x):
    time.sleep(x)
    return x * x

def measure_multiple_processes_execution_times():
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
        futures = []
        for i in range(5):
            start_time = time.time()
            future = executor.submit(task_function, i)
            futures.append((future, start_time))

        for future, start_time in futures:
            result = future.result()
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Task completed with result: {result}")
            print(f"Execution time: {execution_time} seconds")

if __name__ == "__main__":
    measure_multiple_processes_execution_times()