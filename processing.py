import os
import sys
import json
import polars as pl

class DataFrame():
    def iter_chunks(self, file, size=100_000):
        counter = 0
        with open(file, "r") as fi:
            data = []
            for i, line in enumerate(fi.readlines()):
                if counter >= size: # process current junk
                    tmp = data.copy()
                    data.clear()
                    counter = 0
                    yield (
                        f"chunk_{i}", pl.json_normalize(tmp, infer_schema_length=1_000_000).rename(
                        lambda c:
                            c.replace(".", "_").replace("data_ech_result_", "").replace("data_ech_", "")
                        ).explode("results").unnest("results")
                    )
                try:
                    data.append({"results": json.loads(line)["data"]["ech"]["result"]})
                except KeyError:
                    continue
                except:
                    print(f"Failed to read string to json:\n{line}")
                    sys.exit(1)
                counter += 1
                        
            # process leftovers
            if len(data) > 0:
                yield (f"chunk_last", pl.json_normalize(data, infer_schema_length=1_000_000).rename(
                    lambda c:
                        c.replace(".", "_").replace("data_ech_result_", "").replace("data_ech_", "")
                    ).explode("results").unnest("results")
                )
        

# break down large file into smaller parquet files
def chunk_file(file, chunk_dir, size=20_000):
    print(f"=== Chunking Input File ===")
    print(f"=> chunking {file} with {size} rows per chunk")

    for (name, chunk) in DataFrame().iter_chunks(file, size=size):
        file_path = f"{os.path.join(chunk_dir, name)}.parquet"
        chunk.write_parquet(file_path)
        print(f"==> created: {file_path}.parquet")


# load each parquet chunk and combine into single dataframe
def combine_chunks(directory): 
    print(f"=== Merging Chunks ===")
    ordered = os.listdir(directory)
    ordered.sort()
    filtered = list(filter(lambda n: n.startswith("chunk_"), ordered))
    print(f"=> found {len(filtered)} chunks")
    
    return pl.concat([pl.read_parquet(os.path.join(directory,file)) for file in filtered], how="diagonal")

def remove_chunks(directory):
    print(f"=== Deleting Chunks ===")
    ordered = os.listdir(directory)
    ordered.sort()
    filtered = list(filter(lambda n: n.startswith("chunk_"), ordered))
    
    workdir = os.getcwd()
    print(f"=> deleting {len(filtered)} chunks from: '{os.path.join(workdir, directory)}'")
    
    for file in filtered:
        file_path = os.path.join(workdir, directory, file)
        print(f"==> deleted: {file_path}")
        os.remove(file_path)




import tempfile
def run(file_path, chunk_size=1000):
    temp_dir = tempfile.TemporaryDirectory()
    print(f"Preparing: {file_path} into chunks of size {chunk_size}")
    print(f"Creating temporary directory for chunking: {temp_dir.name}")

    chunk_file(file_path, temp_dir.name, size=chunk_size)
    print("")

    df = combine_chunks(temp_dir.name)
    print("")

    out_path = os.path.join(os.getcwd(), "processed.parquet")
    print(f"Writing final dataframe as parquet to: {out_path}")

    df.write_parquet(out_path)

    remove_chunks(temp_dir.name)


chunk_dir = "chunks"
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("File path to raw data required")
        sys.exit(1)

    file_path, chunk_size = sys.argv[1], 20_000

    if len(sys.argv) > 2:
        chunk_size = int(sys.argv[2])

    run(file_path, chunk_size=chunk_size)


