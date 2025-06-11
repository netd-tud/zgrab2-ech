import os
import sys
import json
import polars as pl
import zstandard as zstd
import io
import tempfile
import click

class DataFrame():

    def __init__(self, module):
        self.mod = module

    dctx = zstd.ZstdDecompressor()
    error_df = []

    def iter_zstd(self, file, size=100_000):
        return self._iter_stream(
            io.TextIOWrapper(
                self.dctx.stream_reader(open(file, "rb")), 
                encoding="utf-8",
            ), size)



    def iter_file(self, file, size=100_000):
        return self._iter_stream(open(file, "r"), size)

    def _iter_stream(self, stream, size):
        data, counter = [], 0
        for i, line in enumerate(stream):
            if counter >= size: # process current junk
                tmp = data.copy()
                data.clear()
                counter = 0
                yield (
                    f"chunk_{i}",
                    pl.json_normalize(tmp, infer_schema_length=1_000_000)
                    .explode("results")
                    .unnest("results") if self.mod == "ech" else pl.json_normalize(tmp, infer_schema_length=1_000_000)
                )

            try:
                raw = json.loads(line)
                row = raw["data"][self.mod]

                if row.get("error", None):
                    row["domain"] = raw["domain"]
                    self.error_df.append({
                        "scan_target": raw["domain"],
                        "scan_timestamp": row["timestamp"],
                        "scan_error": row["error"],
                        "protocol": "",
                    })
                    continue

                data.append({
                    "scan_target": raw["domain"], 
                    "results": row.get("result", None), 
                    "scan_timestamp": row["timestamp"],
                    "scan_error": ""
                })
            except:
                print(f"Failed to read string to json:\n{line}")
                sys.exit(1)
            counter += 1
                        
        # process leftovers
        if len(data) > 0:
            yield (
                f"chunk_last",
                pl.json_normalize(data, infer_schema_length=1_000_000)
                .explode("results")
                .unnest("results") if self.mod == "ech" else pl.json_normalize(data, infer_schema_length=1_000_000)
            )

        

# break down large file into smaller parquet files
def chunk_file(mod, file, chunk_dir, size=20_000, compressed=False):
    print(f"=== Chunking Input File ===")
    print(f"=> chunking {file} with {size} rows per chunk")

    df = DataFrame(mod)
    readerFn = df.iter_file(file, size) if not compressed else df.iter_zstd(file, size)

    for (name, chunk) in readerFn:
        file_path = f"{os.path.join(chunk_dir, name)}.parquet"
        chunk.write_parquet(file_path)
        print(f"==> created: {file_path}.parquet")

    if len(df.error_df) > 0:
        print(f"Writing error cases as df")
        errs = pl.json_normalize(df.error_df, infer_schema_length=1_000_000)
        errs.write_parquet(f"{os.path.join(chunk_dir, 'chunk_errors')}.parquet")


# load each parquet chunk and combine into single dataframe
def combine_chunks(directory): 
    print(f"=== Merging Chunks ===")
    ordered = os.listdir(directory)
    ordered.sort()
    ok_chunks = list(filter(lambda n: n.startswith("chunk_") and not n.endswith("_errors.parquet"), ordered))
    err_chunk = list(filter(lambda n: n.endswith("_errors.parquet"), ordered))

    print(f"=> found {len(ok_chunks)} chunks: {ok_chunks}")
    
    ok_df = pl.concat([pl.read_parquet(os.path.join(directory,file)) for file in ok_chunks]) #, how="diagonal")
    if len(err_chunk) <= 0:
        return ok_df

    print(f"=> found error chunk. Adding to result data-frame")
    err_df = pl.read_parquet(os.path.join(directory,err_chunk[0]))

    missing_cols = set(ok_df.columns) - set(err_df.columns)
    for col in missing_cols:
        dtype = ok_df.schema[col]
        err_df = err_df.with_columns(pl.lit(None, dtype=dtype).alias(col))

    err_df = err_df.select(ok_df.columns)

    return pl.concat([ok_df, err_df], how="vertical")


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



@click.command()
@click.option("--file", default=None, help="input file of (compressed/decompressed) zgrab2 results")
@click.option("--chunk-size", "chunk_size", default=1000, help="# of rows per chunk")
@click.option("--mod", default="ech", help="module used with zgrab2, required for schema parsing")
def run(mod, file, chunk_size):
    if not file:
        print("Must provide input file")
        sys.exit(1)

    compressed = file.endswith(".zst")

    temp_dir = tempfile.TemporaryDirectory()
    print(f"Preparing: {file} into chunks of size {chunk_size}")
    print(f"Creating temporary directory for chunking: {temp_dir.name}")

    chunk_file(mod, file, temp_dir.name, size=chunk_size, compressed=compressed)
    print("")

    df = combine_chunks(temp_dir.name)
    print("")

    out_path = os.path.join(os.getcwd(), "processed.parquet")
    print(f"Writing final dataframe as parquet to: {out_path}")

    df.write_parquet(out_path)

    remove_chunks(temp_dir.name)


chunk_dir = "chunks"
if __name__ == "__main__":
    run()


