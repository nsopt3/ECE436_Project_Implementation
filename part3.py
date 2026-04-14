import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Configuration
INPUT_CSV = "packet_info.csv"
OUTPUT_DIR = "part3_results"

# ---------------------------------------------------
#                   Helper Functions
# ---------------------------------------------------
# Safely creates a directory if it doesn't exist, and returns a Path object.
def ensure_output_dir(path: str) -> Path:
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    return out

# Essentially a data cleaning and validation pipeline for our packet trace. 
# Takes a raw .csv and converts it into a clean dataframe for analysis.
def load_packet_data(csv_file: str) -> pd.DataFrame:  
    df = pd.read_csv(csv_file)

    # Clean whitespace
    df.columns = df.columns.str.strip()
   
    column_map = {
        "Pkt_Time": "timestamp",
        "Src_Address": "src_ip",
        "Src_Port": "src_port",
        "Dst_Address": "dst_ip",
        "Dst_Port": "dst_port",
        "Protocol": "protocol",
        "Length_(B)": "length",
    }

    # Validate columns exist, and stop execution if missing columns.
    missing_input_cols = [col for col in column_map if col not in df.columns]
    if missing_input_cols:
        raise ValueError(
            f"Missing required columns in {csv_file}: {missing_input_cols}\n"
            f"Found columns: {list(df.columns)}"
        )

    df = df.rename(columns=column_map)

    required_cols = [
        "timestamp", "length", "protocol",
        "src_ip", "dst_ip", "src_port", "dst_port"
    ]

    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns after rename: {missing}")

    # Convert numeric fields, e.g. if we have a string, convert it to a number
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["length"] = pd.to_numeric(df["length"], errors="coerce")
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")

    df["protocol"] = df["protocol"].astype(str).str.strip()

    # Drop packets missing critical info, since we can't analyze packets without time, length, protocol, etc.
    df = df.dropna(subset=["timestamp", "length", "protocol", "src_ip", "dst_ip"])

    # Sort by time, since interarrival calculation depends on time order.
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


# Here, we take packet data and assign each packet to a flow, by creating a unique string identifier.
def add_flow_id(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Build the flow id string
    df["flow_id"] = (
        df["src_ip"].astype(str) + ":" +
        df["src_port"].fillna(-1).astype("Int64").astype(str) + " -> " +
        df["dst_ip"].astype(str) + ":" +
        df["dst_port"].fillna(-1).astype("Int64").astype(str) + " | " +
        df["protocol"].astype(str)
    )
    return df


# ---------------------------------------------------
#                   Metric Calculations
# ---------------------------------------------------

# Computes the core statistical profile of our packet sizes. 
def compute_packet_size_metrics(df: pd.DataFrame) -> dict:
    sizes = df["length"]

    return {
        "packet_count": int(len(sizes)),
        "min_packet_size_bytes": float(sizes.min()),
        "max_packet_size_bytes": float(sizes.max()),
        "mean_packet_size_bytes": float(sizes.mean()),
        "median_packet_size_bytes": float(sizes.median()),
        "std_packet_size_bytes": float(sizes.std()),
    }

# Computes how much time passes between consecutive packets, summarizes timings.
def compute_interarrival_metrics(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    df = df.copy()
    df["interarrival_time"] = df["timestamp"].diff()

    inter = df["interarrival_time"].dropna()

    metrics = {
        "mean_interarrival_sec": float(inter.mean()) if not inter.empty else 0.0,
        "median_interarrival_sec": float(inter.median()) if not inter.empty else 0.0,
        "min_interarrival_sec": float(inter.min()) if not inter.empty else 0.0,
        "max_interarrival_sec": float(inter.max()) if not inter.empty else 0.0,
        "std_interarrival_sec": float(inter.std()) if not inter.empty else 0.0,
    }

    return df, metrics

# We are now working with per-flow statistics! 
def compute_flow_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flow duration = last packet time - first packet time per flow.
    """
    flow_summary = (
        df.groupby("flow_id")
        .agg(
            protocol=("protocol", "first"),
            src_ip=("src_ip", "first"),
            dst_ip=("dst_ip", "first"),
            src_port=("src_port", "first"),
            dst_port=("dst_port", "first"),
            packet_count=("length", "count"),
            total_bytes=("length", "sum"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max")
        )
        .reset_index()
    )

    flow_summary["flow_duration_sec"] = (
        flow_summary["last_seen"] - flow_summary["first_seen"]
    )

    flow_summary["avg_packet_size_bytes"] = (
        flow_summary["total_bytes"] / flow_summary["packet_count"]
    )

    return flow_summary.sort_values("total_bytes", ascending=False).reset_index(drop=True)

# Traffic composition, i.e., what protocols make up this traffic. 
def compute_protocol_distribution(df: pd.DataFrame) -> pd.DataFrame:
    protocol_summary = (
        df.groupby("protocol")
        .agg(
            packet_count=("protocol", "count"),
            total_bytes=("length", "sum")
        )
        .reset_index()
        .sort_values("packet_count", ascending=False)
        .reset_index(drop=True)
    )

    total_packets = protocol_summary["packet_count"].sum()
    total_bytes = protocol_summary["total_bytes"].sum()

    protocol_summary["packet_percent"] = (
        100 * protocol_summary["packet_count"] / total_packets
        if total_packets > 0 else 0
    )
    protocol_summary["byte_percent"] = (
        100 * protocol_summary["total_bytes"] / total_bytes
        if total_bytes > 0 else 0
    )

    return protocol_summary


# ---------------------------------------------------
#                   Plotting
# ---------------------------------------------------
def plot_packet_size_histogram(df: pd.DataFrame, output_dir: Path) -> None:
    plt.figure(figsize=(8, 5))
    plt.hist(df["length"], bins=30)
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(output_dir / "packet_size_histogram.png")
    plt.close()


def plot_interarrival_histogram(df: pd.DataFrame, output_dir: Path) -> None:
    inter = df["interarrival_time"].dropna()
    if inter.empty:
        return

    plt.figure(figsize=(8, 5))
    plt.hist(inter, bins=30)
    plt.title("Inter-arrival Time Distribution")
    plt.xlabel("Inter-arrival Time (seconds)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(output_dir / "interarrival_histogram.png")
    plt.close()


def plot_protocol_distribution(protocol_df: pd.DataFrame, output_dir: Path) -> None:
    if protocol_df.empty:
        return

    plt.figure(figsize=(8, 5))
    plt.bar(protocol_df["protocol"], protocol_df["packet_count"])
    plt.title("Protocol Distribution by Packet Count")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_dir / "protocol_distribution.png")
    plt.close()


def plot_top_flows(flow_df: pd.DataFrame, output_dir: Path, top_n: int = 10) -> None:
    top = flow_df.head(top_n)
    if top.empty:
        return

    labels = [
        f"{row['src_ip']}→{row['dst_ip']} ({row['protocol']})"
        for _, row in top.iterrows()
    ]

    plt.figure(figsize=(10, 6))
    plt.barh(labels, top["total_bytes"])
    plt.title(f"Top {top_n} Flows by Total Bytes")
    plt.xlabel("Total Bytes")
    plt.ylabel("Flow")
    plt.tight_layout()
    plt.savefig(output_dir / "top_flows_by_bytes.png")
    plt.close()


# ---------------------------------------------------
#                   main()
# ---------------------------------------------------
def main():
    output_dir = ensure_output_dir(OUTPUT_DIR)

    print(f"Loading packet data from: {INPUT_CSV}")
    df = load_packet_data(INPUT_CSV)
    df = add_flow_id(df)

    print("Computing packet size metrics...")
    packet_metrics = compute_packet_size_metrics(df)

    print("Computing inter-arrival metrics...")
    df, interarrival_metrics = compute_interarrival_metrics(df)

    print("Computing flow metrics...")
    flow_df = compute_flow_metrics(df)

    print("Computing protocol distribution...")
    protocol_df = compute_protocol_distribution(df)

    # Save tables
    df.to_csv(output_dir / "packets_with_interarrival.csv", index=False)
    flow_df.to_csv(output_dir / "flow_summary.csv", index=False)
    protocol_df.to_csv(output_dir / "protocol_summary.csv", index=False)

    # Save overall metrics
    summary_lines = []
    summary_lines.append("=== PACKET SIZE METRICS ===")
    for k, v in packet_metrics.items():
        summary_lines.append(f"{k}: {v}")

    summary_lines.append("\n=== INTER-ARRIVAL METRICS ===")
    for k, v in interarrival_metrics.items():
        summary_lines.append(f"{k}: {v}")

    summary_lines.append("\n=== OVERALL TRACE METRICS ===")
    summary_lines.append(f"capture_start_time: {df['timestamp'].min()}")
    summary_lines.append(f"capture_end_time: {df['timestamp'].max()}")
    summary_lines.append(f"trace_duration_sec: {df['timestamp'].max() - df['timestamp'].min()}")
    summary_lines.append(f"total_packets: {len(df)}")
    summary_lines.append(f"total_bytes: {df['length'].sum()}")
    summary_lines.append(f"total_flows: {flow_df['flow_id'].nunique()}")

    with open(output_dir / "summary_metrics.txt", "w") as f:
        f.write("\n".join(summary_lines))

    # Create plots
    print("Generating plots...")
    plot_packet_size_histogram(df, output_dir)
    plot_interarrival_histogram(df, output_dir)
    plot_protocol_distribution(protocol_df, output_dir)
    plot_top_flows(flow_df, output_dir)

    print("\nDone.")
    print(f"Results saved in: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
