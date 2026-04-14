import argparse
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec


# load the capture file

def load_capture(filepath):
    print(f"[*] Opening capture: {filepath}")
    # keep_packets=False discards each packet after we read it
    # without this, large captures will eat all your ram
    return pyshark.FileCapture(filepath, keep_packets=False)


# pull out dns records from the capture

def parse_dns(cap):
    records = []

    for pkt in cap:
        try:
            # skip anything that isn't a dns packet
            if not hasattr(pkt, "dns"):
                continue

            dns = pkt.dns
            ts = float(pkt.sniff_timestamp)
            qname = ""
            ips = []

            # grab the domain name being queried
            if hasattr(dns, "qry_name"):
                qname = dns.qry_name.lower().rstrip(".")

            # flags_response == "1" means this is an answer, not a question
            is_response = (
                hasattr(dns, "flags_response")
                and dns.flags_response == "1"
            )

            # if it's a response, grab the ip addresses it resolved to
            # "a" = ipv4 record, "aaaa" = ipv6 record
            if is_response:
                for attr in ("a", "aaaa"):
                    if hasattr(dns, attr):
                        ips.extend(str(getattr(dns, attr)).split(","))

            # store everything we care about for this packet
            records.append({
                "timestamp":    ts,
                "query_name":   qname,
                "is_response":  is_response,
                "response_ips": ips,
            })

        except AttributeError:
            continue

    df = pd.DataFrame(records)
    print(f"[*] DNS records found: {len(df)}")
    return df


# pull out https packets (port 443)

def parse_https(cap):
    records = []

    for pkt in cap:
        try:
            # need both ip and tcp layers, otherwise skip
            if not (hasattr(pkt, "ip") and hasattr(pkt, "tcp")):
                continue

            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)

            # only care about traffic on port 443
            if src_port != 443 and dst_port != 443:
                continue

            ts = float(pkt.sniff_timestamp)
            length = int(pkt.length)

            # if the source is port 443, the server is sending to us
            # if the dest is port 443, we're the ones sending
            direction = "received" if src_port == 443 else "sent"

            records.append({
                "timestamp": ts,
                "src_ip":    pkt.ip.src,
                "dst_ip":    pkt.ip.dst,
                "length":    length,
                "direction": direction,
            })

        except (AttributeError, ValueError):
            continue

    df = pd.DataFrame(records)
    print(f"[*] HTTPS packets found: {len(df)}")
    return df


# compute dns metrics

def dns_metrics(df_dns, top_n=20):
    # filter to just queries (not responses) so we count lookups, not answers
    queries = df_dns[
        ~df_dns["is_response"] & (df_dns["query_name"] != "")
    ]
    # count how many times each domain was queried, keep the top n
    query_counts = queries["query_name"].value_counts().head(top_n)

    # build a domain -> set of ips mapping from the response packets
    domain_to_ips = {}
    for _, row in df_dns[df_dns["is_response"]].iterrows():
        if row["query_name"] and row["response_ips"]:
            # strip whitespace from each ip just in case
            ips = {ip.strip() for ip in row["response_ips"] if ip.strip()}
            # setdefault creates the key with an empty set if it doesn't exist yet
            domain_to_ips.setdefault(row["query_name"], set()).update(ips)

    return query_counts, domain_to_ips


# compute https data volume per remote ip

def https_metrics(df_https, top_n=20):
    if df_https.empty:
        return pd.DataFrame()

    df_https = df_https.copy()

    # figure out which ip is the remote server for each packet
    # sent = we're talking to dst, received = src is talking to us
    df_https["remote_ip"] = df_https.apply(
        lambda r: r["dst_ip"] if r["direction"] == "sent" else r["src_ip"],
        axis=1
    )

    # group by remote ip and direction, then sum up the bytes
    volume = (
        df_https
        .groupby(["remote_ip", "direction"])["length"]
        .sum()
        # pivot so sent and received become their own columns
        .unstack(fill_value=0)
        .rename(columns={
            "sent":     "bytes_sent",
            "received": "bytes_received"
        })
    )

    # add a total column so we can sort by overall traffic
    volume["total"] = volume.sum(axis=1)
    return volume.sort_values("total", ascending=False).head(top_n)


# plot everything

def plot_results(query_counts, https_volume):
    fig = plt.figure(figsize=(16, 10), facecolor="#0d1117")
    fig.suptitle(
        "Part 4 - DNS & HTTPS Behaviour Analysis",
        fontsize=16,
        fontweight="bold",
        color="#c9d1d9",
        y=0.98
    )

    # gridspec lets us stack two subplots vertically with some spacing
    gs = gridspec.GridSpec(2, 1, figure=fig, hspace=0.55)

    # dns query count chart

    ax1 = fig.add_subplot(gs[0])
    ax1.set_facecolor("#161b22")

    if not query_counts.empty:
        # [::-1] reverses the order so the highest count is at the top
        bars = ax1.barh(
            query_counts.index[::-1],
            query_counts.values[::-1],
            color="#58a6ff",
            edgecolor="#21262d"
        )
        ax1.set_xlabel("Query Count", color="#8b949e")
        ax1.set_title("Top DNS Queries (domains resolved)", color="#c9d1d9", pad=8)
        ax1.tick_params(colors="#8b949e", labelsize=8)
        ax1.spines[:].set_color("#30363d")

        # add a count label at the end of each bar
        for bar in bars:
            w = bar.get_width()
            ax1.text(
                w + 0.3,
                bar.get_y() + bar.get_height() / 2,
                str(int(w)),
                va="center",
                ha="left",
                fontsize=7,
                color="#8b949e"
            )
    else:
        ax1.text(
            0.5, 0.5, "No DNS data found",
            transform=ax1.transAxes,
            ha="center", va="center",
            color="#8b949e"
        )

    # https data volume chart

    ax2 = fig.add_subplot(gs[1])
    ax2.set_facecolor("#161b22")

    if not https_volume.empty:
        ips = https_volume.index.tolist()
        x = range(len(ips))
        width = 0.35

        # convert bytes to KB so the numbers aren't huge
        sent_kb = (
            https_volume
            .get("bytes_sent", pd.Series(dtype=float))
            .fillna(0).values / 1024
        )
        recv_kb = (
            https_volume
            .get("bytes_received", pd.Series(dtype=float))
            .fillna(0).values / 1024
        )

        # offset the two bars left/right so they sit side by side
        ax2.bar(
            [i - width / 2 for i in x], sent_kb,
            width=width, label="Sent (KB)",
            color="#3fb950", edgecolor="#21262d"
        )
        ax2.bar(
            [i + width / 2 for i in x], recv_kb,
            width=width, label="Received (KB)",
            color="#f78166", edgecolor="#21262d"
        )

        ax2.set_xticks(list(x))
        ax2.set_xticklabels(
            ips, rotation=40, ha="right", fontsize=7, color="#8b949e"
        )
        ax2.set_ylabel("Data (KB)", color="#8b949e")
        ax2.set_title(
            "HTTPS Data Volume per Remote IP (port 443)",
            color="#c9d1d9", pad=8
        )
        ax2.tick_params(colors="#8b949e")
        ax2.spines[:].set_color("#30363d")
        ax2.legend(facecolor="#21262d", labelcolor="#c9d1d9", fontsize=8)
    else:
        ax2.text(
            0.5, 0.5, "No HTTPS data found",
            transform=ax2.transAxes,
            ha="center", va="center",
            color="#8b949e"
        )

    plt.savefig(
        "part4_output.png", dpi=150,
        bbox_inches="tight", facecolor=fig.get_facecolor()
    )
    print("[*] Plot saved -> part4_output.png")
    plt.show()


# main

def main():
    parser = argparse.ArgumentParser(description="Part 4 - DNS & HTTPS analysis")
    parser.add_argument("capture_file", help="Path to .pcap or .pcapng file")
    parser.add_argument(
        "--top", type=int, default=20,
        help="How many top entries to show (default: 20)"
    )
    args = parser.parse_args()

    # dns pass — pyshark reads sequentially so we need a separate pass for each
    cap_dns = load_capture(args.capture_file)
    df_dns = parse_dns(cap_dns)
    cap_dns.close()

    query_counts, domain_to_ips = dns_metrics(df_dns, top_n=args.top)

    print("\nTop DNS Queries")
    print(query_counts.to_string())

    print("\nDomain -> IP Mappings (first 10)")
    for i, (domain, ips) in enumerate(domain_to_ips.items()):
        if i >= 10:
            print("  ...")
            break
        print(f"  {domain:45s} -> {', '.join(sorted(ips))}")

    # https pass
    cap_https = load_capture(args.capture_file)
    df_https = parse_https(cap_https)
    cap_https.close()

    https_volume = https_metrics(df_https, top_n=args.top)

    if not https_volume.empty:
        print("\nHTTPS Volume per Remote IP (KB)")
        print((https_volume / 1024).round(1).to_string())

    plot_results(query_counts, https_volume)


if __name__ == "__main__":
    main()